//! Optional LLM layer over an OpenAI-compatible chat completions API.
//!
//! Built for small, cheap models and few tokens: the model never sees raw
//! traffic, only a short digest of sources the rules could not settle, it is
//! only called when that digest changes, and calls are capped per hour and per day.

use std::{
    hash::{DefaultHasher, Hash, Hasher},
    sync::Mutex,
    time::Duration,
};

use anyhow::{Context as _, bail};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    config::LlmConfig,
    policy::{self, Rule},
};

pub struct Usage {
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
}

pub struct Llm {
    pub cfg: LlmConfig,
    http: reqwest::Client,
    key: Option<String>,
    last_digest: Mutex<u64>,
    /// Request options the endpoint rejected; learned on first failure.
    quirks: Mutex<Quirks>,
}

#[derive(Default, Clone, Copy)]
struct Quirks {
    no_temperature: bool,
    /// `response_format: json_schema` rejected; fall back to json_object.
    no_json_schema: bool,
    no_json_mode: bool,
    /// `reasoning_effort` rejected.
    no_reasoning_effort: bool,
    max_completion_tokens: bool,
}

#[derive(Debug, Deserialize)]
pub struct ProposedAction {
    pub target: String,
    pub action: String,
    #[serde(default)]
    pub ttl: Option<String>,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct Analysis {
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub actions: Vec<ProposedAction>,
}

const ANALYZE_SYSTEM: &str = "You are the security analyst for one Linux server. You get a digest of \
suspicious inbound sources seen by eBPF/XDP packet counters and SSH logs, and propose actions.
- action: \"ban\" (drop all its traffic), \"review\" (a human should look) or \"ignore\" (noise).
- target: an IP from the digest, or a /24 (IPv6 /64) containing 2+ listed IPs.
- ttl for bans: \"1h\", \"24h\", \"7d\"... shorter for first offences, longer for clear attacks.
- A successful SSH login after failures or from a new location is \"review\", never \"ignore\".
- confidence: 0-1, how sure you are the action is right. Don't ban on weak evidence.
- The operator policy overrides these guidelines.
Reply with JSON only: {\"summary\":\"<=25 words\",\"actions\":[{\"target\":\"<an IP or /24 from the digest>\",\
\"action\":\"ban\",\"ttl\":\"24h\",\"confidence\":0.9,\"reason\":\"<=15 words\"}]}. One action per source that needs one.";

impl Llm {
    pub fn new(cfg: &LlmConfig) -> anyhow::Result<Self> {
        let key = cfg
            .api_key
            .clone()
            .or_else(|| std::env::var(&cfg.api_key_env).ok())
            .filter(|k| !k.is_empty());
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(cfg.timeout_secs))
            .user_agent("netwatch/0.1")
            .build()?;
        Ok(Self {
            cfg: cfg.clone(),
            http,
            key,
            last_digest: Mutex::new(0),
            quirks: Mutex::new(Quirks::default()),
        })
    }

    /// One chat completion. Retries once per rejected option (temperature,
    /// response_format, max_tokens naming) since providers disagree on them.
    pub async fn chat(
        &self,
        system: &str,
        user: &str,
        max_tokens: u32,
    ) -> anyhow::Result<(String, Usage)> {
        self.chat_with(system, user, max_tokens, None, false).await
    }

    /// Like `chat`, constraining the reply to a JSON schema where the endpoint
    /// supports structured outputs (OpenAI, Ollama, llama.cpp, vLLM), and with
    /// `no_reasoning` asking reasoning models to answer without thinking first.
    pub async fn chat_with(
        &self,
        system: &str,
        user: &str,
        max_tokens: u32,
        schema: Option<&Value>,
        no_reasoning: bool,
    ) -> anyhow::Result<(String, Usage)> {
        let url = format!(
            "{}/chat/completions",
            self.cfg.base_url.trim_end_matches('/')
        );
        for _ in 0..6 {
            let q = *self.quirks.lock().unwrap();
            let mut body = json!({
                "model": self.cfg.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            });
            body[if q.max_completion_tokens {
                "max_completion_tokens"
            } else {
                "max_tokens"
            }] = json!(max_tokens);
            if !q.no_temperature {
                body["temperature"] = json!(0);
            }
            if no_reasoning && !q.no_reasoning_effort {
                body["reasoning_effort"] = json!("none");
            }
            // json_mode = false sends no response_format at all, schema included.
            if let Some(schema) = schema.filter(|_| self.cfg.json_mode && !q.no_json_schema) {
                body["response_format"] = json!({
                    "type": "json_schema",
                    "json_schema": {"name": "reply", "strict": true, "schema": schema},
                });
            } else if self.cfg.json_mode && !q.no_json_mode {
                body["response_format"] = json!({"type": "json_object"});
            }
            let mut req = self.http.post(&url).json(&body);
            if let Some(k) = &self.key {
                req = req.bearer_auth(k);
            }
            let resp = req.send().await.context("LLM request failed")?;
            let status = resp.status();
            let text = resp.text().await?;
            if matches!(status.as_u16(), 400 | 422 | 501) {
                let mut q = self.quirks.lock().unwrap();
                let lower = text.to_lowercase();
                // Ollama, for models without constrained decoding.
                let no_structured = lower.contains("structured output");
                if lower.contains("max_tokens") && !q.max_completion_tokens {
                    q.max_completion_tokens = true;
                    continue;
                }
                if lower.contains("reasoning") && no_reasoning && !q.no_reasoning_effort {
                    q.no_reasoning_effort = true;
                    continue;
                }
                if lower.contains("temperature") && !q.no_temperature {
                    q.no_temperature = true;
                    continue;
                }
                if schema.is_some()
                    && self.cfg.json_mode
                    && !q.no_json_schema
                    && (no_structured
                        || lower.contains("json_schema")
                        || lower.contains("response_format"))
                {
                    q.no_json_schema = true;
                    continue;
                }
                if (no_structured || lower.contains("response_format")) && !q.no_json_mode {
                    q.no_json_mode = true;
                    continue;
                }
            }
            if !status.is_success() {
                bail!(
                    "LLM returned {status}: {}",
                    text.chars().take(300).collect::<String>()
                );
            }
            let v: Value = serde_json::from_str(&text).context("LLM response is not JSON")?;
            let msg = &v["choices"][0]["message"];
            let content = msg["content"].as_str().unwrap_or("").to_string();
            if content.trim().is_empty() {
                if msg["reasoning"].as_str().is_some_and(|r| !r.is_empty())
                    || msg["reasoning_content"]
                        .as_str()
                        .is_some_and(|r| !r.is_empty())
                {
                    bail!(
                        "the model used its {max_tokens} output tokens reasoning and gave no answer; \
                         use a model without reasoning, or one that honours reasoning_effort"
                    );
                }
                bail!("LLM response has no message content");
            }
            let usage = Usage {
                prompt_tokens: v["usage"]["prompt_tokens"].as_i64().unwrap_or(0),
                completion_tokens: v["usage"]["completion_tokens"].as_i64().unwrap_or(0),
            };
            return Ok((content, usage));
        }
        bail!("LLM endpoint kept rejecting the request")
    }

    /// True if this digest differs from the last one analysed.
    pub fn digest_changed(&self, digest: &str) -> bool {
        let mut h = DefaultHasher::new();
        digest.hash(&mut h);
        let h = h.finish();
        let mut last = self.last_digest.lock().unwrap();
        if *last == h {
            return false;
        }
        *last = h;
        true
    }

    pub async fn analyze(&self, context: &str) -> anyhow::Result<(Analysis, Usage)> {
        let (content, usage) = self
            .chat_with(
                ANALYZE_SYSTEM,
                context,
                self.cfg.max_output_tokens,
                Some(&analysis_schema()),
                true,
            )
            .await?;
        let analysis: Analysis =
            serde_json::from_str(extract_json(&content)).with_context(|| {
                format!(
                    "LLM reply is not the expected JSON: {}",
                    truncate(&content, 200)
                )
            })?;
        Ok((analysis, usage))
    }

    /// Turns a natural-language policy into validated rules.
    pub async fn compile_policy(&self, text: &str) -> anyhow::Result<(Vec<Rule>, Usage)> {
        let kinds: Vec<String> = policy::FINDING_KINDS
            .iter()
            .map(|(k, d)| format!("  {k}: {d}"))
            .collect();
        let defaults: Vec<String> = policy::defaults()
            .iter()
            .map(|r| {
                format!(
                    "  {} -> {}{}",
                    r.description,
                    r.action.as_str(),
                    r.ttl_secs.map(|t| format!(" {t}s")).unwrap_or_default()
                )
            })
            .collect();
        let system = format!(
            "Convert an operator's natural-language ban policy for a network monitor into JSON rules.
Schema: {{\"rules\":[{{\"id\":\"user:1\",\"description\":\"short\",\"action\":\"ban|review|ignore|never_ban\",\
\"ttl_secs\":86400,\"when\":{{...}}}}]}}
\"when\" conditions (all optional, ALL must hold, at least one required):
  findings_any: list of finding kinds (any matches):
{}
  min_score: 0-100 (40 suspicious, 70 likely malicious, 85+ certain)
  countries / not_countries: ISO 3166 alpha-2 codes
  asns: AS numbers; cidrs: [\"198.51.100.0/24\"]; ports_any: local ports touched
  in_feed: true/false (listed on a threat-intel blocklist); min_ssh_failed: number
ttl_secs: ban duration in seconds, null for permanent; omit for non-ban actions.
First matching rule wins, except never_ban which always wins: put exceptions first.
Encode only what the operator asked for. These built-in defaults apply after your rules:
{}
Reply with JSON only.",
            kinds.join("\n"),
            defaults.join("\n")
        );
        let (content, usage) = self.chat(&system, text, 1500).await?;
        #[derive(Deserialize)]
        struct Out {
            rules: Vec<Rule>,
        }
        let mut out: Out = serde_json::from_str(extract_json(&content)).with_context(|| {
            format!(
                "LLM reply is not valid rules JSON: {}",
                truncate(&content, 300)
            )
        })?;
        policy::validate(&mut out.rules)?;
        Ok((out.rules, usage))
    }
}

/// Whether a proposed target is one of the digest's sources, or a network
/// holding one. Models sometimes name addresses they weren't given.
pub fn in_digest(target: &ipnet::IpNet, digest: &str) -> bool {
    digest
        .lines()
        .filter_map(|l| {
            l.split_whitespace()
                .next()?
                .parse::<std::net::IpAddr>()
                .ok()
        })
        .any(|ip| target.contains(&ip))
}

/// The reply `analyze` asks for, enforced where the endpoint supports
/// structured outputs, so small models can't drift from it.
fn analysis_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "summary": {"type": "string"},
            "actions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string"},
                        "action": {"type": "string", "enum": ["ban", "review", "ignore"]},
                        "ttl": {"type": "string"},
                        "confidence": {"type": "number"},
                        "reason": {"type": "string"},
                    },
                    "required": ["target", "action", "ttl", "confidence", "reason"],
                    "additionalProperties": false,
                },
            },
        },
        "required": ["summary", "actions"],
        "additionalProperties": false,
    })
}

/// Strips reasoning (`<think>…</think>`), markdown fences or prose around the JSON object.
pub fn extract_json(s: &str) -> &str {
    let s = s
        .rfind("</think>")
        .map_or(s, |i| &s[i + "</think>".len()..]);
    match (s.find('{'), s.rfind('}')) {
        (Some(a), Some(b)) if b > a => &s[a..=b],
        _ => s,
    }
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_targets_from_the_digest_count() {
        let digest =
            "198.51.100.66 NL AS64500 Example score=92\n2001:db8::7 US AS64501 Example score=50";
        let t = |s: &str| crate::util::parse_target(s).unwrap();
        assert!(in_digest(&t("198.51.100.66"), digest));
        assert!(in_digest(&t("198.51.100.0/24"), digest));
        assert!(in_digest(&t("2001:db8::/64"), digest));
        assert!(!in_digest(&t("203.0.113.7"), digest));
        assert!(!in_digest(&t("198.51.101.0/24"), digest));
    }

    #[test]
    fn the_example_reply_names_no_address() {
        // Small models copied a concrete example address as a ban target.
        let example = &ANALYZE_SYSTEM[ANALYZE_SYSTEM.find("Reply with JSON").unwrap()..];
        assert!(!example.contains("203.0.113"), "{example}");
        assert!(example.contains("<an IP or /24 from the digest>"));
        let schema = analysis_schema();
        let fields = schema["properties"]["actions"]["items"]["required"]
            .as_array()
            .unwrap();
        assert_eq!(fields.len(), 5);
    }

    /// The `response_format` analyze sends, as a fake endpoint received it.
    async fn analysis_format(json_mode: bool) -> Value {
        use axum::{Json, Router, routing::post};
        let seen = std::sync::Arc::new(Mutex::new(Value::Null));
        let app = Router::new().route(
            "/v1/chat/completions",
            post({
                let seen = seen.clone();
                move |Json(body): Json<Value>| async move {
                    *seen.lock().unwrap() = body["response_format"].clone();
                    Json(json!({
                        "choices": [{"message": {"content": r#"{"summary":"x","actions":[]}"#}}],
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                    }))
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}/v1", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await });
        let cfg = LlmConfig {
            base_url,
            model: "m".into(),
            json_mode,
            ..LlmConfig::default()
        };
        Llm::new(&cfg).unwrap().analyze("digest").await.unwrap();
        seen.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn json_mode_false_sends_no_response_format() {
        assert_eq!(analysis_format(true).await["type"], "json_schema");
        assert_eq!(analysis_format(false).await, Value::Null);
    }

    #[test]
    fn extracts_fenced_json() {
        let s = "```json\n{\"summary\":\"x\",\"actions\":[]}\n```";
        let a: Analysis = serde_json::from_str(extract_json(s)).unwrap();
        assert_eq!(a.summary, "x");
        let t = "<think>maybe {\"a\":1}?</think>\n{\"summary\":\"y\",\"actions\":[]}";
        let a: Analysis = serde_json::from_str(extract_json(t)).unwrap();
        assert_eq!(a.summary, "y");
    }
}
