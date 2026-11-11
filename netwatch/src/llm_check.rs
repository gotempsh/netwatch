//! `netwatch llm check`: does the `[llm]` endpoint answer, and can its model do
//! netwatch's job? It sends the analysis prompt the daemon sends, with a fixed
//! sample: an SSH brute forcer on a blocklist, which any usable model flags,
//! and a source that touched a web port a few times, which none should ban.

use std::{net::IpAddr, path::Path, time::Instant};

use anyhow::{Context as _, bail};

use crate::{
    config::Config,
    llm::{Analysis, Llm},
};

const ATTACKER: &str = "198.51.100.66";
const HARMLESS: &str = "203.0.113.25";
const SAMPLE: &str = "Operator policy: none
Host listens on tcp [22,443] udp []; sshd password auth: yes; mode: Observe
Sources:
198.51.100.66 NL AS64500 Example Hosting score=92 findings=[ssh_bruteforce:60,port_scan:40,threat_feed:30] ports(214)=[22/tcp,23/tcp,3389/tcp,5900/tcp,6379/tcp,8080/tcp] syn=2210 in_pkts=4810 ssh_failed=388 ssh_invalid_users=57 ssh_ok=0 feeds=blocklist.de
203.0.113.25 US AS64501 Example CDN score=41 findings=[closed_probe:41] ports(2)=[443/tcp,80/tcp] syn=6 in_pkts=310";

pub async fn run(config_path: &Path) -> anyhow::Result<()> {
    let mut cfg = Config::load(config_path)?.llm;
    let shown = config_path.display();
    if cfg.model.is_empty() {
        bail!(
            "no model under [llm] in {shown}; set base_url and model, for example a local Ollama: base_url = \"http://127.0.0.1:11434/v1\", model = \"qwen3:1.7b\""
        );
    }
    let env_file = config_path.with_file_name("env");
    let key = key(&cfg.api_key, &cfg.api_key_env, &env_file);
    cfg.api_key = key.value.clone();
    let base = cfg.base_url.trim_end_matches('/').to_string();

    let unlisted = probe(&base, &cfg.model, &key, &cfg.api_key_env, &env_file).await?;

    let llm = Llm::new(&cfg)?;
    let started = Instant::now();
    let (analysis, usage) = llm.analyze(SAMPLE).await.map_err(|e| {
        let msg = format!("{e:#}");
        if msg.contains("not the expected JSON") {
            anyhow::anyhow!(
                "{} at {base} answered, but not with the JSON netwatch asks for, so the daemon couldn't use it. Small models often can't; try a bigger one. {msg}",
                cfg.model
            )
        } else {
            let e = e.context(format!("{} at {base} didn't answer the analysis prompt", cfg.model));
            match &unlisted {
                Some(note) => anyhow::anyhow!("{e:#}. {note}"),
                None => e,
            }
        }
    })?;
    let secs = started.elapsed().as_secs_f64();
    let tokens = usage.prompt_tokens + usage.completion_tokens;
    match judge(&analysis) {
        Ok(what) => println!(
            "{} at {base} works for netwatch: it answered the analysis prompt in {secs:.1} s ({tokens} tokens) and {what}",
            cfg.model
        ),
        Err(why) => bail!(
            "{} at {base} answered in {secs:.1} s, but its judgement was wrong: {why}. A bigger model judges better.",
            cfg.model
        ),
    }
    if !cfg.enabled {
        eprintln!(
            "enabled = false under [llm] in {shown}, so the daemon doesn't use it yet; set enabled = true, then: sudo netwatch restart"
        );
    }
    Ok(())
}

struct Key {
    value: Option<String>,
    /// Where it came from, for messages.
    from: String,
    /// The env file exists but this user can't read it.
    unreadable: bool,
}

/// The key the daemon would use: `api_key`, the environment, or the env file
/// systemd and launchd give the daemon.
fn key(api_key: &Option<String>, var: &str, env_file: &Path) -> Key {
    if let Some(k) = api_key.clone().filter(|k| !k.is_empty()) {
        return Key {
            value: Some(k),
            from: "api_key in the config".into(),
            unreadable: false,
        };
    }
    if let Some(k) = std::env::var(var).ok().filter(|k| !k.is_empty()) {
        return Key {
            value: Some(k),
            from: format!("${var}"),
            unreadable: false,
        };
    }
    match std::fs::read_to_string(env_file) {
        Ok(text) => Key {
            value: env_value(&text, var),
            from: format!("{var} in {}", env_file.display()),
            unreadable: false,
        },
        Err(e) => Key {
            value: None,
            from: String::new(),
            unreadable: e.kind() == std::io::ErrorKind::PermissionDenied,
        },
    }
}

/// `var` from `KEY=value` lines, as systemd's EnvironmentFile reads them.
fn env_value(text: &str, var: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.strip_prefix("export ").unwrap_or(l).split_once('='))
        .filter(|(k, _)| k.trim() == var)
        .map(|(_, v)| v.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
        .rfind(|v| !v.is_empty())
}

fn is_ollama(base: &str) -> bool {
    base.contains(":11434")
}

/// GET /models: tells a dead endpoint, a refused key and a missing model apart
/// before the real call. Endpoints without /models are skipped. A model that
/// another server doesn't list isn't fatal: single-model servers (llama.cpp)
/// answer whatever the request names, and proxies route names they don't
/// list. It returns what to say if the real call then fails.
async fn probe(
    base: &str,
    model: &str,
    key: &Key,
    var: &str,
    env_file: &Path,
) -> anyhow::Result<Option<String>> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let mut req = http.get(format!("{base}/models"));
    if let Some(k) = &key.value {
        req = req.bearer_auth(k);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) if e.is_connect() => bail!(
            "nothing answers at {base}; {}",
            if is_ollama(base) {
                "start Ollama: ollama serve".to_string()
            } else {
                "check base_url under [llm]".to_string()
            }
        ),
        Err(e) if e.is_timeout() => bail!("{base} didn't answer within 10 s"),
        Err(e) => return Err(e).with_context(|| format!("reaching {base}")),
    };
    let status = resp.status();
    if status.as_u16() == 401 || status.as_u16() == 403 {
        match &key.value {
            Some(_) => bail!("{base} refused the API key from {} ({status})", key.from),
            None if key.unreadable => bail!(
                "{base} wants an API key, and {} needs root to read: sudo netwatch llm check",
                env_file.display()
            ),
            None => bail!(
                "{base} wants an API key: put {var}=<key> in {} (mode 0600)",
                env_file.display()
            ),
        }
    }
    if !status.is_success() {
        return Ok(None);
    }
    let Ok(body) = resp.json::<serde_json::Value>().await else {
        return Ok(None);
    };
    let ids: Vec<&str> = body["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| m["id"].as_str())
        .collect();
    if ids.is_empty() || has_model(&ids, model) {
        return Ok(None);
    }
    if is_ollama(base) {
        bail!("Ollama at {base} doesn't have {model}; pull it: ollama pull {model}");
    }
    let some: Vec<&str> = ids.iter().take(8).copied().collect();
    Ok(Some(format!(
        "{base} doesn't list {model}; set model under [llm] to one it lists: {}{}",
        some.join(", "),
        if ids.len() > some.len() { ", ..." } else { "" }
    )))
}

/// Ollama lists `name:tag` and treats a bare name as `name:latest`; Gemini
/// lists `models/name` and takes `name`.
fn has_model(ids: &[&str], model: &str) -> bool {
    ids.iter()
        .map(|id| id.strip_prefix("models/").unwrap_or(id))
        .any(|id| id == model || id == format!("{model}:latest"))
}

fn covers(target: &str, ip: &str) -> bool {
    let ip: IpAddr = ip.parse().expect("sample addresses parse");
    target == ip.to_string()
        || target
            .parse::<ipnet::IpNet>()
            .is_ok_and(|net| net.contains(&ip))
}

/// What a usable model does with the sample: flags the brute forcer and
/// doesn't ban the other source.
fn judge(a: &Analysis) -> Result<String, String> {
    if a.actions
        .iter()
        .any(|x| x.action == "ban" && covers(&x.target, HARMLESS))
    {
        return Err(format!(
            "it proposed banning {HARMLESS}, which only touched ports 80 and 443 a few times"
        ));
    }
    let Some(x) = a
        .actions
        .iter()
        .find(|x| covers(&x.target, ATTACKER) && matches!(x.action.as_str(), "ban" | "review"))
    else {
        return Err(format!(
            "it didn't flag {ATTACKER}, which failed 388 SSH logins, scanned 214 ports and is on a blocklist"
        ));
    };
    let ttl = x
        .ttl
        .as_deref()
        .map(|t| format!(" {t}"))
        .unwrap_or_default();
    Ok(format!(
        "proposed {} {}{ttl} (confidence {:.2})",
        x.action, x.target, x.confidence
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::ProposedAction;

    fn action(target: &str, action: &str) -> ProposedAction {
        ProposedAction {
            target: target.into(),
            action: action.into(),
            ttl: Some("24h".into()),
            confidence: 0.9,
            reason: String::new(),
        }
    }

    fn analysis(actions: Vec<ProposedAction>) -> Analysis {
        Analysis {
            summary: String::new(),
            actions,
        }
    }

    #[test]
    fn a_usable_answer_flags_the_attacker_and_spares_the_other() {
        let ok = judge(&analysis(vec![
            action(ATTACKER, "ban"),
            action(HARMLESS, "ignore"),
        ]));
        assert_eq!(
            ok.unwrap(),
            "proposed ban 198.51.100.66 24h (confidence 0.90)"
        );
        assert!(judge(&analysis(vec![action("198.51.100.0/24", "review")])).is_ok());

        let missed = judge(&analysis(vec![action(HARMLESS, "review")])).unwrap_err();
        assert!(missed.contains("didn't flag 198.51.100.66"), "{missed}");
        let ignored = judge(&analysis(vec![action(ATTACKER, "ignore")])).unwrap_err();
        assert!(ignored.contains("didn't flag"), "{ignored}");
        let banned = judge(&analysis(vec![
            action(ATTACKER, "ban"),
            action(HARMLESS, "ban"),
        ]));
        assert!(banned.unwrap_err().contains("banning 203.0.113.25"));
    }

    #[test]
    fn the_sample_is_what_the_daemon_sends() {
        // Same layout as daemon.rs builds and Source::digest_line writes.
        assert!(include_str!("daemon.rs").contains("\"Operator policy: {policy_text}\\nHost listens on tcp [{}] udp [{}]; sshd password auth: {}; mode: {:?}\\n\""));
        assert!(include_str!("daemon.rs").contains("format!(\"{ctx}Sources:\\n{digest}\")"));
        assert!(
            include_str!("engine.rs")
                .contains("\"{} {} score={} findings=[{}] ports({})=[{}] syn={} in_pkts={}\"")
        );
        for kind in ["ssh_bruteforce", "port_scan", "threat_feed", "closed_probe"] {
            assert!(
                crate::policy::FINDING_KINDS.iter().any(|(k, _)| *k == kind),
                "{kind}"
            );
        }
    }

    #[test]
    fn reads_the_key_as_systemd_would() {
        let text = "# netwatch secrets\nNETWATCH_SLACK_WEBHOOK=https://hooks.example/x\nexport NETWATCH_LLM_API_KEY=\"sk-test\"\n";
        assert_eq!(
            env_value(text, "NETWATCH_LLM_API_KEY").as_deref(),
            Some("sk-test")
        );
        assert_eq!(env_value(text, "MISSING"), None);
        assert_eq!(
            env_value("NETWATCH_LLM_API_KEY=\n", "NETWATCH_LLM_API_KEY"),
            None
        );
    }

    /// A fake OpenAI-compatible endpoint: `status` for /models (with `models`
    /// listed on 200) and `reply` as the chat completion's content, whatever
    /// model is asked for. An empty `reply` answers 404, as for an unknown model.
    async fn endpoint(status: u16, models: &'static [&'static str], reply: &'static str) -> String {
        use axum::{
            Json, Router,
            http::StatusCode,
            routing::{get, post},
        };
        let listed = serde_json::json!({"data": models.iter().map(|m| serde_json::json!({"id": m})).collect::<Vec<_>>()});
        let app = Router::new()
            .route(
                "/v1/models",
                get(move || async move { (StatusCode::from_u16(status).unwrap(), Json(listed)) }),
            )
            .route(
                "/v1/chat/completions",
                post(move || async move {
                    if reply.is_empty() {
                        let e = serde_json::json!({"error": {"message": "model not found"}});
                        return (StatusCode::NOT_FOUND, Json(e));
                    }
                    (
                        StatusCode::OK,
                        Json(serde_json::json!({
                            "choices": [{"message": {"content": reply}}],
                            "usage": {"prompt_tokens": 400, "completion_tokens": 60},
                        })),
                    )
                }),
            );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, app).await });
        format!("http://{addr}/v1")
    }

    /// Runs the check against `base_url` with a config in its own directory.
    async fn check(name: &str, base_url: &str) -> anyhow::Result<()> {
        let dir =
            std::env::temp_dir().join(format!("netwatch-llmcheck-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("netwatch.toml");
        std::fs::write(
            &path,
            format!("interface = \"lo\"\n[llm]\nenabled = true\nbase_url = \"{base_url}\"\nmodel = \"m:1b\"\napi_key_env = \"NETWATCH_TEST_NO_SUCH_KEY\"\n"),
        )
        .unwrap();
        let result = run(&path).await;
        std::fs::remove_dir_all(&dir).unwrap();
        result
    }

    const GOOD: &str = r#"{"summary":"brute forcer","actions":[{"target":"198.51.100.66","action":"ban","ttl":"24h","confidence":0.9,"reason":"ssh brute force"}]}"#;
    const WRONG: &str = r#"{"summary":"cdn","actions":[{"target":"203.0.113.25","action":"ban","ttl":"24h","confidence":0.9,"reason":"probe"}]}"#;

    #[tokio::test]
    async fn says_what_is_wrong_with_the_endpoint() {
        let msg = |r: anyhow::Result<()>| format!("{:#}", r.unwrap_err());

        let dead = msg(check("dead", "http://127.0.0.1:1/v1").await);
        assert!(
            dead.contains("nothing answers at http://127.0.0.1:1/v1; check base_url"),
            "{dead}"
        );

        let locked = msg(check("locked", &endpoint(401, &[], GOOD).await).await);
        assert!(
            locked.contains("wants an API key: put NETWATCH_TEST_NO_SUCH_KEY=<key> in"),
            "{locked}"
        );
        assert!(locked.contains("/env (mode 0600)"), "{locked}");

        let missing = msg(check("missing", &endpoint(200, &["other:3b"], "").await).await);
        assert!(
            missing.contains("doesn't list m:1b; set model under [llm] to one it lists: other:3b"),
            "{missing}"
        );
        assert!(
            missing.contains("m:1b at http://")
                && missing.contains("didn't answer the analysis prompt: LLM returned 404"),
            "{missing}"
        );

        // A single-model server (llama.cpp) lists its file and answers any name.
        check(
            "single",
            &endpoint(200, &["models/Qwen3-1.7B-Q4_K_M.gguf"], GOOD).await,
        )
        .await
        .unwrap();

        let wrong = msg(check("wrong", &endpoint(200, &["m:1b"], WRONG).await).await);
        assert!(
            wrong.contains("its judgement was wrong: it proposed banning 203.0.113.25"),
            "{wrong}"
        );

        let prose = msg(check(
            "prose",
            &endpoint(200, &["m:1b"], "I would ban the first one.").await,
        )
        .await);
        assert!(
            prose.contains("not with the JSON netwatch asks for"),
            "{prose}"
        );

        // No /models (404) is fine; the analysis call decides.
        check("good", &endpoint(404, &[], GOOD).await)
            .await
            .unwrap();
        check("listed", &endpoint(200, &["m:1b"], GOOD).await)
            .await
            .unwrap();
    }

    #[test]
    fn ollama_names_match_with_or_without_a_tag() {
        let ids = ["qwen2.5:3b", "llama3.2:latest"];
        assert!(has_model(&ids, "qwen2.5:3b"));
        assert!(has_model(&ids, "llama3.2"));
        assert!(!has_model(&ids, "qwen2.5"));
        assert!(has_model(&["models/gemini-2.0-flash"], "gemini-2.0-flash"));
    }
}
