//! Notifications to a Slack incoming webhook. Outbound only: Slack never talks
//! back, so the API and UI stay read-only and approvals stay on the CLI.
//!
//! Notes are batched (one message per 10 s at most) and capped per hour;
//! whatever the cap drops is counted and mentioned in the next message.

use std::{collections::VecDeque, time::Duration};

use tokio::sync::mpsc;

use crate::config::SlackConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Critical,
}

impl Level {
    fn emoji(self) -> &'static str {
        match self {
            Level::Info => ":information_source:",
            Level::Warn => ":warning:",
            Level::Critical => ":rotating_light:",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Note {
    pub level: Level,
    pub title: String,
    pub body: String,
    /// A command worth running next, shown as code.
    pub cmd: Option<String>,
}

#[derive(Clone, Default)]
pub struct Notifier {
    tx: Option<mpsc::UnboundedSender<Note>>,
    pub cfg: SlackConfig,
}

const BATCH: Duration = Duration::from_secs(10);
const MAX_NOTES_PER_MESSAGE: usize = 15;

impl Notifier {
    /// Starts the sender when Slack is enabled and the webhook variable is set.
    pub fn start(cfg: &SlackConfig, host: &str) -> Self {
        if !cfg.enabled {
            return Self {
                tx: None,
                cfg: cfg.clone(),
            };
        }
        let url = match std::env::var(&cfg.webhook_env) {
            Ok(u) if u.starts_with("https://") => u,
            _ => {
                log::warn!(
                    "slack is enabled but ${} is not set to an https:// webhook URL; notifications are off",
                    cfg.webhook_env
                );
                return Self {
                    tx: None,
                    cfg: cfg.clone(),
                };
            }
        };
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(run(rx, url, host.to_string(), cfg.max_per_hour.max(1)));
        log::info!("slack notifications on");
        Self {
            tx: Some(tx),
            cfg: cfg.clone(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.tx.is_some()
    }

    pub fn send(
        &self,
        level: Level,
        title: impl Into<String>,
        body: impl Into<String>,
        cmd: Option<String>,
    ) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(Note {
                level,
                title: title.into(),
                body: body.into(),
                cmd,
            });
        }
    }
}

async fn run(mut rx: mpsc::UnboundedReceiver<Note>, url: String, host: String, per_hour: u32) {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("netwatch/0.1")
        .build()
        .expect("http client");
    let mut sent: VecDeque<std::time::Instant> = VecDeque::new();
    let mut suppressed = 0usize;
    while let Some(first) = rx.recv().await {
        tokio::time::sleep(BATCH).await;
        let mut notes = vec![first];
        while let Ok(n) = rx.try_recv() {
            notes.push(n);
        }
        let hour_ago = std::time::Instant::now() - Duration::from_secs(3600);
        while sent.front().is_some_and(|t| *t < hour_ago) {
            sent.pop_front();
        }
        if sent.len() >= per_hour as usize {
            suppressed += notes.len();
            continue;
        }
        let text = format_message(&host, &notes, suppressed);
        let body =
            serde_json::json!({ "text": text, "unfurl_links": false, "unfurl_media": false });
        let mut ok = false;
        for attempt in 0..2 {
            match http
                .post(&url)
                .json(&body)
                .send()
                .await
                .and_then(|r| r.error_for_status())
            {
                Ok(_) => {
                    ok = true;
                    break;
                }
                Err(e) if attempt == 0 => {
                    log::warn!("slack post failed ({e}), retrying");
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
                Err(e) => log::warn!("slack post failed: {e}"),
            }
        }
        if ok {
            sent.push_back(std::time::Instant::now());
            suppressed = 0;
        } else {
            suppressed += notes.len();
        }
    }
}

/// Slack mrkdwn needs &, < and > escaped.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn format_message(host: &str, notes: &[Note], suppressed: usize) -> String {
    let mut out = format!("*netwatch · {}*", esc(host));
    if suppressed > 0 {
        out.push_str(&format!("\n_{suppressed} earlier notification(s) dropped by the hourly limit; see `netwatch alerts`_"));
    }
    for n in notes.iter().take(MAX_NOTES_PER_MESSAGE) {
        out.push_str(&format!("\n{} *{}*", n.level.emoji(), esc(&n.title)));
        if !n.body.is_empty() {
            out.push_str(&format!("\n{}", esc(&n.body)));
        }
        if let Some(c) = &n.cmd {
            out.push_str(&format!("\n`{}`", c.replace('`', "'")));
        }
    }
    if notes.len() > MAX_NOTES_PER_MESSAGE {
        out.push_str(&format!(
            "\n_+{} more; see `netwatch alerts` and `netwatch proposals`_",
            notes.len() - MAX_NOTES_PER_MESSAGE
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_format() {
        let n = |t: &str| Note {
            level: Level::Warn,
            title: t.into(),
            body: "a <b> & c".into(),
            cmd: Some("sudo netwatch approve 3".into()),
        };
        let m = format_message("dc1", &[n("ban 1.2.3.4")], 2);
        assert!(m.starts_with("*netwatch · dc1*\n_2 earlier"));
        assert!(
            m.contains(":warning: *ban 1.2.3.4*\na &lt;b&gt; &amp; c\n`sudo netwatch approve 3`")
        );
        let many: Vec<Note> = (0..20).map(|i| n(&i.to_string())).collect();
        assert!(
            format_message("h", &many, 0)
                .ends_with("_+5 more; see `netwatch alerts` and `netwatch proposals`_")
        );
    }
}
