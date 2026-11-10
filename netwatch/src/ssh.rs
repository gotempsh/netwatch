//! Follows sshd and Tailscale SSH logs from journald (macOS: the unified log).
//! XDP only sees connection attempts; the logs say who tried which user and
//! whether they got in.

use std::{net::IpAddr, process::Stdio, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};

use crate::{daemon::App, engine::SshEvent};

/// Parses one log message. `unit` distinguishes sshd from tailscaled.
pub fn parse(ts: i64, tailscale: bool, msg: &str) -> Option<SshEvent> {
    let w: Vec<&str> = msg.split_whitespace().collect();
    // sshd ends the line with "from <ip> port <port>", and a username can be
    // "from" or "port" too, so the last match is the right one.
    let after = |key: &str| {
        w.iter()
            .rposition(|x| *x == key)
            .and_then(|i| w.get(i + 1))
            .copied()
    };
    let ip = |s: Option<&str>| s.and_then(|s| s.parse::<IpAddr>().ok());
    let ev = |kind, user: Option<&str>, ip: IpAddr, method: Option<&str>| SshEvent {
        ts,
        kind,
        user: user.map(str::to_string),
        ip,
        method: method.map(str::to_string),
        port: after("port").and_then(|p| p.parse().ok()),
    };

    if tailscale {
        // audit: SSH login: user=alice uid=1000 from=100.88.14.3 ts_user=... node=...
        if !msg.contains("SSH login:") {
            return None;
        }
        let field = |k: &str| w.iter().find_map(|x| x.strip_prefix(k));
        return Some(ev(
            "tailscale_login",
            field("user="),
            ip(field("from="))?,
            Some("tailscale"),
        ));
    }

    match w.as_slice() {
        // Accepted publickey for alice from 1.2.3.4 port 5555 ssh2
        ["Accepted", method, "for", user, "from", addr, ..] => {
            Some(ev("accepted", Some(user), ip(Some(addr))?, Some(method)))
        }
        // Failed password for invalid user bob from 1.2.3.4 port 5555 ssh2
        [
            "Failed",
            method,
            "for",
            "invalid",
            "user",
            user,
            "from",
            addr,
            ..,
        ] => Some(ev("failed", Some(user), ip(Some(addr))?, Some(method))),
        ["Failed", method, "for", user, "from", addr, ..] => {
            Some(ev("failed", Some(user), ip(Some(addr))?, Some(method)))
        }
        // Invalid user bob from 1.2.3.4 port 5555
        ["Invalid", "user", rest @ ..] => {
            let addr = ip(after("from"))?;
            // "Invalid user  from 1.2.3.4": no username, unless the user is "from".
            let user = match rest {
                ["from", a, ..] if a.parse::<IpAddr>().is_ok() => None,
                _ => rest.first().copied(),
            };
            Some(ev("invalid_user", user, addr, None))
        }
        // Connection closed by authenticating user alice 1.2.3.4 port 5555 [preauth]
        [
            "Connection",
            "closed" | "reset",
            "by",
            "authenticating",
            "user",
            user,
            addr,
            ..,
        ] => Some(ev("preauth_close", Some(user), ip(Some(addr))?, None)),
        _ => None,
    }
}

/// Runs forever, restarting journalctl if it exits.
#[cfg(target_os = "linux")]
pub async fn follow(app: Arc<App>) {
    loop {
        let since = {
            let store = app.store.lock().unwrap();
            store.last_ssh_ts().ok().flatten()
        };
        // First run: backfill a day of history so new_login_location has a baseline.
        let since = since.map_or_else(|| "-24h".to_string(), |t| format!("@{t}"));
        if let Err(e) = follow_once(&app, &since).await {
            log::warn!("ssh log follower: {e:#}");
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

#[cfg(target_os = "linux")]
async fn follow_once(app: &Arc<App>, since: &str) -> anyhow::Result<()> {
    let mut child = Command::from(crate::host::command("journalctl"))
        .args(["-f", "-o", "json", "--no-pager", "--since", since])
        .args(app.cfg.ssh_units.iter().flat_map(|u| ["-u", u.as_str()]))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut lines = BufReader::new(child.stdout.take().expect("piped")).lines();
    while let Some(line) = lines.next_line().await? {
        let Ok(j) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let Some(msg) = j["MESSAGE"].as_str() else {
            continue;
        };
        let ts = j["__REALTIME_TIMESTAMP"]
            .as_str()
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0)
            / 1_000_000;
        let tailscale = j["_SYSTEMD_UNIT"].as_str() == Some("tailscaled.service")
            || j["SYSLOG_IDENTIFIER"].as_str() == Some("tailscaled");
        if let Some(ev) = parse(ts, tailscale, msg) {
            app.record_ssh(ev);
        }
    }
    child.wait().await?;
    Ok(())
}

/// sshd forks per connection; on recent macOS the authenticating child is sshd-session.
#[cfg(target_os = "macos")]
const MAC_PREDICATE: &str =
    r#"process == "sshd" OR process == "sshd-session" OR process == "sshd-auth""#;

/// Runs forever: backfills with `log show`, then follows `log stream`.
#[cfg(target_os = "macos")]
pub async fn follow(app: Arc<App>) {
    loop {
        let since = {
            let store = app.store.lock().unwrap();
            store.last_ssh_ts().ok().flatten()
        };
        // First run: a day of history, so new_login_location has a baseline.
        let since = match since {
            Some(t) => match chrono::DateTime::from_timestamp(t, 0) {
                Some(d) => vec![
                    "--start".to_string(),
                    d.with_timezone(&chrono::Local)
                        .format("%Y-%m-%d %H:%M:%S")
                        .to_string(),
                ],
                None => vec!["--last".into(), "24h".into()],
            },
            None => vec!["--last".into(), "24h".into()],
        };
        let mut show: Vec<String> = vec!["show".into()];
        show.extend(since);
        if let Err(e) = follow_log(&app, &show).await {
            log::warn!("ssh log backfill: {e:#}");
        }
        if let Err(e) = follow_log(&app, &["stream".to_string()]).await {
            log::warn!("ssh log follower: {e:#}");
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

#[cfg(target_os = "macos")]
async fn follow_log(app: &Arc<App>, verb: &[String]) -> anyhow::Result<()> {
    let mut child = Command::new("/usr/bin/log")
        .args(verb)
        .args(["--info", "--style", "ndjson", "--predicate", MAC_PREDICATE])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut lines = BufReader::new(child.stdout.take().expect("piped")).lines();
    while let Some(line) = lines.next_line().await? {
        if let Some(ev) = parse_unified_log(&line) {
            app.record_ssh(ev);
        }
    }
    child.wait().await?;
    Ok(())
}

/// One `log --style ndjson` line: `{"timestamp":"2026-11-05 20:04:01.123456+0100","eventMessage":...}`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_unified_log(line: &str) -> Option<SshEvent> {
    let j: serde_json::Value = serde_json::from_str(line).ok()?;
    let msg = j["eventMessage"].as_str()?;
    let ts = j["timestamp"]
        .as_str()
        .and_then(|t| chrono::DateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S%.f%z").ok())
        .map_or(0, |d| d.timestamp());
    parse(ts, false, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sshd_lines() {
        let e = parse(
            1,
            false,
            "Accepted password for alice from 192.168.1.141 port 50346 ssh2",
        )
        .unwrap();
        assert_eq!(
            (e.kind, e.user.as_deref(), e.method.as_deref()),
            ("accepted", Some("alice"), Some("password"))
        );
        let e = parse(
            1,
            false,
            "Failed password for invalid user admin from 203.0.113.5 port 4242 ssh2",
        )
        .unwrap();
        assert_eq!(
            (e.kind, e.user.as_deref(), e.port),
            ("failed", Some("admin"), Some(4242))
        );
        let e = parse(
            1,
            false,
            "Failed password for root from 2001:db8::1 port 4242 ssh2",
        )
        .unwrap();
        assert_eq!(e.ip.to_string(), "2001:db8::1");
        let e = parse(1, false, "Invalid user oracle from 203.0.113.5 port 4242").unwrap();
        assert_eq!(
            (e.kind, e.user.as_deref()),
            ("invalid_user", Some("oracle"))
        );
        let e = parse(1, false, "Invalid user  from 203.0.113.5 port 4242").unwrap();
        assert_eq!(e.user, None);
        // Usernames that are also the words around the address.
        for user in ["port", "from"] {
            let e = parse(
                1,
                false,
                &format!("Invalid user {user} from 203.0.113.5 port 4242"),
            )
            .unwrap();
            assert_eq!(
                (e.user.as_deref(), e.ip.to_string().as_str(), e.port),
                (Some(user), "203.0.113.5", Some(4242))
            );
            let e = parse(
                1,
                false,
                &format!("Failed password for invalid user {user} from 203.0.113.5 port 4242 ssh2"),
            )
            .unwrap();
            assert_eq!((e.user.as_deref(), e.port), (Some(user), Some(4242)));
        }
        let e = parse(
            1,
            false,
            "Connection closed by authenticating user alice 192.168.1.141 port 59424 [preauth]",
        )
        .unwrap();
        assert_eq!(e.kind, "preauth_close");
        assert!(parse(1, false, "Server listening on 0.0.0.0 port 22.").is_none());
    }

    #[test]
    fn unified_log_lines() {
        let line = r#"{"timestamp":"2026-11-05 20:04:01.123456+0100","messageType":"Default","processImagePath":"/usr/sbin/sshd","eventMessage":"Failed keyboard-interactive/pam for invalid user admin from 203.0.113.5 port 4242 ssh2"}"#;
        let e = parse_unified_log(line).unwrap();
        assert_eq!(
            (e.kind, e.user.as_deref(), e.method.as_deref(), e.ts),
            (
                "failed",
                Some("admin"),
                Some("keyboard-interactive/pam"),
                1_793_905_441
            )
        );
        assert!(parse_unified_log("Filtering the log data using \"process == sshd\"").is_none());
        assert!(parse_unified_log(r#"{"count":12,"finished":1}"#).is_none());
    }

    #[test]
    fn tailscale_line() {
        let e = parse(
            1,
            true,
            "audit: SSH login: user=alice uid=1000 from=100.88.14.3 ts_user=tagged-devices node=laptop.tail1234.ts.net.",
        )
        .unwrap();
        assert_eq!(
            (e.kind, e.user.as_deref(), e.ip.to_string().as_str()),
            ("tailscale_login", Some("alice"), "100.88.14.3")
        );
    }
}
