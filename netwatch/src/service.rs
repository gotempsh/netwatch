//! `netwatch start`, `stop` and `restart`: the daemon's service, through
//! systemd on Linux and launchd on macOS.

use std::{path::Path, time::Duration};

use anyhow::{Context as _, bail};

use crate::config::Config;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    Start,
    Stop,
    Restart,
}

impl Action {
    fn verb(self) -> &'static str {
        match self {
            Action::Start => "start",
            Action::Stop => "stop",
            Action::Restart => "restart",
        }
    }
}

/// Where to look when the daemon doesn't come up.
pub fn logs() -> &'static str {
    if cfg!(target_os = "macos") {
        "sudo launchctl print system/dev.netwatch, and /var/log/netwatch.log"
    } else {
        "systemctl status netwatch, and journalctl -u netwatch -n 50"
    }
}

/// `config` is the one the installed daemon runs with (`update::installed_config`).
pub async fn run(action: Action, config: &Path) -> anyhow::Result<()> {
    let verb = action.verb();
    let Some(api_url) = &api_url(action, config)? else {
        may_act(verb)?;
        platform(action)?;
        println!("stopped netwatch; its bans are lifted until it starts again");
        return Ok(());
    };
    if action == Action::Start && started_at(api_url).await.is_some() {
        println!("netwatch is already running");
        return Ok(());
    }
    may_act(verb)?;
    let asked = crate::util::now_unix();
    platform(action)?;
    // The daemon loads its programs and the database before the API answers.
    // After a restart it must be the new one, not the old one still shutting down.
    for _ in 0..60 {
        if started_at(api_url)
            .await
            .is_some_and(|t| action == Action::Start || t >= asked - 1)
        {
            println!("netwatch is running; netwatch status shows what it sees");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    bail!(
        "the service {verb}ed, but nothing answers at {api_url} after 30 seconds, so the daemon is failing to start. Its last log lines:\n{}\nMore: {}",
        recent_log(),
        logs()
    )
}

/// Where the daemon will answer once it's up, from the config it loads; None
/// for stop, which never reads the config: a broken one is often why the
/// daemon keeps restarting, and stop is how to end that.
fn api_url(action: Action, config: &Path) -> anyhow::Result<Option<String>> {
    if action == Action::Stop {
        return Ok(None);
    }
    let verb = action.verb();
    let cfg = Config::load(config).with_context(|| {
        format!(
            "the daemon can't start with {}, so it wasn't {verb}ed; fix it, then: sudo netwatch {verb}",
            config.display()
        )
    })?;
    Ok(Some(cfg.api_url()))
}

fn may_act(verb: &str) -> anyhow::Result<()> {
    if crate::util::in_container() {
        bail!(
            "netwatch runs in a container here; {verb} the container instead: docker {verb} <container> (or docker compose {verb})"
        );
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("{verb} needs root: sudo netwatch {verb}");
    }
    Ok(())
}

/// Whether the service was stopped (`netwatch stop`), as opposed to running,
/// starting or failing. An update leaves a stopped daemon alone.
#[cfg(target_os = "macos")]
pub fn stopped() -> bool {
    crate::macos::launchd::stopped()
}

#[cfg(not(target_os = "macos"))]
pub fn stopped() -> bool {
    std::process::Command::new("systemctl")
        .args(["is-active", "netwatch.service"])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "inactive")
}

/// The daemon's last log lines, best effort.
fn recent_log() -> String {
    let out = if cfg!(target_os = "macos") {
        std::process::Command::new("tail")
            .args(["-n", "8", "/var/log/netwatch.log"])
            .output()
    } else {
        std::process::Command::new("journalctl")
            .args(["-u", "netwatch", "-n", "8", "--no-pager", "-o", "cat"])
            .output()
    };
    let text = out
        .map(|o| String::from_utf8_lossy(&o.stdout).trim_end().to_string())
        .unwrap_or_default();
    if text.is_empty() {
        "    (none)".into()
    } else {
        text.lines()
            .map(|l| format!("    {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// When the daemon answering at `api_url` started, or None if none answers.
async fn started_at(api_url: &str) -> Option<i64> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?;
    let overview: serde_json::Value = http
        .get(format!("{api_url}/api/overview"))
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .await
        .ok()?;
    overview["started_at"].as_i64()
}

#[cfg(target_os = "macos")]
fn platform(action: Action) -> anyhow::Result<()> {
    use crate::macos::launchd;
    match action {
        Action::Start => launchd::start(),
        Action::Stop => launchd::stop(),
        Action::Restart => launchd::restart(),
    }
}

#[cfg(not(target_os = "macos"))]
fn platform(action: Action) -> anyhow::Result<()> {
    use std::{path::Path, process::Command};

    use anyhow::Context as _;

    const UNIT: &str = "/etc/systemd/system/netwatch.service";
    if !Path::new(UNIT).exists() {
        bail!(
            "{UNIT} is missing, so netwatch isn't installed as a service; install it with: curl -fsSL https://gotempsh.github.io/netwatch/install.sh | sh"
        );
    }
    let out = Command::new("systemctl")
        .args([action.verb(), "netwatch.service"])
        .output()
        .context("running systemctl")?;
    if !out.status.success() {
        bail!(
            "systemctl {} netwatch.service: {}. Check: {}",
            action.verb(),
            String::from_utf8_lossy(&out.stderr).trim(),
            logs()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // These never call run(): Linux tests run as root (`sudo -E`), where it
    // would drive the machine's real service.

    #[test]
    fn stop_doesnt_read_the_config_but_start_and_restart_refuse_a_broken_one() {
        let path =
            std::env::temp_dir().join(format!("netwatch-broken-{}.toml", std::process::id()));
        std::fs::write(&path, "interface = \n").unwrap();
        let stop = api_url(Action::Stop, &path);
        let others = [Action::Start, Action::Restart].map(|a| (a, api_url(a, &path)));
        std::fs::remove_file(&path).unwrap();

        assert!(stop.unwrap().is_none());
        for (action, result) in others {
            let msg = format!("{:#}", result.unwrap_err());
            let verb = action.verb();
            assert!(
                msg.contains(&format!(
                    "so it wasn't {verb}ed; fix it, then: sudo netwatch {verb}"
                )),
                "{msg}"
            );
            assert!(msg.contains("parsing"), "{msg}");
        }
    }

    #[test]
    fn start_and_restart_wait_on_the_configured_api_address() {
        let path = std::env::temp_dir().join(format!("netwatch-port-{}.toml", std::process::id()));
        std::fs::write(
            &path,
            "interface = \"lo\"\napi_listen = \"127.0.0.1:9999\"\n",
        )
        .unwrap();
        let url = api_url(Action::Restart, &path);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(url.unwrap().as_deref(), Some("http://127.0.0.1:9999"));
    }
}
