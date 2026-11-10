//! `netwatch install` / `uninstall` / `update-geoip`: the single binary sets
//! itself up as a launchd daemon, as scripts/install.sh does with systemd.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context as _, bail};

use crate::config::Config;

pub const LABEL: &str = "dev.netwatch";
const GEOIP_LABEL: &str = "dev.netwatch.geoip";
const UPDATE_LABEL: &str = "dev.netwatch.update";
const BIN: &str = "/usr/local/bin/netwatch";
const LOG: &str = "/var/log/netwatch.log";

fn plist_path(label: &str) -> PathBuf {
    PathBuf::from(format!("/Library/LaunchDaemons/{label}.plist"))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn plist(label: &str, args: &[&str], extra: &str) -> String {
    let args: String = args
        .iter()
        .map(|a| format!("\t\t<string>{}</string>\n", xml_escape(a)))
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{label}</string>
	<key>ProgramArguments</key>
	<array>
{args}	</array>
	<key>StandardOutPath</key>
	<string>{LOG}</string>
	<key>StandardErrorPath</key>
	<string>{LOG}</string>
{extra}</dict>
</plist>
"#
    )
}

fn daemon_plist(config: &Path) -> String {
    plist(
        LABEL,
        &[BIN, "--config", &config.to_string_lossy(), "run"],
        "\t<key>RunAtLoad</key>\n\t<true/>\n\t<key>KeepAlive</key>\n\t<true/>\n\t<key>ThrottleInterval</key>\n\t<integer>10</integer>\n",
    )
}

fn geoip_plist(config: &Path) -> String {
    // DB-IP publishes on the 1st; the 3rd leaves room for a late release.
    plist(
        GEOIP_LABEL,
        &[BIN, "--config", &config.to_string_lossy(), "update-geoip"],
        "\t<key>StartCalendarInterval</key>\n\t<dict>\n\t\t<key>Day</key>\n\t\t<integer>3</integer>\n\t\t<key>Hour</key>\n\t\t<integer>4</integer>\n\t</dict>\n",
    )
}

fn update_plist(config: &Path) -> String {
    // Daily at 05:17; launchd runs a missed time when the Mac wakes.
    plist(
        UPDATE_LABEL,
        &[BIN, "--config", &config.to_string_lossy(), "update"],
        "\t<key>StartCalendarInterval</key>\n\t<dict>\n\t\t<key>Hour</key>\n\t\t<integer>5</integer>\n\t\t<key>Minute</key>\n\t\t<integer>17</integer>\n\t</dict>\n",
    )
}

/// The `--config` path in the installed daemon's plist.
pub fn installed_config() -> Option<PathBuf> {
    config_in_plist(&std::fs::read_to_string(plist_path(LABEL)).ok()?)
}

fn config_in_plist(plist: &str) -> Option<PathBuf> {
    let strings: Vec<String> = plist
        .split("<string>")
        .skip(1)
        .filter_map(|s| s.split_once("</string>"))
        .map(|(v, _)| {
            v.replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&amp;", "&")
        })
        .collect();
    let i = strings.iter().position(|s| s == "--config")?;
    strings.get(i + 1).map(PathBuf::from)
}

pub fn update_job_installed() -> bool {
    plist_path(UPDATE_LABEL).exists()
}

/// `netwatch update --auto on|off`: the daily `netwatch update` job.
pub fn set_update_job(config: &Path, on: bool) -> anyhow::Result<()> {
    let path = plist_path(UPDATE_LABEL);
    let _ = launchctl(&["bootout", &format!("system/{UPDATE_LABEL}")]);
    if !on {
        let _ = std::fs::remove_file(&path);
        return Ok(());
    }
    std::fs::write(&path, update_plist(config))?;
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o644))?;
    launchctl(&["bootstrap", "system", &path.to_string_lossy()])
}

fn launchctl(args: &[&str]) -> anyhow::Result<()> {
    let out = Command::new("/bin/launchctl")
        .args(args)
        .output()
        .context("running launchctl")?;
    if !out.status.success() {
        bail!(
            "launchctl {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn require_root(what: &str) -> anyhow::Result<()> {
    if !super::is_root() {
        bail!("{what} needs root: sudo netwatch {what}");
    }
    Ok(())
}

/// Copies this binary into place, writes the config if there is none, fetches
/// the GeoIP databases and (re)starts the launchd daemons.
pub fn install(config: &Path) -> anyhow::Result<()> {
    require_root("install")?;
    // The plist keeps this path, and update and uninstall read it back: a
    // relative one would mean something else from another directory.
    let config = &std::path::absolute(config)?;
    let exe = std::env::current_exe()?.canonicalize()?;
    std::fs::create_dir_all("/usr/local/bin")?;
    if exe != Path::new(BIN) {
        let tmp = format!("{BIN}.new");
        std::fs::copy(&exe, &tmp).with_context(|| format!("copying {} to {BIN}", exe.display()))?;
        std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
        std::fs::rename(&tmp, BIN)?;
        println!("installed {BIN}");
    }

    if let Some(dir) = config.parent() {
        std::fs::create_dir_all(dir)?;
    }
    if !config.exists() {
        std::fs::write(config, toml::to_string_pretty(&Config::default())?)?;
        println!(
            "wrote {} (interface = auto, mode = observe)",
            config.display()
        );
    }
    let cfg = Config::load(config)?;
    if let Some(dir) = cfg.db_path.parent() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o750))?;
    }
    if (!cfg.geoip_city.exists() || !cfg.geoip_asn.exists())
        && let Err(e) = update_geoip(&cfg)
    {
        eprintln!(
            "GeoIP download failed ({e:#}); netwatch runs without locations until `sudo netwatch update-geoip` works"
        );
    }

    for (label, body) in [
        (LABEL, daemon_plist(config)),
        (GEOIP_LABEL, geoip_plist(config)),
    ] {
        let path = plist_path(label);
        std::fs::write(&path, body)?;
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o644))?;
        let _ = launchctl(&["bootout", &format!("system/{label}")]);
        launchctl(&["bootstrap", "system", &path.to_string_lossy()])?;
    }
    println!(
        "started {LABEL} ({} on {}, mode {:?}); logs in {LOG}",
        crate::kernel::ENGINE,
        cfg.interface,
        cfg.mode
    );
    println!("UI: http://{}  ·  CLI: netwatch status", cfg.api_listen);
    Ok(())
}

/// Everything install and update put in /usr/local/bin.
fn installed_binaries() -> [&'static str; 2] {
    [BIN, crate::update::PREVIOUS]
}

pub fn uninstall(config: &Path, purge: bool) -> anyhow::Result<()> {
    require_root("uninstall")?;
    // Booting out the update job would stop an update halfway through; the
    // lock is in the data directory of the config the daemon runs with.
    let installed = Config::load(&crate::update::installed_config(config)).unwrap_or_default();
    let _lock = crate::update::Lock::take(&installed)?;
    // --purge deletes directories, so only the ones the given config (the
    // default unless --config says otherwise) names, never ones read from
    // the plist.
    let cfg = Config::load(config).unwrap_or_default();
    for label in [LABEL, GEOIP_LABEL, UPDATE_LABEL] {
        let _ = launchctl(&["bootout", &format!("system/{label}")]);
        let _ = std::fs::remove_file(plist_path(label));
    }
    println!("stopped and removed {LABEL}");
    for bin in installed_binaries() {
        let _ = std::fs::remove_file(bin);
    }
    if purge {
        for dir in [
            cfg.db_path.parent(),
            config.parent(),
            cfg.control_socket.parent(),
        ]
        .into_iter()
        .flatten()
        {
            if dir.ends_with("netwatch") {
                let _ = std::fs::remove_dir_all(dir);
                println!("removed {}", dir.display());
            }
        }
        let _ = std::fs::remove_file(LOG);
    } else {
        println!(
            "kept {} and the database; `sudo netwatch uninstall --purge` removes them",
            config.display()
        );
    }
    Ok(())
}

fn writing(path: &Path) -> String {
    if super::is_root() {
        format!("writing {}", path.display())
    } else {
        format!(
            "can't write {}; run it as root: sudo netwatch update-geoip",
            path.display()
        )
    }
}

fn writable(dir: &Path) -> bool {
    let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    // SAFETY: c is NUL-terminated.
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

/// "2026-11" and the month before.
fn months(now: chrono::DateTime<chrono::Utc>) -> [String; 2] {
    use chrono::Datelike;
    let (y, m) = (now.year(), now.month());
    let (py, pm) = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
    [format!("{y}-{m:02}"), format!("{py}-{pm:02}")]
}

/// Downloads the free DB-IP Lite city and ASN databases (CC BY 4.0), as
/// scripts/netwatch-update-geoip does. The daemon reloads changed files.
pub fn update_geoip(cfg: &Config) -> anyhow::Result<()> {
    for (kind, dest) in [("city", &cfg.geoip_city), ("asn", &cfg.geoip_asn)] {
        if let Some(dir) = dest.parent() {
            std::fs::create_dir_all(dir).with_context(|| writing(dir))?;
            // Fail before downloading 100 MB that can't be saved.
            if !super::is_root() && !writable(dir) {
                bail!("{}", writing(dir));
            }
        }
        let tmp_gz = dest.with_extension("mmdb.gz.part");
        let tmp = dest.with_extension("mmdb.part");
        let mut done = false;
        // The new month's file appears a day or two in; fall back to last month.
        for month in months(chrono::Utc::now()) {
            let url = format!("https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz");
            let ok = Command::new("/usr/bin/curl")
                .args(["-fsSL", "--retry", "3", "-o"])
                .arg(&tmp_gz)
                .arg(&url)
                .status()
                .is_ok_and(|s| s.success());
            if !ok {
                continue;
            }
            let out = Command::new("/usr/bin/gunzip")
                .arg("-c")
                .arg(&tmp_gz)
                .output()?;
            if !out.status.success() || out.stdout.is_empty() {
                continue;
            }
            std::fs::write(&tmp, &out.stdout).with_context(|| writing(&tmp))?;
            std::fs::rename(&tmp, dest).with_context(|| writing(dest))?;
            println!("updated {} ({month})", dest.display());
            done = true;
            break;
        }
        let _ = std::fs::remove_file(&tmp_gz);
        if !done {
            bail!("could not download dbip-{kind}-lite");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_config_path_back_from_the_plist() {
        for path in ["/etc/netwatch/netwatch.toml", "/opt/a&b <x>/netwatch.toml"] {
            let p = daemon_plist(Path::new(path));
            assert_eq!(config_in_plist(&p), Some(PathBuf::from(path)));
        }
        assert_eq!(config_in_plist("<plist></plist>"), None);
    }

    #[test]
    fn uninstall_removes_the_binary_update_kept() {
        assert_eq!(
            installed_binaries(),
            [
                "/usr/local/bin/netwatch",
                "/usr/local/bin/netwatch.previous"
            ]
        );
    }

    #[test]
    fn plists_are_well_formed() {
        let p = daemon_plist(Path::new("/etc/netwatch/netwatch.toml"));
        assert!(p.contains("<string>dev.netwatch</string>"));
        assert!(
            p.contains("<string>/usr/local/bin/netwatch</string>\n\t\t<string>--config</string>")
        );
        assert!(p.contains("<key>KeepAlive</key>"));
        let out = Command::new("/usr/bin/plutil")
            .args(["-lint", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn();
        if let Ok(mut child) = out {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(p.as_bytes()).unwrap();
            assert!(
                child.wait_with_output().unwrap().status.success(),
                "plutil rejects:\n{p}"
            );
        }
        assert!(geoip_plist(Path::new("/etc/x.toml")).contains("StartCalendarInterval"));
    }

    #[test]
    fn geoip_months() {
        let d = |s: &str| {
            chrono::DateTime::parse_from_rfc3339(s)
                .unwrap()
                .with_timezone(&chrono::Utc)
        };
        assert_eq!(months(d("2026-11-05T00:00:00Z")), ["2026-11", "2026-10"]);
        assert_eq!(months(d("2027-01-02T00:00:00Z")), ["2027-01", "2026-12"]);
    }
}
