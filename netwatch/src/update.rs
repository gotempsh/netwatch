//! `netwatch update`: installs the latest GitHub release over an installed
//! netwatch the way the one-line installer does (the release's own
//! scripts/install.sh on Linux, its `netwatch install` on macOS), and goes
//! back to the running version if the new daemon doesn't come up.
//! `--auto on` runs it daily from a systemd timer or a launchd job.

use std::{
    os::unix::fs::{DirBuilderExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use anyhow::{Context as _, bail};
use semver::Version;
use sha2::{Digest as _, Sha256};

use crate::config::Config;

pub const RELEASES: &str = "https://github.com/gotempsh/netwatch/releases";
pub const BIN: &str = "/usr/local/bin/netwatch";
/// The binary an update replaced, kept to go back to; uninstall removes it.
pub const PREVIOUS: &str = "/usr/local/bin/netwatch.previous";
/// How long the new daemon has to answer on the API with its version.
const START_WAIT: Duration = Duration::from_secs(60);

#[cfg(target_os = "linux")]
const UNIT_DIR: &str = "/etc/systemd/system";
#[cfg(target_os = "linux")]
const UPDATE_SERVICE: &str = include_str!("../../scripts/systemd/netwatch-update.service");
#[cfg(target_os = "linux")]
const UPDATE_TIMER: &str = include_str!("../../scripts/systemd/netwatch-update.timer");

/// The release archive for this machine, as the installer names it.
pub fn asset() -> anyhow::Result<&'static str> {
    Ok(match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "netwatch-linux-x86_64",
        ("linux", "aarch64") => "netwatch-linux-aarch64",
        ("macos", "aarch64") => "netwatch-macos-arm64",
        ("macos", "x86_64") => "netwatch-macos-x86_64",
        (os, arch) => bail!("there is no netwatch release for {os} {arch}; build from source"),
    })
}

fn running() -> Version {
    Version::parse(env!("CARGO_PKG_VERSION")).expect("the crate version is semver")
}

/// `v0.1.3` -> 0.1.3.
fn parse_tag(tag: &str) -> anyhow::Result<Version> {
    Version::parse(tag.strip_prefix('v').unwrap_or(tag))
        .with_context(|| format!("the latest release's tag {tag:?} is not a version"))
}

/// `.../releases/tag/v0.1.3` -> `v0.1.3`.
fn tag_from_location(location: &str) -> Option<&str> {
    let (_, tag) = location.rsplit_once("/releases/tag/")?;
    let tag = tag.split(['?', '#']).next()?;
    (!tag.is_empty() && !tag.contains('/')).then_some(tag)
}

/// The hash SHA256SUMS lists for `file` (`sha256sum` output: `<hex>  <name>`).
fn listed_sum<'a>(sums: &'a str, file: &str) -> Option<&'a str> {
    sums.lines().find_map(|l| {
        let mut parts = l.split_whitespace();
        let (hash, name) = (parts.next()?, parts.next()?);
        (name.trim_start_matches('*') == file && hash.len() == 64).then_some(hash)
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn client(redirects: bool) -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(concat!("netwatch/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .redirect(if redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        })
        .build()?)
}

/// The tag `releases/latest` points at. Reading the redirect needs no API
/// token and has no rate limit.
async fn latest_tag(releases: &str) -> anyhow::Result<String> {
    let url = format!("{releases}/latest");
    let resp = client(false)?
        .get(&url)
        .send()
        .await
        .with_context(|| format!("checking {url}"))?;
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|l| l.to_str().ok())
        .unwrap_or_default();
    match tag_from_location(location) {
        Some(tag) => Ok(tag.to_string()),
        None => bail!(
            "{url} answered {} without pointing at a release",
            resp.status()
        ),
    }
}

async fn download(http: &reqwest::Client, url: &str) -> anyhow::Result<Vec<u8>> {
    let resp = http
        .get(url)
        .send()
        .await
        .with_context(|| format!("downloading {url}"))?;
    if !resp.status().is_success() {
        bail!("downloading {url}: {}", resp.status());
    }
    Ok(resp
        .bytes()
        .await
        .with_context(|| format!("downloading {url}"))?
        .to_vec())
}

/// Downloads `<asset>.tar.gz` of `tag`, checks it against the same release's
/// SHA256SUMS, unpacks it in `dir` and returns the unpacked directory.
async fn fetch(releases: &str, tag: &str, asset: &str, dir: &Path) -> anyhow::Result<PathBuf> {
    let http = client(true)?;
    let base = format!("{releases}/download/{tag}");
    let file = format!("{asset}.tar.gz");
    let sums = download(&http, &format!("{base}/SHA256SUMS")).await?;
    let sums = String::from_utf8_lossy(&sums);
    let Some(want) = listed_sum(&sums, &file) else {
        bail!("{file} is not listed in {tag}'s SHA256SUMS; nothing was installed");
    };
    let archive = download(&http, &format!("{base}/{file}")).await?;
    let got = hex(&Sha256::digest(&archive));
    if !got.eq_ignore_ascii_case(want) {
        bail!("{file} of {tag} doesn't match its SHA256SUMS; nothing was installed");
    }
    let path = dir.join(&file);
    std::fs::write(&path, &archive).with_context(|| format!("writing {}", path.display()))?;
    let out = Command::new("tar")
        .arg("-xzf")
        .arg(&path)
        .arg("-C")
        .arg(dir)
        .output()
        .context("running tar")?;
    if !out.status.success() {
        bail!(
            "unpacking {file}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(dir.join(asset))
}

/// A private directory, removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> anyhow::Result<Self> {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("netwatch-update-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        // Fails if someone else created it in between: root unpacks nothing there.
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .with_context(|| format!("creating {}", path.display()))?;
        Ok(Self(path))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One update at a time: the timer and a person can start one together.
/// Turning automatic updates on or off and uninstalling take it too, because
/// on macOS they stop the update job, and with it an update in progress.
pub struct Lock {
    _file: std::fs::File,
}

impl Lock {
    pub fn take(cfg: &Config) -> anyhow::Result<Self> {
        Self::take_in(
            cfg.db_path
                .parent()
                .unwrap_or(Path::new("/var/lib/netwatch")),
        )
    }

    fn take_in(dir: &Path) -> anyhow::Result<Self> {
        use std::os::fd::AsRawFd as _;
        std::fs::create_dir_all(dir)?;
        let path = dir.join("update.lock");
        let file =
            std::fs::File::create(&path).with_context(|| format!("opening {}", path.display()))?;
        // SAFETY: the descriptor is open for the lifetime of `file`.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            bail!("another netwatch update is running");
        }
        Ok(Self { _file: file })
    }
}

// ---- messages ----

pub fn up_to_date(v: &Version) -> String {
    format!("netwatch {v} is the latest release")
}

pub fn available(installed: &Version, latest: &Version) -> String {
    format!(
        "netwatch {latest} is available (installed: {installed}); install it with: sudo netwatch update"
    )
}

pub fn updated(from: &Version, to: &Version) -> String {
    format!("updated netwatch {from} to {to}; the daemon is running it")
}

fn auto_state(on: bool) -> &'static str {
    if on {
        "automatic updates are on: netwatch installs new releases daily"
    } else {
        "automatic updates are off; `sudo netwatch update --auto on` installs new releases daily"
    }
}

fn log_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        "/var/log/netwatch.log"
    } else {
        "journalctl -u netwatch -n 50"
    }
}

/// The last lines of a command's output, for an error message.
fn tail(out: &std::process::Output, lines: usize) -> String {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let all: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

// ---- installing ----

/// Refuses anything the installer didn't set up: a container, a build run
/// from the source tree, a copy somewhere else.
fn check_managed() -> anyhow::Result<()> {
    let exe = std::env::current_exe().unwrap_or_default();
    if Path::new("/.dockerenv").exists() || std::env::var_os("container").is_some() {
        bail!(
            "netwatch runs in a container here; pull the new image instead: docker pull ghcr.io/gotempsh/netwatch"
        );
    }
    check_binary(&exe, Path::new(BIN))?;
    let service = if cfg!(target_os = "macos") {
        "/Library/LaunchDaemons/dev.netwatch.plist"
    } else {
        "/etc/systemd/system/netwatch.service"
    };
    if !Path::new(service).exists() {
        bail!(
            "{service} is missing, so the installer didn't set up this netwatch; install it with: curl -fsSL https://gotempsh.github.io/netwatch/install.sh | sh"
        );
    }
    Ok(())
}

/// `bin` is the file the installer wrote and `exe` is it. A symlink at `bin`
/// itself is someone's own build linked into place, which an update would
/// replace with a release; a symlinked parent directory is fine.
fn check_binary(exe: &Path, bin: &Path) -> anyhow::Result<()> {
    if let Ok(target) = std::fs::read_link(bin) {
        bail!(
            "{} links to {}, so it isn't the installer's binary and netwatch update won't replace it; update that build yourself",
            bin.display(),
            target.display()
        );
    }
    if !same_file(exe, bin) {
        bail!(
            "netwatch update replaces {}, which the installer set up, but this is {}; run {} update, or rebuild from source",
            bin.display(),
            exe.display(),
            bin.display()
        );
    }
    Ok(())
}

/// Whether two paths are the same file. Comparing paths isn't enough: where
/// /usr/local is a symlink (Fedora CoreOS and Silverblue point it at
/// /var/usrlocal), the running binary's path resolves somewhere else.
fn same_file(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(a), Ok(b)) => (a.dev(), a.ino()) == (b.dev(), b.ino()),
        _ => false,
    }
}

/// The config the installed daemon runs with. On macOS that's the path in
/// its launchd plist, which `install` may have been given with --config, so
/// an update, its rollback and the daily job keep it. The Linux service
/// always runs with the default path.
pub fn installed_config(given: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    if let Some(path) = crate::macos::launchd::installed_config() {
        return path;
    }
    given.to_path_buf()
}

/// The new release's own installer: it updates the binary and the service
/// files and restarts the daemon.
fn install(unpacked: &Path, config: &Path) -> std::io::Result<std::process::Output> {
    if cfg!(target_os = "macos") {
        Command::new(unpacked.join("netwatch"))
            .arg("--config")
            .arg(config)
            .arg("install")
            .output()
    } else {
        Command::new(unpacked.join("scripts/install.sh")).output()
    }
}

/// Puts the saved binary back and restarts the daemon with it.
fn roll_back(config: &Path) -> anyhow::Result<()> {
    if cfg!(target_os = "macos") {
        let out = Command::new(PREVIOUS)
            .arg("--config")
            .arg(config)
            .arg("install")
            .output()?;
        if !out.status.success() {
            bail!("{}", tail(&out, 5));
        }
    } else {
        let tmp = format!("{BIN}.rollback");
        std::fs::copy(PREVIOUS, &tmp)?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
        std::fs::rename(&tmp, BIN)?;
        let out = Command::new("systemctl")
            .args(["restart", "netwatch.service"])
            .output()?;
        if !out.status.success() {
            bail!("{}", tail(&out, 5));
        }
    }
    Ok(())
}

/// Waits for the daemon to answer on the API with `version`.
async fn wait_for(cfg: &Config, version: &Version) -> bool {
    let http = reqwest::Client::new();
    let url = format!("{}/api/overview", cfg.api_url());
    let want = version.to_string();
    let deadline = tokio::time::Instant::now() + START_WAIT;
    while tokio::time::Instant::now() < deadline {
        if let Ok(resp) = http.get(&url).timeout(Duration::from_secs(3)).send().await
            && let Ok(v) = resp.json::<serde_json::Value>().await
            && v["version"].as_str() == Some(want.as_str())
        {
            return true;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    false
}

fn require_root(cmd: &str) -> anyhow::Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("this needs root: sudo {cmd}");
    }
    Ok(())
}

pub async fn run(given: &Path, check: bool, auto: Option<&str>) -> anyhow::Result<()> {
    let config = &installed_config(given);
    let cfg = &Config::load(config)?;
    if let Some(auto) = auto {
        require_root(&format!("netwatch update --auto {auto}"))?;
        let _lock = Lock::take(cfg)?;
        let on = auto == "on";
        set_auto(config, on)?;
        eprintln!("{}", auto_state(on));
        return Ok(());
    }
    let asset = asset()?;
    let current = running();
    let tag = latest_tag(RELEASES).await?;
    let latest = parse_tag(&tag)?;
    if check {
        if latest > current {
            println!("{}", available(&current, &latest));
        } else {
            println!("{}", up_to_date(&current));
        }
        println!("{}", auto_state(auto_enabled()));
        return Ok(());
    }
    if latest <= current {
        eprintln!("{}", up_to_date(&current));
        return Ok(());
    }

    require_root("netwatch update")?;
    check_managed()?;
    let _lock = Lock::take(cfg)?;
    let dir = TempDir::new()?;
    let unpacked = fetch(RELEASES, &tag, asset, &dir.0).await?;

    // Before anything changes: does the new binary run here, and is it what the tag says?
    let out = Command::new(unpacked.join("netwatch"))
        .arg("--version")
        .output()
        .with_context(|| format!("running the downloaded netwatch {latest}"))?;
    let says = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() || says != format!("netwatch {latest}") {
        bail!(
            "the downloaded netwatch {latest} doesn't run here ({}); nothing was installed",
            if says.is_empty() { tail(&out, 3) } else { says }
        );
    }

    std::fs::copy(BIN, PREVIOUS).with_context(|| format!("saving {BIN} to {PREVIOUS}"))?;
    let result = install(&unpacked, config);
    let failure = match &result {
        Err(e) => Some(format!("its installer didn't run: {e}")),
        Ok(out) if !out.status.success() => Some(format!("its installer said:\n{}", tail(out, 10))),
        Ok(_) if !wait_for(cfg, &latest).await => Some(format!(
            "the daemon didn't answer with version {latest} within {}s",
            START_WAIT.as_secs()
        )),
        Ok(_) => None,
    };
    let Some(why) = failure else {
        eprintln!("{}", updated(&current, &latest));
        return Ok(());
    };
    match roll_back(config) {
        Ok(()) => bail!(
            "netwatch {latest} didn't start, so {current} is back in place ({}): {why}",
            log_hint()
        ),
        Err(e) => bail!(
            "netwatch {latest} didn't start ({why}), and putting {current} back failed too ({e:#}); reinstall it with: curl -fsSL https://gotempsh.github.io/netwatch/install.sh | NETWATCH_VERSION=v{current} sh"
        ),
    }
}

// ---- automatic updates ----

#[cfg(target_os = "linux")]
fn auto_enabled() -> bool {
    Command::new("systemctl")
        .args(["is-enabled", "--quiet", "netwatch-update.timer"])
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(target_os = "macos")]
fn auto_enabled() -> bool {
    crate::macos::launchd::update_job_installed()
}

#[cfg(target_os = "linux")]
fn set_auto(_config: &Path, on: bool) -> anyhow::Result<()> {
    let systemctl = |args: &[&str]| -> anyhow::Result<()> {
        let out = Command::new("systemctl")
            .args(args)
            .output()
            .context("running systemctl")?;
        if !out.status.success() {
            bail!("systemctl {}: {}", args.join(" "), tail(&out, 3));
        }
        Ok(())
    };
    if on {
        check_managed()?;
        // Written here too, so an install from before these units existed can turn it on.
        for (name, body) in [
            ("netwatch-update.service", UPDATE_SERVICE),
            ("netwatch-update.timer", UPDATE_TIMER),
        ] {
            let path = Path::new(UNIT_DIR).join(name);
            std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
        }
        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", "--now", "netwatch-update.timer"])
    } else {
        if Path::new(UNIT_DIR).join("netwatch-update.timer").exists() {
            systemctl(&["disable", "--now", "netwatch-update.timer"])?;
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn set_auto(config: &Path, on: bool) -> anyhow::Result<()> {
    if on {
        check_managed()?;
    }
    crate::macos::launchd::set_update_job(config, on)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_tag_from_the_redirect() {
        let base = "https://github.com/gotempsh/netwatch/releases";
        assert_eq!(
            tag_from_location(&format!("{base}/tag/v0.1.3")),
            Some("v0.1.3")
        );
        assert_eq!(
            tag_from_location(&format!("{base}/tag/v0.2.0-rc.1?x=1")),
            Some("v0.2.0-rc.1")
        );
        assert_eq!(tag_from_location(base), None);
        assert_eq!(tag_from_location(""), None);
        assert_eq!(tag_from_location(&format!("{base}/tag/")), None);
    }

    #[test]
    fn compares_versions() {
        assert_eq!(parse_tag("v0.1.3").unwrap(), Version::new(0, 1, 3));
        assert!(parse_tag("v0.1.10").unwrap() > parse_tag("v0.1.9").unwrap());
        // A release candidate you run is newer than the release before it.
        assert!(parse_tag("v0.2.0-rc.1").unwrap() > parse_tag("v0.1.9").unwrap());
        assert!(parse_tag("latest").is_err());
    }

    #[test]
    fn finds_the_listed_hash() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let sums = format!("{a}  netwatch-linux-x86_64.tar.gz\n{b} *netwatch-macos-arm64.tar.gz\n");
        assert_eq!(
            listed_sum(&sums, "netwatch-linux-x86_64.tar.gz"),
            Some(a.as_str())
        );
        assert_eq!(
            listed_sum(&sums, "netwatch-macos-arm64.tar.gz"),
            Some(b.as_str())
        );
        assert_eq!(listed_sum(&sums, "netwatch-linux-aarch64.tar.gz"), None);
        assert_eq!(
            listed_sum(
                "short  netwatch-linux-x86_64.tar.gz",
                "netwatch-linux-x86_64.tar.gz"
            ),
            None
        );
    }

    #[test]
    fn names_this_machines_archive() {
        let a = asset().unwrap();
        assert!(
            a.starts_with(&format!("netwatch-{}-", std::env::consts::OS)),
            "{a}"
        );
    }

    #[test]
    fn the_same_file_through_a_symlinked_directory() {
        let dir = tempdir("same");
        let real = dir.join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("netwatch"), "x").unwrap();
        std::fs::write(real.join("other"), "x").unwrap();
        // Like /usr/local -> ../var/usrlocal.
        std::os::unix::fs::symlink(&real, dir.join("link")).unwrap();
        let resolved = real.join("netwatch").canonicalize().unwrap();
        assert!(same_file(&resolved, &dir.join("link/netwatch")));
        assert!(!same_file(&resolved, &dir.join("link/other")));
        assert!(!same_file(&resolved, &dir.join("link/missing")));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refuses_a_binary_linked_into_place() {
        let dir = tempdir("linked");
        let real = dir.join("real");
        std::fs::create_dir(&real).unwrap();
        let build = dir.join("build");
        std::fs::write(&build, "x").unwrap();
        // Someone's own build linked in as the binary: an update would replace the link.
        let bin = real.join("netwatch");
        std::os::unix::fs::symlink(&build, &bin).unwrap();
        let e = check_binary(&build, &bin).unwrap_err().to_string();
        assert!(
            e.contains("links to") && e.contains("won't replace it"),
            "{e}"
        );
        // The installer's own file, reached through a symlinked directory, is fine.
        std::fs::remove_file(&bin).unwrap();
        std::fs::write(&bin, "x").unwrap();
        std::os::unix::fs::symlink(&real, dir.join("link")).unwrap();
        check_binary(&bin.canonicalize().unwrap(), &dir.join("link/netwatch")).unwrap();
        // And a different file still isn't.
        assert!(check_binary(&build, &dir.join("link/netwatch")).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn one_update_at_a_time() {
        let dir = tempdir("lock");
        let held = Lock::take_in(&dir).unwrap();
        let e = Lock::take_in(&dir).err().expect("a second lock is refused");
        assert_eq!(e.to_string(), "another netwatch update is running");
        drop(held);
        // Another test's child process can hold a copy of the descriptor for
        // a moment between fork and exec; the lock is free once it execs.
        let mut free = false;
        for _ in 0..100 {
            free = Lock::take_in(&dir).is_ok();
            if free {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(free, "the lock is free again once released");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn messages() {
        let (a, b) = (Version::new(0, 1, 2), Version::new(0, 1, 3));
        assert_eq!(up_to_date(&a), "netwatch 0.1.2 is the latest release");
        assert_eq!(
            available(&a, &b),
            "netwatch 0.1.3 is available (installed: 0.1.2); install it with: sudo netwatch update"
        );
        assert_eq!(
            updated(&a, &b),
            "updated netwatch 0.1.2 to 0.1.3; the daemon is running it"
        );
        assert!(auto_state(false).contains("sudo netwatch update --auto on"));
    }

    /// A release server: `releases/latest` redirects to the tag, and the tag
    /// has an archive and SHA256SUMS, optionally wrong.
    async fn serve(archive: Vec<u8>, sums: String) -> String {
        use axum::{Router, http::header, response::IntoResponse, routing::get};
        let app = Router::new()
            .route(
                "/releases/latest",
                get(|| async {
                    (
                        axum::http::StatusCode::FOUND,
                        [(
                            header::LOCATION,
                            "https://example.invalid/o/r/releases/tag/v9.9.9",
                        )],
                    )
                        .into_response()
                }),
            )
            .route(
                "/releases/download/v9.9.9/SHA256SUMS",
                get(move || async move { sums }),
            )
            .route(
                &format!("/releases/download/v9.9.9/{}.tar.gz", asset().unwrap()),
                get(move || async move { archive }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}/releases")
    }

    /// `<asset>/netwatch` packed as the release workflow does.
    fn archive() -> Vec<u8> {
        let dir = TempDir::new().unwrap();
        let top = dir.0.join(asset().unwrap());
        std::fs::create_dir(&top).unwrap();
        std::fs::write(top.join("netwatch"), "#!/bin/sh\necho netwatch 9.9.9\n").unwrap();
        let out = dir.0.join("a.tar.gz");
        assert!(
            Command::new("tar")
                .arg("-czf")
                .arg(&out)
                .arg("-C")
                .arg(&dir.0)
                .arg(asset().unwrap())
                .status()
                .unwrap()
                .success()
        );
        std::fs::read(out).unwrap()
    }

    #[tokio::test]
    async fn fetches_and_checks_a_release() {
        let tgz = archive();
        let file = format!("{}.tar.gz", asset().unwrap());
        let sums = format!("{}  {file}\n", hex(&Sha256::digest(&tgz)));
        let releases = serve(tgz, sums).await;
        assert_eq!(latest_tag(&releases).await.unwrap(), "v9.9.9");
        let dir = tempdir("ok");
        let unpacked = fetch(&releases, "v9.9.9", asset().unwrap(), &dir)
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(unpacked.join("netwatch")).unwrap(),
            "#!/bin/sh\necho netwatch 9.9.9\n"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn refuses_an_archive_that_does_not_match() {
        let tgz = archive();
        let file = format!("{}.tar.gz", asset().unwrap());
        let releases = serve(tgz, format!("{}  {file}\n", "0".repeat(64))).await;
        let dir = tempdir("bad");
        let e = fetch(&releases, "v9.9.9", asset().unwrap(), &dir)
            .await
            .unwrap_err();
        assert_eq!(
            e.to_string(),
            format!("{file} of v9.9.9 doesn't match its SHA256SUMS; nothing was installed")
        );
        assert!(!dir.join(&file).exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn tempdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "netwatch-update-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir(&d).unwrap();
        d
    }
}
