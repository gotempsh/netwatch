//! Seeing the host from inside a container.
//!
//! In a container (docker compose with `network_mode: host`, `pid: host` and
//! `privileged`), /proc and the network are already the host's. Host files are
//! read through /proc/1/root, and host tools (sshd, journalctl, ip, wg,
//! tailscale) run in PID 1's mount namespace, so the image carries none of them
//! and the compose file needs no host bind mounts. Outside a container every
//! function here is a no-op, as it always is on macOS.

#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::process::Command;
#[cfg(target_os = "linux")]
use std::{
    path::{Path, PathBuf},
    sync::LazyLock,
};

#[cfg(target_os = "linux")]
static CONTAINER: LazyLock<bool> = LazyLock::new(|| match std::env::var("NETWATCH_CONTAINER") {
    Ok(v) => v == "1" || v == "true",
    Err(_) => Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists(),
});

#[cfg(target_os = "linux")]
pub fn in_container() -> bool {
    *CONTAINER
}

/// A host path: as is on the host, under /proc/1/root in a container.
#[cfg(target_os = "linux")]
pub fn path(p: &str) -> PathBuf {
    if in_container() {
        Path::new("/proc/1/root").join(p.trim_start_matches('/'))
    } else {
        PathBuf::from(p)
    }
}

/// A command that runs the host's `prog`, with the host's filesystem.
pub fn command(prog: &str) -> Command {
    #[allow(unused_mut)]
    let mut c = Command::new(prog);
    #[cfg(target_os = "linux")]
    if in_container() {
        // SAFETY: only async-signal-safe calls (open, setns, close, chdir) between fork and exec.
        unsafe {
            c.pre_exec(|| {
                let fd = libc::open(c"/proc/1/ns/mnt".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let r = libc::setns(fd, libc::CLONE_NEWNS);
                libc::close(fd);
                if r != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::chdir(c"/".as_ptr());
                Ok(())
            });
        }
    }
    c
}

/// The host's name.
#[cfg(target_os = "macos")]
pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: gethostname writes at most buf.len() bytes.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return String::new();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end])
        .trim_end_matches(".local")
        .to_string()
}

/// The host's name. A container has its own UTS namespace, so read /etc/hostname there.
#[cfg(target_os = "linux")]
pub fn hostname() -> String {
    let p = if in_container() {
        path("/etc/hostname")
    } else {
        PathBuf::from("/proc/sys/kernel/hostname")
    };
    std::fs::read_to_string(p)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Docker doesn't mount tracefs in containers; the TCP tracepoints need it.
#[cfg(target_os = "linux")]
pub fn ensure_tracefs() {
    if !in_container()
        || [
            "/sys/kernel/tracing/events",
            "/sys/kernel/debug/tracing/events",
        ]
        .iter()
        .any(|p| Path::new(p).exists())
    {
        return;
    }
    // SAFETY: plain mount(2) with static C strings.
    let r = unsafe {
        libc::mount(
            c"nodev".as_ptr(),
            c"/sys/kernel/tracing".as_ptr(),
            c"tracefs".as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if r != 0 {
        log::warn!(
            "mounting tracefs failed ({}); connection tracking needs a privileged container",
            std::io::Error::last_os_error()
        );
    }
}
