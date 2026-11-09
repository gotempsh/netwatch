//! macOS support. The engine, flow table, detection, policy, store and UI are
//! shared with Linux; this module replaces what Linux gets from the kernel:
//!
//! - `sensor`: the XDP, TC and tracepoint programs of netwatch-ebpf, as a
//!   userspace state machine producing the same netwatch-common records;
//! - `bpf`: /dev/bpf capture, whose extended header gives each packet's
//!   direction and, for outgoing ones, the sending process;
//! - `kernel`: the `Kernel` the daemon drives, with one capture thread per interface;
//! - `pf`: bans, as a pf table in the anchor com.apple/netwatch;
//! - `proc`: socket owners from libproc; `netif`: interfaces from the routing sysctl;
//! - `launchd`: `netwatch install` / `uninstall`.

pub mod bpf;
pub mod kernel;
pub mod launchd;
pub mod netif;
pub mod pf;
pub mod proc;
pub mod sensor;

use std::ffi::CString;

/// An integer sysctl such as `net.inet.ip.portrange.first`.
pub fn sysctl_u32(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    let mut v: u32 = 0;
    let mut len = size_of::<u32>();
    // SAFETY: v and len describe a valid 4-byte buffer.
    let r = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&raw mut v).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (r == 0 && len == size_of::<u32>()).then_some(v)
}

/// Remote Login (System Settings > General > Sharing) runs sshd from launchd.
pub fn remote_login_enabled() -> bool {
    std::process::Command::new("/bin/launchctl")
        .args(["print", "system/com.openssh.sshd"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// launchd has no EnvironmentFile: read `KEY=value` lines (the Slack webhook,
/// the LLM key) from the file systemd would load, if it exists.
pub fn load_env_file(path: &std::path::Path) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim().trim_matches(|c| c == '"' || c == '\'');
            if std::env::var_os(k.trim()).is_none() {
                // SAFETY: called at startup, before any other thread exists.
                unsafe { std::env::set_var(k.trim(), v) };
            }
        }
    }
}
