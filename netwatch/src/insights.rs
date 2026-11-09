//! Plain-language observations with a suggested command, computed from
//! current state. Deterministic: no LLM involved.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use crate::{
    config::Mode,
    daemon::App,
    policy::Action,
    util::{is_public, now_unix, port_label},
};

#[cfg(target_os = "linux")]
const DISABLE_SSH_PASSWORDS: &str = "printf 'PasswordAuthentication no\\nKbdInteractiveAuthentication no\\n' | sudo tee \
    /etc/ssh/sshd_config.d/10-no-passwords.conf && sudo sshd -t && sudo systemctl reload ssh";
/// macOS's sshd_config includes sshd_config.d; launchd restarts Remote Login's sshd.
#[cfg(target_os = "macos")]
const DISABLE_SSH_PASSWORDS: &str = "printf 'PasswordAuthentication no\\nKbdInteractiveAuthentication no\\n' | sudo tee \
    /etc/ssh/sshd_config.d/10-no-passwords.conf && sudo sshd -t && sudo launchctl kickstart -k system/com.openssh.sshd";

/// Which process holds a connection to an address.
#[cfg(target_os = "linux")]
fn find_conn(ip: &str) -> (String, String) {
    (
        "`ss -tnp | grep <ip>`".into(),
        format!("sudo ss -tnp | grep {ip}"),
    )
}
#[cfg(target_os = "macos")]
fn find_conn(ip: &str) -> (String, String) {
    (
        "`lsof -nP -i @<ip>`".into(),
        format!("sudo lsof -nP -i @{ip}"),
    )
}

#[cfg(target_os = "linux")]
const BANS_DROPPED: &str =
    "Banned traffic is dropped in XDP before the kernel network stack sees it.";
#[cfg(target_os = "macos")]
const BANS_DROPPED: &str =
    "Banned traffic is dropped by pf (anchor com.apple/netwatch) while netwatch runs.";

#[cfg(target_os = "linux")]
const UPDATE_GEOIP: &str = "sudo netwatch-update-geoip";
#[cfg(target_os = "macos")]
const UPDATE_GEOIP: &str = "sudo netwatch update-geoip";

#[derive(Debug, Clone, Serialize)]
pub struct Insight {
    pub level: &'static str,
    pub title: String,
    pub detail: String,
    pub action: Option<String>,
}

/// Same effect as `drop_syn_ip_options`, but on every interface and not persisted across reboots.
const NFT_DROP_IPOPT_SYN: &str = "sudo nft add table ip cve_2026_98432 && sudo nft add chain ip cve_2026_98432 pre \
    '{ type filter hook prerouting priority -300; }' && sudo nft add rule ip cve_2026_98432 pre \
    'ip hdrlength gt 5 tcp flags & (syn | ack) == syn counter drop'";

/// First upstream release of each stable branch with the CVE-2026-98432 fix; 7.3 and later are fixed.
const CVE_2026_98432_FIXED: &[(u32, u32, u32)] = &[
    (7, 2, 10),
    (6, 18, 56),
    (6, 12, 113),
    (6, 6, 159),
    (6, 1, 190),
    (5, 15, 223),
    (5, 10, 272),
];

/// The nftables table that drops IPv4 TCP with IP options before the TCP stack, if any:
/// a rule on a prerouting/input/ingress hook matching `ip hdrlength > 5` and dropping,
/// not narrowed to particular addresses, interfaces or ports.
fn nft_ipopt_drop_table(ruleset: &str) -> Option<String> {
    let mut table = String::new();
    let mut hooked = false;
    for line in ruleset.lines().map(str::trim) {
        if let Some(t) = line.strip_prefix("table ") {
            table = t.split(" {").next().unwrap_or(t).trim().to_string();
        } else if line.starts_with("chain ") {
            hooked = false;
        } else if line.starts_with("type ") && line.contains(" hook ") {
            hooked = ["prerouting", "input", "ingress"]
                .iter()
                .any(|h| line.contains(&format!("hook {h} ")));
        } else if hooked
            && line.contains("hdrlength > 5")
            && line.split_whitespace().any(|w| w == "drop")
            && !["saddr", "daddr", "iif", "oif", "dport", "sport", "ct state"]
                .iter()
                .any(|n| line.contains(n))
        {
            return Some(table);
        }
    }
    None
}

/// What stops the CVE-2026-98432 trigger before the TCP stack, if anything:
/// `drop_syn_ip_options` in XDP, or an nftables rule (checked at most once a minute).
pub fn ipopt_mitigation(cfg: &crate::config::Config) -> Option<String> {
    static NFT: std::sync::Mutex<Option<(std::time::Instant, Option<String>)>> =
        std::sync::Mutex::new(None);
    if cfg.drop_syn_ip_options {
        return Some(format!(
            "drop_syn_ip_options drops them in XDP on {}",
            cfg.interface
        ));
    }
    let mut cached = NFT.lock().unwrap();
    if cached
        .as_ref()
        .is_none_or(|(at, _)| at.elapsed().as_secs() >= 60)
    {
        let table = crate::host::command("nft")
            .args(["list", "ruleset"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| nft_ipopt_drop_table(&String::from_utf8_lossy(&o.stdout)));
        *cached = Some((std::time::Instant::now(), table));
    }
    cached
        .as_ref()
        .and_then(|(_, t)| t.clone())
        .map(|t| format!("the nftables table {t} drops them"))
}

#[derive(Debug, PartialEq)]
enum KernelFix {
    Fixed,
    /// An upstream kernel older than the fix (or an end-of-life branch with none).
    Missing,
    /// A distribution kernel whose base predates the fix; it may carry a backport.
    AskDistro,
}

/// Judges `uname -r` ("6.8.0-45-generic", "6.6.159") against the upstream fixes.
fn cve_2026_98432_fix(release: &str) -> Option<KernelFix> {
    let release = release.trim();
    let (base, suffix) = release.split_once('-').unwrap_or((release, ""));
    let mut it = base
        .trim_end_matches('+')
        .split('.')
        .map(|n| n.parse::<u32>().ok());
    let (major, minor) = (it.next()??, it.next()??);
    let patch = it.next().flatten().unwrap_or(0);
    let fixed = (major, minor) >= (7, 3)
        || CVE_2026_98432_FIXED
            .iter()
            .any(|&(a, b, c)| (a, b) == (major, minor) && patch >= c);
    Some(match (fixed, suffix.is_empty()) {
        (true, _) => KernelFix::Fixed,
        (false, true) => KernelFix::Missing,
        (false, false) => KernelFix::AskDistro,
    })
}

fn add(
    out: &mut Vec<Insight>,
    level: &'static str,
    title: String,
    detail: String,
    action: Option<String>,
) {
    out.push(Insight {
        level,
        title,
        detail,
        action,
    });
}

pub fn compute(app: &App) -> anyhow::Result<Vec<Insight>> {
    let now = now_unix();
    let mut out = Vec::new();
    let pending = app
        .store
        .lock()
        .unwrap()
        .proposals(true, None, 10_000)?
        .len();
    let e = app.engine.lock().unwrap();
    let cfg = &app.cfg;
    let hour = now - 3600;
    let active: Vec<_> = e
        .states
        .values()
        .filter(|s| !s.allowlisted && is_public(s.ip) && s.last_activity() >= hour)
        .collect();

    // Successful logins that look wrong come first.
    for s in e.states.values() {
        for f in s
            .findings
            .iter()
            .filter(|f| f.kind == "login_after_failures" || f.kind == "new_login_location")
        {
            add(
                &mut out,
                "critical",
                format!("Suspicious SSH login from {} ({})", s.ip, s.location),
                format!(
                    "{} Check `last -i`, running processes and ~/.ssh/authorized_keys.",
                    f.summary
                ),
                Some(format!(
                    "sudo netwatch ban {} --ttl 7d --reason \"suspicious login\"",
                    s.ip
                )),
            );
        }
    }

    if e.rates.syn_pps >= cfg.thresholds.global_syn_pps {
        add(
            &mut out,
            "critical",
            format!("Possible distributed SYN flood: {:.0} SYN/s", e.rates.syn_pps),
            "Interface-wide connection attempts are far above normal. Check top sources by SYN; consider range bans."
                .into(),
            Some("netwatch top --sort syn".into()),
        );
    }

    let outbound: Vec<_> = e
        .states
        .values()
        .filter(|s| s.kinds().contains(&"outbound_to_listed"))
        .collect();
    if !outbound.is_empty() {
        let ips: Vec<String> = outbound
            .iter()
            .take(5)
            .map(|s| format!("{} ({})", s.ip, s.feeds.join(",")))
            .collect();
        add(
            &mut out,
            "critical",
            format!(
                "This host talked to {} threat-listed address(es)",
                outbound.len()
            ),
            format!(
                "Connections initiated from here to listed IPs can mean a compromised container or process: {}. \
                 Find the process with {}.",
                ips.join(", "),
                find_conn("").0
            ),
            Some(find_conn(&outbound[0].ip.to_string()).1),
        );
    }

    // CVE-2026-98432: a SYN with IPv4 options reaches a kernel use-after-free before any application.
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let release = release.trim();
    let fix = cve_2026_98432_fix(release);
    let kernel_note = match fix {
        Some(KernelFix::Fixed) => format!("This kernel ({release}) already has the fix."),
        Some(KernelFix::Missing) => {
            format!("This kernel ({release}) predates the fix: upgrade and reboot.")
        }
        Some(KernelFix::AskDistro) => format!(
            "This kernel ({release}) is based on a release older than the upstream fix; check your distribution's \
             advisory for whether it carries the backport."
        ),
        None => format!("Couldn't read the kernel version ({release:?}); check it is patched."),
    };
    let mut senders: Vec<_> = e.states.values().filter(|s| s.ipopt_last >= hour).collect();
    senders.sort_by_key(|s| std::cmp::Reverse(s.total.ipopt_syn));
    let shown: Vec<String> = senders
        .iter()
        .take(5)
        .map(|s| format!("{} ({})", s.ip, s.location))
        .collect();
    let mitigation = ipopt_mitigation(cfg);
    match (&mitigation, senders.is_empty()) {
        (Some(m), false) => add(
            &mut out,
            "warn",
            format!(
                "{} source(s) sent the CVE-2026-98432 trigger; {m}",
                senders.len()
            ),
            format!(
                "TCP SYNs with IPv4 options, the input for the Linux TCP use-after-free. They were stopped before \
                 the TCP stack ({m}), and the senders get ban proposals. Senders in the last hour: {}. {kernel_note}",
                shown.join(", ")
            ),
            None,
        ),
        (None, false) => add(
            &mut out,
            if fix == Some(KernelFix::Fixed) {
                "warn"
            } else {
                "critical"
            },
            format!(
                "{} source(s) sent the CVE-2026-98432 trigger (TCP SYNs with IPv4 options)",
                senders.len()
            ),
            format!(
                "Linux kernel TCP use-after-free, CVSS 9.8: it fires during the handshake, before any application \
                 sees the connection. {kernel_note} Until then, set drop_syn_ip_options = true or add the nftables \
                 rule below. Senders: {}.",
                shown.join(", ")
            ),
            Some(NFT_DROP_IPOPT_SYN.into()),
        ),
        (Some(m), true) if matches!(fix, Some(KernelFix::Missing | KernelFix::AskDistro)) => add(
            &mut out,
            "info",
            "CVE-2026-98432 is mitigated until the kernel is patched".into(),
            format!(
                "TCP SYNs with IPv4 options can't reach the kernel bug: {m}. {kernel_note} netwatch still alerts on \
                 anyone who sends them."
            ),
            None,
        ),
        (None, true) if matches!(fix, Some(KernelFix::Missing | KernelFix::AskDistro)) => add(
            &mut out,
            "warn",
            "The kernel may be exposed to CVE-2026-98432".into(),
            format!(
                "A crafted TCP SYN with IPv4 options can crash or take over an unpatched kernel through any \
                 listening port. {kernel_note} Until then, set drop_syn_ip_options = true or add the nftables rule \
                 below."
            ),
            Some(NFT_DROP_IPOPT_SYN.into()),
        ),
        _ => {}
    }

    // SSH exposure.
    let ssh_public: Vec<_> = active
        .iter()
        .filter(|s| s.ports.values().any(|p| p.port == 22 && p.syn > 0) || s.ssh.failed_total > 0)
        .collect();
    match (e.sshd_password_auth, ssh_public.len()) {
        (Some(true), n) if n > 0 => add(
            &mut out,
            "critical",
            format!("sshd accepts passwords and {n} internet source(s) tried to reach it in the last hour"),
            "Password logins on an internet-reachable sshd invite brute force. Use keys only (Tailscale SSH already \
             covers the tailnet). Confirm a key-based login works in a second session before reloading sshd."
                .into(),
            Some(
                DISABLE_SSH_PASSWORDS.into(),
            ),
        ),
        (Some(true), _) => add(
            &mut out,
            "warn",
            "sshd accepts password logins".into(),
            match public_ssh_addrs(&e).as_slice() {
                [] => "No internet source has reached port 22 yet, but if the router ever forwards it, passwords are \
                       exposed. Confirm a key-based login works before disabling them."
                    .into(),
                addrs => format!(
                    "Port 22 listens on the public address {}, so it can be reached directly from the internet \
                     (unless a provider firewall blocks it). No internet source has tried it in the last hour yet. \
                     Confirm a key-based login works before disabling passwords.",
                    addrs.join(", ")
                ),
            },
            Some(
                DISABLE_SSH_PASSWORDS.into(),
            ),
        ),
        _ => {}
    }

    // Listening services the internet is actually hitting.
    let mut by_port: BTreeMap<u16, Vec<&crate::engine::IpState>> = BTreeMap::new();
    for s in &active {
        for p in s
            .ports
            .values()
            .filter(|p| p.syn > 0 && p.last_seen >= hour && e.listening.tcp.contains(&p.port))
        {
            by_port.entry(p.port).or_default().push(s);
        }
    }
    for (port, srcs) in &by_port {
        let sensitive = cfg.auth_ports.contains(port) || cfg.sensitive_ports.contains(port);
        let top: Vec<String> = srcs
            .iter()
            .take(3)
            .map(|s| format!("{} {}", s.ip, s.location))
            .collect();
        add(
            &mut out,
            if sensitive { "warn" } else { "info" },
            format!(
                "{} is reachable from the internet: {} source(s) connected in the last hour",
                port_label(*port),
                srcs.len()
            ),
            format!(
                "Top: {}.{}",
                top.join("; "),
                if sensitive {
                    " If only you need it, bind it to the Tailscale IP or firewall it on the public interface."
                } else {
                    ""
                }
            ),
            Some(format!("netwatch sources --port {port}")),
        );
    }

    // Scanners and where they come from.
    let scanners: Vec<_> = active
        .iter()
        .filter(|s| {
            s.kinds()
                .iter()
                .any(|k| matches!(*k, "port_scan" | "closed_probe" | "sensitive_probe"))
        })
        .collect();
    if !scanners.is_empty() {
        let mut asn: HashMap<String, usize> = HashMap::new();
        for s in &scanners {
            *asn.entry(format!(
                "AS{} {}",
                s.geo.asn.unwrap_or(0),
                s.geo.as_org.as_deref().unwrap_or("?")
            ))
            .or_default() += 1;
        }
        let mut asn: Vec<(String, usize)> = asn.into_iter().collect();
        asn.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        let top: Vec<String> = asn
            .iter()
            .take(3)
            .map(|(a, n)| format!("{a} ({n})"))
            .collect();
        add(
            &mut out,
            "info",
            format!(
                "{} scanner(s) probed this host in the last hour",
                scanners.len()
            ),
            format!(
                "Mostly background internet noise; closed ports are refused by the kernel anyway. Top networks: {}.",
                top.join(", ")
            ),
            Some("netwatch sources --flagged".into()),
        );
    }

    let listed = active
        .iter()
        .filter(|s| !s.feeds.is_empty() && s.total.in_packets > 0)
        .count();
    if listed > 0 {
        add(
            &mut out,
            "info",
            format!("{listed} threat-feed listed source(s) contacted this host in the last hour"),
            "Listed sources that also probe are banned by the default 'listed-prober' rule.".into(),
            None,
        );
    }

    if pending > 0 {
        add(
            &mut out,
            "warn",
            format!("{pending} proposed action(s) waiting for approval"),
            "Rules and the LLM propose; nothing is applied in observe mode until you approve."
                .into(),
            Some("netwatch proposals".into()),
        );
    }

    if cfg.mode == Mode::Observe {
        let would = active
            .iter()
            .filter(|s| !s.banned && e.rule_for(s).is_some_and(|r| r.action == Action::Ban))
            .count();
        if would > 0 {
            add(
                &mut out,
                "info",
                format!("{would} source(s) would be banned automatically in enforce mode"),
                "Set mode = \"enforce\" in the config once you trust the proposals.".into(),
                Some("netwatch proposals".into()),
            );
        }
    }

    if !e.bans.is_empty() {
        let dropped: u64 = e
            .states
            .values()
            .filter(|s| s.banned)
            .map(|s| s.total.blocked)
            .sum();
        add(
            &mut out,
            "info",
            format!(
                "{} active ban(s) dropped {dropped} packets since start",
                e.bans.len()
            ),
            if cfg.drop_banned {
                BANS_DROPPED.into()
            } else {
                "drop_banned = false: banned traffic is only counted (dry run).".into()
            },
            Some("netwatch bans".into()),
        );
    }

    if e.global.events_lost > 0 {
        add(
            &mut out,
            "warn",
            format!("{} probe events were lost", e.global.events_lost),
            "The ring buffer filled up (a burst of new source/port pairs). Counters are still exact.".into(),
            None,
        );
    }
    if !e.geo.available() {
        add(
            &mut out,
            "warn",
            "No geolocation database".into(),
            format!(
                "Expected {} and {}.",
                cfg.geoip_city.display(),
                cfg.geoip_asn.display()
            ),
            Some(UPDATE_GEOIP.into()),
        );
    }
    if app.llm.is_none() {
        add(
            &mut out,
            "info",
            "AI analysis is off".into(),
            "Add an [llm] section with any OpenAI-compatible endpoint to get proposals for cases the rules can't \
             settle, and to write the ban policy in plain English."
                .into(),
            None,
        );
    }
    if out.iter().all(|i| i.level == "info") && scanners.is_empty() && by_port.is_empty() {
        add(
            &mut out,
            "info",
            "No suspicious inbound activity in the last hour".into(),
            String::new(),
            None,
        );
    }

    let rank = |l: &str| match l {
        "critical" => 0,
        "warn" => 1,
        _ => 2,
    };
    out.sort_by_key(|i| rank(i.level));
    Ok(out)
}

/// Public host addresses sshd (port 22) is reachable on, from the listener table.
fn public_ssh_addrs(e: &crate::engine::Engine) -> Vec<String> {
    let Some(l) = e.flows.listeners.get(&(netwatch_common::PROTO_TCP, 22)) else {
        return Vec::new();
    };
    let wildcard = l.addrs.iter().any(|a| a.is_unspecified());
    let mut out: Vec<String> = e
        .flows
        .host_addrs
        .iter()
        .filter(|a| crate::util::is_public(**a) && (wildcard || l.addrs.contains(*a)))
        .map(|a| a.to_string())
        .collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cve_2026_98432_fix_by_kernel_release() {
        let fix = |r: &str| cve_2026_98432_fix(r).unwrap();
        assert_eq!(fix("6.6.159"), KernelFix::Fixed);
        assert_eq!(fix("6.6.158"), KernelFix::Missing);
        assert_eq!(fix("7.3.0"), KernelFix::Fixed);
        assert_eq!(fix("7.2.9\n"), KernelFix::Missing);
        // An end-of-life branch never got the fix.
        assert_eq!(fix("6.8.12"), KernelFix::Missing);
        assert_eq!(fix("5.4.300"), KernelFix::Missing);
        // Distribution kernels may backport it without changing the base version.
        assert_eq!(fix("6.8.0-45-generic"), KernelFix::AskDistro);
        assert_eq!(fix("5.14.0-503.11.1.el9_5.x86_64"), KernelFix::AskDistro);
        assert_eq!(fix("6.12.113-1-lts"), KernelFix::Fixed);
        assert_eq!(cve_2026_98432_fix("garbage"), None);
    }

    #[test]
    fn nftables_rules_that_stop_the_cve_2026_98432_trigger() {
        // As `nft list ruleset` prints the published mitigation.
        let input = "table inet cve_2026_98432 {
	chain input {
		type filter hook input priority raw - 10; policy accept;
		ip protocol tcp ip hdrlength > 5 counter packets 0 bytes 0 drop
	}
}";
        assert_eq!(
            nft_ipopt_drop_table(input).as_deref(),
            Some("inet cve_2026_98432")
        );
        let suggested = "table ip cve_2026_98432 {
	chain pre {
		type filter hook prerouting priority raw; policy accept;
		ip hdrlength > 5 tcp flags & (syn | ack) == syn counter packets 3 bytes 180 drop
	}
}";
        assert_eq!(
            nft_ipopt_drop_table(suggested).as_deref(),
            Some("ip cve_2026_98432")
        );
        // Not before the TCP stack, only counted, or only for some sources: no protection.
        let forward = input.replace("hook input", "hook forward");
        assert_eq!(nft_ipopt_drop_table(&forward), None);
        assert_eq!(
            nft_ipopt_drop_table(&input.replace(" drop", " accept")),
            None
        );
        assert_eq!(
            nft_ipopt_drop_table(
                &input.replace("ip protocol tcp", "ip saddr 1.2.3.4 ip protocol tcp")
            ),
            None
        );
        assert_eq!(nft_ipopt_drop_table(""), None);
    }
}
