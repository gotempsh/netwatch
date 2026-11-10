//! External knowledge about addresses: threat feeds and the dynamic allowlist
//! (peers this host depends on and must never ban).

use std::{collections::BTreeSet, net::IpAddr, time::Duration};

use ipnet::IpNet;
use serde::Serialize;

use crate::config::{Config, Feed};

/// One blocklist feed, stored as sorted, merged ranges for binary search,
/// plus the entries as listed so a match can name its range.
pub struct FeedList {
    pub name: String,
    pub about: String,
    pub entries: usize,
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
    nets4: Vec<(u32, u8)>,
    nets6: Vec<(u128, u8)>,
}

/// Why an address is on a feed: the feed, the listed range that contains it, and what the feed means.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FeedHit {
    pub name: String,
    pub range: String,
    pub about: String,
}

/// What a well-known feed means, for feeds configured without an `about`.
pub fn feed_about(name: &str) -> &'static str {
    match name {
        "spamhaus_drop" => {
            "Spamhaus DROP: whole networks run by or hijacked for spam and cybercrime"
        }
        "spamhaus_edrop" => {
            "Spamhaus EDROP: networks hijacked for spam and cybercrime (extension of DROP)"
        }
        "dshield" => "DShield: the networks attacking honeypots most in the last days",
        "feodo" => "Feodo Tracker: command servers of banking trojans",
        "fullbogons" => {
            "Team Cymru full bogons: address space not allocated to anyone, so traffic from it is spoofed"
        }
        "firehol_level1" => "FireHOL level 1: DShield, Feodo, full bogons and Spamhaus DROP merged",
        "firehol_level2" | "firehol_level3" => {
            "FireHOL: attackers reported in the last days by several blocklists"
        }
        "blocklist_de" => {
            "blocklist.de: addresses reported for attacks on SSH, mail, FTP and web services"
        }
        "cinsscore" => "CINS Army: addresses with a poor reputation in Sentinel IPS",
        "et_compromised" => "Emerging Threats: known compromised hosts",
        _ => "",
    }
}

/// The longest listed prefix that contains `x`.
fn longest<T: Ord + Copy>(
    nets: &[(T, u8)],
    x: T,
    bits: u8,
    mask: impl Fn(T, u8) -> T,
) -> Option<(T, u8)> {
    (0..=bits)
        .rev()
        .map(|p| (mask(x, p), p))
        .find(|n| nets.binary_search(n).is_ok())
}

fn mask4(x: u32, p: u8) -> u32 {
    if p == 0 {
        0
    } else {
        x & (u32::MAX << (32 - p))
    }
}

fn mask6(x: u128, p: u8) -> u128 {
    if p == 0 {
        0
    } else {
        x & (u128::MAX << (128 - p))
    }
}

fn merge<T: Ord + Copy>(mut ranges: Vec<(T, T)>, next: impl Fn(T) -> T) -> Vec<(T, T)> {
    ranges.sort();
    let mut out: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (lo, hi) in ranges {
        match out.last_mut() {
            Some(last) if lo <= next(last.1) => last.1 = last.1.max(hi),
            _ => out.push((lo, hi)),
        }
    }
    out
}

fn contains<T: Ord + Copy>(ranges: &[(T, T)], x: T) -> bool {
    let i = ranges.partition_point(|r| r.0 <= x);
    i > 0 && ranges[i - 1].1 >= x
}

impl FeedList {
    pub fn parse(name: &str, text: &str) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        let mut nets4 = Vec::new();
        let mut nets6 = Vec::new();
        let mut entries = 0;
        for line in text.lines() {
            let tok = line
                .split(['#', ';'])
                .next()
                .unwrap_or("")
                .split_whitespace()
                .next();
            let Some(tok) = tok else { continue };
            let Ok(net) = crate::util::parse_target(tok) else {
                continue;
            };
            entries += 1;
            match net {
                IpNet::V4(n) => {
                    v4.push((u32::from(n.network()), u32::from(n.broadcast())));
                    nets4.push((u32::from(n.network()), n.prefix_len()));
                }
                IpNet::V6(n) => {
                    v6.push((u128::from(n.network()), u128::from(n.broadcast())));
                    nets6.push((u128::from(n.network()), n.prefix_len()));
                }
            }
        }
        nets4.sort_unstable();
        nets4.dedup();
        nets6.sort_unstable();
        nets6.dedup();
        Self {
            name: name.to_string(),
            about: feed_about(name).to_string(),
            entries,
            v4: merge(v4, |x| x.saturating_add(1)),
            v6: merge(v6, |x| x.saturating_add(1)),
            nets4,
            nets6,
        }
    }

    /// The listed range containing `ip`, as written in the feed (the most specific one).
    pub fn range_of(&self, ip: IpAddr) -> Option<IpNet> {
        let v4 = match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(v6) => v6.to_ipv4_mapped(),
        };
        match (v4, ip) {
            (Some(v4), _) => longest(&self.nets4, u32::from(v4), 32, mask4)
                .and_then(|(n, p)| ipnet::Ipv4Net::new(n.into(), p).ok().map(IpNet::V4)),
            (None, IpAddr::V6(v6)) => longest(&self.nets6, u128::from(v6), 128, mask6)
                .and_then(|(n, p)| ipnet::Ipv6Net::new(n.into(), p).ok().map(IpNet::V6)),
            _ => None,
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => contains(&self.v4, u32::from(v4)),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => contains(&self.v4, u32::from(v4)),
                None => contains(&self.v6, u128::from(v6)),
            },
        }
    }
}

#[derive(Default)]
pub struct Feeds {
    pub lists: Vec<FeedList>,
}

impl Feeds {
    /// Feeds listing `ip`. Feeds such as FireHOL level1 include the bogon ranges
    /// (RFC 1918, CGNAT, …), so private addresses never match.
    pub fn matches(&self, ip: IpAddr) -> Vec<String> {
        if !crate::util::is_public(ip) {
            return Vec::new();
        }
        self.lists
            .iter()
            .filter(|l| l.contains(ip))
            .map(|l| l.name.clone())
            .collect()
    }

    /// Like `matches`, with the listed range and what each feed means.
    pub fn hits(&self, ip: IpAddr) -> Vec<FeedHit> {
        if !crate::util::is_public(ip) {
            return Vec::new();
        }
        self.lists
            .iter()
            .filter(|l| l.contains(ip))
            .map(|l| FeedHit {
                name: l.name.clone(),
                range: l.range_of(ip).map(|n| n.to_string()).unwrap_or_default(),
                about: l.about.clone(),
            })
            .collect()
    }
}

/// "spamhaus_drop (185.93.89.0/24), dshield (…)" for finding summaries.
pub fn listed_on(hits: &[FeedHit]) -> String {
    hits.iter()
        .map(|h| {
            if h.range.is_empty() {
                h.name.clone()
            } else {
                format!("{} ({})", h.name, h.range)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent("netwatch/0.1")
        .build()
        .expect("http client")
}

pub async fn fetch_feeds(feeds: &[Feed]) -> Feeds {
    let http = client();
    let mut out = Feeds::default();
    for feed in feeds {
        let res = async {
            http.get(&feed.url)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await
        }
        .await;
        match res {
            Ok(text) => {
                let mut list = FeedList::parse(&feed.name, &text);
                if let Some(about) = feed.about.as_ref().filter(|a| !a.is_empty()) {
                    list.about = about.clone();
                }
                log::info!("threat feed {}: {} entries", feed.name, list.entries);
                out.lists.push(list);
            }
            Err(e) => log::warn!("threat feed {} failed: {e}", feed.name),
        }
    }
    out
}

/// Cloudflare's published ranges, with a built-in copy if the fetch fails.
pub async fn cloudflare_ranges() -> Vec<IpNet> {
    const FALLBACK: &str = "173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 \
        108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 \
        104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 \
        2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32";
    let http = client();
    let mut text = String::new();
    for url in [
        "https://www.cloudflare.com/ips-v4",
        "https://www.cloudflare.com/ips-v6",
    ] {
        match async { http.get(url).send().await?.error_for_status()?.text().await }.await {
            Ok(t) => {
                text.push_str(&t);
                text.push('\n');
            }
            Err(e) => {
                log::warn!("cloudflare ranges unavailable ({e}), using built-in list");
                text = FALLBACK.to_string();
                break;
            }
        }
    }
    text.split_whitespace()
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// How long a discovery command (`tailscale status`, `wg show`, ...) may take.
/// Startup waits for the allowlist, so a CLI that hangs, such as Tailscale's
/// when its daemon or app isn't running, must not hold it up.
const RUN_TIMEOUT: Duration = Duration::from_secs(10);

/// What a discovery command said.
enum Answer {
    Output(String),
    /// Not installed, not running, or it failed: it has no addresses to give.
    Nothing,
    /// Still running at the deadline: whatever it would say is unknown.
    TimedOut,
}

fn run(cmd: &str, args: &[&str]) -> Answer {
    // The Mac App Store and standalone Tailscale apps keep their CLI inside the bundle.
    #[cfg(target_os = "macos")]
    let cmd = match cmd {
        "tailscale" if !in_path("tailscale") => {
            "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
        }
        _ => cmd,
    };
    let mut c = crate::host::command(cmd);
    c.args(args);
    match run_with_timeout(c, RUN_TIMEOUT) {
        Ok(Some(out)) => Answer::Output(out),
        Ok(None) => Answer::Nothing,
        Err(()) => {
            log::warn!(
                "`{cmd} {}` didn't answer within {}s; trying again in 10 minutes",
                args.join(" "),
                RUN_TIMEOUT.as_secs()
            );
            Answer::TimedOut
        }
    }
}

/// The command's stdout if it exits successfully, `Ok(None)` if it can't be
/// started or fails, `Err(())` if it hasn't finished within `timeout`.
/// "Finished" includes anything it started that still holds its stdout, such
/// as the real CLI behind a wrapper script: the command runs in its own
/// process group, and the whole group is killed at the deadline.
fn run_with_timeout(mut c: std::process::Command, timeout: Duration) -> Result<Option<String>, ()> {
    use std::{io::Read as _, os::unix::process::CommandExt as _, process::Stdio};
    let Ok(mut child) = c
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
    else {
        return Ok(None);
    };
    let group = child.id() as libc::pid_t;
    let kill_group = || {
        // SAFETY: kill has no memory-safety preconditions; the group is ours.
        unsafe { libc::kill(-group, libc::SIGKILL) };
    };
    // Read while waiting: a full pipe would stop a chatty command from exiting.
    let mut stdout = child.stdout.take().expect("piped");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20))
            }
            _ => {
                kill_group();
                let _ = child.wait();
                return Err(());
            }
        }
    };
    // The output ends when the last process holding the pipe exits.
    let left = deadline.saturating_duration_since(std::time::Instant::now());
    match rx.recv_timeout(left) {
        Ok(out) => Ok(status
            .success()
            .then(|| String::from_utf8_lossy(&out).into_owned())),
        Err(_) => {
            kill_group();
            Err(())
        }
    }
}

fn endpoint_ip(s: &str) -> Option<IpAddr> {
    s.parse::<std::net::SocketAddr>().ok().map(|a| a.ip())
}

/// What a source last gave, and how many refreshes in a row it has timed out since.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct Found {
    addrs: BTreeSet<IpNet>,
    timeouts: u32,
}

/// Addresses discovered from the running system that must never be banned,
/// by source ("wireguard", "tailscale", ...).
pub type Peers = std::collections::BTreeMap<&'static str, Found>;

/// Refreshes in a row a timed-out source keeps its last addresses for.
/// A stopped Tailscale hangs rather than failing, so without a limit its
/// former peers would stay exempt from bans until netwatch restarts.
const KEEP_THROUGH_TIMEOUTS: u32 = 2;

pub fn all_peers(peers: &Peers) -> impl Iterator<Item = IpNet> + '_ {
    peers.values().flat_map(|f| f.addrs.iter().copied())
}

/// A source's public addresses from its answer. A command that timed out
/// keeps what it gave last time for a couple of refreshes: a slow `tailscale`
/// shouldn't take its peers off the allowlist, but one that keeps hanging
/// (its daemon stopped) lets them go.
fn record(
    out: &mut Peers,
    previous: &Peers,
    source: &'static str,
    answer: Answer,
    parse: impl Fn(&str) -> Vec<IpAddr>,
) {
    let found = match answer {
        Answer::Output(text) => Found {
            addrs: parse(&text)
                .into_iter()
                .filter(|ip| crate::util::is_public(*ip))
                .map(IpNet::from)
                .collect(),
            timeouts: 0,
        },
        Answer::Nothing => Found::default(),
        Answer::TimedOut => {
            let last = previous.get(source).cloned().unwrap_or_default();
            let timeouts = last.timeouts.saturating_add(1);
            if timeouts == KEEP_THROUGH_TIMEOUTS + 1 && !last.addrs.is_empty() {
                log::warn!(
                    "{source} discovery has timed out {timeouts} times in a row; its {} addresses are no longer allowlisted",
                    last.addrs.len()
                );
            }
            Found {
                addrs: if timeouts <= KEEP_THROUGH_TIMEOUTS {
                    last.addrs
                } else {
                    BTreeSet::new()
                },
                timeouts,
            }
        }
    };
    out.insert(source, found);
}

/// `wg show all endpoints`: `<iface>\t<peer pubkey>\t<endpoint>`.
fn wireguard_endpoints(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| l.split('\t').nth(2).and_then(endpoint_ip))
        .collect()
}

/// `tailscale status --json`: every peer's known and current endpoints.
fn tailscale_peers(text: &str) -> Vec<IpAddr> {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let Some(peers) = json["Peer"].as_object() else {
        return Vec::new();
    };
    peers
        .values()
        .flat_map(|peer| {
            let addrs = peer["Addrs"].as_array().into_iter().flatten();
            addrs.chain(std::iter::once(&peer["CurAddr"]))
        })
        .filter_map(|a| a.as_str().and_then(endpoint_ip))
        .collect()
}

/// `tailscale debug derp-map`: DERP relays and STUN servers.
fn derp_nodes(text: &str) -> Vec<IpAddr> {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let Some(regions) = json["Regions"].as_object() else {
        return Vec::new();
    };
    regions
        .values()
        .flat_map(|r| r["Nodes"].as_array().into_iter().flatten())
        .flat_map(|node| ["IPv4", "IPv6"].map(|k| node[k].as_str()))
        .filter_map(|s| s?.parse::<IpAddr>().ok())
        .collect()
}

pub fn discover_peers(cfg: &Config, previous: &Peers) -> Peers {
    let mut out = Peers::new();
    if cfg.allow_wireguard_peers {
        let answer = run("wg", &["show", "all", "endpoints"]);
        record(&mut out, previous, "wireguard", answer, wireguard_endpoints);
    }
    if cfg.allow_tailscale_peers {
        let answer = run("tailscale", &["status", "--json"]);
        record(&mut out, previous, "tailscale", answer, tailscale_peers);
        let answer = run("tailscale", &["debug", "derp-map"]);
        record(&mut out, previous, "derp", answer, derp_nodes);
    }
    // The default gateway.
    #[cfg(target_os = "macos")]
    {
        let answer = run("route", &["-n", "get", "default"]);
        record(&mut out, previous, "gateway", answer, |t| {
            route_field(t, "gateway")
                .and_then(|g| g.parse().ok())
                .into_iter()
                .collect()
        });
    }
    #[cfg(target_os = "linux")]
    {
        let answer = run("ip", &["-j", "route", "show", "default"]);
        record(
            &mut out,
            previous,
            "gateway",
            answer,
            |t| match serde_json::from_str(t) {
                Ok(serde_json::Value::Array(routes)) => routes
                    .iter()
                    .filter_map(|r| r["gateway"].as_str()?.parse().ok())
                    .collect(),
                _ => Vec::new(),
            },
        );
    }
    out
}

#[cfg(target_os = "macos")]
fn in_path(prog: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(prog).is_file()))
}

/// A `key: value` line from `route -n get` output.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn route_field(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (k, v) = l.trim().split_once(':')?;
        (k.trim() == key).then(|| v.trim().to_string())
    })
}

/// Local ports with a listener reachable from outside (not bound to loopback).
#[derive(Default, Clone)]
pub struct Listening {
    pub tcp: BTreeSet<u16>,
    pub udp: BTreeSet<u16>,
}

impl Listening {
    #[cfg(target_os = "macos")]
    pub fn scan() -> Self {
        let mut l = Self::default();
        for s in crate::procs::sockets() {
            if !s.listening() || s.local.is_loopback() {
                continue;
            }
            if s.proto == netwatch_common::PROTO_TCP {
                l.tcp.insert(s.lport);
            } else {
                l.udp.insert(s.lport);
            }
        }
        l
    }

    #[cfg(target_os = "linux")]
    pub fn scan() -> Self {
        let mut l = Self::default();
        for (file, tcp) in [
            ("/proc/net/tcp", true),
            ("/proc/net/tcp6", true),
            ("/proc/net/udp", false),
            ("/proc/net/udp6", false),
        ] {
            let Ok(text) = std::fs::read_to_string(file) else {
                continue;
            };
            for line in text.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() < 4 {
                    continue;
                }
                // TCP_LISTEN = 0A; unconnected UDP sockets show TCP_CLOSE = 07.
                if cols[3] != if tcp { "0A" } else { "07" } {
                    continue;
                }
                let Some((addr, port)) = cols[1].split_once(':') else {
                    continue;
                };
                if is_loopback_hex(addr) {
                    continue;
                }
                if let Ok(port) = u16::from_str_radix(port, 16) {
                    if tcp {
                        l.tcp.insert(port)
                    } else {
                        l.udp.insert(port)
                    };
                }
            }
        }
        l
    }

    pub fn has(&self, proto: u8, port: u16) -> bool {
        match proto {
            netwatch_common::PROTO_TCP => self.tcp.contains(&port),
            netwatch_common::PROTO_UDP => self.udp.contains(&port),
            _ => true,
        }
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn is_loopback_hex(addr: &str) -> bool {
    match addr.len() {
        // Little-endian IPv4: 127.x.x.x ends in "7F".
        8 => addr.ends_with("7F"),
        32 => {
            addr == "00000000000000000000000001000000"
                || (addr.starts_with("0000000000000000FFFF0000") && addr.ends_with("7F"))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::run_with_timeout;

    fn sh(script: &str) -> std::process::Command {
        let mut c = std::process::Command::new("sh");
        c.args(["-c", script]);
        c
    }

    #[test]
    fn a_timed_out_source_keeps_its_last_addresses_for_a_while() {
        use super::{Answer, KEEP_THROUGH_TIMEOUTS, Peers, all_peers, record, tailscale_peers};
        use std::collections::BTreeSet;
        let ip = |s: &str| ipnet::IpNet::from(s.parse::<std::net::IpAddr>().unwrap());
        let status = r#"{"Peer":{"a":{"Addrs":["203.0.113.5:41641","10.0.0.2:41641"],"CurAddr":"198.51.100.7:41641"}}}"#;
        let refresh = |previous: &Peers, answer| {
            let mut out = Peers::new();
            record(&mut out, previous, "tailscale", answer, tailscale_peers);
            out
        };
        let addrs = |p: &Peers| all_peers(p).collect::<BTreeSet<_>>();
        let first = refresh(&Peers::new(), Answer::Output(status.into()));
        // Private addresses never go on the list.
        let known: BTreeSet<_> = [ip("198.51.100.7"), ip("203.0.113.5")].into();
        assert_eq!(addrs(&first), known);

        // A slow refresh or two keeps them.
        let mut peers = first.clone();
        for _ in 0..KEEP_THROUGH_TIMEOUTS {
            peers = refresh(&peers, Answer::TimedOut);
            assert_eq!(addrs(&peers), known);
        }
        // One that keeps hanging, as a stopped Tailscale does, lets them go.
        peers = refresh(&peers, Answer::TimedOut);
        assert!(addrs(&peers).is_empty());
        peers = refresh(&peers, Answer::TimedOut);
        assert!(addrs(&peers).is_empty());
        // An answer starts the count again.
        peers = refresh(&peers, Answer::Output(status.into()));
        peers = refresh(&peers, Answer::TimedOut);
        assert_eq!(addrs(&peers), known);

        // Failed or not installed: there are no peers to keep.
        assert!(addrs(&refresh(&first, Answer::Nothing)).is_empty());
    }

    #[test]
    fn reads_wireguard_and_derp_addresses() {
        use super::{derp_nodes, wireguard_endpoints};
        let wg = "wg0\tKEY=\t203.0.113.9:51820\nwg0\tKEY2=\t(none)\n";
        assert_eq!(
            wireguard_endpoints(wg),
            vec!["203.0.113.9".parse::<std::net::IpAddr>().unwrap()]
        );
        let derp = r#"{"Regions":{"1":{"Nodes":[{"IPv4":"192.0.2.1","IPv6":"2001:db8::1"}]}}}"#;
        assert_eq!(derp_nodes(derp).len(), 2);
        assert!(derp_nodes("not json").is_empty());
    }

    #[test]
    fn a_hanging_command_is_cut_off() {
        let start = std::time::Instant::now();
        let r = run_with_timeout(sh("sleep 30"), std::time::Duration::from_millis(200));
        assert_eq!(r, Err(()));
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn a_process_left_holding_the_output_is_cut_off_too() {
        // The command exits at once, but what it started keeps stdout open.
        let start = std::time::Instant::now();
        let r = run_with_timeout(
            sh("sleep 30 & echo hi"),
            std::time::Duration::from_millis(500),
        );
        assert_eq!(r, Err(()));
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn what_a_timed_out_command_started_is_killed_too() {
        // A wrapper without `exec`: the shell waits on a child that hangs.
        let pidfile = std::env::temp_dir().join(format!("netwatch-rwt-{}", std::process::id()));
        let script = format!("sleep 30 & echo $! > {}; wait", pidfile.display());
        let r = run_with_timeout(sh(&script), std::time::Duration::from_millis(500));
        assert_eq!(r, Err(()));
        let pid: libc::pid_t = std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        std::fs::remove_file(&pidfile).unwrap();
        // Killed, then reaped by init: gone within a moment.
        // SAFETY: signal 0 only checks that the process exists.
        let gone = (0..100).any(|_| {
            let alive = unsafe { libc::kill(pid, 0) } == 0;
            if alive {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            !alive
        });
        assert!(gone, "the hung grandchild {pid} is still running");
    }

    #[test]
    fn output_failure_and_missing_commands() {
        let t = std::time::Duration::from_secs(10);
        assert_eq!(run_with_timeout(sh("echo hi"), t), Ok(Some("hi\n".into())));
        assert_eq!(run_with_timeout(sh("echo hi; exit 1"), t), Ok(None));
        let missing = std::process::Command::new("/nonexistent/netwatch-test");
        assert_eq!(run_with_timeout(missing, t), Ok(None));
        // More than a pipe holds: read while waiting, or it never exits.
        let big = run_with_timeout(sh("head -c 300000 /dev/zero | tr '\\0' a"), t)
            .unwrap()
            .unwrap();
        assert_eq!(big.len(), 300000);
    }

    use super::*;

    #[test]
    fn feed_matching() {
        let f = FeedList::parse(
            "t",
            "# c\n1.2.3.0/24\n5.5.5.5 ; x\n1.2.4.0/24\n2001:db8::/32\n",
        );
        assert_eq!(f.entries, 4);
        assert!(f.contains("1.2.3.9".parse().unwrap()));
        assert!(f.contains("1.2.4.255".parse().unwrap()));
        assert!(!f.contains("1.2.5.0".parse().unwrap()));
        assert!(f.contains("5.5.5.5".parse().unwrap()));
        assert!(f.contains("::ffff:5.5.5.5".parse().unwrap()));
        assert!(f.contains("2001:db8::1".parse().unwrap()));
        assert!(!f.contains("2001:db9::1".parse().unwrap()));

        let feeds = Feeds {
            lists: vec![FeedList::parse("bogons", "192.168.0.0/16\n8.8.8.0/24\n")],
        };
        assert!(feeds.matches("192.168.1.10".parse().unwrap()).is_empty());
        assert_eq!(feeds.matches("8.8.8.8".parse().unwrap()), vec!["bogons"]);

        // The most specific listed range is named, even when ranges overlap or merge.
        let f = FeedList::parse(
            "spamhaus_drop",
            "185.93.0.0/16\n185.93.89.0/24\n185.93.90.0/24\n2001:db8::/32\n",
        );
        assert_eq!(
            f.range_of("185.93.89.132".parse().unwrap())
                .unwrap()
                .to_string(),
            "185.93.89.0/24"
        );
        assert_eq!(
            f.range_of("185.93.1.1".parse().unwrap())
                .unwrap()
                .to_string(),
            "185.93.0.0/16"
        );
        assert_eq!(
            f.range_of("::ffff:185.93.90.1".parse().unwrap())
                .unwrap()
                .to_string(),
            "185.93.90.0/24"
        );
        assert_eq!(
            f.range_of("2001:db8::1".parse().unwrap())
                .unwrap()
                .to_string(),
            "2001:db8::/32"
        );
        assert_eq!(f.range_of("8.8.8.8".parse().unwrap()), None);
        let feeds = Feeds { lists: vec![f] };
        let hits = feeds.hits("185.93.89.132".parse().unwrap());
        assert_eq!(hits[0].range, "185.93.89.0/24");
        assert!(hits[0].about.starts_with("Spamhaus DROP"));
        assert_eq!(listed_on(&hits), "spamhaus_drop (185.93.89.0/24)");
    }
}
