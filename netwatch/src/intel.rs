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

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    // The Mac App Store and standalone Tailscale apps keep their CLI inside the bundle.
    #[cfg(target_os = "macos")]
    let cmd = match cmd {
        "tailscale" if !in_path("tailscale") => {
            "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
        }
        _ => cmd,
    };
    let out = crate::host::command(cmd).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn endpoint_ip(s: &str) -> Option<IpAddr> {
    s.parse::<std::net::SocketAddr>().ok().map(|a| a.ip())
}

/// Addresses discovered from the running system that must never be banned.
pub fn discover_peers(cfg: &Config) -> BTreeSet<IpNet> {
    let mut out = BTreeSet::new();
    if cfg.allow_wireguard_peers {
        // Output: <iface>\t<peer pubkey>\t<endpoint>
        if let Some(text) = run("wg", &["show", "all", "endpoints"]) {
            for line in text.lines() {
                if let Some(ip) = line.split('\t').nth(2).and_then(endpoint_ip) {
                    out.insert(IpNet::from(ip));
                }
            }
        }
    }
    if cfg.allow_tailscale_peers {
        if let Some(json) = run("tailscale", &["status", "--json"])
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            && let Some(peers) = json["Peer"].as_object()
        {
            for peer in peers.values() {
                let addrs = peer["Addrs"].as_array().into_iter().flatten();
                for a in addrs.chain(std::iter::once(&peer["CurAddr"])) {
                    if let Some(ip) = a.as_str().and_then(endpoint_ip) {
                        out.insert(IpNet::from(ip));
                    }
                }
            }
        }
        // DERP relays and STUN servers.
        if let Some(json) = run("tailscale", &["debug", "derp-map"])
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            && let Some(regions) = json["Regions"].as_object()
        {
            for node in regions
                .values()
                .flat_map(|r| r["Nodes"].as_array().into_iter().flatten())
            {
                for k in ["IPv4", "IPv6"] {
                    if let Some(ip) = node[k].as_str().and_then(|s| s.parse::<IpAddr>().ok()) {
                        out.insert(IpNet::from(ip));
                    }
                }
            }
        }
    }
    // The default gateway.
    #[cfg(target_os = "macos")]
    if let Some(gw) =
        run("route", &["-n", "get", "default"]).and_then(|t| route_field(&t, "gateway"))
        && let Ok(ip) = gw.parse::<IpAddr>()
    {
        out.insert(IpNet::from(ip));
    }
    #[cfg(target_os = "linux")]
    if let Some(text) = run("ip", &["-j", "route", "show", "default"]) {
        if let Ok(serde_json::Value::Array(routes)) = serde_json::from_str(&text) {
            for r in routes {
                if let Some(ip) = r["gateway"].as_str().and_then(|s| s.parse::<IpAddr>().ok()) {
                    out.insert(IpNet::from(ip));
                }
            }
        }
    }
    out.retain(|n| crate::util::is_public(n.addr()));
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
