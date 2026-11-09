use std::{
    net::{IpAddr, Ipv6Addr},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, bail};
use ipnet::IpNet;

/// Kernel maps store every address as 16 bytes, IPv4 in mapped form.
pub fn key_to_ip(key: [u8; 16]) -> IpAddr {
    let v6 = Ipv6Addr::from(key);
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

pub fn ip_to_key(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// LPM trie key (prefix length, data) for a network, IPv4 shifted into the mapped range.
pub fn net_to_lpm(net: &IpNet) -> (u32, [u8; 16]) {
    match net {
        IpNet::V4(n) => (
            96 + n.prefix_len() as u32,
            ip_to_key(IpAddr::V4(n.network())),
        ),
        IpNet::V6(n) => (n.prefix_len() as u32, n.network().octets()),
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn lpm_to_net(prefix: u32, data: [u8; 16]) -> IpNet {
    match key_to_ip(data) {
        IpAddr::V4(v4) if prefix >= 96 => IpNet::new(IpAddr::V4(v4), (prefix - 96) as u8),
        ip => IpNet::new(ip, prefix.min(128) as u8),
    }
    .unwrap_or_else(|_| IpNet::from(key_to_ip(data)))
}

/// Accepts a bare address or a CIDR.
pub fn parse_target(s: &str) -> anyhow::Result<IpNet> {
    let s = s.trim();
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(net.trunc());
    }
    let ip: IpAddr = s
        .parse()
        .with_context(|| format!("not an IP or CIDR: {s}"))?;
    Ok(IpNet::from(ip))
}

/// Public unicast address worth analysing (not private, loopback, CGNAT, link-local...).
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || (o[0] == 100 && (o[1] & 0xc0) == 64))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s & 0xfe00) == 0xfc00
                || (s & 0xffc0) == 0xfe80)
        }
    }
}

/// /24 for IPv4, /64 for IPv6: the unit for "this whole range is hostile" advice.
pub fn neighbourhood(ip: IpAddr) -> IpNet {
    let len = if ip.is_ipv4() { 24 } else { 64 };
    IpNet::new(ip, len)
        .map(|n| n.trunc())
        .unwrap_or_else(|_| IpNet::from(ip))
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The clock kernel timestamps use: `bpf_ktime_get_boot_ns` on Linux. On macOS
/// CLOCK_MONOTONIC also keeps counting while asleep; the capture sensor stamps with it.
#[cfg(target_os = "linux")]
const BOOT_CLOCK: libc::clockid_t = libc::CLOCK_BOOTTIME;
#[cfg(target_os = "macos")]
const BOOT_CLOCK: libc::clockid_t = libc::CLOCK_MONOTONIC;

fn clock_ns(clock: libc::clockid_t) -> i128 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(clock, &mut ts) };
    ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128
}

/// Now on the clock `bpf_ktime_get_boot_ns` uses.
#[cfg_attr(target_os = "linux", cfg(test))]
pub fn boot_now_ns() -> u64 {
    clock_ns(BOOT_CLOCK) as u64
}

/// Converts `bpf_ktime_get_boot_ns` timestamps to unix seconds.
#[derive(Clone, Copy)]
pub struct BootClock {
    offset_ns: i128,
}

impl BootClock {
    pub fn new() -> Self {
        Self {
            offset_ns: clock_ns(libc::CLOCK_REALTIME) - clock_ns(BOOT_CLOCK),
        }
    }

    /// Unix time in nanoseconds (a packet timestamp) on the boot clock.
    #[cfg(target_os = "macos")]
    pub fn boot_ns_of_unix(&self, unix_ns: i128) -> u64 {
        (unix_ns - self.offset_ns).max(0) as u64
    }

    pub fn to_unix(self, boot_ns: u64) -> i64 {
        ((boot_ns as i128 + self.offset_ns) / 1_000_000_000) as i64
    }
}

pub fn proto_name(p: u8) -> &'static str {
    match p {
        netwatch_common::PROTO_TCP => "tcp",
        netwatch_common::PROTO_UDP => "udp",
        netwatch_common::PROTO_ICMP => "icmp",
        netwatch_common::PROTO_ICMPV6 => "icmp6",
        _ => "ip",
    }
}

pub fn service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        111 => "RPC",
        123 => "NTP",
        135 => "MSRPC",
        139 => "NetBIOS",
        143 => "IMAP",
        161 => "SNMP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        465 | 587 => "SMTP-sub",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        1521 => "Oracle",
        1900 => "SSDP",
        2375 | 2376 => "Docker API",
        3306 => "MySQL",
        3389 => "RDP",
        5060 => "SIP",
        5432 => "PostgreSQL",
        5555 => "ADB",
        5900 => "VNC",
        5984 => "CouchDB",
        6379 => "Redis",
        6443 => "Kubernetes API",
        7547 => "TR-069",
        8080 => "HTTP-alt",
        8443 => "HTTPS-alt",
        9200 => "Elasticsearch",
        10250 => "Kubelet",
        11211 => "Memcached",
        27017 => "MongoDB",
        41641 => "Tailscale",
        51820 => "WireGuard",
        _ => return None,
    })
}

pub fn port_label(port: u16) -> String {
    match service_name(port) {
        Some(name) => format!("{port} ({name})"),
        None => port.to_string(),
    }
}

pub fn parse_duration(s: &str) -> anyhow::Result<i64> {
    let d = humantime::parse_duration(s).with_context(|| format!("invalid duration: {s}"))?;
    if d.as_secs() == 0 {
        bail!("duration must be at least 1s");
    }
    Ok(d.as_secs() as i64)
}

pub fn fmt_secs(secs: i64) -> String {
    humantime::format_duration(std::time::Duration::from_secs(secs.max(0) as u64)).to_string()
}

pub fn fmt_bytes(b: f64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{v:.0} {}", U[i])
    } else {
        format!("{v:.1} {}", U[i])
    }
}

/// Unicode regional-indicator flag for an ISO country code.
pub fn flag(cc: &str) -> String {
    if cc.len() != 2 || !cc.bytes().all(|b| b.is_ascii_alphabetic()) {
        return String::new();
    }
    cc.to_ascii_uppercase()
        .chars()
        .filter_map(|c| char::from_u32(0x1F1E6 + (c as u32 - 'A' as u32)))
        .collect()
}
