//! Network interfaces from sysfs: which ones get flow tracking, and their
//! byte/packet counters (the authoritative per-interface throughput).
//! On macOS the same information comes from the routing sysctl (see macos/netif.rs).

#[cfg(target_os = "linux")]
use std::{collections::BTreeMap, path::Path};

use netwatch_common::{IF_INVERT, IF_RAW_IP};
use serde::Serialize;

#[cfg(target_os = "macos")]
pub use crate::macos::netif::{addresses, default_route_interface, list_with};

#[cfg(target_os = "linux")]
const ARPHRD_ETHER: u32 = 1;
#[cfg(target_os = "linux")]
const ARPHRD_LOOPBACK: u32 = 772;
/// tun devices in IFF_TUN mode, WireGuard, Tailscale.
#[cfg(target_os = "linux")]
const ARPHRD_NONE: u32 = 65534;

#[derive(Debug, Clone, Serialize)]
pub struct IfInfo {
    pub name: String,
    pub ifindex: u32,
    /// ethernet, bridge, tunnel, loopback or other.
    pub kind: &'static str,
    pub up: bool,
    pub mac: Option<String>,
    pub addrs: Vec<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

impl IfInfo {
    /// IfConfig flags for the flow programs; None = can't parse this link type.
    pub fn flow_flags(&self) -> Option<u32> {
        match self.kind {
            "ethernet" => Some(0),
            "bridge" => Some(IF_INVERT),
            "tunnel" => Some(IF_RAW_IP),
            _ => None,
        }
    }
}

/// The interface carrying the IPv4 default route (IPv6 if there is none).
#[cfg(target_os = "linux")]
pub fn default_route_interface() -> Option<String> {
    let read = |p| std::fs::read_to_string(p).unwrap_or_default();
    parse_default_route(&read("/proc/net/route"), &read("/proc/net/ipv6_route"))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_default_route(v4: &str, v6: &str) -> Option<String> {
    let cols = |l: &str| l.split_whitespace().map(str::to_string).collect::<Vec<_>>();
    v4.lines()
        .skip(1)
        .map(cols)
        .find(|c| c.len() > 7 && c[1] == "00000000" && c[7] == "00000000")
        .map(|c| c[0].clone())
        .or_else(|| {
            v6.lines()
                .map(cols)
                .find(|c| {
                    c.len() == 10 && c[0].bytes().all(|b| b == b'0') && c[1] == "00" && c[9] != "lo"
                })
                .map(|c| c[9].clone())
        })
}

#[cfg(target_os = "linux")]
fn read_u64(p: &Path) -> u64 {
    std::fs::read_to_string(p)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// All interfaces; `addrs` comes from `addresses()`.
#[cfg(target_os = "linux")]
pub fn list_with(addrs: &BTreeMap<String, Vec<String>>) -> Vec<IfInfo> {
    let Ok(dir) = std::fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let mut out: Vec<IfInfo> = dir
        .filter_map(Result::ok)
        .map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let base = e.path();
            let ty = read_u64(&base.join("type")) as u32;
            let kind = match ty {
                ARPHRD_LOOPBACK => "loopback",
                ARPHRD_ETHER if base.join("bridge").exists() => "bridge",
                ARPHRD_ETHER => "ethernet",
                ARPHRD_NONE => "tunnel",
                _ => "other",
            };
            let st = base.join("statistics");
            let oper = std::fs::read_to_string(base.join("operstate")).unwrap_or_default();
            let flags = std::fs::read_to_string(base.join("flags"))
                .ok()
                .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
                .unwrap_or(0);
            let mac = std::fs::read_to_string(base.join("address"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|m| !m.is_empty() && m != "00:00:00:00:00:00");
            IfInfo {
                ifindex: read_u64(&base.join("ifindex")) as u32,
                kind,
                // "unknown" is normal for tunnels; IFF_UP decides.
                up: oper.trim() == "up" || (oper.trim() == "unknown" && flags & 1 != 0),
                mac,
                addrs: addrs.get(&name).cloned().unwrap_or_default(),
                rx_bytes: read_u64(&st.join("rx_bytes")),
                tx_bytes: read_u64(&st.join("tx_bytes")),
                rx_packets: read_u64(&st.join("rx_packets")),
                tx_packets: read_u64(&st.join("tx_packets")),
                rx_dropped: read_u64(&st.join("rx_dropped")),
                tx_dropped: read_u64(&st.join("tx_dropped")),
                rx_errors: read_u64(&st.join("rx_errors")),
                tx_errors: read_u64(&st.join("tx_errors")),
                name,
            }
        })
        .collect();
    out.sort_by_key(|i| i.ifindex);
    out
}

/// Interface name -> "addr/prefix" list, from `ip -j addr`.
#[cfg(target_os = "linux")]
pub fn addresses() -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    let Ok(o) = crate::host::command("ip").args(["-j", "addr"]).output() else {
        return out;
    };
    let Ok(serde_json::Value::Array(links)) = serde_json::from_slice(&o.stdout) else {
        return out;
    };
    for l in links {
        let Some(name) = l["ifname"].as_str() else {
            continue;
        };
        let addrs: Vec<String> = l["addr_info"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| {
                Some(format!(
                    "{}/{}",
                    a["local"].as_str()?,
                    a["prefixlen"].as_u64()?
                ))
            })
            .collect();
        out.insert(name.to_string(), addrs);
    }
    out
}

/// `pattern` is an exact name or a prefix ending in `*`.
pub fn matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn patterns() {
        assert!(super::matches("br-*", "br-69071e367b92"));
        assert!(super::matches("docker0", "docker0"));
        assert!(!super::matches("docker0", "docker01"));
        assert!(!super::matches("wg*", "eno1"));
    }

    #[test]
    fn default_route() {
        let v4 = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                  docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n\
                  enp7s0\t00000000\tC1E13FB2\t0003\t0\t0\t0\t00000000\t0\t0\t0\n";
        assert_eq!(
            super::parse_default_route(v4, "").as_deref(),
            Some("enp7s0")
        );
        let v6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 \
                  fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n";
        assert_eq!(
            super::parse_default_route("Iface\n", v6).as_deref(),
            Some("eth0")
        );
        assert_eq!(super::parse_default_route("Iface\n", ""), None);
    }
}
