//! Interfaces and their counters from the routing sysctl (64-bit counters,
//! unlike getifaddrs' if_data), addresses from getifaddrs.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use crate::netif::IfInfo;

const IFT_ETHER: u8 = 0x06;
const IFT_LOOP: u8 = 0x18;
const IFT_BRIDGE: u8 = 0xd1;

fn kind(name: &str, ift: u8) -> &'static str {
    match () {
        _ if ift == IFT_LOOP || name.starts_with("lo") => "loopback",
        _ if ift == IFT_BRIDGE || name.starts_with("bridge") => "bridge",
        // utun: Tailscale, WireGuard, every VPN and Private Relay; ipsec: IKEv2 VPNs.
        _ if name.starts_with("utun") || name.starts_with("ipsec") || name.starts_with("tun") => {
            "tunnel"
        }
        _ if ift == IFT_ETHER => "ethernet",
        _ => "other",
    }
}

fn prefix_len(mask: &[u8]) -> u32 {
    mask.iter().map(|b| b.count_ones()).sum()
}

/// Interface name -> "addr/prefix" list.
pub fn addresses() -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a list we free below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return out;
    }
    let mut p = head;
    while !p.is_null() {
        // SAFETY: p walks the list getifaddrs returned.
        let ifa = unsafe { &*p };
        p = ifa.ifa_next;
        if ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: ifa_name is a NUL-terminated C string.
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: sa_family is valid for every sockaddr; the casts match it.
        let fam = unsafe { (*ifa.ifa_addr).sa_family } as i32;
        let entry = match fam {
            libc::AF_INET => unsafe {
                let a = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                let ip = Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
                let len = if ifa.ifa_netmask.is_null() {
                    32
                } else {
                    let m = &*(ifa.ifa_netmask as *const libc::sockaddr_in);
                    prefix_len(&m.sin_addr.s_addr.to_ne_bytes())
                };
                format!("{}/{len}", IpAddr::V4(ip))
            },
            libc::AF_INET6 => unsafe {
                let a = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                let mut b = a.sin6_addr.s6_addr;
                // KAME embeds the scope in bytes 2-3 of link-local addresses.
                if b[0] == 0xfe && b[1] & 0xc0 == 0x80 {
                    b[2] = 0;
                    b[3] = 0;
                }
                let len = if ifa.ifa_netmask.is_null() {
                    128
                } else {
                    let m = &*(ifa.ifa_netmask as *const libc::sockaddr_in6);
                    prefix_len(&m.sin6_addr.s6_addr)
                };
                format!("{}/{len}", Ipv6Addr::from(b))
            },
            _ => continue,
        };
        out.entry(name).or_default().push(entry);
    }
    // SAFETY: head came from getifaddrs.
    unsafe { libc::freeifaddrs(head) };
    out
}

/// Every interface with its counters; `addrs` comes from `addresses()`.
pub fn list_with(addrs: &BTreeMap<String, Vec<String>>) -> Vec<IfInfo> {
    let mut mib = [libc::CTL_NET, libc::PF_ROUTE, 0, 0, libc::NET_RT_IFLIST2, 0];
    let mut len: libc::size_t = 0;
    // SAFETY: sizing call with a NULL buffer.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            6,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Vec::new();
    }
    // Interfaces can appear between the two calls.
    len += 4096;
    let mut buf = vec![0u64; len / 8 + 1];
    // SAFETY: buf holds at least len bytes.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            6,
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Vec::new();
    }
    // SAFETY: byte view of the initialised part of buf.
    let b = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), len) };
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 4 <= b.len() {
        let msglen = u16::from_ne_bytes([b[pos], b[pos + 1]]) as usize;
        if msglen == 0 || pos + msglen > b.len() {
            break;
        }
        let msg = &b[pos..pos + msglen];
        pos += msglen;
        if msg[3] as i32 != libc::RTM_IFINFO2 || msg.len() < size_of::<libc::if_msghdr2>() {
            continue;
        }
        // SAFETY: msg is at least one if_msghdr2 long; read_unaligned copes with packing.
        let h: libc::if_msghdr2 = unsafe { std::ptr::read_unaligned(msg.as_ptr().cast()) };
        // The link-level sockaddr_dl follows: len, family, index, type, nlen, alen, slen, data.
        let dl = &msg[size_of::<libc::if_msghdr2>()..];
        if dl.len() < 8 {
            continue;
        }
        let (nlen, alen) = (dl[5] as usize, dl[6] as usize);
        let Some(name) = dl.get(8..8 + nlen) else {
            continue;
        };
        let name = String::from_utf8_lossy(name).into_owned();
        let mac = dl
            .get(8 + nlen..8 + nlen + alen)
            .filter(|m| m.len() == 6 && m.iter().any(|&x| x != 0))
            .map(|m| {
                m.iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            });
        let d = h.ifm_data;
        let flags = h.ifm_flags;
        out.push(IfInfo {
            ifindex: h.ifm_index as u32,
            kind: kind(&name, d.ifi_type),
            up: flags & libc::IFF_UP != 0 && flags & libc::IFF_RUNNING != 0,
            mac,
            addrs: addrs.get(&name).cloned().unwrap_or_default(),
            rx_bytes: d.ifi_ibytes,
            tx_bytes: d.ifi_obytes,
            rx_packets: d.ifi_ipackets,
            tx_packets: d.ifi_opackets,
            rx_dropped: d.ifi_iqdrops,
            tx_dropped: h.ifm_snd_drops.max(0) as u64,
            rx_errors: d.ifi_ierrors,
            tx_errors: d.ifi_oerrors,
            name,
        });
    }
    out.sort_by_key(|i| i.ifindex);
    out
}

/// The interface of the IPv4 default route (IPv6 if there is none).
pub fn default_route_interface() -> Option<String> {
    for family in ["-inet", "-inet6"] {
        let out = std::process::Command::new("/sbin/route")
            .args(["-n", "get", family, "default"])
            .output()
            .ok()?;
        if !out.status.success() {
            continue;
        }
        if let Some(i) =
            crate::intel::route_field(&String::from_utf8_lossy(&out.stdout), "interface")
        {
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interfaces_and_addresses() {
        let addrs = addresses();
        assert!(
            addrs
                .get("lo0")
                .is_some_and(|a| a.iter().any(|x| x == "127.0.0.1/8")),
            "{addrs:?}"
        );
        let list = list_with(&addrs);
        let lo = list.iter().find(|i| i.name == "lo0").expect("lo0");
        assert_eq!((lo.kind, lo.up), ("loopback", true));
        assert!(lo.rx_packets > 0 && lo.ifindex > 0);
        assert!(list.windows(2).all(|w| w[0].ifindex <= w[1].ifindex));
    }

    #[test]
    fn kinds() {
        assert_eq!(kind("en0", IFT_ETHER), "ethernet");
        assert_eq!(kind("utun4", 1), "tunnel");
        assert_eq!(kind("bridge100", IFT_BRIDGE), "bridge");
        assert_eq!(kind("gif0", 0x37), "other");
    }
}
