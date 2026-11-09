//! Which process (and container) owns a socket, from /proc. Complements the
//! TCP tracepoints: covers UDP, listeners, and connections opened before
//! netwatch started. On macOS the sockets come from libproc (see macos/proc.rs).

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use netwatch_common::{PROTO_TCP, PROTO_UDP};
use serde::Serialize;

#[cfg(target_os = "macos")]
pub use crate::macos::proc::{scan, sockets};

/// How a process's `unit` is shown: a systemd service, or a macOS app bundle.
#[cfg(target_os = "linux")]
pub const UNIT_SUFFIX: &str = ".service";
#[cfg(target_os = "macos")]
pub const UNIT_SUFFIX: &str = ".app";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Owner {
    pub pid: u32,
    pub comm: String,
    pub exe: Option<String>,
    /// Docker container name (or short id for other runtimes).
    pub container: Option<String>,
    /// systemd service outside containers ("ssh", "temps-agent"): names
    /// processes whose comm is meaningless, like binaries named by hash.
    /// On macOS, the app bundle ("Google Chrome" for its helpers).
    pub unit: Option<String>,
    /// Network namespace inode; None if the process was gone before we looked.
    #[serde(skip)]
    pub netns: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcSock {
    pub proto: u8,
    pub local: IpAddr,
    pub lport: u16,
    pub remote: IpAddr,
    pub rport: u16,
    /// Kernel socket state (TCP: 0x0A listen, 0x01 established; UDP: 0x07 unconnected).
    pub state: u8,
    pub inode: u64,
}

impl ProcSock {
    pub fn listening(&self) -> bool {
        (self.proto == PROTO_TCP && self.state == 0x0a)
            || (self.proto == PROTO_UDP && self.state == 0x07)
    }
}

/// /proc/net address: IPv4 as one little-endian word, IPv6 as four.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_addr(hex: &str) -> Option<(IpAddr, u16)> {
    let (a, p) = hex.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    let ip = match a.len() {
        8 => IpAddr::V4(Ipv4Addr::from(
            u32::from_str_radix(a, 16).ok()?.swap_bytes(),
        )),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                let w = u32::from_str_radix(&a[i * 8..i * 8 + 8], 16).ok()?;
                b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
            }
            let v6 = Ipv6Addr::from(b);
            v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)
        }
        _ => return None,
    };
    Some((ip, port))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_proc_net(text: &str, proto: u8) -> Vec<ProcSock> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let c: Vec<&str> = line.split_whitespace().collect();
            if c.len() < 10 {
                return None;
            }
            let (local, lport) = parse_addr(c[1])?;
            let (remote, rport) = parse_addr(c[2])?;
            Some(ProcSock {
                proto,
                local,
                lport,
                remote,
                rport,
                state: u8::from_str_radix(c[3], 16).ok()?,
                inode: c[9].parse().ok()?,
            })
        })
        .collect()
}

/// Sockets in the host network namespace.
#[cfg(target_os = "linux")]
pub fn sockets() -> Vec<ProcSock> {
    let mut out = Vec::new();
    for (file, proto) in [
        ("/proc/net/tcp", PROTO_TCP),
        ("/proc/net/tcp6", PROTO_TCP),
        ("/proc/net/udp", PROTO_UDP),
        ("/proc/net/udp6", PROTO_UDP),
    ] {
        if let Ok(t) = std::fs::read_to_string(file) {
            out.extend(parse_proc_net(&t, proto));
        }
    }
    out
}

/// socket inode -> pid, by walking /proc/<pid>/fd.
#[cfg(target_os = "linux")]
pub fn socket_inodes() -> HashMap<u64, u32> {
    let mut out = HashMap::new();
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return out;
    };
    for p in procs.filter_map(Result::ok) {
        let Ok(pid) = p.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(p.path().join("fd")) else {
            continue;
        };
        for fd in fds.filter_map(Result::ok) {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                let t = target.to_string_lossy();
                if let Some(inode) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                    if let Ok(i) = inode.parse() {
                        out.entry(i).or_insert(pid);
                    }
                }
            }
        }
    }
    out
}

/// Inode of a network namespace link such as /proc/1/ns/net ("net:[4026531840]").
pub fn netns_of(path: &str) -> Option<u64> {
    let l = std::fs::read_link(path).ok()?;
    l.to_str()?
        .strip_prefix("net:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// Container id from a cgroup path: docker-<id>.scope, /docker/<id>, cri-containerd-<id>.scope, libpod-<id>.scope.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn container_id(cgroup: &str) -> Option<String> {
    for line in cgroup.lines() {
        let path = line.rsplit(':').next()?;
        for seg in path.split('/').rev() {
            let seg = seg.strip_suffix(".scope").unwrap_or(seg);
            let id = seg.rsplit(['-', ':']).next().unwrap_or(seg);
            if id.len() == 64 && id.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Some(id.to_string());
            }
        }
    }
    None
}

/// Innermost systemd service in a cgroup path, without the suffix.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn unit_of(cgroup: &str) -> Option<String> {
    let path = cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .or_else(|| cgroup.lines().next()?.rsplit(':').next())?;
    path.split('/')
        .rev()
        .find_map(|seg| seg.strip_suffix(".service"))
        .map(str::to_string)
}

/// Resolves pids to owners, caching container names (they never change for an id).
#[derive(Default)]
pub struct OwnerCache {
    by_pid: HashMap<u32, (Owner, i64)>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    containers: HashMap<String, String>,
}

impl OwnerCache {
    /// Owner of a live pid; `comm_hint` (from the capture header) is used if the process is gone.
    #[cfg(target_os = "macos")]
    pub fn owner(&mut self, pid: u32, comm_hint: Option<&str>, now: i64) -> Option<Owner> {
        if pid == 0 {
            return None;
        }
        if let Some((o, ts)) = self.by_pid.get(&pid)
            && now - ts < 60
        {
            return Some(o.clone());
        }
        let (comm, exe) = match crate::macos::proc::describe(pid) {
            Some(d) => d,
            None => (comm_hint.filter(|c| !c.is_empty())?.to_string(), None),
        };
        let unit = exe.as_deref().and_then(crate::macos::proc::app_bundle);
        let o = Owner {
            pid,
            comm,
            exe,
            container: None,
            unit,
            netns: None,
        };
        self.by_pid.insert(pid, (o.clone(), now));
        Some(o)
    }

    /// Owner of a live pid; `comm_hint` (from the kernel event) is used if the process is gone.
    #[cfg(target_os = "linux")]
    pub fn owner(&mut self, pid: u32, comm_hint: Option<&str>, now: i64) -> Option<Owner> {
        if pid == 0 {
            return None;
        }
        if let Some((o, ts)) = self.by_pid.get(&pid) {
            if now - ts < 60 {
                return Some(o.clone());
            }
        }
        let base = format!("/proc/{pid}");
        let comm = std::fs::read_to_string(format!("{base}/comm"))
            .ok()
            .map(|s| s.trim().to_string());
        let Some(comm) = comm.or_else(|| comm_hint.map(str::to_string)) else {
            return None;
        };
        let exe = std::fs::read_link(format!("{base}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
        let cgroup = std::fs::read_to_string(format!("{base}/cgroup")).unwrap_or_default();
        let container = container_id(&cgroup).map(|id| self.container_name(&id));
        let unit = if container.is_none() {
            unit_of(&cgroup)
        } else {
            None
        };
        let netns = netns_of(&format!("{base}/ns/net"));
        let o = Owner {
            pid,
            comm,
            exe,
            container,
            unit,
            netns,
        };
        self.by_pid.insert(pid, (o.clone(), now));
        Some(o)
    }

    #[cfg(target_os = "linux")]
    fn container_name(&mut self, id: &str) -> String {
        if let Some(n) = self.containers.get(id) {
            return n.clone();
        }
        let name = std::fs::read_to_string(crate::host::path(&format!(
            "/var/lib/docker/containers/{id}/config.v2.json"
        )))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|v| {
            v["Name"]
                .as_str()
                .map(|n| n.trim_start_matches('/').to_string())
        })
        .unwrap_or_else(|| id[..12].to_string());
        self.containers.insert(id.to_string(), name.clone());
        name
    }

    pub fn prune(&mut self, now: i64) {
        self.by_pid.retain(|_, (_, ts)| now - *ts < 300);
    }
}

pub struct Scan {
    /// Every host-namespace socket with its owner, when one can be found.
    pub socks: Vec<(ProcSock, Option<Owner>)>,
    /// Container addresses on Docker networks -> the container's main process.
    pub containers: HashMap<IpAddr, Owner>,
}

#[cfg(target_os = "linux")]
pub fn scan(cache: &mut OwnerCache, now: i64) -> Scan {
    let inodes = socket_inodes();
    let socks = sockets()
        .into_iter()
        .map(|s| {
            let owner = inodes
                .get(&s.inode)
                .and_then(|&pid| cache.owner(pid, None, now));
            (s, owner)
        })
        .collect();
    Scan {
        socks,
        containers: container_addrs(cache, now),
    }
}

/// Running Docker containers' addresses, from their config.v2.json. Flows on
/// the bridges have the container's address as the local side.
#[cfg(target_os = "linux")]
fn container_addrs(cache: &mut OwnerCache, now: i64) -> HashMap<IpAddr, Owner> {
    let mut out = HashMap::new();
    let Ok(dirs) = std::fs::read_dir(crate::host::path("/var/lib/docker/containers")) else {
        return out;
    };
    for d in dirs.filter_map(Result::ok) {
        let Ok(text) = std::fs::read_to_string(d.path().join("config.v2.json")) else {
            continue;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        let pid = v["State"]["Pid"].as_u64().unwrap_or(0) as u32;
        if v["State"]["Running"].as_bool() != Some(true) || pid == 0 {
            continue;
        }
        let Some(owner) = cache.owner(pid, None, now) else {
            continue;
        };
        let nets = v["NetworkSettings"]["Networks"]
            .as_object()
            .into_iter()
            .flat_map(|n| n.values());
        for n in nets {
            for k in ["IPAddress", "GlobalIPv6Address"] {
                if let Some(ip) = n[k].as_str().and_then(|s| s.parse().ok()) {
                    out.insert(ip, owner.clone());
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_net_lines() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
            0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 23456 1\n\
            1: 0801A8C0:0016 8D01A8C0:D2F0 01 00000000:00000000 02:000A5E1C 00000000     0        0 98765 4";
        let s = parse_proc_net(tcp, PROTO_TCP);
        assert_eq!(s[0].local, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!((s[0].lport, s[0].state, s[0].inode), (53, 0x0a, 23456));
        assert!(s[0].listening());
        assert_eq!(
            (s[1].local.to_string(), s[1].lport),
            ("192.168.1.8".into(), 22)
        );
        assert_eq!(
            (s[1].remote.to_string(), s[1].rport),
            ("192.168.1.141".into(), 0xd2f0)
        );

        let tcp6 = "header\n 0: 0000000000000000FFFF00000801A8C0:01BB 00000000000000000000000000000000:0000 0A 0:0 00:0 0 0 0 555 1";
        assert_eq!(
            parse_proc_net(tcp6, PROTO_TCP)[0].local.to_string(),
            "192.168.1.8"
        );
    }

    #[test]
    fn container_ids() {
        let id = "4f1c5e2a9b7d3c8e1f0a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e";
        assert_eq!(
            container_id(&format!("0::/system.slice/docker-{id}.scope")).as_deref(),
            Some(id)
        );
        assert_eq!(
            container_id(&format!("12:pids:/docker/{id}")).as_deref(),
            Some(id)
        );
        assert_eq!(
            container_id("0::/user.slice/user-1000.slice/session-3.scope"),
            None
        );
        assert_eq!(
            unit_of("0::/system.slice/temps-agent.service").as_deref(),
            Some("temps-agent")
        );
        assert_eq!(
            unit_of("0::/user.slice/user-1000.slice/user@1000.service/app.slice/foo.service")
                .as_deref(),
            Some("foo")
        );
        assert_eq!(unit_of("0::/init.scope"), None);
    }
}
