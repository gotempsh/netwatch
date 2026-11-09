//! Owns the loaded XDP program and its maps.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, anyhow, bail};
use aya::{
    Ebpf,
    maps::{Array, HashMap, LpmTrie, MapData, PerCpuArray, RingBuf, lpm_trie::Key},
    programs::{
        SchedClassifier, TcAttachType, TracePoint, Xdp, XdpMode,
        tc::{SchedClassifierLinkId, qdisc_add_clsact},
    },
};
use ipnet::IpNet;
use netwatch_common::{
    CFG_DROP_IPOPT_SYN, CFG_ENFORCE, CFG_SAMPLE_DNS, CFG_SAMPLE_TCP, Config as KConfig, FlowKey,
    FlowStats, GlobalStats, IfConfig, ProbeKey, ProbeStats, SockKey, SrcStats, TP_KIND_SOCKADDR,
    TP_NONE, TcpHealth, TpLayout,
};

use crate::util::{lpm_to_net, net_to_lpm};

/// What accounts for and drops traffic, for logs and notifications.
pub const ENGINE: &str = "XDP";

/// Ring buffers handed to the async readers.
pub struct Rings {
    pub probes: RingBuf<MapData>,
    pub socks: RingBuf<MapData>,
    pub payloads: RingBuf<MapData>,
}

/// An interface with the flow programs attached.
pub struct Attached {
    pub ifindex: u32,
    links: Option<(SchedClassifierLinkId, SchedClassifierLinkId)>,
}

/// What `sync_interfaces` should attach to.
pub struct WantIf {
    pub name: String,
    pub ifindex: u32,
    pub flags: u32,
}

/// (category, name, program) for each tracepoint netwatch uses, in TP_* index order.
const TRACEPOINTS: [(&str, &str, &str); 4] = [
    ("sock", "inet_sock_set_state", "nw_sock_state"),
    ("tcp", "tcp_retransmit_skb", "nw_tcp_retransmit"),
    ("tcp", "tcp_send_reset", "nw_tcp_send_reset"),
    ("tcp", "tcp_receive_reset", "nw_tcp_recv_reset"),
];

pub struct Kernel {
    // Owns the programs and their links; dropping it detaches everything.
    ebpf: Ebpf,
    pub attach_mode: &'static str,
    /// Flow programs loaded (TC); false if the kernel refused them.
    pub flows_ok: bool,
    /// Tracepoints that attached, by name.
    pub tracepoints: Vec<(String, bool)>,
    pub attached: BTreeMap<String, Attached>,
    flows: HashMap<MapData, FlowKey, FlowStats>,
    health: HashMap<MapData, SockKey, TcpHealth>,
    ifaces: HashMap<MapData, u32, IfConfig>,
    sources: HashMap<MapData, [u8; 16], SrcStats>,
    probes: HashMap<MapData, ProbeKey, ProbeStats>,
    allow: LpmTrie<MapData, [u8; 16], u32>,
    block: LpmTrie<MapData, [u8; 16], u32>,
    global: PerCpuArray<MapData, GlobalStats>,
    config: Array<MapData, KConfig>,
}

fn take<T: TryFrom<aya::maps::Map>>(ebpf: &mut Ebpf, name: &str) -> anyhow::Result<T>
where
    T::Error: std::error::Error + Send + Sync + 'static,
{
    let map = ebpf
        .take_map(name)
        .ok_or_else(|| anyhow!("map {name} missing from eBPF object"))?;
    T::try_from(map).with_context(|| format!("map {name} has unexpected type"))
}

impl Kernel {
    pub fn load(iface: &str, mode: &str) -> anyhow::Result<(Self, Rings)> {
        // Older kernels charge BPF maps against RLIMIT_MEMLOCK.
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/netwatch"
        )))
        .context("loading eBPF object")?;
        let program: &mut Xdp = ebpf
            .program_mut("netwatch")
            .ok_or_else(|| anyhow!("program netwatch missing"))?
            .try_into()?;
        program
            .load()
            .context("verifier rejected the XDP program")?;

        let attach_mode = match mode {
            "skb" => {
                program
                    .attach(iface, XdpMode::Skb)
                    .with_context(|| format!("attaching to {iface} (skb)"))?;
                "skb"
            }
            "driver" => {
                program
                    .attach(iface, XdpMode::Driver)
                    .with_context(|| format!("attaching to {iface} (driver)"))?;
                "driver"
            }
            "auto" => match program.attach(iface, XdpMode::Driver) {
                Ok(_) => "driver",
                Err(e) => {
                    log::warn!(
                        "native XDP unavailable on {iface} ({e}), falling back to generic mode"
                    );
                    program
                        .attach(iface, XdpMode::Skb)
                        .with_context(|| format!("attaching to {iface}"))?;
                    "skb"
                }
            },
            other => bail!("unknown xdp_mode {other:?} (expected auto, driver or skb)"),
        };

        // Flow programs: loaded once, attached per interface by sync_interfaces.
        let mut flows_ok = true;
        for name in ["nw_flow_in", "nw_flow_out"] {
            let res = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow!("program {name} missing"))
                .and_then(|p| Ok(<&mut SchedClassifier>::try_from(p)?.load()?));
            if let Err(e) = res {
                log::warn!("flow program {name} not loaded, connection tracking disabled: {e:#}");
                flows_ok = false;
            }
        }

        // Tracepoints: field offsets come from this kernel's tracefs.
        let mut layouts: Array<MapData, TpLayout> = take(&mut ebpf, "TP_LAYOUT")?;
        let mut tracepoints = Vec::new();
        for (i, (cat, name, prog)) in TRACEPOINTS.iter().enumerate() {
            let res = (|| -> anyhow::Result<()> {
                let layout = read_layout(cat, name)?;
                layouts.set(i as u32, layout, 0)?;
                let p: &mut TracePoint = ebpf
                    .program_mut(prog)
                    .ok_or_else(|| anyhow!("program {prog} missing"))?
                    .try_into()?;
                p.load()?;
                p.attach(cat, name)?;
                Ok(())
            })();
            if let Err(e) = &res {
                log::warn!("tracepoint {cat}:{name} unavailable: {e:#}");
            }
            tracepoints.push((format!("{cat}:{name}"), res.is_ok()));
        }

        let rings = Rings {
            probes: take(&mut ebpf, "EVENTS")?,
            socks: take(&mut ebpf, "SOCK_EVENTS")?,
            payloads: take(&mut ebpf, "PAYLOADS")?,
        };
        let kernel = Self {
            sources: take(&mut ebpf, "SOURCES")?,
            probes: take(&mut ebpf, "PROBES")?,
            allow: take(&mut ebpf, "ALLOW")?,
            block: take(&mut ebpf, "BLOCK")?,
            global: take(&mut ebpf, "GLOBAL")?,
            config: take(&mut ebpf, "CONFIG")?,
            flows: take(&mut ebpf, "FLOWS")?,
            health: take(&mut ebpf, "TCP_HEALTH")?,
            ifaces: take(&mut ebpf, "IFACES")?,
            attach_mode,
            flows_ok,
            tracepoints,
            attached: BTreeMap::new(),
            ebpf,
        };
        Ok((kernel, rings))
    }

    pub fn configure(
        &mut self,
        drop_banned: bool,
        drop_ipopt_syn: bool,
        sample_dns: bool,
        sample_tcp: bool,
        eph: (u16, u16),
    ) -> anyhow::Result<()> {
        let mut flags = 0;
        if drop_ipopt_syn {
            flags |= CFG_DROP_IPOPT_SYN;
        }
        if drop_banned {
            flags |= CFG_ENFORCE;
        }
        if sample_dns {
            flags |= CFG_SAMPLE_DNS;
        }
        if sample_tcp {
            flags |= CFG_SAMPLE_TCP;
        }
        self.config.set(
            0,
            KConfig {
                flags,
                eph_lo: eph.0,
                eph_hi: eph.1,
            },
            0,
        )?;
        Ok(())
    }

    /// Nothing to undo: the programs detach when the process exits.
    pub fn shutdown(&mut self) {}

    /// Attaches the flow programs to every wanted interface and detaches from
    /// the ones that went away (Docker bridges come and go).
    pub fn sync_interfaces(&mut self, want: &[WantIf]) {
        if !self.flows_ok {
            return;
        }
        let gone: Vec<String> = self
            .attached
            .keys()
            .filter(|n| !want.iter().any(|w| &w.name == *n))
            .cloned()
            .collect();
        for name in gone {
            let a = self.attached.remove(&name).expect("present");
            let _ = self.ifaces.remove(&a.ifindex);
            if let Some((li, lo)) = a.links {
                // The links die with the device anyway; errors here are expected.
                let _ = self.classifier("nw_flow_in").map(|p| p.detach(li));
                let _ = self.classifier("nw_flow_out").map(|p| p.detach(lo));
            }
            log::info!("flow tracking stopped on {name}");
        }
        for w in want {
            match self.attached.get(&w.name) {
                // Same device (a recreated bridge gets a new ifindex).
                Some(a) if a.ifindex == w.ifindex => continue,
                Some(_) => {
                    let a = self.attached.remove(&w.name).expect("present");
                    let _ = self.ifaces.remove(&a.ifindex);
                }
                None => {}
            }
            if let Err(e) = self.ifaces.insert(
                w.ifindex,
                IfConfig {
                    flags: w.flags,
                    _pad: 0,
                },
                0,
            ) {
                log::warn!("flow tracking on {}: {e}", w.name);
                continue;
            }
            match self.attach_tc(&w.name) {
                Ok(links) => {
                    log::info!("flow tracking on {} (ifindex {})", w.name, w.ifindex);
                    self.attached.insert(
                        w.name.clone(),
                        Attached {
                            ifindex: w.ifindex,
                            links: Some(links),
                        },
                    );
                }
                Err(e) => log::warn!("flow tracking on {}: {e:#}", w.name),
            }
        }
    }

    fn classifier(&mut self, name: &str) -> anyhow::Result<&mut SchedClassifier> {
        Ok(self
            .ebpf
            .program_mut(name)
            .ok_or_else(|| anyhow!("program {name} missing"))?
            .try_into()?)
    }

    fn attach_tc(
        &mut self,
        iface: &str,
    ) -> anyhow::Result<(SchedClassifierLinkId, SchedClassifierLinkId)> {
        // Needed for the netlink path on kernels before 6.6; harmless with TCX.
        let _ = qdisc_add_clsact(iface);
        let li = self
            .classifier("nw_flow_in")?
            .attach(iface, TcAttachType::Ingress)?;
        match self
            .classifier("nw_flow_out")?
            .attach(iface, TcAttachType::Egress)
        {
            Ok(lo) => Ok((li, lo)),
            Err(e) => {
                let _ = self.classifier("nw_flow_in").map(|p| p.detach(li));
                Err(e.into())
            }
        }
    }

    pub fn flows(&self) -> Vec<(FlowKey, FlowStats)> {
        self.flows
            .iter()
            .take(netwatch_common::MAX_FLOWS as usize * 2)
            .filter_map(Result::ok)
            .collect()
    }

    pub fn delete_flows(&mut self, keys: &[FlowKey]) {
        for k in keys {
            let _ = self.flows.remove(k);
        }
    }

    pub fn tcp_health(&self) -> Vec<(SockKey, TcpHealth)> {
        self.health
            .iter()
            .take(netwatch_common::MAX_TCP_HEALTH as usize * 2)
            .filter_map(Result::ok)
            .collect()
    }

    pub fn delete_health(&mut self, keys: &[SockKey]) {
        for k in keys {
            let _ = self.health.remove(k);
        }
    }

    pub fn sources(&self) -> Vec<([u8; 16], SrcStats)> {
        self.sources
            .iter()
            .take(netwatch_common::MAX_SOURCES as usize * 2)
            .filter_map(Result::ok)
            .collect()
    }

    pub fn probes(&self) -> Vec<(ProbeKey, ProbeStats)> {
        self.probes
            .iter()
            .take(netwatch_common::MAX_PROBES as usize * 2)
            .filter_map(Result::ok)
            .collect()
    }

    pub fn global(&self) -> GlobalStats {
        let mut g = GlobalStats::default();
        if let Ok(per_cpu) = self.global.get(&0, 0) {
            for v in per_cpu.iter() {
                g.packets += v.packets;
                g.bytes += v.bytes;
                g.in_packets += v.in_packets;
                g.syn += v.syn;
                g.blocked += v.blocked;
                g.dropped += v.dropped;
                g.events_lost += v.events_lost;
                g.non_ip += v.non_ip;
                g.sock_events_lost += v.sock_events_lost;
                g.ipopt_syn += v.ipopt_syn;
                g.ipopt_dropped += v.ipopt_dropped;
            }
        }
        g
    }

    pub fn block(&mut self, net: &IpNet) -> anyhow::Result<()> {
        let (len, data) = net_to_lpm(net);
        self.block.insert(&Key::new(len, data), 1, 0)?;
        Ok(())
    }

    pub fn unblock(&mut self, net: &IpNet) -> anyhow::Result<()> {
        let (len, data) = net_to_lpm(net);
        match self.block.remove(&Key::new(len, data)) {
            Ok(()) | Err(aya::maps::MapError::KeyNotFound) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Makes the kernel allowlist exactly `want`.
    pub fn sync_allow(&mut self, want: &BTreeSet<IpNet>) -> anyhow::Result<()> {
        let have: BTreeSet<IpNet> = trie_entries(&self.allow).into_iter().collect();
        for net in have.difference(want) {
            let (len, data) = net_to_lpm(net);
            let _ = self.allow.remove(&Key::new(len, data));
        }
        for net in want.difference(&have) {
            let (len, data) = net_to_lpm(net);
            self.allow.insert(&Key::new(len, data), 1, 0)?;
        }
        Ok(())
    }
}

fn tracefs_format(cat: &str, name: &str) -> anyhow::Result<String> {
    for root in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
        if let Ok(t) = std::fs::read_to_string(format!("{root}/events/{cat}/{name}/format")) {
            return Ok(t);
        }
    }
    bail!("no tracefs format for {cat}:{name} (is tracefs mounted?)")
}

fn read_layout(cat: &str, name: &str) -> anyhow::Result<TpLayout> {
    parse_layout(&tracefs_format(cat, name)?)
        .ok_or_else(|| anyhow!("unexpected field layout for {cat}:{name}"))
}

/// Parses `field:<type> <name>; offset:<n>; size:<n>;` lines from a tracefs format file.
pub fn parse_layout(format: &str) -> Option<TpLayout> {
    let mut l = TpLayout::default();
    let mut saddr_size = 0;
    for line in format.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("field:") else {
            continue;
        };
        let mut parts = rest.split(';').map(str::trim);
        let decl = parts.next()?;
        let mut offset = None;
        let mut size = None;
        for p in parts {
            if let Some(v) = p.strip_prefix("offset:") {
                offset = v.parse::<u16>().ok();
            } else if let Some(v) = p.strip_prefix("size:") {
                size = v.parse::<u16>().ok();
            }
        }
        let (Some(offset), Some(size)) = (offset, size) else {
            continue;
        };
        let name = decl.rsplit(' ').next()?.split('[').next()?;
        let slot = match name {
            "skaddr" => &mut l.skaddr,
            "oldstate" => &mut l.oldstate,
            "newstate" => &mut l.newstate,
            "protocol" => &mut l.protocol,
            "sport" => &mut l.sport,
            "dport" => &mut l.dport,
            "family" => &mut l.family,
            "saddr" => {
                saddr_size = size;
                &mut l.saddr
            }
            "daddr" => &mut l.daddr,
            "saddr_v6" => &mut l.saddr_v6,
            "daddr_v6" => &mut l.daddr_v6,
            _ => continue,
        };
        *slot = offset;
    }
    if l.saddr == TP_NONE || l.daddr == TP_NONE {
        return None;
    }
    // Newer kernels store both families in a 28-byte sockaddr_in6 union.
    if saddr_size == 28 {
        l.kind = TP_KIND_SOCKADDR;
    } else if l.sport == TP_NONE || l.dport == TP_NONE || l.family == TP_NONE {
        return None;
    }
    l.valid = 1;
    Some(l)
}

fn trie_entries(trie: &LpmTrie<MapData, [u8; 16], u32>) -> Vec<IpNet> {
    trie.keys()
        .filter_map(Result::ok)
        .map(|k| lpm_to_net(k.prefix_len(), k.data()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracefs_layouts() {
        let fields = "name: inet_sock_set_state\nformat:\n\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
            \tfield:const void * skaddr;\toffset:8;\tsize:8;\tsigned:0;\n\tfield:int oldstate;\toffset:16;\tsize:4;\tsigned:1;\n\
            \tfield:int newstate;\toffset:20;\tsize:4;\tsigned:1;\n\tfield:__u16 sport;\toffset:24;\tsize:2;\tsigned:0;\n\
            \tfield:__u16 dport;\toffset:26;\tsize:2;\tsigned:0;\n\tfield:__u16 family;\toffset:28;\tsize:2;\tsigned:0;\n\
            \tfield:__u16 protocol;\toffset:30;\tsize:2;\tsigned:0;\n\tfield:__u8 saddr[4];\toffset:32;\tsize:4;\tsigned:0;\n\
            \tfield:__u8 daddr[4];\toffset:36;\tsize:4;\tsigned:0;\n\tfield:__u8 saddr_v6[16];\toffset:40;\tsize:16;\tsigned:0;\n\
            \tfield:__u8 daddr_v6[16];\toffset:56;\tsize:16;\tsigned:0;\n";
        let l = parse_layout(fields).unwrap();
        assert_eq!(
            (l.kind, l.skaddr, l.oldstate, l.sport, l.saddr, l.daddr_v6),
            (0, 8, 16, 24, 32, 56)
        );

        let sockaddr = "\tfield:const void * skaddr;\toffset:16;\tsize:8;\tsigned:0;\n\
            \tfield:__u8 saddr[28];\toffset:32;\tsize:28;\tsigned:0;\n\tfield:__u8 daddr[28];\toffset:60;\tsize:28;\tsigned:0;\n";
        let l = parse_layout(sockaddr).unwrap();
        assert_eq!(
            (l.kind, l.saddr, l.daddr, l.sport),
            (TP_KIND_SOCKADDR, 32, 60, TP_NONE)
        );
        assert!(parse_layout("\tfield:int x;\toffset:8;\tsize:4;\tsigned:1;\n").is_none());
    }
}
