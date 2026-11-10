//! The macOS `Kernel`: the same interface as the eBPF loader (kernel.rs), backed
//! by capture threads feeding a [`Sensor`]. Events reach the daemon through
//! channels instead of ring buffers.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    path::PathBuf,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use anyhow::Context as _;
use ipnet::IpNet;
use netwatch_common::{
    CFG_ENFORCE, CFG_SAMPLE_DNS, CFG_SAMPLE_TCP, FlowKey, FlowStats, GlobalStats, PROTO_TCP,
    PayloadEvent, ProbeEvent, ProbeKey, ProbeStats, SockEvent, SockKey, SrcStats, TcpHealth,
};
use tokio::sync::mpsc;

use super::{
    bpf::{self, Device, Frame, L3, Pcap},
    pf::Pf,
    sensor::{NetSet, Packet, SYN_SENT, Sensor},
};
use crate::util::{BootClock, boot_now_ns, ip_to_key};

/// What accounts for and drops traffic, for logs and notifications.
pub const ENGINE: &str = "/dev/bpf";

/// Bytes kept per packet: Ethernet + IPv6 + TCP with options + PAYLOAD_CAP.
const SNAPLEN: u32 = 14 + 4 + 40 + 60 + netwatch_common::PAYLOAD_CAP as u32;
/// Event batches buffered towards the daemon, like the ring buffers.
const CHANNEL_BATCHES: usize = 1024;

pub struct Rings {
    pub probes: mpsc::Receiver<Vec<ProbeEvent>>,
    pub socks: mpsc::Receiver<Vec<SockEvent>>,
    pub payloads: mpsc::Receiver<Vec<PayloadEvent>>,
}

/// An interface whose flows are recorded.
pub struct Attached;

/// What `sync_interfaces` should attach to.
pub struct WantIf {
    pub name: String,
    pub ifindex: u32,
    pub flags: u32,
}

struct Shared {
    sensor: Mutex<Sensor>,
    clock: BootClock,
    /// This host's addresses: the direction of packets whose capture header doesn't say.
    local: RwLock<HashSet<[u8; 16]>>,
    probes: mpsc::Sender<Vec<ProbeEvent>>,
    payloads: mpsc::Sender<Vec<PayloadEvent>>,
    socks: std::sync::mpsc::SyncSender<Vec<SockEvent>>,
}

struct Capture {
    ifindex: u32,
    flows: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Capture {
    fn halt(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

enum Source {
    Device(Device),
    /// NETWATCH_PCAP: a capture file replayed once, its last packet stamped "now".
    Replay {
        pcap: Pcap,
        offset_ns: i128,
        pos: usize,
        end: usize,
    },
}

impl Source {
    fn dlt(&self) -> u32 {
        match self {
            Source::Device(d) => d.dlt,
            Source::Replay { pcap, .. } => pcap.dlt,
        }
    }

    /// Waits for the next batch; false when there was none.
    fn fill(&mut self) -> std::io::Result<bool> {
        match self {
            Source::Device(d) => d.fill(),
            Source::Replay { pcap, pos, end, .. } => {
                *pos = *end;
                if *pos >= pcap.frames.len() {
                    std::thread::sleep(Duration::from_millis(250));
                    return Ok(false);
                }
                *end = (*pos + 1024).min(pcap.frames.len());
                Ok(true)
            }
        }
    }

    fn for_each(&self, mut f: impl FnMut(Frame)) {
        match self {
            Source::Device(d) => d.frames().for_each(f),
            Source::Replay {
                pcap,
                offset_ns,
                pos,
                end,
            } => {
                for (ts, len, data) in &pcap.frames[*pos..*end] {
                    f(Frame {
                        ts_unix_ns: ts + offset_ns,
                        wire_len: *len,
                        egress: None,
                        pid: 0,
                        comm: [0; 16],
                        retransmit: false,
                        data,
                    });
                }
            }
        }
    }
}

pub struct Kernel {
    shared: Arc<Shared>,
    /// "capture" (bans counted only), "capture+pf" (bans dropped by pf), or
    /// "capture+pf-unreferenced" (pf runs, but pf.conf never evaluates the anchor, so
    /// bans are only counted).
    pub attach_mode: &'static str,
    pub flows_ok: bool,
    /// Kernel features the sensor relies on, by name.
    pub tracepoints: Vec<(String, bool)>,
    pub attached: BTreeMap<String, Attached>,
    primary: String,
    captures: BTreeMap<String, Capture>,
    replay: bool,
    /// The primary capture, opened by `load` (so a missing permission fails
    /// early) and started by the first `sync_interfaces`, once configured.
    pending: Option<(u32, Source)>,
    pf: Option<Pf>,
    block: BTreeSet<IpNet>,
    allow: BTreeSet<IpNet>,
}

fn unix_now_ns() -> i128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as i128)
}

fn host_addresses() -> HashSet<[u8; 16]> {
    super::netif::addresses()
        .values()
        .flatten()
        .filter_map(|a| a.split('/').next()?.parse().ok())
        .map(ip_to_key)
        .collect()
}

/// The IP source address, to tell direction from addresses alone.
fn ip_src(ip: &[u8]) -> Option<[u8; 16]> {
    match ip.first()? >> 4 {
        4 => {
            let s = ip.get(12..16)?;
            Some(ip_to_key(std::net::IpAddr::from([s[0], s[1], s[2], s[3]])))
        }
        6 => ip.get(8..24)?.try_into().ok(),
        _ => None,
    }
}

impl Kernel {
    pub fn load(iface: &str, _xdp_mode: &str) -> anyhow::Result<(Self, Rings)> {
        let (probes_tx, probes) = mpsc::channel(CHANNEL_BATCHES);
        let (payloads_tx, payloads) = mpsc::channel(CHANNEL_BATCHES);
        let (socks_out, socks) = mpsc::channel(CHANNEL_BATCHES);
        let (socks_tx, socks_rx) = std::sync::mpsc::sync_channel(CHANNEL_BATCHES);
        std::thread::Builder::new()
            .name("owners".into())
            .spawn(move || resolve_owners(socks_rx, socks_out))?;

        let shared = Arc::new(Shared {
            sensor: Mutex::new(Sensor::new((49152, 65535))),
            clock: BootClock::new(),
            local: RwLock::new(host_addresses()),
            probes: probes_tx,
            payloads: payloads_tx,
            socks: socks_tx,
        });
        let replay = std::env::var_os("NETWATCH_PCAP").map(PathBuf::from);
        let ifindex = nix_if_index(iface);
        let source = match &replay {
            Some(path) => {
                let pcap =
                    Pcap::read(path).with_context(|| format!("reading {}", path.display()))?;
                let last = pcap.frames.last().map_or(0, |f| f.0);
                log::warn!(
                    "NETWATCH_PCAP: replaying {} packets from {} as {iface}",
                    pcap.frames.len(),
                    path.display()
                );
                Source::Replay {
                    pcap,
                    offset_ns: unix_now_ns() - last,
                    pos: 0,
                    end: 0,
                }
            }
            None => Source::Device(Device::open(iface, SNAPLEN).with_context(|| {
                if super::is_root() {
                    format!("capturing on {iface}")
                } else {
                    format!("capturing on {iface}: /dev/bpf needs root (sudo netwatch run)")
                }
            })?),
        };
        let ext = match &source {
            Source::Device(d) => d.ext,
            Source::Replay { .. } => false,
        };
        if !ext && replay.is_none() {
            log::warn!(
                "no extended BPF headers: direction comes from addresses and connects have no process until the next socket scan"
            );
        }
        let k = Self {
            shared,
            attach_mode: "capture",
            flows_ok: true,
            tracepoints: vec![(
                "bpf:extended-header (direction, sending process)".into(),
                ext,
            )],
            attached: BTreeMap::new(),
            primary: iface.to_string(),
            captures: BTreeMap::new(),
            replay: replay.is_some(),
            pending: Some((ifindex, source)),
            pf: None,
            block: BTreeSet::new(),
            allow: BTreeSet::new(),
        };
        Ok((
            k,
            Rings {
                probes,
                socks,
                payloads,
            },
        ))
    }

    fn spawn(
        &mut self,
        name: &str,
        ifindex: u32,
        if_flags: u32,
        primary: bool,
        flows: bool,
        source: Source,
    ) -> anyhow::Result<()> {
        let flows = Arc::new(AtomicBool::new(flows));
        let stop = Arc::new(AtomicBool::new(false));
        let (shared, f, s, n) = (
            self.shared.clone(),
            flows.clone(),
            stop.clone(),
            name.to_string(),
        );
        let handle = std::thread::Builder::new()
            .name(format!("bpf-{name}"))
            .spawn(move || capture(shared, source, n, ifindex, if_flags, primary, f, s))?;
        self.captures.insert(
            name.to_string(),
            Capture {
                ifindex,
                flows,
                stop,
                handle: Some(handle),
            },
        );
        Ok(())
    }

    pub fn configure(
        &mut self,
        drop_banned: bool,
        drop_ipopt_syn: bool,
        sample_dns: bool,
        sample_tcp: bool,
        eph: (u16, u16),
    ) -> anyhow::Result<()> {
        if drop_ipopt_syn {
            log::warn!("drop_syn_ip_options is for a Linux TCP bug; ignored on macOS");
        }
        let mut flags = 0;
        if sample_dns {
            flags |= CFG_SAMPLE_DNS;
        }
        if sample_tcp {
            flags |= CFG_SAMPLE_TCP;
        }
        if drop_banned && self.pf.is_none() && !self.replay {
            match Pf::start() {
                Ok(pf) => {
                    if pf.unreferenced {
                        log::warn!(
                            "the pf ruleset has no anchor \"com.apple/*\", so bans in {} are not evaluated; add `anchor \"{}\"` to /etc/pf.conf",
                            super::pf::ANCHOR,
                            super::pf::ANCHOR
                        );
                    }
                    self.attach_mode = if pf.unreferenced {
                        "capture+pf-unreferenced"
                    } else {
                        "capture+pf"
                    };
                    self.pf = Some(pf);
                }
                Err(e) => log::warn!("bans will be counted but not dropped: {e:#}"),
            }
        }
        if self.pf.is_some() {
            flags |= CFG_ENFORCE;
        }
        let mut s = self.shared.sensor.lock().unwrap();
        s.flags = flags;
        s.eph = eph;
        Ok(())
    }

    /// Nothing to undo on Linux; here the pf rules go and the captures stop.
    pub fn shutdown(&mut self) {
        if let Some(mut pf) = self.pf.take() {
            pf.stop();
        }
        for c in self.captures.values_mut() {
            c.stop.store(true, Ordering::Relaxed);
        }
    }

    /// Records flows on every wanted interface and stops on the ones that went
    /// away (utun devices come and go with VPNs).
    pub fn sync_interfaces(&mut self, want: &[WantIf]) {
        *self.shared.local.write().unwrap() = host_addresses();
        // A capture whose interface vanished has ended; it reopens when it returns.
        let dead: Vec<String> = self
            .captures
            .iter()
            .filter(|(n, c)| {
                **n != self.primary && c.handle.as_ref().is_some_and(|h| h.is_finished())
            })
            .map(|(n, _)| n.clone())
            .collect();
        for n in dead {
            self.captures.remove(&n);
            self.attached.remove(&n);
        }
        let gone: Vec<String> = self
            .captures
            .keys()
            .filter(|n| **n != self.primary && !want.iter().any(|w| &w.name == *n))
            .cloned()
            .collect();
        for name in gone {
            if let Some(mut c) = self.captures.remove(&name) {
                c.halt();
            }
            self.attached.remove(&name);
            log::info!("flow tracking stopped on {name}");
        }
        if let Some((ifindex, source)) = self.pending.take() {
            let primary = self.primary.clone();
            let flows = want.iter().any(|w| w.name == primary);
            if let Err(e) = self.spawn(&primary, ifindex, 0, true, flows, source) {
                log::error!("capture on {primary}: {e:#}");
            }
        }
        if !want.iter().any(|w| w.name == self.primary) {
            if let Some(c) = self.captures.get(&self.primary) {
                c.flows.store(false, Ordering::Relaxed);
            }
            self.attached.remove(&self.primary);
        }
        for w in want {
            if let Some(c) = self.captures.get(&w.name) {
                if c.ifindex == w.ifindex || w.name == self.primary {
                    c.flows.store(true, Ordering::Relaxed);
                    self.attached.entry(w.name.clone()).or_insert(Attached);
                    continue;
                }
                // Same name, new device.
                if let Some(mut c) = self.captures.remove(&w.name) {
                    c.halt();
                }
            }
            if self.replay {
                continue;
            }
            match Device::open(&w.name, SNAPLEN) {
                Ok(dev) => match self.spawn(
                    &w.name,
                    w.ifindex,
                    w.flags,
                    false,
                    true,
                    Source::Device(dev),
                ) {
                    Ok(()) => {
                        log::info!("flow tracking on {} (ifindex {})", w.name, w.ifindex);
                        self.attached.insert(w.name.clone(), Attached);
                    }
                    Err(e) => log::warn!("flow tracking on {}: {e:#}", w.name),
                },
                Err(e) => log::warn!("flow tracking on {}: {e}", w.name),
            }
        }
    }

    fn send(&self, out: super::sensor::Outbox) {
        send_out(&self.shared, out);
    }

    pub fn flows(&self) -> Vec<(FlowKey, FlowStats)> {
        let (flows, out) = {
            let mut s = self.shared.sensor.lock().unwrap();
            s.housekeep(boot_now_ns());
            let flows = s.flows.iter().map(|(k, f)| (*k, f.st)).collect();
            (flows, s.take_out())
        };
        self.send(out);
        flows
    }

    pub fn delete_flows(&mut self, keys: &[FlowKey]) {
        let mut s = self.shared.sensor.lock().unwrap();
        for k in keys {
            s.flows.remove(k);
        }
    }

    pub fn tcp_health(&self) -> Vec<(SockKey, TcpHealth)> {
        let s = self.shared.sensor.lock().unwrap();
        s.health.iter().map(|(k, v)| (*k, *v)).collect()
    }

    pub fn delete_health(&mut self, keys: &[SockKey]) {
        let mut s = self.shared.sensor.lock().unwrap();
        for k in keys {
            s.health.remove(k);
        }
    }

    pub fn sources(&self) -> Vec<([u8; 16], SrcStats)> {
        let s = self.shared.sensor.lock().unwrap();
        s.sources.iter().map(|(k, v)| (*k, *v)).collect()
    }

    pub fn probes(&self) -> Vec<(ProbeKey, ProbeStats)> {
        let s = self.shared.sensor.lock().unwrap();
        s.probes.iter().map(|(k, v)| (*k, *v)).collect()
    }

    pub fn global(&self) -> GlobalStats {
        self.shared.sensor.lock().unwrap().global
    }

    fn sync_rules(&mut self) -> anyhow::Result<()> {
        {
            let mut s = self.shared.sensor.lock().unwrap();
            s.block = NetSet::from_nets(&self.block);
            s.allow = NetSet::from_nets(&self.allow);
        }
        if let Some(pf) = &self.pf {
            pf.sync(&self.block, &self.allow)?;
        }
        Ok(())
    }

    pub fn block(&mut self, net: &IpNet) -> anyhow::Result<()> {
        if self.block.insert(*net) {
            self.sync_rules()?;
        }
        Ok(())
    }

    pub fn unblock(&mut self, net: &IpNet) -> anyhow::Result<()> {
        if self.block.remove(net) {
            self.sync_rules()?;
        }
        Ok(())
    }

    /// Makes the allowlist exactly `want`.
    pub fn sync_allow(&mut self, want: &BTreeSet<IpNet>) -> anyhow::Result<()> {
        if &self.allow != want {
            self.allow = want.clone();
            self.sync_rules()?;
        }
        Ok(())
    }
}

fn nix_if_index(name: &str) -> u32 {
    let Ok(c) = std::ffi::CString::new(name) else {
        return 0;
    };
    // SAFETY: c is NUL-terminated.
    unsafe { libc::if_nametoindex(c.as_ptr()) }
}

fn send_out(shared: &Shared, out: super::sensor::Outbox) {
    if out.is_empty() {
        return;
    }
    let mut lost = (0, 0);
    if !out.probes.is_empty() && shared.probes.try_send(out.probes).is_err() {
        lost.0 += 1;
    }
    if !out.payloads.is_empty() {
        // Payload samples only add names; losing some under load is harmless.
        let _ = shared.payloads.try_send(out.payloads);
    }
    if !out.socks.is_empty() && shared.socks.try_send(out.socks).is_err() {
        lost.1 += 1;
    }
    if lost != (0, 0) {
        let mut s = shared.sensor.lock().unwrap();
        s.global.events_lost += lost.0;
        s.global.sock_events_lost += lost.1;
    }
}

#[allow(clippy::too_many_arguments)]
fn capture(
    shared: Arc<Shared>,
    mut src: Source,
    name: String,
    ifindex: u32,
    if_flags: u32,
    primary: bool,
    flows: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) {
    let dlt = src.dlt();
    if !matches!(
        dlt,
        bpf::DLT_EN10MB | bpf::DLT_NULL | bpf::DLT_LOOP | bpf::DLT_RAW | 101
    ) {
        log::warn!("{name}: link type {dlt} is not parsed; no traffic will be seen there");
    }
    let mut drops_seen = 0;
    let mut checked = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        match src.fill() {
            Ok(false) => {}
            Ok(true) => {
                let out = {
                    let local = shared.local.read().unwrap();
                    let track = flows.load(Ordering::Relaxed);
                    let mut s = shared.sensor.lock().unwrap();
                    src.for_each(|fr| match bpf::l3(dlt, fr.data) {
                        L3::Ip(ip) => {
                            let egress = fr
                                .egress
                                .unwrap_or_else(|| ip_src(ip).is_some_and(|a| local.contains(&a)));
                            s.packet(&Packet {
                                ts_ns: shared.clock.boot_ns_of_unix(fr.ts_unix_ns),
                                ifindex,
                                if_flags,
                                primary,
                                flows: track,
                                egress,
                                pid: fr.pid,
                                comm: fr.comm,
                                retransmit: fr.retransmit,
                                wire_len: fr.wire_len as u64,
                                ip,
                            });
                        }
                        L3::Other if primary && fr.egress != Some(true) => {
                            s.non_ip(fr.wire_len as u64)
                        }
                        L3::Other => {}
                    });
                    s.take_out()
                };
                send_out(&shared, out);
            }
            Err(e) => {
                log::warn!("capture on {name} ended: {e}");
                return;
            }
        }
        if checked.elapsed() >= Duration::from_secs(60) {
            checked = Instant::now();
            if let Source::Device(d) = &src
                && let Some((_, drops)) = d.stats()
                && drops > drops_seen
            {
                log::warn!(
                    "{name}: the kernel dropped {} packets (capture buffer full)",
                    drops - drops_seen
                );
                drops_seen = drops;
            }
        }
    }
}

/// Fills in the process for connects the capture header didn't attribute
/// (the pid/comm the connect tracepoint would have given), from libproc.
fn resolve_owners(rx: std::sync::mpsc::Receiver<Vec<SockEvent>>, tx: mpsc::Sender<Vec<SockEvent>>) {
    let mut ports: HashMap<(u8, u16), u32> = HashMap::new();
    let mut scanned: Option<Instant> = None;
    while let Ok(mut batch) = rx.recv() {
        for ev in batch
            .iter_mut()
            .filter(|e| e.newstate == SYN_SENT && e.pid == 0)
        {
            // Ports are reused quickly; trust a scan for two seconds, rescan at most twice a second.
            let stale = scanned.is_none_or(|t| t.elapsed() > Duration::from_secs(2));
            let mut pid = if stale {
                None
            } else {
                ports.get(&(PROTO_TCP, ev.lport)).copied()
            };
            if pid.is_none() && scanned.is_none_or(|t| t.elapsed() > Duration::from_millis(500)) {
                ports = super::proc::port_owners();
                scanned = Some(Instant::now());
                pid = ports.get(&(PROTO_TCP, ev.lport)).copied();
            }
            if let Some(pid) = pid {
                ev.pid = pid;
                if let Some((name, _)) = super::proc::describe(pid) {
                    let n = name.len().min(15);
                    ev.comm = [0; 16];
                    ev.comm[..n].copy_from_slice(&name.as_bytes()[..n]);
                }
            }
        }
        if tx.blocking_send(batch).is_err() {
            return;
        }
    }
}
