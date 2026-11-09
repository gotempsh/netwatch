//! The eBPF programs of netwatch-ebpf, in userspace. Fed one captured packet
//! at a time, it keeps the same maps (sources, probes, flows, TCP health) and
//! emits the same events (new probes, TCP state changes, payload samples), so
//! everything above the kernel boundary is shared with Linux.
//!
//! - `netwatch` (XDP) becomes [`Sensor::account`]: inbound packets on the
//!   primary interface, per source and per (source, local port).
//! - `nw_flow_in`/`nw_flow_out` (TC) become [`Sensor::flow`]: both directions
//!   on every tracked interface, with the first payload of each direction.
//! - The TCP tracepoints become [`Sensor::tcp`]: state changes read from the
//!   flags on the wire. pid and comm come from the capture header of the
//!   packet that caused them (the SYN a process sent), as `bpf_get_current_*`
//!   give them on Linux.
//!
//! What the wire can't show: retransmits of segments the kernel never sent
//! (the capture header flags our own retransmits), and transitions of sockets
//! without traffic. Owners of those come from the periodic libproc scan.

use std::collections::{BTreeMap, HashMap, HashSet};

use ipnet::IpNet;
use netwatch_common::{
    CFG_ENFORCE, CFG_SAMPLE_DNS, CFG_SAMPLE_TCP, FlowKey, FlowStats, GlobalStats, IF_INVERT,
    INIT_LOCAL, INIT_REMOTE, INIT_UNKNOWN, MAX_FLOWS, MAX_PROBES, MAX_SOURCES, MAX_TCP_HEALTH,
    PAYLOAD_CAP, PL_DNS, PL_TCP_FIRST, PROTO_ICMP, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP,
    PayloadEvent, ProbeEvent, ProbeKey, ProbeStats, SockEvent, SockKey, SrcStats, TcpHealth,
};

use crate::util::net_to_lpm;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// Linux TCP states, as the tracepoint reports them (flows.rs reads these).
pub const ESTABLISHED: u8 = 1;
pub const SYN_SENT: u8 = 2;
pub const SYN_RECV: u8 = 3;
pub const FIN_WAIT1: u8 = 4;
pub const CLOSE: u8 = 7;
pub const CLOSE_WAIT: u8 = 8;
/// Not a kernel state: the connection ended; later packets (retransmitted
/// FINs, TIME_WAIT ACKs) don't start a new one unless they carry a fresh SYN.
const DONE: u8 = 0xff;

/// macOS gives up on a connect after 75 s (net.inet.tcp.keepinit).
const CONNECT_TIMEOUT_NS: u64 = 75_000_000_000;
/// Events queued between drains, like the ring buffers' capacity.
const OUTBOX_MAX: usize = 1 << 16;

/// One captured packet, link-layer header removed.
pub struct Packet<'a> {
    /// Boot-clock nanoseconds (see `BootClock::boot_ns_of_unix`).
    pub ts_ns: u64,
    pub ifindex: u32,
    /// `IfConfig` flags of the interface (IF_INVERT for bridges).
    pub if_flags: u32,
    /// Accounted per source, like the XDP program on `interface`.
    pub primary: bool,
    /// Recorded as flows, like the TC programs on tracked interfaces.
    pub flows: bool,
    /// Transmitted on the interface (egress).
    pub egress: bool,
    /// The sending process, for egress packets the kernel could attribute.
    pub pid: u32,
    pub comm: [u8; 16],
    /// The kernel marked this egress segment as a TCP retransmission.
    pub retransmit: bool,
    /// Frame length on the wire, link header included (what XDP and TC count).
    pub wire_len: u64,
    /// From the IP header on; may be cut at the snap length.
    pub ip: &'a [u8],
}

/// Networks matched as the eBPF LPM tries are: any covering entry matches.
#[derive(Default)]
pub struct NetSet {
    by_len: BTreeMap<u32, HashSet<u128>>,
}

fn mask(a: u128, len: u32) -> u128 {
    if len == 0 {
        0
    } else {
        a & (u128::MAX << (128 - len.min(128)))
    }
}

impl NetSet {
    pub fn from_nets<'a>(nets: impl IntoIterator<Item = &'a IpNet>) -> Self {
        let mut s = Self::default();
        for n in nets {
            s.insert(n);
        }
        s
    }

    pub fn insert(&mut self, net: &IpNet) {
        let (len, data) = net_to_lpm(net);
        self.by_len
            .entry(len)
            .or_default()
            .insert(mask(u128::from_be_bytes(data), len));
    }

    pub fn contains(&self, addr: [u8; 16]) -> bool {
        let a = u128::from_be_bytes(addr);
        self.by_len
            .iter()
            .any(|(len, set)| set.contains(&mask(a, *len)))
    }
}

/// Per-flow TCP lifecycle, read from the flags.
#[derive(Clone, Copy, Default)]
struct Tcp {
    /// 0 = not tracked (the flow started before netwatch saw its handshake).
    state: u8,
    /// Stands in for the kernel socket address the tracepoint reports.
    sk: u64,
    since_ns: u64,
    synack_out: bool,
    fin_out: bool,
    fin_in: bool,
}

pub struct Flow {
    pub st: FlowStats,
    tcp: Tcp,
}

#[derive(Default)]
pub struct Outbox {
    pub probes: Vec<ProbeEvent>,
    pub socks: Vec<SockEvent>,
    pub payloads: Vec<PayloadEvent>,
}

impl Outbox {
    pub fn is_empty(&self) -> bool {
        self.probes.is_empty() && self.socks.is_empty() && self.payloads.is_empty()
    }
}

pub struct Sensor {
    /// `Config::flags` (CFG_*).
    pub flags: u32,
    pub eph: (u16, u16),
    pub sources: HashMap<[u8; 16], SrcStats>,
    pub probes: HashMap<ProbeKey, ProbeStats>,
    pub flows: HashMap<FlowKey, Flow>,
    pub health: HashMap<SockKey, TcpHealth>,
    pub global: GlobalStats,
    pub block: NetSet,
    pub allow: NetSet,
    pub out: Outbox,
    next_sk: u64,
}

struct Ip {
    src: [u8; 16],
    dst: [u8; 16],
    proto: u8,
    ttl: u8,
    /// Offset of the L4 header.
    l4: usize,
    first_fragment: bool,
    /// Bytes after the IP header, according to the header.
    plen: usize,
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn mapped(a: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[10] = 0xff;
    out[11] = 0xff;
    out[12..].copy_from_slice(&a[..4]);
    out
}

fn parse_ip(b: &[u8]) -> Option<Ip> {
    match b.first()? >> 4 {
        4 => {
            let ihl = ((b[0] & 0x0f) as usize) * 4;
            if ihl < 20 || b.len() < 20 {
                return None;
            }
            let tot = be16(b, 2)? as usize;
            Some(Ip {
                src: mapped(&b[12..16]),
                dst: mapped(&b[16..20]),
                proto: b[9],
                ttl: b[8],
                l4: ihl,
                first_fragment: be16(b, 6)? & 0x1fff == 0,
                plen: tot.saturating_sub(ihl),
            })
        }
        6 => {
            if b.len() < 40 {
                return None;
            }
            Some(Ip {
                src: b[8..24].try_into().ok()?,
                dst: b[24..40].try_into().ok()?,
                proto: b[6],
                ttl: b[7],
                l4: 40,
                first_fragment: true,
                plen: be16(b, 4)? as usize,
            })
        }
        _ => None,
    }
}

/// Drops the oldest sixteenth of a full map, as an LRU map would over time.
fn make_room<K: Clone + Eq + std::hash::Hash, V>(
    m: &mut HashMap<K, V>,
    cap: u32,
    last: impl Fn(&V) -> u64,
) {
    if m.len() < cap as usize {
        return;
    }
    let mut ts: Vec<u64> = m.values().map(&last).collect();
    let n = ts.len() / 16;
    let (_, cut, _) = ts.select_nth_unstable(n);
    let cut = *cut;
    m.retain(|_, v| last(v) > cut);
}

impl Sensor {
    pub fn new(eph: (u16, u16)) -> Self {
        Self {
            flags: 0,
            eph,
            sources: HashMap::new(),
            probes: HashMap::new(),
            flows: HashMap::new(),
            health: HashMap::new(),
            global: GlobalStats::default(),
            block: NetSet::default(),
            allow: NetSet::default(),
            out: Outbox::default(),
            next_sk: 0,
        }
    }

    pub fn take_out(&mut self) -> Outbox {
        std::mem::take(&mut self.out)
    }

    /// A frame on the primary interface that isn't IPv4 or IPv6 (ARP, LLDP...).
    pub fn non_ip(&mut self, wire_len: u64) {
        self.global.packets += 1;
        self.global.bytes += wire_len;
        self.global.non_ip += 1;
    }

    pub fn packet(&mut self, p: &Packet) {
        let Some(ip) = parse_ip(p.ip) else {
            if p.primary && !p.egress {
                self.non_ip(p.wire_len);
            }
            return;
        };
        if p.primary && !p.egress {
            self.account(p, &ip);
        }
        if p.flows {
            self.flow(p, &ip);
        }
    }

    // -- XDP: per-source accounting -------------------------------------------

    fn account(&mut self, p: &Packet, ip: &Ip) {
        let now = p.ts_ns;
        let len = p.wire_len;
        self.global.packets += 1;
        self.global.bytes += len;
        let (lo, hi) = self.eph;
        let ephemeral = |port: u16| port >= lo && port <= hi;

        let (mut port, mut tcp_flags, mut syn, mut inbound) = (0u16, 0u8, false, false);
        if ip.first_fragment {
            let l4 = &p.ip[ip.l4.min(p.ip.len())..];
            match ip.proto {
                PROTO_TCP => {
                    port = be16(l4, 2).unwrap_or(0);
                    tcp_flags = l4.get(13).copied().unwrap_or(0);
                    syn = tcp_flags & (TCP_SYN | TCP_ACK) == TCP_SYN;
                    inbound = syn || !ephemeral(port);
                }
                PROTO_UDP => {
                    port = be16(l4, 2).unwrap_or(0);
                    inbound = !ephemeral(port);
                }
                PROTO_ICMP => inbound = l4.first() == Some(&8),
                PROTO_ICMPV6 => inbound = l4.first() == Some(&128),
                _ => {}
            }
        }
        let blocked = self.block.contains(ip.src) && !self.allow.contains(ip.src);

        make_room(&mut self.sources, MAX_SOURCES, |s| s.last_seen_ns);
        let s = self.sources.entry(ip.src).or_insert_with(|| SrcStats {
            first_seen_ns: now,
            ..Default::default()
        });
        s.packets += 1;
        s.bytes += len;
        if inbound {
            s.in_packets += 1;
            s.in_bytes += len;
            s.syn += syn as u64;
            s.udp_in += (ip.proto == PROTO_UDP) as u64;
            s.icmp_in += (ip.proto == PROTO_ICMP || ip.proto == PROTO_ICMPV6) as u64;
        }
        s.blocked += blocked as u64;
        s.last_seen_ns = now;
        // SYNs with IPv4 options are a Linux TCP bug (CVE-2026-98432); macOS
        // doesn't count them, so none of those alerts fire here.

        if blocked {
            self.global.blocked += 1;
            if self.flags & CFG_ENFORCE != 0 {
                // pf drops it after the capture tap, as XDP_DROP would.
                self.global.dropped += 1;
                return;
            }
        }
        if !inbound {
            return;
        }
        self.global.in_packets += 1;
        self.global.syn += syn as u64;
        let key = ProbeKey {
            addr: ip.src,
            port,
            proto: ip.proto,
            _pad: 0,
        };
        if let Some(pr) = self.probes.get_mut(&key) {
            pr.packets += 1;
            pr.bytes += len;
            pr.syn += syn as u64;
            pr.last_seen_ns = now;
            return;
        }
        make_room(&mut self.probes, MAX_PROBES, |p| p.last_seen_ns);
        self.probes.insert(
            key,
            ProbeStats {
                packets: 1,
                bytes: len,
                syn: syn as u64,
                first_seen_ns: now,
                last_seen_ns: now,
            },
        );
        if self.out.probes.len() >= OUTBOX_MAX {
            self.global.events_lost += 1;
            return;
        }
        self.out.probes.push(ProbeEvent {
            addr: ip.src,
            dst: ip.dst,
            ts_ns: now,
            port,
            proto: ip.proto,
            tcp_flags,
            ttl: ip.ttl,
            _pad: [0; 3],
        });
    }

    // -- TC: flows --------------------------------------------------------------

    fn flow(&mut self, p: &Packet, ip: &Ip) {
        let now = p.ts_ns;
        let len = p.wire_len;
        // On a bridge the local side is the VM: what the bridge transmits goes to it.
        let out = p.egress != (p.if_flags & IF_INVERT != 0);

        let (mut sport, mut dport, mut tcp_flags) = (0u16, 0u16, 0u8);
        let (mut pl_off, mut pl_len) = (0usize, 0usize);
        if ip.first_fragment && (ip.proto == PROTO_TCP || ip.proto == PROTO_UDP) {
            let l4 = ip.l4;
            let (Some(s), Some(d)) = (be16(p.ip, l4), be16(p.ip, l4 + 2)) else {
                return;
            };
            (sport, dport) = (s, d);
            if ip.proto == PROTO_TCP {
                let doff = p.ip.get(l4 + 12).copied().unwrap_or(0x50);
                tcp_flags = p.ip.get(l4 + 13).copied().unwrap_or(0);
                let hdr = ((doff >> 4) as usize) * 4;
                pl_off = l4 + hdr;
                pl_len = ip.plen.saturating_sub(hdr);
            } else {
                pl_off = l4 + 8;
                pl_len = (be16(p.ip, l4 + 4).unwrap_or(0) as usize).saturating_sub(8);
            }
        }
        let key = if out {
            FlowKey {
                local: ip.src,
                remote: ip.dst,
                ifindex: p.ifindex,
                lport: sport,
                rport: dport,
                proto: ip.proto,
                _pad: [0; 3],
            }
        } else {
            FlowKey {
                local: ip.dst,
                remote: ip.src,
                ifindex: p.ifindex,
                lport: dport,
                rport: sport,
                proto: ip.proto,
                _pad: [0; 3],
            }
        };
        let dns = ip.proto == PROTO_UDP
            && (sport == 53 || dport == 53)
            && self.flags & CFG_SAMPLE_DNS != 0;

        if !self.flows.contains_key(&key) {
            make_room(&mut self.flows, MAX_FLOWS, |f| f.st.last_seen_ns);
            let initiator = if ip.proto == PROTO_TCP {
                match tcp_flags & (TCP_SYN | TCP_ACK) {
                    TCP_SYN if out => INIT_LOCAL,
                    TCP_SYN => INIT_REMOTE,
                    // Saw the SYN-ACK first: the other side opened it.
                    x if x == TCP_SYN | TCP_ACK && out => INIT_REMOTE,
                    x if x == TCP_SYN | TCP_ACK => INIT_LOCAL,
                    // Mid-stream: started before netwatch.
                    _ => INIT_UNKNOWN,
                }
            } else if out {
                INIT_LOCAL
            } else {
                INIT_REMOTE
            };
            let mut st = FlowStats {
                first_seen_ns: now,
                last_seen_ns: now,
                initiator,
                ..Default::default()
            };
            if out {
                st.pkts_out = 1;
                st.bytes_out = len;
                st.flags_out = tcp_flags;
            } else {
                st.pkts_in = 1;
                st.bytes_in = len;
                st.flags_in = tcp_flags;
            }
            self.flows.insert(
                key,
                Flow {
                    st,
                    tcp: Tcp::default(),
                },
            );
            // The first packet carries no payload worth sampling unless it is DNS
            // (a SYN has none; TCP payload needs the handshake to have been seen).
            if dns {
                self.sample(p, &key, out, PL_DNS, pl_off, pl_len);
            }
        } else {
            let f = self.flows.get_mut(&key).expect("present");
            if out {
                f.st.pkts_out += 1;
                f.st.bytes_out += len;
                f.st.flags_out |= tcp_flags;
            } else {
                f.st.pkts_in += 1;
                f.st.bytes_in += len;
                f.st.flags_in |= tcp_flags;
            }
            f.st.last_seen_ns = now;
            let bit = if out { 2 } else { 1 };
            if ip.proto == PROTO_TCP
                && pl_len > 0
                && self.flags & CFG_SAMPLE_TCP != 0
                && f.st.initiator != INIT_UNKNOWN
                && f.st.sampled & bit == 0
            {
                f.st.sampled |= bit;
                self.sample(p, &key, out, PL_TCP_FIRST, pl_off, pl_len);
            }
            if dns {
                self.sample(p, &key, out, PL_DNS, pl_off, pl_len);
            }
        }
        // Bridged VMs have their own TCP stacks; the tracepoints see only ours.
        if ip.proto == PROTO_TCP && ip.first_fragment && p.if_flags & IF_INVERT == 0 {
            self.tcp(p, &key, out, tcp_flags);
        }
    }

    fn sample(&mut self, p: &Packet, key: &FlowKey, out: bool, kind: u8, off: usize, plen: usize) {
        let avail = p.ip.len().saturating_sub(off);
        let n = plen.min(avail).min(PAYLOAD_CAP);
        if n == 0 || self.out.payloads.len() >= OUTBOX_MAX {
            return;
        }
        let mut data = [0u8; PAYLOAD_CAP];
        data[..n].copy_from_slice(&p.ip[off..off + n]);
        self.out.payloads.push(PayloadEvent {
            ts_ns: p.ts_ns,
            key: *key,
            out: out as u8,
            kind,
            len: plen.min(u16::MAX as usize) as u16,
            caplen: n as u16,
            _pad: [0; 6],
            data,
        });
    }

    // -- Tracepoints: TCP lifecycle and health ------------------------------------

    fn tcp(&mut self, p: &Packet, key: &FlowKey, out: bool, flags: u8) {
        let sk_key = SockKey {
            local: key.local,
            remote: key.remote,
            lport: key.lport,
            rport: key.rport,
            _pad: 0,
        };
        let rst = flags & TCP_RST != 0;
        let syn = flags & TCP_SYN != 0;
        let ack = flags & TCP_ACK != 0;
        let fin = flags & TCP_FIN != 0;

        if (out && p.retransmit) || rst {
            make_room(&mut self.health, MAX_TCP_HEALTH, |h| h.last_ns);
            let h = self.health.entry(sk_key).or_default();
            if out && p.retransmit {
                h.retrans += 1;
            }
            if rst {
                if out {
                    h.rst_sent += 1
                } else {
                    h.rst_recv += 1
                }
            }
            h.last_ns = p.ts_ns;
        }

        let Some(t) = self.flows.get(key).map(|f| f.tcp) else {
            return;
        };
        let mut t = t;
        let mut emit: Vec<(u8, u8)> = Vec::new();
        match t.state {
            // A fresh SYN starts a connection, also on a 4-tuple that was used before.
            0 | DONE if syn && !ack => {
                self.next_sk += 1;
                t = Tcp {
                    sk: self.next_sk,
                    since_ns: p.ts_ns,
                    ..Default::default()
                };
                if out {
                    t.state = SYN_SENT;
                    emit.push((CLOSE, SYN_SENT));
                } else {
                    t.state = SYN_RECV;
                }
            }
            SYN_SENT if !out && syn && ack => {
                t.state = ESTABLISHED;
                emit.push((SYN_SENT, ESTABLISHED));
            }
            SYN_SENT if !out && rst => {
                t.state = DONE;
                emit.push((SYN_SENT, CLOSE));
            }
            SYN_RECV if out && syn && ack => t.synack_out = true,
            SYN_RECV if !out && ack && !syn && !rst && t.synack_out => {
                t.state = ESTABLISHED;
                emit.push((SYN_RECV, ESTABLISHED));
            }
            // A refused or abandoned handshake never became a socket.
            SYN_RECV if rst => t.state = DONE,
            ESTABLISHED | FIN_WAIT1 | CLOSE_WAIT if rst => {
                emit.push((t.state, CLOSE));
                t.state = DONE;
            }
            ESTABLISHED | FIN_WAIT1 | CLOSE_WAIT if fin => {
                if out {
                    t.fin_out = true
                } else {
                    t.fin_in = true
                }
                if t.fin_out && t.fin_in {
                    emit.push((t.state, CLOSE));
                    t.state = DONE;
                } else if t.state == ESTABLISHED {
                    let next = if out { FIN_WAIT1 } else { CLOSE_WAIT };
                    emit.push((ESTABLISHED, next));
                    t.state = next;
                }
            }
            _ => {}
        }
        if let Some(f) = self.flows.get_mut(key) {
            f.tcp = t;
        }
        for (old, new) in emit {
            // pid/comm only mean something for the transition the process caused.
            let (pid, comm) = if new == SYN_SENT {
                (p.pid, p.comm)
            } else {
                (0, [0; 16])
            };
            self.sock_event(p.ts_ns, t.sk, &sk_key, old, new, pid, comm);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn sock_event(
        &mut self,
        ts_ns: u64,
        sk: u64,
        k: &SockKey,
        oldstate: u8,
        newstate: u8,
        pid: u32,
        comm: [u8; 16],
    ) {
        if self.out.socks.len() >= OUTBOX_MAX {
            self.global.sock_events_lost += 1;
            return;
        }
        self.out.socks.push(SockEvent {
            ts_ns,
            skaddr: sk,
            local: k.local,
            remote: k.remote,
            comm,
            pid,
            lport: k.lport,
            rport: k.rport,
            oldstate,
            newstate,
            _pad: [0; 6],
        });
    }

    /// Connects nobody answered: the kernel gives up after 75 s, so does this.
    pub fn housekeep(&mut self, now_ns: u64) {
        let mut timed_out = Vec::new();
        for (k, f) in self.flows.iter_mut() {
            if f.tcp.state == SYN_SENT && now_ns.saturating_sub(f.tcp.since_ns) > CONNECT_TIMEOUT_NS
            {
                f.tcp.state = DONE;
                timed_out.push((*k, f.tcp.sk));
            }
        }
        for (k, sk) in timed_out {
            let sk_key = SockKey {
                local: k.local,
                remote: k.remote,
                lport: k.lport,
                rport: k.rport,
                _pad: 0,
            };
            self.sock_event(now_ns, sk, &sk_key, SYN_SENT, CLOSE, 0, [0; 16]);
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const ME: [u8; 4] = [192, 168, 1, 20];
    pub const THEM: [u8; 4] = [203, 0, 113, 7];

    /// An IPv4 TCP segment with `payload`.
    pub fn tcp4(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let tot = 20 + 20 + payload.len();
        let mut b = vec![0u8; tot];
        b[0] = 0x45;
        b[2..4].copy_from_slice(&(tot as u16).to_be_bytes());
        b[8] = 64;
        b[9] = PROTO_TCP;
        b[12..16].copy_from_slice(&src);
        b[16..20].copy_from_slice(&dst);
        b[20..22].copy_from_slice(&sport.to_be_bytes());
        b[22..24].copy_from_slice(&dport.to_be_bytes());
        b[32] = 0x50;
        b[33] = flags;
        b[40..].copy_from_slice(payload);
        b
    }

    pub fn udp4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let tot = 20 + 8 + payload.len();
        let mut b = vec![0u8; tot];
        b[0] = 0x45;
        b[2..4].copy_from_slice(&(tot as u16).to_be_bytes());
        b[8] = 64;
        b[9] = PROTO_UDP;
        b[12..16].copy_from_slice(&src);
        b[16..20].copy_from_slice(&dst);
        b[20..22].copy_from_slice(&sport.to_be_bytes());
        b[22..24].copy_from_slice(&dport.to_be_bytes());
        b[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        b[28..].copy_from_slice(payload);
        b
    }

    fn pkt(ip: &[u8], egress: bool, ts_ns: u64) -> Packet<'_> {
        Packet {
            ts_ns,
            ifindex: 4,
            if_flags: 0,
            primary: true,
            flows: true,
            egress,
            pid: if egress { 4242 } else { 0 },
            comm: *b"curl\0\0\0\0\0\0\0\0\0\0\0\0",
            retransmit: false,
            wire_len: ip.len() as u64 + 14,
            ip,
        }
    }

    fn sensor() -> Sensor {
        let mut s = Sensor::new((49152, 65535));
        s.flags = CFG_SAMPLE_DNS | CFG_SAMPLE_TCP;
        s
    }

    #[test]
    fn inbound_scan_counts_sources_and_new_probes() {
        let mut s = sensor();
        for (i, port) in [22u16, 23, 3389, 22].iter().enumerate() {
            s.packet(&pkt(
                &tcp4(THEM, ME, 40000, *port, TCP_SYN, b""),
                false,
                i as u64,
            ));
        }
        let src = s.sources[&mapped(&THEM)];
        assert_eq!((src.packets, src.in_packets, src.syn), (4, 4, 4));
        assert_eq!(s.probes.len(), 3);
        let ports: Vec<u16> = s.take_out().probes.iter().map(|e| e.port).collect();
        assert_eq!(ports, [22, 23, 3389]);
        assert_eq!((s.global.in_packets, s.global.syn), (4, 4));
    }

    #[test]
    fn replies_to_our_connections_are_not_inbound() {
        let mut s = sensor();
        // SYN-ACK to an ephemeral port: an answer to a connect from here.
        s.packet(&pkt(
            &tcp4(THEM, ME, 443, 51000, TCP_SYN | TCP_ACK, b""),
            false,
            1,
        ));
        let src = s.sources[&mapped(&THEM)];
        assert_eq!((src.packets, src.in_packets), (1, 0));
        assert!(s.probes.is_empty());
        // Egress is never per-source accounting (XDP sees ingress only).
        s.packet(&pkt(&tcp4(ME, THEM, 51000, 443, TCP_ACK, b""), true, 2));
        assert_eq!(s.sources.len(), 1);
    }

    #[test]
    fn outbound_connect_lifecycle_with_owner_and_first_payload() {
        let mut s = sensor();
        let hello = b"GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n";
        s.packet(&pkt(
            &tcp4(ME, THEM, 51000, 80, TCP_SYN, b""),
            true,
            1_000_000,
        ));
        s.packet(&pkt(
            &tcp4(THEM, ME, 80, 51000, TCP_SYN | TCP_ACK, b""),
            false,
            21_000_000,
        ));
        s.packet(&pkt(
            &tcp4(ME, THEM, 51000, 80, TCP_ACK, hello),
            true,
            22_000_000,
        ));
        s.packet(&pkt(
            &tcp4(ME, THEM, 51000, 80, TCP_ACK, hello),
            true,
            23_000_000,
        ));
        s.packet(&pkt(
            &tcp4(ME, THEM, 51000, 80, TCP_FIN | TCP_ACK, b""),
            true,
            30_000_000,
        ));
        s.packet(&pkt(
            &tcp4(THEM, ME, 80, 51000, TCP_FIN | TCP_ACK, b""),
            false,
            31_000_000,
        ));
        let out = s.take_out();
        let states: Vec<(u8, u8)> = out.socks.iter().map(|e| (e.oldstate, e.newstate)).collect();
        assert_eq!(
            states,
            [
                (CLOSE, SYN_SENT),
                (SYN_SENT, ESTABLISHED),
                (ESTABLISHED, FIN_WAIT1),
                (FIN_WAIT1, CLOSE)
            ]
        );
        assert_eq!(
            (out.socks[0].pid, &out.socks[0].comm[..4]),
            (4242, &b"curl"[..])
        );
        assert_eq!(out.socks[1].pid, 0);
        assert!(out.socks.iter().all(|e| e.skaddr == out.socks[0].skaddr));
        assert_eq!(out.socks[1].ts_ns - out.socks[0].ts_ns, 20_000_000);
        // Only the first payload of the direction is sampled.
        assert_eq!(out.payloads.len(), 1);
        assert_eq!(
            &out.payloads[0].data[..out.payloads[0].caplen as usize],
            hello
        );
        let key = FlowKey {
            local: mapped(&ME),
            remote: mapped(&THEM),
            ifindex: 4,
            lport: 51000,
            rport: 80,
            proto: PROTO_TCP,
            _pad: [0; 3],
        };
        let f = &s.flows[&key].st;
        assert_eq!(
            (f.initiator, f.pkts_out, f.pkts_in, f.sampled),
            (INIT_LOCAL, 4, 2, 2)
        );
    }

    #[test]
    fn refused_and_unanswered_connects_close() {
        let mut s = sensor();
        s.packet(&pkt(&tcp4(ME, THEM, 51001, 5432, TCP_SYN, b""), true, 1));
        s.packet(&pkt(
            &tcp4(THEM, ME, 5432, 51001, TCP_RST | TCP_ACK, b""),
            false,
            2,
        ));
        s.packet(&pkt(&tcp4(ME, THEM, 51002, 6379, TCP_SYN, b""), true, 3));
        s.housekeep(3 + CONNECT_TIMEOUT_NS + 1);
        let states: Vec<(u16, u8, u8)> = s
            .take_out()
            .socks
            .iter()
            .map(|e| (e.rport, e.oldstate, e.newstate))
            .collect();
        assert_eq!(
            states,
            [
                (5432, CLOSE, SYN_SENT),
                (5432, SYN_SENT, CLOSE),
                (6379, CLOSE, SYN_SENT),
                (6379, SYN_SENT, CLOSE)
            ]
        );
        let h = s.health.values().next().unwrap();
        assert_eq!((h.rst_recv, h.rst_sent), (1, 0));
    }

    #[test]
    fn accepted_connection_and_inbound_request_sample() {
        let mut s = sensor();
        let req = b"GET /${jndi:ldap://x/a} HTTP/1.1\r\n\r\n";
        s.packet(&pkt(&tcp4(THEM, ME, 40000, 80, TCP_SYN, b""), false, 1));
        s.packet(&pkt(
            &tcp4(ME, THEM, 80, 40000, TCP_SYN | TCP_ACK, b""),
            true,
            2,
        ));
        s.packet(&pkt(&tcp4(THEM, ME, 40000, 80, TCP_ACK, b""), false, 3));
        s.packet(&pkt(&tcp4(THEM, ME, 40000, 80, TCP_ACK, req), false, 4));
        let out = s.take_out();
        let states: Vec<(u8, u8)> = out.socks.iter().map(|e| (e.oldstate, e.newstate)).collect();
        assert_eq!(states, [(SYN_RECV, ESTABLISHED)]);
        assert_eq!((out.payloads.len(), out.payloads[0].out), (1, 0));
    }

    #[test]
    fn mid_stream_flows_are_not_sampled_or_tracked() {
        let mut s = sensor();
        s.packet(&pkt(&tcp4(ME, THEM, 51003, 443, TCP_ACK, b"data"), true, 1));
        s.packet(&pkt(
            &tcp4(ME, THEM, 51003, 443, TCP_ACK | TCP_FIN, b"more"),
            true,
            2,
        ));
        let out = s.take_out();
        assert!(out.socks.is_empty() && out.payloads.is_empty());
    }

    #[test]
    fn dns_is_sampled_in_both_directions() {
        let mut s = sensor();
        s.packet(&pkt(&udp4(ME, [1, 1, 1, 1], 53000, 53, b"query"), true, 1));
        s.packet(&pkt(
            &udp4([1, 1, 1, 1], ME, 53, 53000, b"answer"),
            false,
            2,
        ));
        let p = s.take_out().payloads;
        assert_eq!(
            p.iter().map(|e| (e.kind, e.out)).collect::<Vec<_>>(),
            [(PL_DNS, 1), (PL_DNS, 0)]
        );
    }

    #[test]
    fn bans_count_and_enforced_bans_stop_probe_records() {
        let mut s = sensor();
        s.block = NetSet::from_nets(&["203.0.113.0/24".parse().unwrap()]);
        s.allow = NetSet::from_nets(&["203.0.113.9/32".parse().unwrap()]);
        s.packet(&pkt(&tcp4(THEM, ME, 40000, 22, TCP_SYN, b""), false, 1));
        assert_eq!(
            (s.global.blocked, s.global.dropped, s.probes.len()),
            (1, 0, 1)
        );
        s.flags |= CFG_ENFORCE;
        s.packet(&pkt(&tcp4(THEM, ME, 40000, 23, TCP_SYN, b""), false, 2));
        assert_eq!(
            (s.global.blocked, s.global.dropped, s.probes.len()),
            (2, 1, 1)
        );
        // The allowlist wins, as in the XDP program.
        s.packet(&pkt(
            &tcp4([203, 0, 113, 9], ME, 40000, 22, TCP_SYN, b""),
            false,
            3,
        ));
        assert_eq!(s.global.blocked, 2);
    }

    #[test]
    fn netset_matches_covering_prefixes() {
        let s = NetSet::from_nets(&[
            "10.0.0.0/8".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ]);
        assert!(s.contains(mapped(&[10, 9, 8, 7])));
        assert!(!s.contains(mapped(&[11, 0, 0, 1])));
        assert!(
            s.contains(
                "2001:db8::1"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
            )
        );
    }

    #[test]
    fn retransmits_are_counted_from_the_capture_flag() {
        let mut s = sensor();
        let ip = tcp4(ME, THEM, 51004, 443, TCP_ACK, b"x");
        let mut p = pkt(&ip, true, 1);
        p.retransmit = true;
        s.packet(&p);
        assert_eq!(s.health.values().next().unwrap().retrans, 1);
    }

    #[test]
    fn full_maps_drop_the_oldest_entries() {
        let mut m: HashMap<u32, u64> = (0..32).map(|i| (i, i as u64)).collect();
        make_room(&mut m, 32, |v| *v);
        assert_eq!(m.len(), 29);
        assert!(!m.contains_key(&0) && m.contains_key(&31));
    }
}
