#![no_std]
#![no_main]
// The BPF target has no `AtomicU64::fetch_add`; the intrinsic lowers to BPF_ATOMIC add.
#![allow(internal_features)]
#![feature(core_intrinsics)]

use core::{
    intrinsics::{AtomicOrdering, atomic_xadd},
    mem,
    ptr::{addr_of_mut, read_unaligned},
};

use aya_ebpf::{
    bindings::{BPF_NOEXIST, xdp_action},
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_boot_ns, bpf_skb_load_bytes,
    },
    macros::{classifier, map, tracepoint, xdp},
    maps::{Array, HashMap, LpmTrie, LruHashMap, PerCpuArray, RingBuf, lpm_trie::Key},
    programs::{TcContext, TracePointContext, XdpContext},
};
use netwatch_common::*;

#[map]
static SOURCES: LruHashMap<[u8; 16], SrcStats> = LruHashMap::with_max_entries(MAX_SOURCES, 0);
#[map]
static PROBES: LruHashMap<ProbeKey, ProbeStats> = LruHashMap::with_max_entries(MAX_PROBES, 0);
#[map]
static ALLOW: LpmTrie<[u8; 16], u32> = LpmTrie::with_max_entries(MAX_RULES, 0);
#[map]
static BLOCK: LpmTrie<[u8; 16], u32> = LpmTrie::with_max_entries(MAX_RULES, 0);
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(EVENTS_BYTES, 0);
#[map]
static GLOBAL: PerCpuArray<GlobalStats> = PerCpuArray::with_max_entries(1, 0);
#[map]
static CONFIG: Array<Config> = Array::with_max_entries(1, 0);
#[map]
static FLOWS: LruHashMap<FlowKey, FlowStats> = LruHashMap::with_max_entries(MAX_FLOWS, 0);
#[map]
static IFACES: HashMap<u32, IfConfig> = HashMap::with_max_entries(MAX_IFACES, 0);
#[map]
static TCP_HEALTH: LruHashMap<SockKey, TcpHealth> = LruHashMap::with_max_entries(MAX_TCP_HEALTH, 0);
#[map]
static SOCK_EVENTS: RingBuf = RingBuf::with_byte_size(SOCK_EVENTS_BYTES, 0);
#[map]
static TP_LAYOUT: Array<TpLayout> = Array::with_max_entries(TP_COUNT, 0);
#[map]
static PAYLOADS: RingBuf = RingBuf::with_byte_size(PAYLOAD_EVENTS_BYTES, 0);

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88a8;

const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
/// TCX_NEXT / TC_ACT_UNSPEC: observe only, let the packet continue.
const TC_NEXT: i32 = -1;

#[xdp]
pub fn netwatch(ctx: XdpContext) -> u32 {
    // Fail open: a parsing problem must never drop traffic.
    try_netwatch(&ctx).unwrap_or(xdp_action::XDP_PASS)
}

#[inline(always)]
fn read<T: Copy>(ctx: &XdpContext, off: usize) -> Result<T, ()> {
    let start = ctx.data();
    if start + off + mem::size_of::<T>() > ctx.data_end() {
        return Err(());
    }
    Ok(unsafe { read_unaligned((start + off) as *const T) })
}

#[inline(always)]
fn be16(ctx: &XdpContext, off: usize) -> Result<u16, ()> {
    read::<u16>(ctx, off).map(u16::from_be)
}

/// Two adjacent bytes. Single-byte reads at variable offsets get their bounds
/// check rewritten by LLVM (`p + 1 > end` into `end > p`), which the verifier
/// can't use, so byte fields are always read in pairs.
#[inline(always)]
fn pair(ctx: &XdpContext, off: usize) -> Result<(u8, u8), ()> {
    read::<[u8; 2]>(ctx, off).map(|b| (b[0], b[1]))
}

#[inline(always)]
fn add(field: *mut u64, n: u64) {
    unsafe { atomic_xadd::<u64, u64, { AtomicOrdering::Relaxed }>(field, n) };
}

struct Pkt {
    src: [u8; 16],
    dst: [u8; 16],
    len: u64,
    proto: u8,
    ttl: u8,
    port: u16,
    tcp_flags: u8,
    syn: bool,
    inbound: bool,
    /// IPv4 header longer than 20 bytes: the packet carries IP options.
    ipopts: bool,
    /// `IPOPT_*` for the first option.
    ipopt_kind: u64,
}

fn try_netwatch(ctx: &XdpContext) -> Result<u32, ()> {
    let now = unsafe { bpf_ktime_get_boot_ns() };
    let len = (ctx.data_end() - ctx.data()) as u64;

    let g = GLOBAL.get_ptr_mut(0).ok_or(())?;
    unsafe {
        (*g).packets += 1;
        (*g).bytes += len;
    }

    let mut off = 14usize;
    let mut ethertype = be16(ctx, 12)?;
    if ethertype == ETH_P_8021Q || ethertype == ETH_P_8021AD {
        ethertype = be16(ctx, 16)?;
        off = 18;
    }

    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    let proto: u8;
    let ttl: u8;
    let l4: usize;
    let mut first_fragment = true;
    let mut ipopt_kind = 0u64;

    match ethertype {
        ETH_P_IP => {
            let (ver_ihl, _tos) = pair(ctx, off)?;
            let ihl = ((ver_ihl & 0x0f) as usize) * 4;
            if ihl < 20 {
                return Ok(xdp_action::XDP_PASS);
            }
            first_fragment = be16(ctx, off + 6)? & 0x1fff == 0;
            (ttl, proto) = pair(ctx, off + 8)?;
            let s: [u8; 4] = read(ctx, off + 12)?;
            let d: [u8; 4] = read(ctx, off + 16)?;
            src[10] = 0xff;
            src[11] = 0xff;
            dst[10] = 0xff;
            dst[11] = 0xff;
            src[12] = s[0];
            src[13] = s[1];
            src[14] = s[2];
            src[15] = s[3];
            dst[12] = d[0];
            dst[13] = d[1];
            dst[14] = d[2];
            dst[15] = d[3];
            l4 = off + ihl;
            if ihl > 20 {
                // Only the first option is classified; a leading NOP is rare enough not to walk past.
                ipopt_kind = match pair(ctx, off + 20)?.0 {
                    7 => IPOPT_RR,
                    68 => IPOPT_TS,
                    _ => IPOPT_OTHER,
                };
            }
        }
        ETH_P_IPV6 => {
            // Extension headers are not walked; such packets count as "other".
            (proto, ttl) = pair(ctx, off + 6)?;
            src = read(ctx, off + 8)?;
            dst = read(ctx, off + 24)?;
            l4 = off + 40;
        }
        _ => {
            unsafe { (*g).non_ip += 1 };
            return Ok(xdp_action::XDP_PASS);
        }
    }

    let (eph_lo, eph_hi, enforce, drop_ipopt_syn) = match CONFIG.get(0) {
        Some(c) if c.eph_lo != 0 => (
            c.eph_lo,
            c.eph_hi,
            c.flags & CFG_ENFORCE != 0,
            c.flags & CFG_DROP_IPOPT_SYN != 0,
        ),
        _ => (32768, 60999, false, false),
    };
    let ephemeral = |p: u16| p >= eph_lo && p <= eph_hi;

    let mut pkt = Pkt {
        src,
        dst,
        len,
        proto,
        ttl,
        port: 0,
        tcp_flags: 0,
        syn: false,
        inbound: false,
        ipopts: ipopt_kind != 0,
        ipopt_kind,
    };
    if first_fragment {
        match proto {
            PROTO_TCP => {
                pkt.port = be16(ctx, l4 + 2)?;
                pkt.tcp_flags = pair(ctx, l4 + 12)?.1;
                pkt.syn = pkt.tcp_flags & (TCP_SYN | TCP_ACK) == TCP_SYN;
                pkt.inbound = pkt.syn || !ephemeral(pkt.port);
            }
            PROTO_UDP => {
                pkt.port = be16(ctx, l4 + 2)?;
                pkt.inbound = !ephemeral(pkt.port);
            }
            // Echo requests only; echo replies and errors answer our own traffic.
            PROTO_ICMP => pkt.inbound = pair(ctx, l4)?.0 == 8,
            PROTO_ICMPV6 => pkt.inbound = pair(ctx, l4)?.0 == 128,
            _ => {}
        }
    }

    let key = Key::new(128, pkt.src);
    let blocked = BLOCK.get(&key).is_some() && ALLOW.get(&key).is_none();

    record_source(&pkt, blocked, now);
    if pkt.syn && pkt.ipopts {
        unsafe { (*g).ipopt_syn += 1 };
        // The kernel bug fires during the handshake, before any application sees the
        // connection, so this is dropped regardless of the allowlist.
        if drop_ipopt_syn {
            unsafe { (*g).ipopt_dropped += 1 };
            return Ok(xdp_action::XDP_DROP);
        }
    }
    if blocked {
        unsafe { (*g).blocked += 1 };
        if enforce {
            unsafe { (*g).dropped += 1 };
            return Ok(xdp_action::XDP_DROP);
        }
    }
    if pkt.inbound {
        unsafe { (*g).in_packets += 1 };
        if pkt.syn {
            unsafe { (*g).syn += 1 };
        }
        record_probe(&pkt, now, g);
    }
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn record_source(pkt: &Pkt, blocked: bool, now: u64) {
    let in_n = pkt.inbound as u64;
    let udp = (pkt.inbound && pkt.proto == PROTO_UDP) as u64;
    let icmp = (pkt.inbound && (pkt.proto == PROTO_ICMP || pkt.proto == PROTO_ICMPV6)) as u64;
    let ipopt_syn = (pkt.syn && pkt.ipopts) as u64;
    for _ in 0..2 {
        if let Some(s) = SOURCES.get_ptr_mut(&pkt.src) {
            unsafe {
                add(addr_of_mut!((*s).packets), 1);
                add(addr_of_mut!((*s).bytes), pkt.len);
                if pkt.inbound {
                    add(addr_of_mut!((*s).in_packets), 1);
                    add(addr_of_mut!((*s).in_bytes), pkt.len);
                    add(addr_of_mut!((*s).syn), pkt.syn as u64);
                    add(addr_of_mut!((*s).udp_in), udp);
                    add(addr_of_mut!((*s).icmp_in), icmp);
                }
                if blocked {
                    add(addr_of_mut!((*s).blocked), 1);
                }
                if ipopt_syn != 0 {
                    add(addr_of_mut!((*s).ipopt_syn), 1);
                    // A lost race only loses a kind bit; the count is atomic.
                    (*s).ipopt_kinds |= pkt.ipopt_kind;
                }
                (*s).last_seen_ns = now;
            }
            return;
        }
        let init = SrcStats {
            packets: 1,
            bytes: pkt.len,
            in_packets: in_n,
            in_bytes: pkt.len * in_n,
            syn: pkt.syn as u64,
            udp_in: udp,
            icmp_in: icmp,
            blocked: blocked as u64,
            ipopt_syn,
            ipopt_kinds: if ipopt_syn != 0 { pkt.ipopt_kind } else { 0 },
            first_seen_ns: now,
            last_seen_ns: now,
        };
        // Lost the insert race against another CPU: loop once and add instead.
        if SOURCES.insert(&pkt.src, &init, BPF_NOEXIST as u64).is_ok() {
            return;
        }
    }
}

#[inline(always)]
fn record_probe(pkt: &Pkt, now: u64, g: *mut GlobalStats) {
    let key = ProbeKey {
        addr: pkt.src,
        port: pkt.port,
        proto: pkt.proto,
        _pad: 0,
    };
    for _ in 0..2 {
        if let Some(p) = PROBES.get_ptr_mut(&key) {
            unsafe {
                add(addr_of_mut!((*p).packets), 1);
                add(addr_of_mut!((*p).bytes), pkt.len);
                add(addr_of_mut!((*p).syn), pkt.syn as u64);
                (*p).last_seen_ns = now;
            }
            return;
        }
        let init = ProbeStats {
            packets: 1,
            bytes: pkt.len,
            syn: pkt.syn as u64,
            first_seen_ns: now,
            last_seen_ns: now,
        };
        if PROBES.insert(&key, &init, BPF_NOEXIST as u64).is_ok() {
            match EVENTS.reserve::<ProbeEvent>(0) {
                Some(mut e) => {
                    e.write(ProbeEvent {
                        addr: pkt.src,
                        dst: pkt.dst,
                        ts_ns: now,
                        port: pkt.port,
                        proto: pkt.proto,
                        tcp_flags: pkt.tcp_flags,
                        ttl: pkt.ttl,
                        _pad: [0; 3],
                    });
                    e.submit(0);
                }
                None => unsafe { (*g).events_lost += 1 },
            }
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Flows: TC on ingress and egress of every monitored interface.

#[classifier]
pub fn nw_flow_in(ctx: TcContext) -> i32 {
    let _ = record_flow(&ctx, false);
    TC_NEXT
}

#[classifier]
pub fn nw_flow_out(ctx: TcContext) -> i32 {
    let _ = record_flow(&ctx, true);
    TC_NEXT
}

#[inline(always)]
fn ld<T>(ctx: &TcContext, off: usize) -> Result<T, ()> {
    ctx.load::<T>(off).map_err(|_| ())
}

#[inline(always)]
fn mapped(a: [u8; 4]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[10] = 0xff;
    out[11] = 0xff;
    out[12] = a[0];
    out[13] = a[1];
    out[14] = a[2];
    out[15] = a[3];
    out
}

fn record_flow(ctx: &TcContext, egress: bool) -> Result<(), ()> {
    let now = unsafe { bpf_ktime_get_boot_ns() };
    let skb = ctx.skb.skb;
    let (ifindex, len, segs) =
        unsafe { ((*skb).ifindex, (*skb).len as u64, (*skb).gso_segs as u64) };
    // GSO/GRO skbs carry several wire packets.
    let pkts = if segs > 1 { segs } else { 1 };
    let flags = unsafe { IFACES.get(&ifindex) }.map_or(0, |c| c.flags);
    let out = egress != (flags & IF_INVERT != 0);

    let mut off = 0usize;
    let ver: u8 = if flags & IF_RAW_IP != 0 {
        ld::<u8>(ctx, 0)? >> 4
    } else {
        let mut et = u16::from_be(ld::<u16>(ctx, 12)?);
        off = 14;
        if et == ETH_P_8021Q || et == ETH_P_8021AD {
            et = u16::from_be(ld::<u16>(ctx, 16)?);
            off = 18;
        }
        match et {
            ETH_P_IP => 4,
            ETH_P_IPV6 => 6,
            _ => return Ok(()),
        }
    };

    // ip_plen: bytes after the IP header, per the header (GSO skbs may say more).
    let (src, dst, proto, l4, first_fragment, ip_plen) = match ver {
        4 => {
            let ihl = ((ld::<u8>(ctx, off)? & 0x0f) as usize) * 4;
            if ihl < 20 {
                return Ok(());
            }
            let tot = u16::from_be(ld::<u16>(ctx, off + 2)?) as usize;
            let frag = u16::from_be(ld::<u16>(ctx, off + 6)?) & 0x1fff;
            let proto = ld::<u8>(ctx, off + 9)?;
            let s = mapped(ld::<[u8; 4]>(ctx, off + 12)?);
            let d = mapped(ld::<[u8; 4]>(ctx, off + 16)?);
            (s, d, proto, off + ihl, frag == 0, tot.saturating_sub(ihl))
        }
        6 => {
            let plen = u16::from_be(ld::<u16>(ctx, off + 4)?) as usize;
            let proto = ld::<u8>(ctx, off + 6)?;
            (
                ld::<[u8; 16]>(ctx, off + 8)?,
                ld::<[u8; 16]>(ctx, off + 24)?,
                proto,
                off + 40,
                true,
                plen,
            )
        }
        _ => return Ok(()),
    };

    // Where the L4 payload starts and how long it is.
    let (mut sport, mut dport, mut tcp_flags) = (0u16, 0u16, 0u8);
    let (mut pl_off, mut pl_len) = (0usize, 0usize);
    if first_fragment && (proto == PROTO_TCP || proto == PROTO_UDP) {
        sport = u16::from_be(ld::<u16>(ctx, l4)?);
        dport = u16::from_be(ld::<u16>(ctx, l4 + 2)?);
        if proto == PROTO_TCP {
            let [doff, flags] = ld::<[u8; 2]>(ctx, l4 + 12)?;
            tcp_flags = flags;
            let hdr = ((doff >> 4) as usize) * 4;
            pl_off = l4 + hdr;
            pl_len = ip_plen.saturating_sub(hdr);
        } else {
            pl_off = l4 + 8;
            pl_len = (u16::from_be(ld::<u16>(ctx, l4 + 4)?) as usize).saturating_sub(8);
        }
    }
    let sample_flags = CONFIG.get(0).map_or(0, |c| c.flags);

    let key = if out {
        FlowKey {
            local: src,
            remote: dst,
            ifindex,
            lport: sport,
            rport: dport,
            proto,
            _pad: [0; 3],
        }
    } else {
        FlowKey {
            local: dst,
            remote: src,
            ifindex,
            lport: dport,
            rport: sport,
            proto,
            _pad: [0; 3],
        }
    };

    for _ in 0..2 {
        if let Some(f) = FLOWS.get_ptr_mut(&key) {
            unsafe {
                if out {
                    add(addr_of_mut!((*f).pkts_out), pkts);
                    add(addr_of_mut!((*f).bytes_out), len);
                    (*f).flags_out |= tcp_flags;
                } else {
                    add(addr_of_mut!((*f).pkts_in), pkts);
                    add(addr_of_mut!((*f).bytes_in), len);
                    (*f).flags_in |= tcp_flags;
                }
                (*f).last_seen_ns = now;
                // First payload in each direction of a connection whose start we saw.
                let bit = if out { 2 } else { 1 };
                if proto == PROTO_TCP
                    && pl_len > 0
                    && sample_flags & CFG_SAMPLE_TCP != 0
                    && (*f).initiator != INIT_UNKNOWN
                    && (*f).sampled & bit == 0
                {
                    (*f).sampled |= bit;
                    sample(ctx, &key, out, PL_TCP_FIRST, pl_off, pl_len, now);
                }
            }
            if proto == PROTO_UDP
                && (sport == 53 || dport == 53)
                && sample_flags & CFG_SAMPLE_DNS != 0
            {
                sample(ctx, &key, out, PL_DNS, pl_off, pl_len, now);
            }
            return Ok(());
        }
        let initiator = if proto == PROTO_TCP {
            match tcp_flags & (TCP_SYN | TCP_ACK) {
                TCP_SYN if out => INIT_LOCAL,
                TCP_SYN => INIT_REMOTE,
                // Saw the SYN-ACK first: the other side opened it.
                x if x == TCP_SYN | TCP_ACK && out => INIT_REMOTE,
                x if x == TCP_SYN | TCP_ACK => INIT_LOCAL,
                // Mid-stream (started before netwatch, or the entry was recycled).
                _ => INIT_UNKNOWN,
            }
        } else if out {
            INIT_LOCAL
        } else {
            INIT_REMOTE
        };
        let mut init = FlowStats {
            first_seen_ns: now,
            last_seen_ns: now,
            initiator,
            ..Default::default()
        };
        if out {
            init.pkts_out = pkts;
            init.bytes_out = len;
            init.flags_out = tcp_flags;
        } else {
            init.pkts_in = pkts;
            init.bytes_in = len;
            init.flags_in = tcp_flags;
        }
        if FLOWS.insert(&key, &init, BPF_NOEXIST as u64).is_ok() {
            if proto == PROTO_UDP
                && (sport == 53 || dport == 53)
                && sample_flags & CFG_SAMPLE_DNS != 0
            {
                sample(ctx, &key, out, PL_DNS, pl_off, pl_len, now);
            }
            return Ok(());
        }
    }
    Ok(())
}

/// Copies up to PAYLOAD_CAP bytes of payload into the ring buffer.
#[inline(always)]
fn sample(ctx: &TcContext, key: &FlowKey, out: bool, kind: u8, off: usize, plen: usize, now: u64) {
    let avail = (ctx.len() as usize).saturating_sub(off);
    let n = if plen < avail { plen } else { avail };
    let n = if n < PAYLOAD_CAP { n } else { PAYLOAD_CAP };
    if n == 0 {
        return;
    }
    // Same value for n in 1..=PAYLOAD_CAP, but provably in range for the verifier.
    let n = ((n - 1) & (PAYLOAD_CAP - 1)) + 1;
    let Some(mut e) = PAYLOADS.reserve::<PayloadEvent>(0) else {
        return;
    };
    let p = e.as_mut_ptr();
    let ok = unsafe {
        (*p).ts_ns = now;
        (*p).key = *key;
        (*p).out = out as u8;
        (*p).kind = kind;
        (*p).len = plen as u16;
        (*p).caplen = n as u16;
        bpf_skb_load_bytes(
            ctx.skb.skb as *const _,
            off as u32,
            (*p).data.as_mut_ptr() as *mut _,
            n as u32,
        ) == 0
    };
    if ok {
        e.submit(0);
    } else {
        e.discard(0);
    }
}

// ---------------------------------------------------------------------------
// TCP lifecycle and health: tracepoints, with field offsets from userspace.

#[inline(always)]
fn tp_read<T>(ctx: &TracePointContext, off: u16) -> Result<T, ()> {
    if off == TP_NONE {
        return Err(());
    }
    unsafe { ctx.read_at::<T>(off as usize) }.map_err(|_| ())
}

/// (local, remote, lport, rport). Every TCP tracepoint reports the socket's
/// own address as "saddr", including resets sent without a socket.
#[inline(always)]
fn tp_addrs(ctx: &TracePointContext, l: &TpLayout) -> Result<([u8; 16], [u8; 16], u16, u16), ()> {
    if l.kind == TP_KIND_SOCKADDR {
        let fam = tp_read::<u16>(ctx, l.saddr)?;
        let sport = u16::from_be(tp_read::<u16>(ctx, l.saddr + 2)?);
        let dport = u16::from_be(tp_read::<u16>(ctx, l.daddr + 2)?);
        match fam {
            AF_INET => Ok((
                mapped(tp_read::<[u8; 4]>(ctx, l.saddr + 4)?),
                mapped(tp_read::<[u8; 4]>(ctx, l.daddr + 4)?),
                sport,
                dport,
            )),
            AF_INET6 => Ok((
                tp_read(ctx, l.saddr + 8)?,
                tp_read(ctx, l.daddr + 8)?,
                sport,
                dport,
            )),
            _ => Err(()),
        }
    } else {
        let fam = tp_read::<u16>(ctx, l.family)?;
        let sport = tp_read::<u16>(ctx, l.sport)?;
        let dport = tp_read::<u16>(ctx, l.dport)?;
        match fam {
            AF_INET => Ok((
                mapped(tp_read::<[u8; 4]>(ctx, l.saddr)?),
                mapped(tp_read::<[u8; 4]>(ctx, l.daddr)?),
                sport,
                dport,
            )),
            AF_INET6 => Ok((
                tp_read(ctx, l.saddr_v6)?,
                tp_read(ctx, l.daddr_v6)?,
                sport,
                dport,
            )),
            _ => Err(()),
        }
    }
}

#[inline(always)]
fn layout(i: u32) -> Result<&'static TpLayout, ()> {
    match TP_LAYOUT.get(i) {
        Some(l) if l.valid == 1 => Ok(l),
        _ => Err(()),
    }
}

#[tracepoint]
pub fn nw_sock_state(ctx: TracePointContext) -> u32 {
    let _ = sock_state(&ctx);
    0
}

fn sock_state(ctx: &TracePointContext) -> Result<(), ()> {
    let l = layout(TP_SET_STATE)?;
    if l.protocol != TP_NONE && tp_read::<u16>(ctx, l.protocol)? != PROTO_TCP as u16 {
        return Ok(());
    }
    let (local, remote, lport, rport) = tp_addrs(ctx, l)?;
    let oldstate = tp_read::<i32>(ctx, l.oldstate)? as u8;
    let newstate = tp_read::<i32>(ctx, l.newstate)? as u8;
    let skaddr = tp_read::<u64>(ctx, l.skaddr).unwrap_or(0);
    match SOCK_EVENTS.reserve::<SockEvent>(0) {
        Some(mut e) => {
            e.write(SockEvent {
                ts_ns: unsafe { bpf_ktime_get_boot_ns() },
                skaddr,
                local,
                remote,
                comm: bpf_get_current_comm().unwrap_or([0; 16]),
                pid: (bpf_get_current_pid_tgid() >> 32) as u32,
                lport,
                rport,
                oldstate,
                newstate,
                _pad: [0; 6],
            });
            e.submit(0);
        }
        None => {
            if let Some(g) = GLOBAL.get_ptr_mut(0) {
                unsafe { (*g).sock_events_lost += 1 };
            }
        }
    }
    Ok(())
}

#[tracepoint]
pub fn nw_tcp_retransmit(ctx: TracePointContext) -> u32 {
    let _ = tcp_health(&ctx, TP_RETRANSMIT);
    0
}

#[tracepoint]
pub fn nw_tcp_send_reset(ctx: TracePointContext) -> u32 {
    let _ = tcp_health(&ctx, TP_SEND_RESET);
    0
}

#[tracepoint]
pub fn nw_tcp_recv_reset(ctx: TracePointContext) -> u32 {
    let _ = tcp_health(&ctx, TP_RECV_RESET);
    0
}

fn tcp_health(ctx: &TracePointContext, which: u32) -> Result<(), ()> {
    let l = layout(which)?;
    let (local, remote, lport, rport) = tp_addrs(ctx, l)?;
    let key = SockKey {
        local,
        remote,
        lport,
        rport,
        _pad: 0,
    };
    let now = unsafe { bpf_ktime_get_boot_ns() };
    for _ in 0..2 {
        if let Some(h) = TCP_HEALTH.get_ptr_mut(&key) {
            unsafe {
                match which {
                    TP_RETRANSMIT => add(addr_of_mut!((*h).retrans), 1),
                    TP_SEND_RESET => add(addr_of_mut!((*h).rst_sent), 1),
                    _ => add(addr_of_mut!((*h).rst_recv), 1),
                }
                (*h).last_ns = now;
            }
            return Ok(());
        }
        let init = TcpHealth {
            retrans: (which == TP_RETRANSMIT) as u64,
            rst_sent: (which == TP_SEND_RESET) as u64,
            rst_recv: (which == TP_RECV_RESET) as u64,
            last_ns: now,
        };
        if TCP_HEALTH.insert(&key, &init, BPF_NOEXIST as u64).is_ok() {
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
