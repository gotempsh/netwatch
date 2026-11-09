#![no_std]

//! Types shared between the XDP program and the userspace daemon.
//!
//! Every address is stored as a 16-byte IPv6 address; IPv4 uses the
//! IPv4-mapped form (`::ffff:a.b.c.d`) so both families share one set of maps.

/// Max distinct source addresses tracked at once (LRU evicts the oldest).
pub const MAX_SOURCES: u32 = 131_072;
/// Max distinct (source, port, protocol) tuples tracked at once.
pub const MAX_PROBES: u32 = 262_144;
/// Max entries in the allow and block LPM tries.
pub const MAX_RULES: u32 = 65_536;
/// Ring buffer size for new-probe events.
pub const EVENTS_BYTES: u32 = 4 * 1024 * 1024;
/// Max concurrent flows (both directions, every monitored interface).
/// Userspace deletes idle entries, so this only has to hold the active set.
pub const MAX_FLOWS: u32 = 131_072;
/// Max TCP connections with retransmit/reset counters.
pub const MAX_TCP_HEALTH: u32 = 65_536;
/// Max interfaces with flow programs attached.
pub const MAX_IFACES: u32 = 64;
/// Ring buffer size for TCP state-change events.
pub const SOCK_EVENTS_BYTES: u32 = 2 * 1024 * 1024;

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

/// `Config::flags`: actually drop blocklisted traffic (otherwise only count it).
pub const CFG_ENFORCE: u32 = 1 << 0;
/// Copy DNS packets (UDP port 53) to userspace for name resolution.
pub const CFG_SAMPLE_DNS: u32 = 1 << 1;
/// Copy the first payload packet of each TCP direction (TLS SNI, HTTP Host, SSH banners).
pub const CFG_SAMPLE_TCP: u32 = 1 << 2;
/// Drop IPv4 TCP SYNs that carry IP options (the CVE-2026-98432 trigger).
pub const CFG_DROP_IPOPT_SYN: u32 = 1 << 3;

/// `SrcStats::ipopt_kinds`: the first IPv4 option in a SYN, by type.
pub const IPOPT_RR: u64 = 1 << 0;
pub const IPOPT_TS: u64 = 1 << 1;
pub const IPOPT_OTHER: u64 = 1 << 2;

/// Ring buffer size for payload samples.
pub const PAYLOAD_EVENTS_BYTES: u32 = 8 * 1024 * 1024;
/// Bytes of payload copied per sample.
pub const PAYLOAD_CAP: usize = 1024;
/// `PayloadEvent::kind`.
pub const PL_DNS: u8 = 1;
pub const PL_TCP_FIRST: u8 = 2;

/// Per-source counters. "Inbound" means traffic initiated by the remote side:
/// TCP SYNs, anything to a non-ephemeral local port, and ICMP echo requests.
/// Everything else (replies to connections this host opened) only lands in
/// `packets`/`bytes`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SrcStats {
    pub packets: u64,
    pub bytes: u64,
    pub in_packets: u64,
    pub in_bytes: u64,
    /// TCP SYN without ACK: new connection attempts.
    pub syn: u64,
    pub udp_in: u64,
    pub icmp_in: u64,
    /// Packets that hit the blocklist (dropped when enforcing).
    pub blocked: u64,
    /// IPv4 TCP SYNs with IP options. Almost no legitimate client sends them;
    /// they trigger CVE-2026-98432 in unpatched kernels.
    pub ipopt_syn: u64,
    /// OR of `IPOPT_*` over those SYNs.
    pub ipopt_kinds: u64,
    /// `bpf_ktime_get_boot_ns` timestamps.
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
}

/// One remote address talking to one local port.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ProbeKey {
    pub addr: [u8; 16],
    /// Local destination port in host byte order (0 for ICMP).
    pub port: u16,
    pub proto: u8,
    pub _pad: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ProbeStats {
    pub packets: u64,
    pub bytes: u64,
    pub syn: u64,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
}

/// Emitted once per new `ProbeKey`, so userspace sees scans in real time
/// without a per-packet event stream.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ProbeEvent {
    pub addr: [u8; 16],
    pub dst: [u8; 16],
    pub ts_ns: u64,
    pub port: u16,
    pub proto: u8,
    pub tcp_flags: u8,
    pub ttl: u8,
    pub _pad: [u8; 3],
}

/// Whole-interface counters, kept per CPU.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct GlobalStats {
    pub packets: u64,
    pub bytes: u64,
    pub in_packets: u64,
    pub syn: u64,
    pub blocked: u64,
    pub dropped: u64,
    pub events_lost: u64,
    pub non_ip: u64,
    /// TCP state events dropped because the ring buffer was full.
    pub sock_events_lost: u64,
    /// IPv4 TCP SYNs with IP options, and how many of them were dropped.
    pub ipopt_syn: u64,
    pub ipopt_dropped: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Config {
    pub flags: u32,
    /// Local ephemeral port range; traffic to these ports is treated as replies.
    pub eph_lo: u16,
    pub eph_hi: u16,
}

/// `IfConfig::flags`: the device has no link-layer header (tun, WireGuard, Tailscale).
pub const IF_RAW_IP: u32 = 1 << 0;
/// The device faces local containers (a bridge): its ingress comes from the
/// local side, so "local" is the packet source instead of the destination.
pub const IF_INVERT: u32 = 1 << 1;

/// Per-interface settings for the flow programs, keyed by ifindex.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct IfConfig {
    pub flags: u32,
    pub _pad: u32,
}

/// `FlowStats::initiator`.
pub const INIT_UNKNOWN: u8 = 0;
/// The remote side opened it (first SYN or first packet arrived from outside).
pub const INIT_REMOTE: u8 = 1;
/// This host (or a local container) opened it.
pub const INIT_LOCAL: u8 = 2;

/// One conversation seen on one interface, oriented local/remote.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub local: [u8; 16],
    pub remote: [u8; 16],
    pub ifindex: u32,
    /// Host byte order; ICMP uses 0/0.
    pub lport: u16,
    pub rport: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FlowStats {
    pub pkts_in: u64,
    pub bytes_in: u64,
    pub pkts_out: u64,
    pub bytes_out: u64,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    /// OR of every TCP flag byte seen in each direction.
    pub flags_in: u8,
    pub flags_out: u8,
    pub initiator: u8,
    /// Bit 0: inbound payload sampled; bit 1: outbound.
    pub sampled: u8,
    pub _pad: [u8; 4],
}

/// The start of a packet's L4 payload, for metadata parsing in userspace.
/// Only parsed fields (names, versions) are kept; raw bytes are never stored.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PayloadEvent {
    pub ts_ns: u64,
    pub key: FlowKey,
    /// 1 when the packet left this side (local -> remote).
    pub out: u8,
    pub kind: u8,
    /// Payload length according to the headers.
    pub len: u16,
    /// Bytes actually copied into `data`.
    pub caplen: u16,
    pub _pad: [u8; 6],
    pub data: [u8; PAYLOAD_CAP],
}

/// A TCP connection from the socket's point of view (local = this host).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SockKey {
    pub local: [u8; 16],
    pub remote: [u8; 16],
    pub lport: u16,
    pub rport: u16,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpHealth {
    pub retrans: u64,
    pub rst_sent: u64,
    pub rst_recv: u64,
    pub last_ns: u64,
}

/// A TCP state transition (`sock:inet_sock_set_state`). `pid`/`comm` are only
/// meaningful for transitions made in syscall context: CLOSE->SYN_SENT
/// (connect) and CLOSE->LISTEN (listen).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SockEvent {
    pub ts_ns: u64,
    pub skaddr: u64,
    pub local: [u8; 16],
    pub remote: [u8; 16],
    pub comm: [u8; 16],
    pub pid: u32,
    pub lport: u16,
    pub rport: u16,
    pub oldstate: u8,
    pub newstate: u8,
    pub _pad: [u8; 6],
}

/// Tracepoint indices in the `TP_LAYOUT` map.
pub const TP_SET_STATE: u32 = 0;
pub const TP_RETRANSMIT: u32 = 1;
pub const TP_SEND_RESET: u32 = 2;
pub const TP_RECV_RESET: u32 = 3;
pub const TP_COUNT: u32 = 4;
/// Field not present in this kernel's tracepoint.
pub const TP_NONE: u16 = 0xffff;
/// `TpLayout::kind`: separate sport/dport/family/saddr/daddr fields.
pub const TP_KIND_FIELDS: u16 = 0;
/// `TpLayout::kind`: saddr/daddr are 28-byte sockaddr_in/sockaddr_in6 unions.
pub const TP_KIND_SOCKADDR: u16 = 1;

/// Byte offsets of tracepoint fields, read by userspace from tracefs so the
/// programs work across kernel versions.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TpLayout {
    pub kind: u16,
    pub skaddr: u16,
    pub oldstate: u16,
    pub newstate: u16,
    pub protocol: u16,
    pub sport: u16,
    pub dport: u16,
    pub family: u16,
    pub saddr: u16,
    pub daddr: u16,
    pub saddr_v6: u16,
    pub daddr_v6: u16,
    /// 1 once userspace filled it in.
    pub valid: u16,
}

impl Default for TpLayout {
    fn default() -> Self {
        Self {
            kind: TP_KIND_FIELDS,
            skaddr: TP_NONE,
            oldstate: TP_NONE,
            newstate: TP_NONE,
            protocol: TP_NONE,
            sport: TP_NONE,
            dport: TP_NONE,
            family: TP_NONE,
            saddr: TP_NONE,
            daddr: TP_NONE,
            saddr_v6: TP_NONE,
            daddr_v6: TP_NONE,
            valid: 0,
        }
    }
}

#[cfg(feature = "user")]
mod user {
    use super::*;
    unsafe impl aya::Pod for SrcStats {}
    unsafe impl aya::Pod for ProbeKey {}
    unsafe impl aya::Pod for ProbeStats {}
    unsafe impl aya::Pod for ProbeEvent {}
    unsafe impl aya::Pod for GlobalStats {}
    unsafe impl aya::Pod for Config {}
    unsafe impl aya::Pod for IfConfig {}
    unsafe impl aya::Pod for FlowKey {}
    unsafe impl aya::Pod for FlowStats {}
    unsafe impl aya::Pod for SockKey {}
    unsafe impl aya::Pod for TcpHealth {}
    unsafe impl aya::Pod for SockEvent {}
    unsafe impl aya::Pod for TpLayout {}
    unsafe impl aya::Pod for PayloadEvent {}
}
