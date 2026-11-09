//! Connection-level view. Joins the kernel flow table (TC, both directions,
//! every monitored interface) with TCP lifecycle tracepoints, socket owners
//! from /proc, DNS answers and first-payload metadata into one record per
//! conversation. Finished flows are handed to the store.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    net::IpAddr,
};

use netwatch_common::{
    FlowKey, FlowStats, INIT_LOCAL, INIT_REMOTE, PL_DNS, PL_TCP_FIRST, PROTO_TCP, PROTO_UDP,
    PayloadEvent, SockEvent, SockKey, TcpHealth,
};
use serde::Serialize;

use crate::{
    dissect::{self, AppMeta, DnsData, DnsMsg},
    procs::{Owner, OwnerCache, Scan},
    util::{BootClock, key_to_ip},
};

// Linux TCP states (include/net/tcp_states.h).
const ESTABLISHED: u8 = 1;
const SYN_SENT: u8 = 2;
const SYN_RECV: u8 = 3;
const CLOSE: u8 = 7;
const LISTEN: u8 = 10;

/// A new UDP socket gets this long to show what it is (a resolver socket is
/// bound before its first query is sent) before it is announced as a listener.
const UDP_SETTLE_SECS: i64 = 10;
/// A DNS query seen before the /proc scan listed its socket stays usable for
/// this long: a little over the 15 s scan interval.
const DNS_SEEN_TTL: i64 = 20;
/// A direction learned from DNS for a flow the kernel table hasn't listed yet.
const DNS_FLOW_TTL: i64 = 30;

const TCP_FIN: u8 = 0x01;
const TCP_RST: u8 = 0x04;

pub fn tcp_state_name(s: u8) -> &'static str {
    match s {
        1 => "established",
        2 => "syn_sent",
        3 => "syn_recv",
        4 => "fin_wait1",
        5 => "fin_wait2",
        6 => "time_wait",
        7 => "closed",
        8 => "close_wait",
        9 => "last_ack",
        10 => "listen",
        11 => "closing",
        12 => "new_syn_recv",
        _ => "unknown",
    }
}

/// Who opened the conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Dir {
    /// The remote side connected to us.
    In,
    /// This host (or a local container) connected out.
    Out,
    Unknown,
}

impl Dir {
    pub fn as_str(self) -> &'static str {
        match self {
            Dir::In => "in",
            Dir::Out => "out",
            Dir::Unknown => "unknown",
        }
    }
}

pub struct Flow {
    pub key: FlowKey,
    pub iface: String,
    pub local: IpAddr,
    pub remote: IpAddr,
    pub dir: Dir,
    pub first_seen: i64,
    pub last_seen: i64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub pkts_in: u64,
    pub pkts_out: u64,
    /// Bytes per second over the last tick.
    pub rate_in: f64,
    pub rate_out: f64,
    pub flags_in: u8,
    pub flags_out: u8,
    /// TCP state from the tracepoints, when this host owns the socket.
    pub tcp_state: Option<u8>,
    pub connect_ms: Option<f64>,
    pub failed: bool,
    pub retrans: u64,
    pub rst_sent: u64,
    pub rst_recv: u64,
    pub owner: Option<Owner>,
    /// The process on the remote end, when that end is on this host too (a
    /// container, or a host process such as docker-proxy).
    pub peer: Option<Owner>,
    /// DNS name the remote address was resolved from, kept once seen: the
    /// lookup may expire before a long flow ends.
    pub name: Option<String>,
    pub app: AppMeta,
    /// Kernel counters at the last tick; the kernel entry may be recycled.
    k: FlowStats,
    /// The request was handed to the engine already.
    noted: bool,
}

/// What a remote client sent to one of this host's services (once per connection).
#[derive(Debug, Clone)]
pub struct InboundRequest {
    pub ts: i64,
    pub remote: IpAddr,
    pub port: u16,
    /// "POST example.com/" or "raw payload".
    pub what: String,
    /// Who accepted the connection (container, unit or process), when known.
    pub served_by: Option<String>,
    pub exploit: Option<&'static crate::exploits::Signature>,
    /// Reported by temps over its socket (see temps.rs), not sampled off the wire.
    pub via_temps: bool,
}

impl Flow {
    fn take_request(&mut self, now: i64) -> Option<InboundRequest> {
        if self.noted
            || self.dir != Dir::In
            || (self.app.http_method.is_none() && self.app.exploit_sig.is_none())
        {
            return None;
        }
        self.noted = true;
        let what = match (&self.app.http_method, &self.app.http_path) {
            (Some(m), Some(p)) => format!("{m} {}{p}", self.app.http_host.as_deref().unwrap_or("")),
            _ => "raw payload".into(),
        };
        let served_by = self.owner.as_ref().map(|o| {
            o.container
                .clone()
                .or_else(|| o.unit.clone())
                .unwrap_or_else(|| o.comm.clone())
        });
        Some(InboundRequest {
            ts: now,
            remote: key_to_ip(self.key.remote),
            port: self.key.lport,
            what,
            served_by,
            exploit: self.app.exploit_sig,
            via_temps: false,
        })
    }

    pub fn closed(&self) -> bool {
        self.failed
            || self.tcp_state == Some(CLOSE)
            || (self.flags_in | self.flags_out) & TCP_RST != 0
            || (self.flags_in & TCP_FIN != 0 && self.flags_out & TCP_FIN != 0)
    }

    pub fn state(&self) -> String {
        if self.key.proto != PROTO_TCP {
            return "active".into();
        }
        if self.failed {
            return "failed".into();
        }
        if self.closed() {
            return "closed".into();
        }
        match self.tcp_state {
            Some(s) => tcp_state_name(s).into(),
            None => "established".into(),
        }
    }

    /// The port that identifies the service (the side that was connected to).
    pub fn service_port(&self) -> u16 {
        match self.dir {
            Dir::In => self.key.lport,
            _ => self.key.rport,
        }
    }
}

/// What a UDP socket is used for, from what netwatch has observed. A bound,
/// unconnected UDP socket is both a service and a resolver's source port until
/// traffic says which.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SockRole {
    /// Not enough evidence: treated like a service (listed, announced, alertable).
    Unknown,
    /// Sent DNS queries as a client.
    Client,
    /// Accepts traffic: TCP listen(), or UDP seen receiving DNS queries or answering them.
    Server,
}

impl SockRole {
    pub fn as_str(self) -> &'static str {
        match self {
            SockRole::Unknown => "unknown",
            SockRole::Client => "client",
            SockRole::Server => "server",
        }
    }
}

/// One bound UDP address of a [`Listener`] and what has been seen from it.
#[derive(Debug, Clone)]
struct UdpSock {
    /// Socket inodes bound here. A scan that finds none of them again is looking
    /// at a new socket (port or pid reuse), which starts without evidence.
    inodes: BTreeSet<u64>,
    role: SockRole,
    reason: String,
}

impl UdpSock {
    fn new(inodes: BTreeSet<u64>) -> Self {
        Self {
            inodes,
            role: SockRole::Unknown,
            reason: String::new(),
        }
    }

    /// Server evidence beats client evidence: a socket answering queries is a
    /// service even if it also forwards some. Nothing is downgraded, and the
    /// first reason for a role is the one kept.
    fn note(&mut self, role: SockRole, reason: String) {
        if self.role == SockRole::Unknown
            || (role == SockRole::Server && self.role == SockRole::Client)
        {
            self.role = role;
            self.reason = reason;
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Listener {
    pub proto: &'static str,
    pub port: u16,
    pub addrs: BTreeSet<IpAddr>,
    pub owner: Option<Owner>,
    /// Owner per bound address: 0.0.0.0:8081 and 203.0.113.1:8081 can be different programs.
    #[serde(skip)]
    pub by_addr: BTreeMap<IpAddr, Owner>,
    pub since: i64,
    /// Bound to something other than loopback.
    pub exposed: bool,
    /// The port is inside the kernel's automatic source-port range
    /// (`ip_local_port_range`). Informational only: resolvers pick source ports
    /// outside it, and services run inside it, so this says nothing about
    /// client or server. See `role`.
    pub ephemeral: bool,
    /// Client or server, from observed traffic (all TCP listeners are servers).
    pub role: SockRole,
    /// Why `role` is what it is, in words.
    pub role_reason: String,
    /// UDP sockets by bound address.
    #[serde(skip)]
    socks: BTreeMap<IpAddr, UdpSock>,
    /// The `listen` event went out (or the socket predates netwatch).
    #[serde(skip)]
    announced: bool,
}

impl Listener {
    fn new(proto: u8, port: u16, owner: Option<Owner>, since: i64, eph: (u16, u16)) -> Self {
        Self {
            proto: proto_label(proto),
            port,
            addrs: BTreeSet::new(),
            owner,
            by_addr: BTreeMap::new(),
            since,
            exposed: false,
            ephemeral: proto == PROTO_UDP && port >= eph.0 && port <= eph.1,
            role: if proto == PROTO_TCP {
                SockRole::Server
            } else {
                SockRole::Unknown
            },
            role_reason: if proto == PROTO_TCP {
                "accepts TCP connections".into()
            } else {
                String::new()
            },
            socks: BTreeMap::new(),
            announced: false,
        }
    }

    /// The bound socket that sends from `local`: the exact bind, else the
    /// same-family wildcard, else (IPv4) a dual-stack `::`, most specific first as in the kernel.
    fn sock_for(&self, local: IpAddr) -> Option<IpAddr> {
        let any4 = IpAddr::from([0u8; 4]);
        let any6 = IpAddr::from([0u16; 8]);
        let wildcard = if local.is_ipv4() { any4 } else { any6 };
        [local, wildcard, any6]
            .into_iter()
            .find(|a| self.socks.contains_key(a))
    }

    /// Recomputes `role` from the sockets: any server makes the port a server;
    /// it is a client only when every socket on it is.
    fn refresh_role(&mut self) {
        if self.proto == "tcp" {
            return;
        }
        let server = self.socks.values().find(|s| s.role == SockRole::Server);
        let all_clients =
            !self.socks.is_empty() && self.socks.values().all(|s| s.role == SockRole::Client);
        (self.role, self.role_reason) = match (server, self.socks.values().next()) {
            (Some(s), _) => (SockRole::Server, s.reason.clone()),
            (None, Some(s)) if all_clients => (SockRole::Client, s.reason.clone()),
            _ => (
                SockRole::Unknown,
                "no DNS client or server traffic seen".into(),
            ),
        };
    }

    /// Whether the `listen` event should go out now. A UDP socket waits out the
    /// settle time for evidence that it is a client.
    fn announce_due(&self, now: i64) -> bool {
        match (self.proto, self.role) {
            ("tcp", _) | (_, SockRole::Server) => true,
            (_, SockRole::Client) => false,
            (_, SockRole::Unknown) => now - self.since >= UDP_SETTLE_SECS,
        }
    }

    /// Who receives connections to `local`: the exact bind wins over the wildcard, as in the kernel.
    pub fn owner_for(&self, local: IpAddr) -> Option<&Owner> {
        if self.addrs.contains(&local) {
            return self.by_addr.get(&local);
        }
        let any = if local.is_ipv4() {
            IpAddr::from([0u8; 4])
        } else {
            IpAddr::from([0u16; 8])
        };
        self.by_addr
            .get(&local)
            .or_else(|| self.by_addr.get(&any))
            .or_else(|| self.by_addr.get(&IpAddr::from([0u16; 8])))
            .or(self.owner.as_ref())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnEvent {
    pub ts: i64,
    /// connect_failed, listen, unlisten
    pub kind: &'static str,
    pub proto: &'static str,
    pub local: String,
    pub lport: u16,
    pub remote: Option<String>,
    pub rport: Option<u16>,
    pub owner: Option<Owner>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsRecord {
    pub ts: i64,
    pub iface: String,
    pub client: String,
    pub server: String,
    /// out: this host asked; in: someone asked this host.
    pub dir: &'static str,
    pub qname: String,
    pub qtype: String,
    pub rcode: String,
    pub answers: Vec<String>,
    pub latency_ms: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct FlowMinute {
    pub ts: i64,
    pub new_in: u64,
    pub new_out: u64,
    pub failed: u64,
    pub dns: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

struct Pending {
    owner: Option<Owner>,
    ts_ns: u64,
    ts: i64,
    /// Socket in a namespace that is neither the host's nor a container's.
    foreign: bool,
}

/// Where a socket lives. The tracepoints fire for every network namespace, but
/// only the host's and its containers' sockets are this host's traffic; others
/// (`ip netns`, test harnesses) would show up as phantom connects and listeners.
#[derive(PartialEq)]
enum Ns {
    Host,
    Container,
    Foreign,
}

#[derive(Default)]
struct SockInfo {
    owner: Option<Owner>,
    state: u8,
    connect_ms: Option<f64>,
    failed: bool,
    last: i64,
}

struct DnsPending {
    ts: i64,
    ts_ns: u64,
    iface: String,
    client: IpAddr,
    server: IpAddr,
    out: bool,
    qname: String,
    qtype: u16,
}

/// An outbound DNS query from a local port that no scanned socket owned yet.
struct DnsSeen {
    local: IpAddr,
    remote: IpAddr,
    rport: u16,
    ts: i64,
}

/// What is known about a UDP flow beyond its packets.
#[derive(Clone, Copy, Default)]
struct UdpHint {
    /// Direction implied by a DNS query on the flow (or a DNS answer we sent).
    dns: Option<Dir>,
    /// The local socket has been seen serving DNS.
    server: bool,
}

pub struct FlowTable {
    pub active: HashMap<FlowKey, Flow>,
    pub listeners: HashMap<(u8, u16), Listener>,
    pub events: VecDeque<ConnEvent>,
    pub dns_log: VecDeque<DnsRecord>,
    pub series: VecDeque<FlowMinute>,
    pub ifnames: HashMap<u32, String>,
    /// Address -> name it was resolved from, until the answer's TTL (min 10 min).
    pub names: HashMap<IpAddr, (String, i64)>,
    pub owners: OwnerCache,
    /// Addresses configured in the host namespace, for events without a pid.
    pub host_addrs: HashSet<IpAddr>,
    pub host_netns: Option<u64>,
    eph: (u16, u16),
    by_sk: HashMap<u64, Pending>,
    socks: HashMap<SockKey, SockInfo>,
    proc_conn: HashMap<(u8, SockKey), Owner>,
    container_ips: HashMap<IpAddr, Owner>,
    scanned_once: bool,
    pending_app: HashMap<FlowKey, Vec<(bool, Vec<u8>)>>,
    /// Inbound requests for the engine, drained every tick.
    pub requests: Vec<InboundRequest>,
    dns_pending: HashMap<(FlowKey, u16), DnsPending>,
    /// Direction from DNS payloads for flows the kernel snapshot hasn't listed yet.
    dns_flow: HashMap<FlowKey, (Dir, i64)>,
    /// Outbound queries from ports with no known socket, by local port, until a scan lists the socket.
    dns_seen: HashMap<u16, Vec<DnsSeen>>,
    archive: Vec<Flow>,
    dns_archive: Vec<DnsRecord>,
    events_archive: Vec<ConnEvent>,
}

fn proto_label(p: u8) -> &'static str {
    crate::util::proto_name(p)
}

fn push_bounded<T>(q: &mut VecDeque<T>, v: T, max: usize) {
    if q.len() >= max {
        q.pop_front();
    }
    q.push_back(v);
}

impl FlowTable {
    pub fn new(eph: (u16, u16)) -> Self {
        Self {
            active: HashMap::new(),
            listeners: HashMap::new(),
            events: VecDeque::new(),
            dns_log: VecDeque::new(),
            series: VecDeque::new(),
            ifnames: HashMap::new(),
            names: HashMap::new(),
            owners: OwnerCache::default(),
            host_addrs: HashSet::new(),
            host_netns: crate::procs::netns_of("/proc/1/ns/net"),
            eph,
            by_sk: HashMap::new(),
            socks: HashMap::new(),
            proc_conn: HashMap::new(),
            container_ips: HashMap::new(),
            scanned_once: false,
            pending_app: HashMap::new(),
            requests: Vec::new(),
            dns_pending: HashMap::new(),
            dns_flow: HashMap::new(),
            dns_seen: HashMap::new(),
            archive: Vec::new(),
            dns_archive: Vec::new(),
            events_archive: Vec::new(),
        }
    }

    /// The owner's namespace when we could read it, else whether `local` is a host address.
    fn ns_of(&self, owner: &Option<Owner>, local: IpAddr) -> Ns {
        let host = match (owner.as_ref().and_then(|o| o.netns), self.host_netns) {
            (Some(ns), Some(h)) => ns == h,
            _ => {
                local.is_unspecified()
                    || local.is_loopback()
                    || self.host_addrs.is_empty()
                    || self.host_addrs.contains(&local)
            }
        };
        match () {
            _ if host => Ns::Host,
            _ if owner.as_ref().is_some_and(|o| o.container.is_some()) => Ns::Container,
            _ => Ns::Foreign,
        }
    }

    fn minute(&mut self, now: i64) -> &mut FlowMinute {
        let ts = now - now % 60;
        if self.series.back().is_none_or(|m| m.ts != ts) {
            push_bounded(
                &mut self.series,
                FlowMinute {
                    ts,
                    ..Default::default()
                },
                60,
            );
        }
        self.series.back_mut().expect("just pushed")
    }

    fn event(&mut self, ev: ConnEvent) {
        self.events_archive.push(ev.clone());
        push_bounded(&mut self.events, ev, 1000);
    }

    pub fn name_of(&self, ip: IpAddr, now: i64) -> Option<&str> {
        self.names
            .get(&ip)
            .filter(|(_, exp)| *exp > now)
            .map(|(n, _)| n.as_str())
    }

    // -- kernel flow table ---------------------------------------------------

    /// Merges one snapshot of the kernel flow map. Returns kernel entries to
    /// delete (idle ones; a returning flow gets a fresh entry and is merged).
    pub fn observe(
        &mut self,
        kflows: Vec<(FlowKey, FlowStats)>,
        health: &[(SockKey, TcpHealth)],
        clock: &BootClock,
        now: i64,
        dt: f64,
    ) -> Vec<FlowKey> {
        for f in self.active.values_mut() {
            f.rate_in = 0.0;
            f.rate_out = 0.0;
        }
        let mut delete = Vec::new();
        let (mut new_in, mut new_out, mut b_in, mut b_out) = (0, 0, 0, 0);
        for (key, st) in kflows {
            let last = clock.to_unix(st.last_seen_ns);
            let eph = self.eph;
            let listening = self.listeners.contains_key(&(key.proto, key.lport));
            let hint = if key.proto == PROTO_UDP && !self.active.contains_key(&key) {
                self.udp_hint(&key)
            } else {
                UdpHint::default()
            };
            let flow = self.active.entry(key).or_insert_with(|| {
                let dir = guess_dir(&key, &st, listening, eph, hint);
                match dir {
                    Dir::In => new_in += 1,
                    Dir::Out => new_out += 1,
                    Dir::Unknown => {}
                }
                Flow {
                    key,
                    iface: String::new(),
                    local: key_to_ip(key.local),
                    remote: key_to_ip(key.remote),
                    dir,
                    first_seen: clock.to_unix(st.first_seen_ns),
                    last_seen: last,
                    bytes_in: 0,
                    bytes_out: 0,
                    pkts_in: 0,
                    pkts_out: 0,
                    rate_in: 0.0,
                    rate_out: 0.0,
                    flags_in: 0,
                    flags_out: 0,
                    tcp_state: None,
                    connect_ms: None,
                    failed: false,
                    retrans: 0,
                    rst_sent: 0,
                    rst_recv: 0,
                    owner: None,
                    peer: None,
                    name: None,
                    app: AppMeta::default(),
                    k: FlowStats::default(),
                    noted: false,
                }
            });
            // A recycled kernel entry starts again from zero.
            if st.bytes_in < flow.k.bytes_in || st.bytes_out < flow.k.bytes_out {
                flow.k = FlowStats::default();
            }
            let (di, dout) = (
                st.bytes_in - flow.k.bytes_in,
                st.bytes_out - flow.k.bytes_out,
            );
            flow.bytes_in += di;
            flow.bytes_out += dout;
            flow.pkts_in += st.pkts_in.saturating_sub(flow.k.pkts_in);
            flow.pkts_out += st.pkts_out.saturating_sub(flow.k.pkts_out);
            flow.rate_in = di as f64 / dt;
            flow.rate_out = dout as f64 / dt;
            flow.flags_in |= st.flags_in;
            flow.flags_out |= st.flags_out;
            flow.last_seen = flow.last_seen.max(last);
            flow.k = st;
            b_in += di;
            b_out += dout;
            if flow.iface.is_empty() {
                flow.iface = self
                    .ifnames
                    .get(&key.ifindex)
                    .cloned()
                    .unwrap_or_else(|| key.ifindex.to_string());
            }
            if now - last > 60 {
                delete.push(key);
            }
        }
        let m = self.minute(now);
        m.new_in += new_in;
        m.new_out += new_out;
        m.bytes_in += b_in;
        m.bytes_out += b_out;

        let health: HashMap<&SockKey, &TcpHealth> = health.iter().map(|(k, h)| (k, h)).collect();
        let pending = std::mem::take(&mut self.pending_app);
        let mut leftover = HashMap::new();
        for (key, samples) in pending {
            match self.active.get_mut(&key) {
                Some(f) => {
                    for (out, data) in samples {
                        let from_initiator = from_initiator(f.dir, out);
                        f.app.absorb(&data, from_initiator);
                    }
                    if let Some(r) = f.take_request(now) {
                        if self.requests.len() < 10_000 {
                            self.requests.push(r);
                        }
                    }
                }
                // The flow shows up on the next snapshot; give it one more tick.
                None if samples.len() < 4 => {
                    leftover.insert(key, samples);
                }
                None => {}
            }
        }
        self.pending_app = leftover;

        let keys: Vec<FlowKey> = self.active.keys().copied().collect();
        for key in keys {
            let sk = SockKey {
                local: key.local,
                remote: key.remote,
                lport: key.lport,
                rport: key.rport,
                _pad: 0,
            };
            let undecided_udp = key.proto == PROTO_UDP && self.active[&key].dir == Dir::Unknown;
            let hint = if undecided_udp {
                self.udp_hint(&key)
            } else {
                UdpHint::default()
            };
            let owner_needed = self.active[&key].owner.is_none();
            let owner = if owner_needed {
                self.find_owner(&key, &sk)
            } else {
                None
            };
            let peer = if self.active[&key].peer.is_none() {
                self.find_peer(&key)
            } else {
                None
            };
            let name = match self.active[&key].name {
                None => self.name_of(key_to_ip(key.remote), now).map(str::to_string),
                Some(_) => None,
            };
            let info = (key.proto == PROTO_TCP)
                .then(|| self.socks.get(&sk))
                .flatten();
            let (state, connect_ms, failed) = info.map_or((None, None, false), |s| {
                (Some(s.state), s.connect_ms, s.failed)
            });
            let f = self.active.get_mut(&key).expect("key from map");
            if owner.is_some() {
                f.owner = owner;
            }
            if peer.is_some() {
                f.peer = peer;
            }
            if name.is_some() {
                f.name = name;
            }
            if state.is_some() {
                f.tcp_state = state;
            }
            f.connect_ms = f.connect_ms.or(connect_ms);
            f.failed |= failed;
            if let Some(h) = health.get(&sk) {
                f.retrans = f.retrans.max(h.retrans);
                f.rst_sent = f.rst_sent.max(h.rst_sent);
                f.rst_recv = f.rst_recv.max(h.rst_recv);
            }
            if undecided_udp {
                f.dir = guess_dir(&f.key, &f.k, false, self.eph, hint);
            }
        }

        // Finished or idle conversations move to the archive.
        let expired: Vec<FlowKey> = self
            .active
            .values()
            .filter(|f| {
                let idle = now - f.last_seen;
                match f.key.proto {
                    PROTO_TCP if f.closed() => idle >= 10,
                    PROTO_TCP => idle >= 900,
                    PROTO_UDP => idle >= 120,
                    _ => idle >= 60,
                }
            })
            .map(|f| f.key)
            .collect();
        for key in expired {
            if let Some(f) = self.active.remove(&key) {
                if !delete.contains(&key) {
                    delete.push(key);
                }
                self.archive.push(f);
            }
        }
        // Hard cap: archive the longest-idle flows first.
        const MAX_ACTIVE: usize = 200_000;
        if self.active.len() > MAX_ACTIVE {
            let mut by_idle: Vec<(i64, FlowKey)> =
                self.active.values().map(|f| (f.last_seen, f.key)).collect();
            by_idle.sort_unstable_by_key(|(t, _)| *t);
            for (_, key) in by_idle.into_iter().take(self.active.len() - MAX_ACTIVE) {
                if let Some(f) = self.active.remove(&key) {
                    delete.push(key);
                    self.archive.push(f);
                }
            }
        }
        delete
    }

    fn find_owner(&self, key: &FlowKey, sk: &SockKey) -> Option<Owner> {
        if key.proto == PROTO_TCP {
            if let Some(o) = self.socks.get(sk).and_then(|s| s.owner.clone()) {
                return Some(o);
            }
        }
        if let Some(o) = self.proc_conn.get(&(key.proto, *sk)) {
            return Some(o.clone());
        }
        // Bridge flows: the local side is a container's address.
        let local = key_to_ip(key.local);
        if let Some(o) = self.container_ips.get(&local) {
            return Some(o.clone());
        }
        // Inbound connections and UDP to a host address: whoever is bound to the local port.
        let host =
            local.is_loopback() || self.host_addrs.is_empty() || self.host_addrs.contains(&local);
        let dir_in = self.active.get(key).is_some_and(|f| f.dir == Dir::In);
        if host && (dir_in || key.proto == PROTO_UDP) {
            return self
                .listeners
                .get(&(key.proto, key.lport))
                .and_then(|l| l.owner_for(local).cloned());
        }
        None
    }

    /// Who owns the other end of the flow, when it is on this host: the socket
    /// with the reversed addresses, or else the container with the remote address.
    fn find_peer(&self, key: &FlowKey) -> Option<Owner> {
        let rev = SockKey {
            local: key.remote,
            remote: key.local,
            lport: key.rport,
            rport: key.lport,
            _pad: 0,
        };
        if key.proto == PROTO_TCP {
            if let Some(o) = self.socks.get(&rev).and_then(|s| s.owner.clone()) {
                return Some(o);
            }
        }
        self.proc_conn
            .get(&(key.proto, rev))
            .or_else(|| self.container_ips.get(&key_to_ip(key.remote)))
            .cloned()
    }

    /// Stale kernel health entries (no flow, quiet for 10 minutes).
    pub fn stale_health(
        &self,
        health: &[(SockKey, TcpHealth)],
        clock: &BootClock,
        now: i64,
    ) -> Vec<SockKey> {
        let live: BTreeSet<(([u8; 16], u16), ([u8; 16], u16))> = self
            .active
            .keys()
            .map(|k| ((k.local, k.lport), (k.remote, k.rport)))
            .collect();
        health
            .iter()
            .filter(|(k, h)| {
                now - clock.to_unix(h.last_ns) > 600
                    && !live.contains(&((k.local, k.lport), (k.remote, k.rport)))
            })
            .map(|(k, _)| *k)
            .collect()
    }

    // -- TCP lifecycle ---------------------------------------------------------

    pub fn observe_sock(&mut self, ev: &SockEvent, clock: &BootClock, now: i64) {
        let key = SockKey {
            local: ev.local,
            remote: ev.remote,
            lport: ev.lport,
            rport: ev.rport,
            _pad: 0,
        };
        let comm = comm_str(&ev.comm);
        match (ev.oldstate, ev.newstate) {
            (CLOSE, SYN_SENT) => {
                let owner = self.owners.owner(ev.pid, Some(&comm), now);
                let foreign = self.ns_of(&owner, key_to_ip(ev.local)) == Ns::Foreign;
                self.by_sk.insert(
                    ev.skaddr,
                    Pending {
                        owner,
                        ts_ns: ev.ts_ns,
                        ts: now,
                        foreign,
                    },
                );
            }
            (CLOSE, LISTEN) => {
                let owner = self.owners.owner(ev.pid, Some(&comm), now);
                let addr = key_to_ip(ev.local);
                // Listeners are keyed by port: a container's :80 is not the host's :80.
                if self.ns_of(&owner, addr) != Ns::Host {
                    return;
                }
                let new = !self.listeners.contains_key(&(PROTO_TCP, ev.lport));
                let l = self
                    .listeners
                    .entry((PROTO_TCP, ev.lport))
                    .or_insert_with(|| {
                        let mut l =
                            Listener::new(PROTO_TCP, ev.lport, owner.clone(), now, self.eph);
                        l.announced = true; // the event below
                        l
                    });
                l.addrs.insert(addr);
                if let Some(o) = &owner {
                    l.by_addr.insert(addr, o.clone());
                }
                l.exposed |= !addr.is_loopback();
                if new {
                    let detail = format!(
                        "{} listening on {}:{}",
                        owner_label(&owner),
                        fmt_addr(addr),
                        ev.lport
                    );
                    self.event(ConnEvent {
                        ts: now,
                        kind: "listen",
                        proto: "tcp",
                        local: addr.to_string(),
                        lport: ev.lport,
                        remote: None,
                        rport: None,
                        owner,
                        detail,
                    });
                }
            }
            (LISTEN, CLOSE) => {
                let addr = key_to_ip(ev.local);
                let Some(l) = self.listeners.get_mut(&(PROTO_TCP, ev.lport)) else {
                    return;
                };
                l.by_addr.remove(&addr);
                if !l.addrs.remove(&addr) || !l.addrs.is_empty() {
                    return;
                }
                if let Some(l) = self.listeners.remove(&(PROTO_TCP, ev.lport)) {
                    let detail = format!(
                        "{} stopped listening on port {}",
                        owner_label(&l.owner),
                        ev.lport
                    );
                    self.event(ConnEvent {
                        ts: now,
                        kind: "unlisten",
                        proto: "tcp",
                        local: key_to_ip(ev.local).to_string(),
                        lport: ev.lport,
                        remote: None,
                        rport: None,
                        owner: l.owner,
                        detail,
                    });
                }
            }
            (SYN_SENT, ESTABLISHED) => {
                let p = self.by_sk.remove(&ev.skaddr);
                if p.as_ref().is_some_and(|p| p.foreign) {
                    return;
                }
                let s = self.socks.entry(key).or_default();
                s.state = ESTABLISHED;
                s.last = now;
                if let Some(p) = p {
                    s.connect_ms = Some(ev.ts_ns.saturating_sub(p.ts_ns) as f64 / 1e6);
                    s.owner = p.owner;
                }
            }
            (SYN_SENT, CLOSE) => {
                let p = self.by_sk.remove(&ev.skaddr);
                let foreign = match &p {
                    Some(p) => p.foreign,
                    None => self.ns_of(&None, key_to_ip(ev.local)) == Ns::Foreign,
                };
                if foreign {
                    return;
                }
                let elapsed = p
                    .as_ref()
                    .map(|p| ev.ts_ns.saturating_sub(p.ts_ns) as f64 / 1e6);
                let owner = p.and_then(|p| p.owner);
                let s = self.socks.entry(key).or_default();
                s.state = CLOSE;
                s.failed = true;
                s.last = now;
                if s.owner.is_none() {
                    s.owner = owner.clone();
                }
                self.minute(now).failed += 1;
                // A quick failure is a refusal (RST/ICMP); a slow one is a timeout.
                let why = match elapsed {
                    Some(ms) if ms < 3000.0 => format!("refused after {ms:.0} ms"),
                    Some(ms) => format!("timed out after {:.0} s", ms / 1000.0),
                    None => "failed".into(),
                };
                let remote = key_to_ip(ev.remote);
                let detail = format!(
                    "{} could not connect to {}:{} ({why})",
                    owner_label(&owner),
                    fmt_addr(remote),
                    ev.rport
                );
                self.event(ConnEvent {
                    ts: now,
                    kind: "connect_failed",
                    proto: "tcp",
                    local: key_to_ip(ev.local).to_string(),
                    lport: ev.lport,
                    remote: Some(remote.to_string()),
                    rport: Some(ev.rport),
                    owner,
                    detail,
                });
            }
            (SYN_RECV, ESTABLISHED) => {
                // Listeners are the host's: a container accepting on a port the host
                // also listens on (docker-proxy publishing it) is not the host's listener.
                let local = key_to_ip(ev.local);
                let owner = match self.container_ips.get(&local) {
                    Some(o) => Some(o.clone()),
                    None if self.is_host_local(local) => self
                        .listeners
                        .get(&(PROTO_TCP, ev.lport))
                        .and_then(|l| l.owner_for(local).cloned()),
                    None => None,
                };
                let s = self.socks.entry(key).or_default();
                s.state = ESTABLISHED;
                s.last = now;
                if s.owner.is_none() {
                    s.owner = owner;
                }
            }
            (_, new) => {
                if new == CLOSE {
                    self.by_sk.remove(&ev.skaddr);
                }
                if let Some(s) = self.socks.get_mut(&key) {
                    s.state = new;
                    s.last = now;
                } else if ev.lport != 0 && new != CLOSE {
                    self.socks.insert(
                        key,
                        SockInfo {
                            state: new,
                            last: now,
                            ..Default::default()
                        },
                    );
                }
            }
        }
        let _ = clock;
    }

    // -- /proc socket scan ------------------------------------------------------

    pub fn apply_scan(&mut self, scan: Scan, now: i64) {
        self.container_ips = scan.containers;
        let mut conn = HashMap::new();
        let mut seen: HashMap<(u8, u16), Listener> = HashMap::new();
        for (s, owner) in scan.socks {
            if s.listening() {
                let l = seen.entry((s.proto, s.lport)).or_insert_with(|| {
                    Listener::new(s.proto, s.lport, owner.clone(), now, self.eph)
                });
                l.addrs.insert(s.local);
                if let Some(o) = &owner {
                    l.by_addr.insert(s.local, o.clone());
                }
                l.exposed |= !s.local.is_loopback();
                if l.owner.is_none() {
                    l.owner = owner;
                }
                if s.proto == PROTO_UDP {
                    l.socks
                        .entry(s.local)
                        .or_insert_with(|| UdpSock::new(BTreeSet::new()))
                        .inodes
                        .insert(s.inode);
                }
            } else if !s.remote.is_unspecified() {
                if let Some(o) = owner {
                    let key = SockKey {
                        local: crate::util::ip_to_key(s.local),
                        remote: crate::util::ip_to_key(s.remote),
                        lport: s.lport,
                        rport: s.rport,
                        _pad: 0,
                    };
                    conn.insert((s.proto, key), o);
                }
            }
        }
        self.proc_conn = conn;

        let first = !self.scanned_once;
        self.scanned_once = true;
        // Listeners that appeared or vanished between scans (TCP ones are
        // usually caught live by the tracepoint; UDP only shows up here).
        let mut gone: Vec<(u8, u16)> = self
            .listeners
            .keys()
            .filter(|k| !seen.contains_key(k))
            .copied()
            .collect();
        gone.sort_unstable();
        for k in gone {
            let l = self.listeners.remove(&k).expect("present");
            // A client socket that closed before it was ever announced leaves no trace.
            if first || l.role == SockRole::Client {
                continue;
            }
            // Seen only briefly and never explained: it counts as the listener it looked like.
            if !l.announced {
                self.listen_event(&l, l.since);
            }
            let detail = format!(
                "{} stopped listening on {}/{}",
                owner_label(&l.owner),
                l.proto,
                l.port
            );
            self.event(ConnEvent {
                ts: now,
                kind: "unlisten",
                proto: l.proto,
                local: l
                    .addrs
                    .iter()
                    .next()
                    .map(|a| a.to_string())
                    .unwrap_or_default(),
                lport: l.port,
                remote: None,
                rport: None,
                owner: l.owner,
                detail,
            });
        }
        for (k, mut l) in seen {
            match self.listeners.get_mut(&k) {
                Some(existing) => {
                    existing.addrs = l.addrs;
                    existing.by_addr = l.by_addr;
                    existing.exposed = l.exposed;
                    if existing.owner.is_none() {
                        existing.owner = l.owner;
                    }
                    // Evidence stays with the socket it was seen on: a socket
                    // whose inodes are all new took over the address (port or pid
                    // reuse) and starts from scratch.
                    let mut fresh = BTreeSet::new();
                    let mut socks = std::mem::take(&mut l.socks);
                    for (addr, sock) in socks.iter_mut() {
                        match existing.socks.remove(addr) {
                            Some(old) if !old.inodes.is_disjoint(&sock.inodes) => {
                                sock.role = old.role;
                                sock.reason = old.reason;
                            }
                            _ => {
                                fresh.insert(*addr);
                            }
                        }
                    }
                    // Every socket replaced: the settle time starts over for the new one.
                    if !fresh.is_empty() && fresh.len() == socks.len() {
                        existing.since = now;
                    }
                    existing.socks = socks;
                    Self::apply_dns_seen(&mut self.dns_seen, existing, &fresh, now);
                }
                None => {
                    let fresh = l.socks.keys().copied().collect();
                    Self::apply_dns_seen(&mut self.dns_seen, &mut l, &fresh, now);
                    l.announced = first;
                    self.listeners.insert(k, l);
                }
            }
        }
        self.dns_seen.retain(|_, v| !v.is_empty());

        let mut due: Vec<(u8, u16)> = self
            .listeners
            .iter()
            .filter(|(_, l)| !l.announced && l.announce_due(now))
            .map(|(k, _)| *k)
            .collect();
        due.sort_unstable();
        for k in due {
            let l = self.listeners.get_mut(&k).expect("present");
            l.announced = true;
            let l = l.clone();
            self.listen_event(&l, now);
        }
    }

    fn listen_event(&mut self, l: &Listener, ts: i64) {
        let addr = l.addrs.iter().next().copied();
        let detail = format!(
            "{} listening on {}:{}/{}",
            owner_label(&l.owner),
            addr.map(fmt_addr).unwrap_or_default(),
            l.port,
            l.proto
        );
        self.event(ConnEvent {
            ts,
            kind: "listen",
            proto: l.proto,
            local: addr.map(|a| a.to_string()).unwrap_or_default(),
            lport: l.port,
            remote: None,
            rport: None,
            owner: l.owner.clone(),
            detail,
        });
    }

    /// Applies DNS queries seen before the scan listed a socket to the new
    /// sockets (`fresh`) of `l`, once each and only while they are recent.
    /// Queries that match no new socket are dropped: a socket that was already
    /// listed would have taken them directly, so they came from one that is gone.
    fn apply_dns_seen(
        dns_seen: &mut HashMap<u16, Vec<DnsSeen>>,
        l: &mut Listener,
        fresh: &BTreeSet<IpAddr>,
        now: i64,
    ) {
        for q in dns_seen
            .get_mut(&l.port)
            .map(std::mem::take)
            .unwrap_or_default()
        {
            if now - q.ts > DNS_SEEN_TTL {
                continue;
            }
            let Some(addr) = l.sock_for(q.local).filter(|a| fresh.contains(a)) else {
                continue;
            };
            if let Some(sock) = l.socks.get_mut(&addr) {
                sock.note(
                    SockRole::Client,
                    format!("sent DNS queries to {}", fmt_endpoint(q.remote, q.rport)),
                );
            }
        }
        l.refresh_role();
    }

    // -- payload samples ----------------------------------------------------------

    pub fn observe_payload(&mut self, ev: &PayloadEvent, now: i64) {
        let data = &ev.data[..(ev.caplen as usize).min(ev.data.len())];
        match ev.kind {
            PL_DNS => self.observe_dns(ev, data, now),
            PL_TCP_FIRST => match self.active.get_mut(&ev.key) {
                Some(f) => {
                    let fi = from_initiator(f.dir, ev.out == 1);
                    f.app.absorb(data, fi);
                    if let Some(r) = f.take_request(now) {
                        if self.requests.len() < 10_000 {
                            self.requests.push(r);
                        }
                    }
                }
                None => {
                    if self.pending_app.len() < 20_000 {
                        self.pending_app
                            .entry(ev.key)
                            .or_default()
                            .push((ev.out == 1, data.to_vec()));
                    }
                }
            },
            _ => {}
        }
    }

    fn observe_dns(&mut self, ev: &PayloadEvent, data: &[u8], now: i64) {
        let Some(msg) = dissect::dns(data) else {
            return;
        };
        let Some((qname, qtype)) = msg.questions.first().cloned() else {
            return;
        };
        let iface = self
            .ifnames
            .get(&ev.key.ifindex)
            .cloned()
            .unwrap_or_default();
        let local = key_to_ip(ev.key.local);
        let remote = key_to_ip(ev.key.remote);
        if let Some(f) = self.active.get_mut(&ev.key) {
            f.app.proto = Some("dns");
            f.app.dns_qname = Some(qname.clone());
        }
        self.note_dns_evidence(&ev.key, &msg, ev.out == 1, now);
        let pkey = (ev.key, msg.id);
        if !msg.response {
            let out = ev.out == 1;
            let (client, server) = if out {
                (local, remote)
            } else {
                (remote, local)
            };
            self.minute(now).dns += 1;
            if self.dns_pending.len() < 50_000 {
                self.dns_pending.insert(
                    pkey,
                    DnsPending {
                        ts: now,
                        ts_ns: ev.ts_ns,
                        iface,
                        client,
                        server,
                        out,
                        qname,
                        qtype,
                    },
                );
            }
            return;
        }
        for a in &msg.answers {
            if let DnsData::Addr(ip) = a.data {
                // Remember the name the client asked for, not the CNAME target.
                self.names
                    .insert(ip, (qname.clone(), now + (a.ttl as i64).max(600)));
            }
        }
        let p = self.dns_pending.remove(&pkey);
        let answers: Vec<String> = msg
            .answers
            .iter()
            .filter_map(|a| match &a.data {
                DnsData::Addr(ip) => Some(ip.to_string()),
                DnsData::Name(n) => Some(format!("CNAME {n}")),
                DnsData::Other => None,
            })
            .take(16)
            .collect();
        let (client, server, out) = match &p {
            Some(p) => (p.client, p.server, p.out),
            // Query not seen (e.g. sent before start): infer from direction.
            None if ev.out == 0 => (local, remote, true),
            None => (remote, local, false),
        };
        let rec = DnsRecord {
            ts: p.as_ref().map_or(now, |p| p.ts),
            iface: p.as_ref().map_or(iface, |p| p.iface.clone()),
            client: client.to_string(),
            server: server.to_string(),
            dir: if out { "out" } else { "in" },
            qname,
            qtype: dissect::qtype_name(qtype),
            rcode: dissect::rcode_name(msg.rcode).into(),
            answers,
            latency_ms: p.map(|p| ev.ts_ns.saturating_sub(p.ts_ns) as f64 / 1e6),
        };
        self.dns_archive.push(rec.clone());
        push_bounded(&mut self.dns_log, rec, 2000);
    }

    /// A UDP port of this host is no address of a container or another namespace.
    fn is_host_local(&self, ip: IpAddr) -> bool {
        !self.container_ips.contains_key(&ip)
            && (ip.is_loopback() || self.host_addrs.is_empty() || self.host_addrs.contains(&ip))
    }

    /// The socket on `lport` that sends from `local`, if a scan listed one.
    fn udp_sock_mut(&mut self, lport: u16, local: IpAddr) -> Option<(&mut Listener, IpAddr)> {
        if !self.is_host_local(local) {
            return None;
        }
        let l = self.listeners.get_mut(&(PROTO_UDP, lport))?;
        let addr = l.sock_for(local)?;
        Some((l, addr))
    }

    fn udp_hint(&mut self, key: &FlowKey) -> UdpHint {
        let dns = self.dns_flow.remove(key).map(|(d, _)| d);
        let local = key_to_ip(key.local);
        let server = self
            .udp_sock_mut(key.lport, local)
            .is_some_and(|(l, addr)| {
                l.socks
                    .get(&addr)
                    .is_some_and(|s| s.role == SockRole::Server)
            });
        UdpHint { dns, server }
    }

    /// What a DNS payload says about the flow and the socket behind it.
    ///
    /// Only well-formed standard queries (and answers this host sent) count,
    /// by flags and shape, not by port alone. A query going out is a client
    /// at work; one coming in, or an answer going out, is a server. The
    /// answer coming back is not needed (queries time out) and is not used:
    /// anyone can send one.
    fn note_dns_evidence(&mut self, key: &FlowKey, msg: &DnsMsg, out: bool, now: i64) {
        if key.proto != PROTO_UDP {
            return;
        }
        let (dir, role) = if msg.is_plain_query() {
            // A socket on :53 sending queries is a resolver's own port (query-source 53).
            let client = out && key.rport == 53 && key.lport != 53;
            (
                if out { Dir::Out } else { Dir::In },
                if out {
                    client.then_some(SockRole::Client)
                } else {
                    Some(SockRole::Server)
                },
            )
        } else if out && msg.is_plain_response() {
            (Dir::In, Some(SockRole::Server))
        } else {
            return;
        };
        match self.active.get_mut(key) {
            Some(f) => f.dir = dir,
            None if self.dns_flow.len() < 50_000 => {
                self.dns_flow.insert(*key, (dir, now));
            }
            None => {}
        }
        let Some(role) = role else { return };
        let (local, remote) = (key_to_ip(key.local), key_to_ip(key.remote));
        let reason = match role {
            SockRole::Client => format!("sent DNS queries to {}", fmt_endpoint(remote, key.rport)),
            _ if out => format!(
                "answers DNS queries from {}",
                fmt_endpoint(remote, key.rport)
            ),
            _ => format!(
                "receives DNS queries from {}",
                fmt_endpoint(remote, key.rport)
            ),
        };
        let keep = self.is_host_local(local) && self.dns_seen.len() < 4096;
        match self.udp_sock_mut(key.lport, local) {
            Some((l, addr)) => {
                l.socks
                    .get_mut(&addr)
                    .expect("sock_for returned it")
                    .note(role, reason);
                l.refresh_role();
            }
            // Socket not listed yet (bound between scans): keep the query for the next scan.
            None if role == SockRole::Client && keep => {
                let v = self.dns_seen.entry(key.lport).or_default();
                if v.len() < 8 {
                    v.push(DnsSeen {
                        local,
                        remote,
                        rport: key.rport,
                        ts: now,
                    });
                }
            }
            None => {}
        }
    }

    // -- housekeeping -----------------------------------------------------------

    pub fn prune(&mut self, now: i64) {
        self.socks.retain(|_, s| {
            if s.state == CLOSE {
                now - s.last < 120
            } else {
                now - s.last < 86_400
            }
        });
        self.by_sk.retain(|_, p| now - p.ts < 300);
        self.names.retain(|_, (_, exp)| *exp > now);
        if self.names.len() > 200_000 {
            self.names.clear();
        }
        self.owners.prune(now);
        self.dns_flow.retain(|_, (_, ts)| now - *ts < DNS_FLOW_TTL);
        self.dns_seen.retain(|_, v| {
            v.retain(|q| now - q.ts <= DNS_SEEN_TTL);
            !v.is_empty()
        });
        // Queries without an answer.
        let timed_out: Vec<(FlowKey, u16)> = self
            .dns_pending
            .iter()
            .filter(|(_, p)| now - p.ts > 5)
            .map(|(k, _)| *k)
            .collect();
        for k in timed_out {
            let p = self.dns_pending.remove(&k).expect("present");
            let rec = DnsRecord {
                ts: p.ts,
                iface: p.iface,
                client: p.client.to_string(),
                server: p.server.to_string(),
                dir: if p.out { "out" } else { "in" },
                qname: p.qname,
                qtype: dissect::qtype_name(p.qtype),
                rcode: "TIMEOUT".into(),
                answers: Vec::new(),
                latency_ms: None,
            };
            self.dns_archive.push(rec.clone());
            push_bounded(&mut self.dns_log, rec, 2000);
        }
    }

    pub fn take_archive(&mut self) -> (Vec<Flow>, Vec<DnsRecord>, Vec<ConnEvent>) {
        (
            std::mem::take(&mut self.archive),
            std::mem::take(&mut self.dns_archive),
            std::mem::take(&mut self.events_archive),
        )
    }

    /// Everything still open, for a clean shutdown.
    pub fn drain_active(&mut self) -> Vec<Flow> {
        self.active.drain().map(|(_, f)| f).collect()
    }
}

/// Direction for a new flow: the kernel's view of who sent the first SYN,
/// corrected by what is listening locally and by port conventions.
///
/// UDP has no handshake, so a bound socket proves nothing: a resolver binds a
/// source port the same way a service does. UDP goes by DNS evidence on the
/// flow or its socket, then by which side sent the first packet netwatch saw,
/// and only then by ports.
fn guess_dir(key: &FlowKey, st: &FlowStats, listening: bool, eph: (u16, u16), udp: UdpHint) -> Dir {
    let ephemeral = |p: u16| p >= eph.0 && p <= eph.1;
    if key.proto == PROTO_UDP {
        return guess_udp_dir(key, st, eph, udp);
    }
    if key.proto == PROTO_TCP {
        match st.initiator {
            INIT_LOCAL => return Dir::Out,
            INIT_REMOTE => return Dir::In,
            _ => {}
        }
    }
    if listening && !ephemeral(key.lport) {
        return Dir::In;
    }
    if key.proto == PROTO_TCP {
        if key.rport < 1024 && key.lport >= 1024 {
            return Dir::Out;
        }
        if ephemeral(key.lport) && !ephemeral(key.rport) {
            return Dir::Out;
        }
        if ephemeral(key.rport) && !ephemeral(key.lport) && listening {
            return Dir::In;
        }
    }
    match st.initiator {
        INIT_LOCAL => Dir::Out,
        INIT_REMOTE => Dir::In,
        _ => Dir::Unknown,
    }
}

fn guess_udp_dir(key: &FlowKey, st: &FlowStats, eph: (u16, u16), udp: UdpHint) -> Dir {
    let ephemeral = |p: u16| p >= eph.0 && p <= eph.1;
    if let Some(dir) = udp.dns {
        return dir;
    }
    // A socket serving DNS: its flows are inbound even if we spoke first (an
    // answer seen after netwatch started, to a query it missed).
    if udp.server {
        return Dir::In;
    }
    match st.initiator {
        INIT_LOCAL => return Dir::Out,
        INIT_REMOTE => return Dir::In,
        _ => {}
    }
    // Nobody saw the first packet: ports are all that is left, and only the
    // client side of a well-known port counts.
    if (key.rport < 1024 && key.lport >= 1024) || (ephemeral(key.lport) && !ephemeral(key.rport)) {
        Dir::Out
    } else {
        Dir::Unknown
    }
}

fn from_initiator(dir: Dir, out: bool) -> bool {
    match dir {
        Dir::Out => out,
        Dir::In => !out,
        Dir::Unknown => !out,
    }
}

fn comm_str(c: &[u8; 16]) -> String {
    let end = c.iter().position(|&b| b == 0).unwrap_or(c.len());
    String::from_utf8_lossy(&c[..end]).into_owned()
}

fn fmt_endpoint(ip: IpAddr, port: u16) -> String {
    format!("{}:{port}", fmt_addr(ip))
}

fn fmt_addr(ip: IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => format!("[{v6}]"),
        v4 => v4.to_string(),
    }
}

pub fn owner_label(o: &Option<Owner>) -> String {
    match o {
        Some(o) => match (&o.container, &o.unit) {
            (Some(c), _) => format!("{} ({}, container {c})", o.comm, o.pid),
            (None, Some(u)) => format!("{} ({}, {u}{})", o.comm, o.pid, crate::procs::UNIT_SUFFIX),
            (None, None) => format!("{} ({})", o.comm, o.pid),
        },
        None => "unknown process".into(),
    }
}

/// An interface with throughput from its sysfs counters.
#[derive(Debug, Clone, Serialize)]
pub struct IfStat {
    #[serde(flatten)]
    pub info: crate::netif::IfInfo,
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub rx_pps: f64,
    pub tx_pps: f64,
    /// Flow programs attached.
    pub flows: bool,
    /// The XDP program (accounting and bans) runs here.
    pub xdp: bool,
}

impl crate::engine::Engine {
    pub fn observe_ifaces(
        &mut self,
        list: Vec<crate::netif::IfInfo>,
        attached: &BTreeSet<String>,
        dt: f64,
    ) {
        self.flows.host_addrs = list
            .iter()
            .flat_map(|i| &i.addrs)
            .filter_map(|a| a.split('/').next()?.parse().ok())
            .collect();
        let prev: HashMap<String, crate::netif::IfInfo> = self
            .ifaces
            .drain(..)
            .map(|i| (i.info.name.clone(), i.info))
            .collect();
        let rate = |now: u64, before: Option<u64>| {
            before.map_or(0.0, |b| now.saturating_sub(b) as f64 / dt)
        };
        self.ifaces = list
            .into_iter()
            .map(|info| {
                let p = prev.get(&info.name);
                IfStat {
                    rx_bps: rate(info.rx_bytes, p.map(|p| p.rx_bytes)) * 8.0,
                    tx_bps: rate(info.tx_bytes, p.map(|p| p.tx_bytes)) * 8.0,
                    rx_pps: rate(info.rx_packets, p.map(|p| p.rx_packets)),
                    tx_pps: rate(info.tx_packets, p.map(|p| p.tx_packets)),
                    flows: attached.contains(&info.name),
                    xdp: info.name == self.cfg.interface,
                    info,
                }
            })
            .collect();
        self.flows.ifnames = self
            .ifaces
            .iter()
            .map(|i| (i.info.ifindex, i.info.name.clone()))
            .collect();
    }

    /// API/store shape of a flow, with geo and DNS names filled in.
    pub fn flow_row(&self, f: &Flow, now: i64, active: bool) -> crate::store::FlowRow {
        let geo = crate::util::is_public(f.remote).then(|| self.geo.lookup(f.remote));
        let port = f.service_port();
        crate::store::FlowRow {
            iface: f.iface.clone(),
            proto: proto_label(f.key.proto).to_string(),
            local: f.local.to_string(),
            lport: f.key.lport,
            remote: f.remote.to_string(),
            rport: f.key.rport,
            dir: f.dir.as_str().to_string(),
            first_seen: f.first_seen,
            last_seen: f.last_seen,
            bytes_in: f.bytes_in,
            bytes_out: f.bytes_out,
            pkts_in: f.pkts_in,
            pkts_out: f.pkts_out,
            state: f.state(),
            connect_ms: f.connect_ms,
            retrans: f.retrans,
            rst_sent: f.rst_sent,
            rst_recv: f.rst_recv,
            pid: f.owner.as_ref().map(|o| o.pid),
            process: f.owner.as_ref().map(|o| o.comm.clone()),
            exe: f.owner.as_ref().and_then(|o| o.exe.clone()),
            container: f.owner.as_ref().and_then(|o| o.container.clone()),
            unit: f.owner.as_ref().and_then(|o| o.unit.clone()),
            remote_pid: f.peer.as_ref().map(|o| o.pid),
            remote_process: f.peer.as_ref().map(|o| o.comm.clone()),
            remote_container: f.peer.as_ref().and_then(|o| o.container.clone()),
            remote_unit: f.peer.as_ref().and_then(|o| o.unit.clone()),
            remote_name: f
                .name
                .clone()
                .or_else(|| self.flows.name_of(f.remote, now).map(str::to_string))
                .or_else(|| f.app.sni.clone()),
            app: if f.app.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::to_value(&f.app).unwrap_or_default()
            },
            country: geo.as_ref().and_then(|g| g.country_code.clone()),
            asn: geo.as_ref().and_then(|g| g.asn),
            as_org: geo.and_then(|g| g.as_org),
            service_port: port,
            service: crate::util::service_name(port).map(str::to_string),
            active,
            rate_in: f.rate_in,
            rate_out: f.rate_out,
        }
    }

    /// Finished flows, DNS queries and connection events since the last call, ready for the store.
    pub fn take_flow_archive(
        &mut self,
        now: i64,
    ) -> (
        Vec<crate::store::FlowRow>,
        Vec<crate::store::DnsRow>,
        Vec<crate::store::ConnEventRow>,
    ) {
        let (flows, dns, events) = self.flows.take_archive();
        let flows = flows.iter().map(|f| self.flow_row(f, now, false)).collect();
        let dns = dns
            .into_iter()
            .map(|d| crate::store::DnsRow {
                ts: d.ts,
                iface: d.iface,
                client: d.client,
                server: d.server,
                dir: d.dir.to_string(),
                qname: d.qname,
                qtype: d.qtype,
                rcode: d.rcode,
                answers: d.answers,
                latency_ms: d.latency_ms,
            })
            .collect();
        let events = events.into_iter().map(conn_event_row).collect();
        (flows, dns, events)
    }

    /// All active flows as finished rows (shutdown).
    pub fn drain_flows(&mut self, now: i64) -> Vec<crate::store::FlowRow> {
        let flows = self.flows.drain_active();
        flows.iter().map(|f| self.flow_row(f, now, false)).collect()
    }
}

pub fn conn_event_row(e: ConnEvent) -> crate::store::ConnEventRow {
    crate::store::ConnEventRow {
        ts: e.ts,
        kind: e.kind.to_string(),
        proto: e.proto.to_string(),
        local: e.local,
        lport: e.lport,
        remote: e.remote,
        rport: e.rport,
        pid: e.owner.as_ref().map(|o| o.pid),
        process: e.owner.as_ref().map(|o| o.comm.clone()),
        container: e.owner.as_ref().and_then(|o| o.container.clone()),
        unit: e.owner.and_then(|o| o.unit),
        detail: e.detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::ip_to_key;

    fn key(l: &str, lp: u16, r: &str, rp: u16, proto: u8) -> FlowKey {
        FlowKey {
            local: ip_to_key(l.parse().unwrap()),
            remote: ip_to_key(r.parse().unwrap()),
            ifindex: 2,
            lport: lp,
            rport: rp,
            proto,
            _pad: [0; 3],
        }
    }

    #[test]
    fn other_namespaces_are_not_this_host() {
        let mut t = FlowTable::new((32768, 60999));
        t.host_netns = None;
        t.host_addrs = ["10.0.0.2".parse().unwrap()].into();
        let clock = BootClock::new();
        let ev = |sk: u64, l: &str, lp: u16, r: &str, rp: u16, old: u8, new: u8| SockEvent {
            ts_ns: 1,
            skaddr: sk,
            local: ip_to_key(l.parse().unwrap()),
            remote: ip_to_key(r.parse().unwrap()),
            comm: [0; 16],
            pid: 0,
            lport: lp,
            rport: rp,
            oldstate: old,
            newstate: new,
            _pad: [0; 6],
        };
        // A refused connect from another namespace (an `ip netns` "attacker" probing us).
        t.observe_sock(
            &ev(1, "203.0.113.50", 40000, "10.0.0.2", 200, CLOSE, SYN_SENT),
            &clock,
            100,
        );
        t.observe_sock(
            &ev(1, "203.0.113.50", 40000, "10.0.0.2", 200, SYN_SENT, CLOSE),
            &clock,
            100,
        );
        // Ours.
        t.observe_sock(
            &ev(2, "10.0.0.2", 40001, "1.1.1.1", 9, CLOSE, SYN_SENT),
            &clock,
            100,
        );
        t.observe_sock(
            &ev(2, "10.0.0.2", 40001, "1.1.1.1", 9, SYN_SENT, CLOSE),
            &clock,
            100,
        );
        let failed: Vec<&str> = t
            .events
            .iter()
            .filter(|e| e.kind == "connect_failed")
            .map(|e| e.local.as_str())
            .collect();
        assert_eq!(failed, ["10.0.0.2"]);

        // Its listener on :22 is not ours, and closing it doesn't close ours.
        t.observe_sock(
            &ev(3, "0.0.0.0", 22, "0.0.0.0", 0, CLOSE, LISTEN),
            &clock,
            100,
        );
        t.observe_sock(
            &ev(4, "203.0.113.50", 8080, "0.0.0.0", 0, CLOSE, LISTEN),
            &clock,
            100,
        );
        t.observe_sock(
            &ev(5, "203.0.113.50", 22, "0.0.0.0", 0, LISTEN, CLOSE),
            &clock,
            100,
        );
        assert!(t.listeners.contains_key(&(PROTO_TCP, 22)));
        assert!(!t.listeners.contains_key(&(PROTO_TCP, 8080)));
        t.observe_sock(
            &ev(3, "0.0.0.0", 22, "0.0.0.0", 0, LISTEN, CLOSE),
            &clock,
            100,
        );
        assert!(t.listeners.is_empty());
    }

    #[test]
    fn direction_heuristics() {
        let eph = (32768, 60999);
        let st = FlowStats::default();
        // Mid-stream TCP to a remote HTTPS port: we connected out.
        assert_eq!(
            guess_dir(
                &key("10.0.0.2", 51000, "1.1.1.1", 443, PROTO_TCP),
                &st,
                false,
                eph,
                UdpHint::default()
            ),
            Dir::Out
        );
        // Someone talking to our listening sshd.
        assert_eq!(
            guess_dir(
                &key("10.0.0.2", 22, "1.2.3.4", 50000, PROTO_TCP),
                &st,
                true,
                eph,
                UdpHint::default()
            ),
            Dir::In
        );
        // SYN seen from the remote side wins over ports.
        let syn_in = FlowStats {
            initiator: INIT_REMOTE,
            ..Default::default()
        };
        assert_eq!(
            guess_dir(
                &key("10.0.0.2", 51000, "1.1.1.1", 443, PROTO_TCP),
                &syn_in,
                false,
                eph,
                UdpHint::default()
            ),
            Dir::In
        );
        // DNS client.
        assert_eq!(
            guess_dir(
                &key("10.0.0.2", 40000, "9.9.9.9", 53, PROTO_UDP),
                &st,
                false,
                eph,
                UdpHint::default()
            ),
            Dir::Out
        );
    }

    #[test]
    fn flow_lifecycle_merges_recycled_entries() {
        let clock = BootClock::new();
        let mut t = FlowTable::new((32768, 60999));
        let k = key("10.0.0.2", 51000, "1.1.1.1", 443, PROTO_TCP);
        let ns = crate::util::boot_now_ns();
        let st = FlowStats {
            bytes_in: 1000,
            bytes_out: 200,
            pkts_in: 2,
            pkts_out: 2,
            initiator: INIT_LOCAL,
            first_seen_ns: ns,
            last_seen_ns: ns,
            ..Default::default()
        };
        let now = crate::util::now_unix();
        t.observe(vec![(k, st)], &[], &clock, now, 1.0);
        // Kernel entry deleted and recreated with smaller counters.
        let st2 = FlowStats {
            bytes_in: 300,
            bytes_out: 0,
            pkts_in: 1,
            ..st
        };
        t.observe(vec![(k, st2)], &[], &clock, now, 1.0);
        let f = &t.active[&k];
        assert_eq!((f.bytes_in, f.bytes_out, f.dir), (1300, 200, Dir::Out));
    }

    #[test]
    fn a_container_behind_a_published_port_owns_its_side_and_sees_docker_proxy_as_the_peer() {
        let mut t = table();
        t.host_addrs.insert("172.24.0.1".parse().unwrap());
        let clock = BootClock::new();
        let now = crate::util::now_unix();
        let pg = Owner {
            container: Some("temps-timescaledb".into()),
            ..owner(4_190_001, "postgres").unwrap()
        };
        t.apply_scan(
            Scan {
                socks: vec![],
                containers: [("172.24.0.2".parse().unwrap(), pg)].into(),
            },
            now,
        );
        let ev = |sk: u64, l: &str, lp: u16, r: &str, rp: u16, old: u8, new: u8| SockEvent {
            ts_ns: 1,
            skaddr: sk,
            local: ip_to_key(l.parse().unwrap()),
            remote: ip_to_key(r.parse().unwrap()),
            comm: *b"docker-proxy\0\0\0\0",
            pid: 4_190_002,
            lport: lp,
            rport: rp,
            oldstate: old,
            newstate: new,
            _pad: [0; 6],
        };
        // docker-proxy publishes :5432 on the host and forwards each client to the container.
        t.observe_sock(
            &ev(1, "0.0.0.0", 5432, "0.0.0.0", 0, CLOSE, LISTEN),
            &clock,
            now,
        );
        t.observe_sock(
            &ev(2, "172.24.0.1", 51476, "172.24.0.2", 5432, CLOSE, SYN_SENT),
            &clock,
            now,
        );
        t.observe_sock(
            &ev(
                2,
                "172.24.0.1",
                51476,
                "172.24.0.2",
                5432,
                SYN_SENT,
                ESTABLISHED,
            ),
            &clock,
            now,
        );
        // The container's accept runs in docker-proxy's context and on a port the host also listens on.
        t.observe_sock(
            &ev(
                3,
                "172.24.0.2",
                5432,
                "172.24.0.1",
                51476,
                SYN_RECV,
                ESTABLISHED,
            ),
            &clock,
            now,
        );
        let k = key("172.24.0.2", 5432, "172.24.0.1", 51476, PROTO_TCP);
        kernel_flow(&mut t, k, INIT_REMOTE);

        let f = &t.active[&k];
        let o = f.owner.as_ref().expect("owner");
        assert_eq!(
            (o.comm.as_str(), o.container.as_deref()),
            ("postgres", Some("temps-timescaledb"))
        );
        assert_eq!(
            f.peer.as_ref().map(|p| p.comm.as_str()),
            Some("docker-proxy")
        );
    }

    // -- UDP roles and DNS clients -------------------------------------------------

    use netwatch_common::PAYLOAD_CAP;

    use crate::procs::ProcSock;

    const HOST4: &str = "192.0.2.10";
    const HOST6: &str = "2001:db8::10";
    const RESOLVER4: &str = "198.51.100.53";
    const RESOLVER6: &str = "2001:db8:53::1";
    const PEER4: &str = "203.0.113.9";

    fn table() -> FlowTable {
        let mut t = FlowTable::new((32768, 60999));
        t.host_netns = None;
        t.host_addrs = [HOST4, HOST6].iter().map(|a| a.parse().unwrap()).collect();
        t
    }

    fn owner(pid: u32, comm: &str) -> Option<Owner> {
        Some(Owner {
            pid,
            comm: comm.into(),
            exe: None,
            container: None,
            unit: None,
            netns: None,
        })
    }

    /// An unconnected UDP socket in /proc/net/udp{,6}.
    fn sock(local: &str, port: u16, inode: u64, pid: u32, comm: &str) -> (ProcSock, Option<Owner>) {
        let local: IpAddr = local.parse().unwrap();
        let remote = if local.is_ipv4() {
            IpAddr::from([0u8; 4])
        } else {
            IpAddr::from([0u16; 8])
        };
        (
            ProcSock {
                proto: PROTO_UDP,
                local,
                lport: port,
                remote,
                rport: 0,
                state: 0x07,
                inode,
            },
            owner(pid, comm),
        )
    }

    fn scan(socks: Vec<(ProcSock, Option<Owner>)>) -> Scan {
        Scan {
            socks,
            containers: HashMap::new(),
        }
    }

    /// A DNS message with one question for www.example.test (type A, class IN).
    fn dns_msg(flags: u16, counts: [u16; 3]) -> Vec<u8> {
        let mut m = vec![0x5a, 0x17];
        m.extend_from_slice(&flags.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        for c in counts {
            m.extend_from_slice(&c.to_be_bytes());
        }
        m.extend_from_slice(b"\x03www\x07example\x04test\x00\x00\x01\x00\x01");
        m
    }

    fn query() -> Vec<u8> {
        dns_msg(0x0100, [0, 0, 0])
    }

    fn answer() -> Vec<u8> {
        dns_msg(0x8180, [0, 0, 0])
    }

    fn payload(key: FlowKey, out: bool, msg: &[u8]) -> PayloadEvent {
        let mut data = [0u8; PAYLOAD_CAP];
        data[..msg.len()].copy_from_slice(msg);
        PayloadEvent {
            ts_ns: 1,
            key,
            out: out as u8,
            kind: PL_DNS,
            len: msg.len() as u16,
            caplen: msg.len() as u16,
            _pad: [0; 6],
            data,
        }
    }

    fn send(t: &mut FlowTable, k: FlowKey, out: bool, msg: &[u8], now: i64) {
        t.observe_payload(&payload(k, out, msg), now);
    }

    /// The kernel flow map lists `k`, first packet seen from `initiator`.
    fn kernel_flow(t: &mut FlowTable, k: FlowKey, initiator: u8) {
        let ns = crate::util::boot_now_ns();
        let st = FlowStats {
            initiator,
            first_seen_ns: ns,
            last_seen_ns: ns,
            pkts_out: 1,
            bytes_out: 60,
            ..Default::default()
        };
        t.observe(
            vec![(k, st)],
            &[],
            &BootClock::new(),
            crate::util::now_unix(),
            1.0,
        );
    }

    fn events(t: &FlowTable) -> Vec<(&'static str, u16)> {
        t.events.iter().map(|e| (e.kind, e.lport)).collect()
    }

    fn role(t: &FlowTable, port: u16) -> SockRole {
        t.listeners[&(PROTO_UDP, port)].role
    }

    /// Baseline scan at 1000; the host's sockets are then scanned every 15 s.
    fn started(t: &mut FlowTable) {
        t.apply_scan(scan(vec![]), 1000);
    }

    /// The socket a resolver opens: bound first (scan sees it), then it queries
    /// and waits for the answer; `answered` says whether it ever comes.
    fn resolver_lifecycle(port: u16, answered: bool) {
        let mut t = table();
        started(&mut t);
        let s = || sock("0.0.0.0", port, 7, 100, "app");
        t.apply_scan(scan(vec![s()]), 1015);
        assert!(
            events(&t).is_empty(),
            "bound, nothing sent yet: no verdict, no event"
        );
        let k = key(HOST4, port, RESOLVER4, 53, PROTO_UDP);
        send(&mut t, k, true, &query(), 1016);
        if answered {
            send(&mut t, k, false, &answer(), 1016);
        }
        t.prune(1030);
        t.apply_scan(scan(vec![s()]), 1030);
        t.apply_scan(scan(vec![s()]), 1045);
        assert!(
            events(&t).is_empty(),
            "port {port}: a DNS client is not a new listener"
        );
        assert_eq!(role(&t, port), SockRole::Client);
        assert_eq!(
            t.listeners[&(PROTO_UDP, port)].role_reason,
            "sent DNS queries to 198.51.100.53:53"
        );
        // The resolver closes the socket.
        t.apply_scan(scan(vec![]), 1060);
        assert!(
            events(&t).is_empty(),
            "closing a client leaves no unlisten either"
        );
        assert!(t.listeners.is_empty());
    }

    #[test]
    fn dns_client_below_the_kernel_ephemeral_range_is_not_a_listener() {
        for port in [1024, 4242, 20000, 32767] {
            resolver_lifecycle(port, true);
        }
    }

    #[test]
    fn dns_client_inside_the_kernel_ephemeral_range_is_not_a_listener() {
        for port in [32768, 41641, 60999, 65000] {
            resolver_lifecycle(port, true);
        }
    }

    #[test]
    fn a_query_that_times_out_still_identifies_the_client() {
        resolver_lifecycle(5000, false);
        // The unanswered query is logged as a timeout and nothing else changes.
        let mut t = table();
        send(
            &mut t,
            key(HOST4, 5000, RESOLVER4, 53, PROTO_UDP),
            true,
            &query(),
            1016,
        );
        t.prune(1030);
        assert_eq!(t.dns_log.back().map(|r| r.rcode.as_str()), Some("TIMEOUT"));
    }

    #[test]
    fn a_query_sent_before_the_scan_lists_the_socket_counts_while_it_is_recent() {
        let mut t = table();
        started(&mut t);
        // Bound and queried between two scans, still open at the next one.
        send(
            &mut t,
            key(HOST4, 5000, RESOLVER4, 53, PROTO_UDP),
            true,
            &query(),
            1010,
        );
        t.apply_scan(scan(vec![sock("0.0.0.0", 5000, 7, 100, "app")]), 1015);
        t.apply_scan(scan(vec![sock("0.0.0.0", 5000, 7, 100, "app")]), 1030);
        assert!(events(&t).is_empty());
        assert_eq!(role(&t, 5000), SockRole::Client);

        // An older query may have come from some earlier socket on that port: ignored.
        let mut t = table();
        started(&mut t);
        send(
            &mut t,
            key(HOST4, 5000, RESOLVER4, 53, PROTO_UDP),
            true,
            &query(),
            1000,
        );
        t.apply_scan(scan(vec![sock("0.0.0.0", 5000, 8, 200, "svc")]), 1030);
        assert_eq!(role(&t, 5000), SockRole::Unknown);
        t.apply_scan(scan(vec![sock("0.0.0.0", 5000, 8, 200, "svc")]), 1045);
        assert_eq!(events(&t), [("listen", 5000)]);
        // And a query is used once.
        assert!(t.dns_seen.is_empty());
    }

    #[test]
    fn a_service_in_the_ephemeral_range_is_still_announced() {
        let mut t = table();
        started(&mut t);
        let s = || sock("0.0.0.0", 41641, 9, 300, "tailscaled");
        t.apply_scan(scan(vec![s()]), 1015);
        assert!(events(&t).is_empty(), "held for the settle time");
        t.apply_scan(scan(vec![s()]), 1030);
        assert_eq!(events(&t), [("listen", 41641)]);
        assert!(t.events[0].detail.contains("tailscaled"));
        let l = &t.listeners[&(PROTO_UDP, 41641)];
        assert!(
            l.ephemeral,
            "the port is in the kernel range: informational"
        );
        assert_eq!(l.role, SockRole::Unknown);
        // One event, not one per scan.
        t.apply_scan(scan(vec![s()]), 1045);
        assert_eq!(events(&t).len(), 1);
        t.apply_scan(scan(vec![]), 1060);
        assert_eq!(events(&t), [("listen", 41641), ("unlisten", 41641)]);
    }

    #[test]
    fn a_socket_that_vanishes_unexplained_is_still_reported() {
        let mut t = table();
        started(&mut t);
        t.apply_scan(scan(vec![sock("0.0.0.0", 5000, 7, 100, "app")]), 1015);
        t.apply_scan(scan(vec![]), 1030);
        assert_eq!(events(&t), [("listen", 5000), ("unlisten", 5000)]);
    }

    #[test]
    fn a_dns_server_stays_a_server() {
        let mut t = table();
        started(&mut t);
        let s = || sock(HOST4, 53, 3, 400, "dnsd");
        t.apply_scan(scan(vec![s()]), 1015);
        let k = key(HOST4, 53, PEER4, 40000, PROTO_UDP);
        send(&mut t, k, false, &query(), 1016);
        send(&mut t, k, true, &answer(), 1016);
        assert_eq!(role(&t, 53), SockRole::Server);
        assert_eq!(
            t.listeners[&(PROTO_UDP, 53)].role_reason,
            "receives DNS queries from 203.0.113.9:40000"
        );
        kernel_flow(&mut t, k, INIT_REMOTE);
        assert_eq!(t.active[&k].dir, Dir::In);
        t.apply_scan(scan(vec![s()]), 1030);
        assert_eq!(
            events(&t),
            [("listen", 53)],
            "a service is announced without waiting for the settle time"
        );

        // Another client of the same server, first seen as our answer (netwatch missed the query).
        let k2 = key(HOST4, 53, "203.0.113.10", 40001, PROTO_UDP);
        kernel_flow(&mut t, k2, INIT_LOCAL);
        assert_eq!(
            t.active[&k2].dir,
            Dir::In,
            "answers go out of a server socket"
        );
    }

    #[test]
    fn an_answer_alone_marks_the_socket_a_server() {
        let mut t = table();
        started(&mut t);
        t.apply_scan(scan(vec![sock("0.0.0.0", 53, 3, 400, "dnsd")]), 1015);
        let k = key(HOST4, 53, PEER4, 40000, PROTO_UDP);
        send(&mut t, k, true, &answer(), 1016);
        kernel_flow(&mut t, k, INIT_LOCAL);
        assert_eq!(t.active[&k].dir, Dir::In);
        assert_eq!(role(&t, 53), SockRole::Server);
        assert_eq!(
            t.listeners[&(PROTO_UDP, 53)].role_reason,
            "answers DNS queries from 203.0.113.9:40000"
        );
    }

    #[test]
    fn one_process_with_a_server_and_client_sockets_is_classified_per_socket() {
        let mut t = table();
        started(&mut t);
        let socks = || {
            vec![
                sock("0.0.0.0", 53, 1, 500, "dnsd"),
                sock("0.0.0.0", 2000, 2, 500, "dnsd"),
            ]
        };
        t.apply_scan(scan(socks()), 1015);
        // Upstream query from the client socket, query from a client of the server.
        let up = key(HOST4, 2000, RESOLVER4, 53, PROTO_UDP);
        let down = key(HOST4, 53, PEER4, 40000, PROTO_UDP);
        send(&mut t, up, true, &query(), 1016);
        send(&mut t, down, false, &query(), 1016);
        kernel_flow(&mut t, up, INIT_LOCAL);
        kernel_flow(&mut t, down, INIT_REMOTE);
        assert_eq!(
            (role(&t, 2000), role(&t, 53)),
            (SockRole::Client, SockRole::Server)
        );
        assert_eq!(
            (t.active[&up].dir, t.active[&down].dir),
            (Dir::Out, Dir::In)
        );
        t.apply_scan(scan(socks()), 1030);
        assert_eq!(
            events(&t),
            [("listen", 53)],
            "only the real service is announced"
        );
    }

    #[test]
    fn a_resolver_on_port_53_is_not_taken_for_a_client() {
        // BIND-style query-source port 53: the socket that serves is the one that asks.
        let mut t = table();
        started(&mut t);
        let s = || sock("0.0.0.0", 53, 1, 500, "dnsd");
        t.apply_scan(scan(vec![s()]), 1015);
        send(
            &mut t,
            key(HOST4, 53, RESOLVER4, 53, PROTO_UDP),
            true,
            &query(),
            1016,
        );
        assert_eq!(role(&t, 53), SockRole::Unknown);
        t.apply_scan(scan(vec![s()]), 1030);
        assert_eq!(events(&t), [("listen", 53)]);
    }

    #[test]
    fn malformed_or_non_dns_traffic_to_port_53_gets_no_exemption() {
        let ok = query();
        let mut cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "not dns",
                b"GET / HTTP/1.1\r\nHost: www.example.test\r\n\r\n".to_vec(),
            ),
            ("noise", vec![0x41; 40]),
            ("empty", Vec::new()),
            ("truncated header", ok[..6].to_vec()),
            ("cut inside the name", ok[..16].to_vec()),
            ("update opcode", dns_msg(0x2800, [0, 0, 0])),
            ("authoritative flag", dns_msg(0x0500, [0, 0, 0])),
            ("records in a query", dns_msg(0x0100, [1, 0, 0])),
            ("rcode in a query", dns_msg(0x0103, [0, 0, 0])),
        ];
        // A query that claims to have no question.
        let mut no_question = ok.clone();
        no_question[4..6].copy_from_slice(&0u16.to_be_bytes());
        cases.push(("no question", no_question));
        for (what, msg) in cases {
            let mut t = table();
            started(&mut t);
            let s = || sock("0.0.0.0", 5000, 7, 100, "app");
            t.apply_scan(scan(vec![s()]), 1015);
            let k = key(HOST4, 5000, RESOLVER4, 53, PROTO_UDP);
            send(&mut t, k, true, &msg, 1016);
            // An inbound "answer" is not evidence either: anyone can send one.
            send(&mut t, k, false, &answer(), 1016);
            assert_eq!(role(&t, 5000), SockRole::Unknown, "{what}");
            assert!(t.dns_seen.is_empty(), "{what}");
            t.apply_scan(scan(vec![s()]), 1030);
            assert_eq!(
                events(&t),
                [("listen", 5000)],
                "{what}: the listener is still announced"
            );
        }
    }

    #[test]
    fn a_reused_port_does_not_inherit_the_old_sockets_verdict() {
        let mut t = table();
        started(&mut t);
        let old = || sock("0.0.0.0", 3000, 1, 100, "app");
        t.apply_scan(scan(vec![old()]), 1015);
        send(
            &mut t,
            key(HOST4, 3000, RESOLVER4, 53, PROTO_UDP),
            true,
            &query(),
            1016,
        );
        t.apply_scan(scan(vec![old()]), 1030);
        assert_eq!(role(&t, 3000), SockRole::Client);
        // Closed and rebound by a new socket of the same pid between two scans.
        let new = || sock("0.0.0.0", 3000, 2, 100, "app");
        t.apply_scan(scan(vec![new()]), 1045);
        assert_eq!(
            role(&t, 3000),
            SockRole::Unknown,
            "new inode: no evidence carried over"
        );
        assert!(
            events(&t).is_empty(),
            "the settle time starts over for the new socket"
        );
        t.apply_scan(scan(vec![new()]), 1060);
        assert_eq!(events(&t), [("listen", 3000)]);

        // The listener went away completely and a different process took the port.
        t.apply_scan(scan(vec![]), 1075);
        t.apply_scan(scan(vec![sock("0.0.0.0", 3000, 3, 900, "other")]), 1090);
        assert_eq!(role(&t, 3000), SockRole::Unknown);
    }

    #[test]
    fn ipv6_and_wildcard_sockets_take_only_their_own_queries() {
        let mut t = table();
        started(&mut t);
        // A dual-stack wildcard, an IPv4-only wildcard and an unrelated port.
        let socks = || {
            vec![
                sock("::", 4000, 1, 100, "app"),
                sock("0.0.0.0", 4001, 2, 100, "app"),
                sock("::", 4001, 3, 100, "app"),
                sock("0.0.0.0", 4002, 4, 100, "app"),
            ]
        };
        t.apply_scan(scan(socks()), 1015);
        // IPv6 query from the dual-stack socket; IPv4 query from the same wildcard.
        send(
            &mut t,
            key(HOST6, 4000, RESOLVER6, 53, PROTO_UDP),
            true,
            &query(),
            1016,
        );
        assert_eq!(role(&t, 4000), SockRole::Client);
        // On 4001 an IPv4 query belongs to 0.0.0.0, not to the IPv6 socket.
        send(
            &mut t,
            key(HOST4, 4001, RESOLVER4, 53, PROTO_UDP),
            true,
            &query(),
            1016,
        );
        let l = &t.listeners[&(PROTO_UDP, 4001)];
        let r4 = l.socks[&"0.0.0.0".parse::<IpAddr>().unwrap()].role;
        let r6 = l.socks[&"::".parse::<IpAddr>().unwrap()].role;
        assert_eq!(
            (r4, r6, l.role),
            (SockRole::Client, SockRole::Unknown, SockRole::Unknown)
        );
        // Nothing leaks to a port nobody queried from.
        assert_eq!(role(&t, 4002), SockRole::Unknown);
        t.apply_scan(scan(socks()), 1030);
        // 4001 is only half explained and 4002 not at all; 4000 is a client.
        assert_eq!(events(&t), [("listen", 4001), ("listen", 4002)]);
    }

    #[test]
    fn a_dual_stack_socket_takes_ipv4_queries_when_nothing_closer_exists() {
        let mut t = table();
        started(&mut t);
        t.apply_scan(scan(vec![sock("::", 4000, 1, 100, "app")]), 1015);
        send(
            &mut t,
            key(HOST4, 4000, RESOLVER4, 53, PROTO_UDP),
            true,
            &query(),
            1016,
        );
        assert_eq!(role(&t, 4000), SockRole::Client);
    }

    #[test]
    fn queries_from_other_hosts_or_containers_do_not_classify_host_sockets() {
        let mut t = table();
        started(&mut t);
        t.container_ips
            .insert("172.17.0.2".parse().unwrap(), owner(700, "app").unwrap());
        t.apply_scan(scan(vec![sock("0.0.0.0", 5000, 7, 100, "svc")]), 1015);
        // A container resolver and a forwarded client happen to use the same source port.
        send(
            &mut t,
            key("172.17.0.2", 5000, RESOLVER4, 53, PROTO_UDP),
            true,
            &query(),
            1016,
        );
        send(
            &mut t,
            key("203.0.113.77", 5000, RESOLVER4, 53, PROTO_UDP),
            true,
            &query(),
            1016,
        );
        assert_eq!(role(&t, 5000), SockRole::Unknown);
        assert!(t.dns_seen.is_empty());
    }

    #[test]
    fn outbound_dns_is_outbound_whatever_the_source_port() {
        for port in [1024, 5000, 32767, 32768, 41641, 60999, 65000] {
            // With DNS sampling: the query itself says so.
            let mut t = table();
            started(&mut t);
            t.apply_scan(scan(vec![sock("0.0.0.0", port, 7, 100, "app")]), 1015);
            let k = key(HOST4, port, RESOLVER4, 53, PROTO_UDP);
            send(&mut t, k, true, &query(), 1016);
            kernel_flow(&mut t, k, INIT_LOCAL);
            assert_eq!(t.active[&k].dir, Dir::Out, "port {port}");
            let m = t.series.back().unwrap();
            assert_eq!((m.new_out, m.new_in), (1, 0), "port {port}");

            // Without it: the bound socket proves nothing, the first packet does.
            let mut t = table();
            started(&mut t);
            t.apply_scan(scan(vec![sock("0.0.0.0", port, 7, 100, "app")]), 1015);
            kernel_flow(&mut t, k, INIT_LOCAL);
            assert_eq!(t.active[&k].dir, Dir::Out, "port {port}, no payload sample");
        }
    }

    #[test]
    fn udp_direction_prefers_observed_evidence_to_ports() {
        let eph = (32768, 60999);
        let none = UdpHint::default();
        let local = FlowStats {
            initiator: INIT_LOCAL,
            ..Default::default()
        };
        let remote = FlowStats {
            initiator: INIT_REMOTE,
            ..Default::default()
        };
        let unseen = FlowStats::default();
        let client = key(HOST4, 5000, RESOLVER4, 53, PROTO_UDP);
        // `listening` (a bound socket) no longer turns an outbound flow around.
        assert_eq!(guess_dir(&client, &local, true, eph, none), Dir::Out);
        assert_eq!(guess_dir(&client, &remote, true, eph, none), Dir::In);
        // DNS evidence wins over the first packet and over ports.
        let out = UdpHint {
            dns: Some(Dir::Out),
            server: false,
        };
        assert_eq!(guess_dir(&client, &remote, true, eph, out), Dir::Out);
        let serving = UdpHint {
            dns: None,
            server: true,
        };
        assert_eq!(
            guess_dir(
                &key(HOST4, 53, PEER4, 40000, PROTO_UDP),
                &local,
                true,
                eph,
                serving
            ),
            Dir::In
        );
        // Nothing saw the start: a client of a well-known port is outbound, a bound service is not guessed.
        assert_eq!(guess_dir(&client, &unseen, true, eph, none), Dir::Out);
        assert_eq!(
            guess_dir(
                &key(HOST4, 41641, PEER4, 41641, PROTO_UDP),
                &unseen,
                true,
                eph,
                none
            ),
            Dir::Unknown
        );
        assert_eq!(
            guess_dir(
                &key(HOST4, 53, PEER4, 40000, PROTO_UDP),
                &unseen,
                true,
                eph,
                none
            ),
            Dir::Unknown
        );
        // TCP keeps its handshake rules.
        let tcp = key(HOST4, 22, PEER4, 50000, PROTO_TCP);
        assert_eq!(guess_dir(&tcp, &unseen, true, eph, none), Dir::In);
        assert_eq!(guess_dir(&tcp, &local, true, eph, none), Dir::Out);
    }

    #[test]
    fn evidence_and_hints_stay_bounded_and_expire() {
        let mut t = table();
        for i in 0..5000u16 {
            send(
                &mut t,
                key(HOST4, 10_000 + i, RESOLVER4, 53, PROTO_UDP),
                true,
                &query(),
                1000,
            );
        }
        assert!(t.dns_seen.len() <= 4096);
        assert_eq!(t.dns_flow.len(), 5000);
        t.prune(1000 + DNS_SEEN_TTL + 1);
        assert!(t.dns_seen.is_empty());
        t.prune(1000 + DNS_FLOW_TTL + 1);
        assert!(t.dns_flow.is_empty());
    }
}
