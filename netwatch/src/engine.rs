//! Turns raw kernel counters, probe events and SSH log events into per-source
//! findings, scores and policy decisions.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    net::IpAddr,
    sync::Arc,
};

use ipnet::IpNet;
use netwatch_common::{
    GlobalStats, IPOPT_OTHER, IPOPT_RR, IPOPT_TS, PROTO_TCP, PROTO_UDP, ProbeEvent, ProbeKey,
    ProbeStats, SrcStats,
};
use serde::Serialize;

use crate::{
    config::Config,
    flows::{Dir, InboundRequest, Listener},
    geo::{Geo, GeoInfo},
    intel::{FeedHit, Feeds, Listening, listed_on},
    policy::{self, Action, Rule, Subject},
    procs::Owner,
    util::{BootClock, is_public, key_to_ip, neighbourhood, port_label, proto_name, service_name},
};

const MAX_PORTS_PER_SOURCE: usize = 4096;
const MAX_EVENTS: usize = 500;
const MAX_STATES: usize = 200_000;
/// Findings from SSH logs (logins) stay visible this long.
const SSH_FLAG_SECS: i64 = 86_400;

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Counters {
    pub packets: u64,
    pub bytes: u64,
    pub in_packets: u64,
    pub in_bytes: u64,
    pub syn: u64,
    pub udp_in: u64,
    pub icmp_in: u64,
    pub blocked: u64,
    /// IPv4 TCP SYNs carrying IP options (CVE-2026-98432 trigger).
    pub ipopt_syn: u64,
}

impl Counters {
    fn from_kernel(s: &SrcStats) -> Self {
        Self {
            packets: s.packets,
            bytes: s.bytes,
            in_packets: s.in_packets,
            in_bytes: s.in_bytes,
            syn: s.syn,
            udp_in: s.udp_in,
            icmp_in: s.icmp_in,
            blocked: s.blocked,
            ipopt_syn: s.ipopt_syn,
        }
    }

    /// Delta between two cumulative snapshots; a shrinking counter means the
    /// LRU entry was evicted and recreated, so the new snapshot is all new.
    fn since(&self, prev: &Self) -> Self {
        if self.packets < prev.packets {
            return *self;
        }
        Self {
            packets: self.packets - prev.packets,
            bytes: self.bytes.saturating_sub(prev.bytes),
            in_packets: self.in_packets.saturating_sub(prev.in_packets),
            in_bytes: self.in_bytes.saturating_sub(prev.in_bytes),
            syn: self.syn.saturating_sub(prev.syn),
            udp_in: self.udp_in.saturating_sub(prev.udp_in),
            icmp_in: self.icmp_in.saturating_sub(prev.icmp_in),
            blocked: self.blocked.saturating_sub(prev.blocked),
            ipopt_syn: self.ipopt_syn.saturating_sub(prev.ipopt_syn),
        }
    }

    fn add(&mut self, o: &Self) {
        self.packets += o.packets;
        self.bytes += o.bytes;
        self.in_packets += o.in_packets;
        self.in_bytes += o.in_bytes;
        self.syn += o.syn;
        self.udp_in += o.udp_in;
        self.icmp_in += o.icmp_in;
        self.blocked += o.blocked;
        self.ipopt_syn += o.ipopt_syn;
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Rates {
    pub in_pps: f64,
    pub in_bps: f64,
    pub syn_ps: f64,
    #[serde(skip)]
    pub icmp_ps: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub kind: &'static str,
    pub score: u32,
    pub summary: String,
}

pub struct PortState {
    pub proto: u8,
    pub port: u16,
    pub first_seen: i64,
    pub last_seen: i64,
    pub packets: u64,
    pub syn: u64,
    /// UDP from a remote this host sent UDP to, from the local port that did:
    /// an answer to our own query (a resolver replying to a client port), not a probe.
    pub reply: bool,
    /// SYNs per minute (unix minute, count), last 10 minutes.
    syn_minutes: VecDeque<(i64, u64)>,
}

impl PortState {
    fn syn_since(&self, minute: i64) -> u64 {
        self.syn_minutes
            .iter()
            .filter(|(m, _)| *m >= minute)
            .map(|(_, n)| n)
            .sum()
    }
}

#[derive(Default)]
pub struct SshTally {
    pub failed: VecDeque<i64>,
    pub invalid_users: BTreeSet<String>,
    /// Connections (source port, user) whose "Invalid user" line was counted
    /// and whose first failed password hasn't been seen yet.
    pub invalid_conns: VecDeque<(u16, Option<String>)>,
    pub failed_total: u64,
    pub accepted: u64,
    pub last_event: i64,
    /// Login anomalies with the time they were seen.
    pub flags: Vec<(i64, Finding)>,
}

pub struct IpState {
    pub ip: IpAddr,
    pub geo: GeoInfo,
    pub location: String,
    pub feeds: Vec<String>,
    /// The listed range and meaning behind each of `feeds`.
    pub feed_hits: Vec<FeedHit>,
    pub allowlisted: bool,
    pub banned: bool,
    pub first_seen: i64,
    pub last_seen: i64,
    pub last_inbound: i64,
    pub total: Counters,
    pub rate: Rates,
    pub ports: HashMap<(u8, u16), PortState>,
    pub ssh: SshTally,
    /// The last few requests this source sent to our services.
    pub requests: VecDeque<InboundRequest>,
    /// Requests that matched a known exploit.
    pub exploits: Vec<InboundRequest>,
    /// When this source last sent a SYN carrying IPv4 options, and which `IPOPT_*` kinds.
    pub ipopt_last: i64,
    pub ipopt_kinds: u64,
    /// When `ipopt_alerts_due` last reported this source.
    ipopt_alerted: i64,
    pub findings: Vec<Finding>,
    pub score: u32,
    pending_hour: Counters,
    reported: HashMap<&'static str, (u32, i64)>,
}

impl IpState {
    pub fn last_activity(&self) -> i64 {
        self.last_inbound.max(self.ssh.last_event)
    }

    pub fn kinds(&self) -> Vec<&str> {
        self.findings.iter().map(|f| f.kind).collect()
    }

    /// Distinct local ports touched within `secs`.
    pub fn ports_within(&self, now: i64, secs: i64) -> usize {
        self.ports
            .values()
            .filter(|p| p.last_seen >= now - secs)
            .count()
    }

    pub fn ssh_failed_within(&self, now: i64, secs: i64) -> u64 {
        self.ssh.failed.iter().filter(|t| **t >= now - secs).count() as u64
    }

    /// Compact one-line description for logs and the LLM digest.
    pub fn digest_line(&self, now: i64) -> String {
        let mut ports: Vec<&PortState> = self
            .ports
            .values()
            .filter(|p| p.last_seen >= now - 3600)
            .collect();
        ports.sort_by_key(|p| std::cmp::Reverse(p.syn.max(p.packets)));
        let ports: Vec<String> = ports
            .iter()
            .take(8)
            .map(|p| format!("{}/{}", p.port, proto_name(p.proto)))
            .collect();
        let kinds: Vec<String> = self
            .findings
            .iter()
            .map(|f| format!("{}:{}", f.kind, f.score))
            .collect();
        let mut line = format!(
            "{} {} score={} findings=[{}] ports({})=[{}] syn={} in_pkts={}",
            self.ip,
            self.location,
            self.score,
            kinds.join(","),
            self.ports_within(now, 3600),
            ports.join(","),
            self.total.syn,
            self.total.in_packets,
        );
        if self.ssh.failed_total > 0 || self.ssh.accepted > 0 {
            line.push_str(&format!(
                " ssh_failed={} ssh_invalid_users={} ssh_ok={}",
                self.ssh.failed_total,
                self.ssh.invalid_users.len(),
                self.ssh.accepted
            ));
        }
        if !self.feeds.is_empty() {
            line.push_str(&format!(" feeds={}", self.feeds.join(",")));
        }
        line
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct SeriesPoint {
    pub ts: i64,
    pub pps: f64,
    pub in_pps: f64,
    pub syn_pps: f64,
    pub dropped_pps: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventView {
    pub ts: i64,
    pub ip: String,
    pub proto: &'static str,
    pub port: u16,
    pub service: Option<&'static str>,
    pub tcp_flags: u8,
    pub ttl: u8,
    pub location: String,
}

/// Parsed SSH log line.
#[derive(Debug, Clone)]
pub struct SshEvent {
    pub ts: i64,
    pub kind: &'static str,
    pub user: Option<String>,
    pub ip: IpAddr,
    pub method: Option<String>,
    /// The client's source port, which tells one connection's lines apart.
    pub port: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub ip: IpAddr,
    pub rule: Rule,
    pub reason: String,
    /// A possible compromise (odd login, talking to a listed host): worth a ping even as a review.
    pub urgent: bool,
}

pub struct AlertDue {
    pub ip: String,
    pub kind: &'static str,
    pub score: u32,
    pub summary: String,
    pub location: String,
}

/// A source that sent the CVE-2026-98432 trigger, whatever its policy state.
pub struct IpoptAlert {
    pub ip: IpAddr,
    pub location: String,
    pub syn: u64,
    pub options: String,
    pub allowlisted: bool,
    pub banned: bool,
}

fn ipopt_names(kinds: u64) -> String {
    let mut opts: Vec<&str> = Vec::new();
    for (bit, name) in [
        (IPOPT_RR, "Record Route"),
        (IPOPT_TS, "Timestamp"),
        (IPOPT_OTHER, "other"),
    ] {
        if kinds & bit != 0 {
            opts.push(name);
        }
    }
    opts.join(", ")
}

pub struct HourDeltaOwned {
    pub ip: String,
    pub country: String,
    pub location: String,
    pub delta: Counters,
    pub score: u32,
}

pub struct Engine {
    pub cfg: Arc<Config>,
    pub clock: BootClock,
    pub geo: Geo,
    pub feeds: Feeds,
    pub listening: Listening,
    pub allow: Vec<IpNet>,
    pub bans: BTreeMap<IpNet, crate::store::BanRow>,
    pub user_rules: Vec<Rule>,
    pub default_rules: Vec<Rule>,
    pub states: HashMap<IpAddr, IpState>,
    pub global: GlobalStats,
    pub rates: SeriesPoint,
    pub series: VecDeque<SeriesPoint>,
    pub events: VecDeque<EventView>,
    /// `sshd -T` says passwords are accepted.
    pub sshd_password_auth: Option<bool>,
    pub flows: crate::flows::FlowTable,
    /// Bytes per group over time, for windowed totals.
    pub bytes: crate::window::ByteWindows,
    pub ifaces: Vec<crate::flows::IfStat>,
    /// Requests temps reported since the last tick (see temps.rs).
    pub temps_requests: Vec<InboundRequest>,
    prev_global: Option<GlobalStats>,
    /// Each kernel source entry's counters at the last tick, kept for as long as
    /// the kernel keeps the entry: a source forgotten here while the kernel still
    /// lists it must not have its all-time totals read back as new traffic.
    kernel_sources: HashMap<[u8; 16], Counters>,
    /// The same for per-port entries: (packets, SYNs).
    kernel_probes: HashMap<ProbeKey, (u64, u64)>,
}

fn minute(ts: i64) -> i64 {
    ts.div_euclid(60)
}

impl Engine {
    pub fn new(cfg: Arc<Config>, geo: Geo, eph: (u16, u16)) -> Self {
        Self {
            cfg,
            clock: BootClock::new(),
            geo,
            feeds: Feeds::default(),
            listening: Listening::scan(),
            allow: Vec::new(),
            bans: BTreeMap::new(),
            user_rules: Vec::new(),
            default_rules: policy::defaults(),
            states: HashMap::new(),
            global: GlobalStats::default(),
            rates: SeriesPoint::default(),
            series: VecDeque::new(),
            events: VecDeque::new(),
            sshd_password_auth: None,
            flows: crate::flows::FlowTable::new(eph),
            bytes: Default::default(),
            ifaces: Vec::new(),
            temps_requests: Vec::new(),
            prev_global: None,
            kernel_sources: HashMap::new(),
            kernel_probes: HashMap::new(),
        }
    }

    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        self.allow.iter().any(|n| n.contains(&ip))
    }

    pub fn ban_for(&self, ip: IpAddr) -> Option<&crate::store::BanRow> {
        self.bans
            .iter()
            .find(|(n, _)| n.contains(&ip))
            .map(|(_, b)| b)
    }

    pub fn set_allow(&mut self, allow: Vec<IpNet>) {
        self.allow = allow;
        for st in self.states.values_mut() {
            st.allowlisted = self.allow.iter().any(|n| n.contains(&st.ip));
        }
    }

    /// Queues a request temps reported for the next evaluation; drops it past 10 000 per tick.
    pub fn observe_temps(&mut self, r: InboundRequest) {
        if self.temps_requests.len() < 10_000 {
            self.temps_requests.push(r);
        }
    }

    pub fn set_bans(&mut self, bans: BTreeMap<IpNet, crate::store::BanRow>) {
        self.bans = bans;
        for st in self.states.values_mut() {
            st.banned = self.bans.keys().any(|n| n.contains(&st.ip));
        }
    }

    /// Re-checks every tracked source against freshly loaded threat feeds.
    /// Replaces the lists that were fetched; lists whose fetch failed keep their last copy.
    pub fn set_feeds(&mut self, mut feeds: Feeds) {
        let fresh: Vec<String> = feeds.lists.iter().map(|l| l.name.clone()).collect();
        let old = std::mem::take(&mut self.feeds.lists);
        feeds
            .lists
            .extend(old.into_iter().filter(|o| !fresh.contains(&o.name)));
        self.feeds = feeds;
        for st in self.states.values_mut() {
            st.feed_hits = self.feeds.hits(st.ip);
            st.feeds = st.feed_hits.iter().map(|h| h.name.clone()).collect();
        }
    }

    pub fn state(&mut self, ip: IpAddr, now: i64) -> &mut IpState {
        if !self.states.contains_key(&ip) {
            let geo = self.geo.lookup(ip);
            let feed_hits = self.feeds.hits(ip);
            let st = IpState {
                ip,
                location: geo.short(),
                geo,
                feeds: feed_hits.iter().map(|h| h.name.clone()).collect(),
                feed_hits,
                allowlisted: self.is_allowed(ip),
                banned: self.ban_for(ip).is_some(),
                first_seen: now,
                last_seen: now,
                last_inbound: 0,
                total: Counters::default(),
                rate: Rates::default(),
                ports: HashMap::new(),
                ssh: SshTally::default(),
                requests: VecDeque::new(),
                exploits: Vec::new(),
                ipopt_last: 0,
                ipopt_kinds: 0,
                ipopt_alerted: 0,
                findings: Vec::new(),
                score: 0,
                pending_hour: Counters::default(),
                reported: HashMap::new(),
            };
            self.states.insert(ip, st);
        }
        self.states.get_mut(&ip).expect("inserted above")
    }

    pub fn observe_global(&mut self, g: GlobalStats, now: i64, dt: f64) {
        if let Some(p) = self.prev_global {
            let r = |a: u64, b: u64| a.saturating_sub(b) as f64 / dt;
            self.rates = SeriesPoint {
                ts: now,
                pps: r(g.packets, p.packets),
                in_pps: r(g.in_packets, p.in_packets),
                syn_pps: r(g.syn, p.syn),
                dropped_pps: r(g.dropped, p.dropped),
            };
            self.series.push_back(self.rates);
            let keep = (1800 / self.cfg.tick_secs.max(1)) as usize;
            while self.series.len() > keep {
                self.series.pop_front();
            }
        }
        self.prev_global = Some(g);
        self.global = g;
    }

    pub fn observe_sources(&mut self, sources: Vec<([u8; 16], SrcStats)>, now: i64, dt: f64) {
        for st in self.states.values_mut() {
            st.rate = Rates::default();
        }
        let clock = self.clock;
        let mut seen = HashMap::with_capacity(sources.len());
        for (key, s) in sources {
            // A walk over a changing map can list a key twice; count it once.
            if seen.contains_key(&key) {
                continue;
            }
            let cur = Counters::from_kernel(&s);
            seen.insert(key, cur);
            let d = match self.kernel_sources.get(&key) {
                Some(prev) => cur.since(prev),
                None => cur,
            };
            if d.packets == 0 && d.blocked == 0 {
                continue;
            }
            let st = self.state(key_to_ip(key), now);
            st.total.add(&d);
            st.pending_hour.add(&d);
            st.last_seen = clock.to_unix(s.last_seen_ns).min(now);
            st.first_seen = st.first_seen.min(clock.to_unix(s.first_seen_ns));
            if d.in_packets > 0 {
                st.last_inbound = now;
            }
            if d.ipopt_syn > 0 {
                st.ipopt_last = now;
                st.ipopt_kinds |= s.ipopt_kinds;
            }
            st.rate = Rates {
                in_pps: d.in_packets as f64 / dt,
                in_bps: d.in_bytes as f64 * 8.0 / dt,
                syn_ps: d.syn as f64 / dt,
                icmp_ps: d.icmp_in as f64 / dt,
            };
        }
        self.kernel_sources = seen;
    }

    pub fn observe_probes(&mut self, probes: Vec<(ProbeKey, ProbeStats)>, now: i64) {
        let clock = self.clock;
        let this_minute = minute(now);
        let mut seen = HashMap::with_capacity(probes.len());
        let mut fresh = Vec::new();
        for (k, p) in probes {
            if seen.contains_key(&k) {
                continue;
            }
            seen.insert(k, (p.packets, p.syn));
            let (dp, ds) = match self.kernel_probes.get(&k) {
                Some(&(packets, syn)) if p.packets >= packets => {
                    (p.packets - packets, p.syn.saturating_sub(syn))
                }
                // New, or evicted and recreated (the counter shrank): all of it is new.
                _ => (p.packets, p.syn),
            };
            if dp > 0 {
                fresh.push((k, p, dp, ds));
            }
        }
        self.kernel_probes = seen;
        // The XDP program calls UDP to a port outside the kernel's ephemeral range
        // "inbound", but resolvers answer client sockets on any port (Hickory picks
        // 1024-65535). Whether a UDP source is answering us comes from the flows this
        // host opened (remote address + local port), built only when a UDP port is undecided.
        let undecided = |e: &Self, k: &ProbeKey| {
            k.proto == PROTO_UDP
                && !e
                    .states
                    .get(&key_to_ip(k.addr))
                    .and_then(|s| s.ports.get(&(k.proto, k.port)))
                    .is_some_and(|ps| ps.reply)
        };
        let replies: HashSet<(IpAddr, u16)> = if fresh.iter().any(|(k, ..)| undecided(self, k)) {
            self.flows
                .active
                .values()
                .filter(|f| f.key.proto == PROTO_UDP && f.dir == Dir::Out)
                .map(|f| (f.remote, f.key.lport))
                .collect()
        } else {
            HashSet::new()
        };
        for (k, p, dp, ds) in fresh {
            let ip = key_to_ip(k.addr);
            let st = self.state(ip, now);
            let key = (k.proto, k.port);
            if !st.ports.contains_key(&key) && st.ports.len() >= MAX_PORTS_PER_SOURCE {
                continue;
            }
            let ps = st.ports.entry(key).or_insert_with(|| PortState {
                proto: k.proto,
                port: k.port,
                first_seen: clock.to_unix(p.first_seen_ns).min(now),
                last_seen: 0,
                packets: 0,
                syn: 0,
                reply: false,
                syn_minutes: VecDeque::new(),
            });
            if k.proto == PROTO_UDP && !ps.reply && replies.contains(&(ip, k.port)) {
                ps.reply = true;
            }
            ps.packets += dp;
            ps.syn += ds;
            ps.last_seen = clock.to_unix(p.last_seen_ns).min(now);
            if ds > 0 {
                match ps.syn_minutes.back_mut() {
                    Some((m, n)) if *m == this_minute => *n += ds,
                    _ => ps.syn_minutes.push_back((this_minute, ds)),
                }
                while ps
                    .syn_minutes
                    .front()
                    .is_some_and(|(m, _)| *m < this_minute - 10)
                {
                    ps.syn_minutes.pop_front();
                }
            }
        }
    }

    pub fn observe_event(&mut self, ev: &ProbeEvent) {
        let now = crate::util::now_unix();
        let ts = self.clock.to_unix(ev.ts_ns).min(now);
        let st = self.state(key_to_ip(ev.addr), now);
        let view = EventView {
            ts,
            ip: st.ip.to_string(),
            proto: proto_name(ev.proto),
            port: ev.port,
            service: service_name(ev.port),
            tcp_flags: ev.tcp_flags,
            ttl: ev.ttl,
            location: st.location.clone(),
        };
        if st.allowlisted {
            return;
        }
        self.events.push_front(view);
        self.events.truncate(MAX_EVENTS);
    }

    /// `known_locations`: where this user logged in from before (from the store).
    pub fn observe_ssh(&mut self, ev: &SshEvent, known_locations: &[String]) -> String {
        let now = crate::util::now_unix();
        let st = self.state(ev.ip, now);
        st.ssh.last_event = st.ssh.last_event.max(ev.ts);
        let public = is_public(ev.ip);
        match ev.kind {
            "failed" | "invalid_user" => {
                // A server that only takes keys logs "Invalid user" and never
                // "Failed password", so that line is the failed attempt. With
                // passwords, it comes just before the connection's first
                // "Failed password for invalid user", the same attempt; the
                // source port pairs the two. Each later password counts.
                let conn = ev.port.map(|p| (p, ev.user.clone()));
                let counted = if ev.kind == "invalid_user" {
                    if let Some(c) = conn {
                        st.ssh.invalid_conns.push_back(c);
                        if st.ssh.invalid_conns.len() > 64 {
                            st.ssh.invalid_conns.pop_front();
                        }
                    }
                    true
                } else {
                    let pending =
                        conn.and_then(|c| st.ssh.invalid_conns.iter().position(|x| *x == c));
                    pending.map(|i| st.ssh.invalid_conns.remove(i)).is_none()
                };
                if counted {
                    st.ssh.failed.push_back(ev.ts);
                    st.ssh.failed_total += 1;
                    while st.ssh.failed.len() > 1000 {
                        st.ssh.failed.pop_front();
                    }
                }
                if let Some(u) = &ev.user
                    && st.ssh.invalid_users.len() < 200
                    && ev.kind == "invalid_user"
                {
                    st.ssh.invalid_users.insert(u.clone());
                }
            }
            "accepted" | "tailscale_login" => {
                st.ssh.accepted += 1;
                let user = ev.user.as_deref().unwrap_or("?");
                let failures = st.ssh.failed.iter().filter(|t| **t >= ev.ts - 3600).count();
                if public && failures >= 5 {
                    st.ssh.flags.push((
                        ev.ts,
                        Finding {
                            kind: "login_after_failures",
                            score: 90,
                            summary: format!(
                                "SSH login as {user} succeeded after {failures} failed attempts in the last hour — possible compromise"
                            ),
                        },
                    ));
                }
                if public && !known_locations.is_empty() && !known_locations.contains(&st.location)
                {
                    st.ssh.flags.push((
                        ev.ts,
                        Finding {
                            kind: "new_login_location",
                            score: 55,
                            summary: format!(
                                "SSH login as {user} from {} — never seen for this user in 90 days (before: {})",
                                st.location,
                                known_locations.join("; ")
                            ),
                        },
                    ));
                }
            }
            _ => {}
        }
        st.location.clone()
    }

    /// Recomputes findings and scores for every recently active source.
    pub fn evaluate(&mut self, now: i64) {
        let reported = std::mem::take(&mut self.temps_requests);
        for r in std::mem::take(&mut self.flows.requests)
            .into_iter()
            .chain(reported)
        {
            let st = self.state(r.remote, now);
            if r.via_temps {
                // A client behind a CDN or tunnel never reaches XDP itself: the request is its activity.
                st.last_inbound = st.last_inbound.max(r.ts);
                st.last_seen = st.last_seen.max(r.ts);
            }
            if r.exploit.is_some() {
                if st.exploits.len() >= 20 {
                    st.exploits.remove(0);
                }
                st.exploits.push(r.clone());
            }
            if st.requests.len() >= 5 {
                st.requests.pop_front();
            }
            st.requests.push_back(r);
        }
        let cfg = self.cfg.clone();
        let th = &cfg.thresholds;
        let listening = &self.listening;
        let listeners = &self.flows.listeners;
        let min_now = minute(now);
        for st in self.states.values_mut() {
            st.ssh.flags.retain(|(t, _)| *t >= now - SSH_FLAG_SECS);
            if now - st.last_activity() > 3600 && st.ssh.flags.is_empty() {
                if !st.findings.is_empty() {
                    st.findings.clear();
                    st.score = 0;
                }
                continue;
            }
            let mut f: Vec<Finding> = Vec::new();

            // Connection attempts (TCP SYN) or inbound UDP first seen in the last 10 minutes.
            let mut recent: Vec<&PortState> = st
                .ports
                .values()
                .filter(|p| {
                    p.first_seen >= now - 600
                        && ((p.proto == PROTO_TCP && p.syn > 0)
                            || (p.proto == PROTO_UDP && !p.reply))
                })
                .collect();
            recent.sort_by_key(|p| p.port);
            let sample = |ps: &[&PortState]| {
                let mut s: Vec<String> = ps.iter().take(6).map(|p| port_label(p.port)).collect();
                if ps.len() > 6 {
                    s.push(format!("+{} more", ps.len() - 6));
                }
                s.join(", ")
            };
            let closed: Vec<&PortState> = recent
                .iter()
                .copied()
                .filter(|p| !listening.has(p.proto, p.port))
                .collect();
            if recent.len() >= th.scan_ports {
                let score = match recent.len() {
                    n if n >= 200 => 90,
                    n if n >= 50 => 78,
                    _ => 55,
                };
                f.push(Finding {
                    kind: "port_scan",
                    score,
                    summary: format!(
                        "Port scan: {} local ports in 10 min ({} closed): {}",
                        recent.len(),
                        closed.len(),
                        sample(&recent)
                    ),
                });
            } else if closed.len() >= th.probe_closed_ports {
                f.push(Finding {
                    kind: "closed_probe",
                    score: 30 + 5 * closed.len().min(6) as u32,
                    summary: format!(
                        "Probed {} ports with no listener: {}",
                        closed.len(),
                        sample(&closed)
                    ),
                });
            }
            let sensitive: Vec<&PortState> = st
                .ports
                .values()
                .filter(|p| p.last_seen >= now - 3600 && cfg.sensitive_ports.contains(&p.port))
                .filter(|p| !p.reply && !listening.has(p.proto, p.port))
                .collect();
            if !sensitive.is_empty() {
                f.push(Finding {
                    kind: "sensitive_probe",
                    score: (35 + 8 * sensitive.len() as u32).min(70),
                    summary: format!(
                        "Probed services that should never be public: {}",
                        sample(&sensitive)
                    ),
                });
            }

            // Repeated attempts against listening services.
            for p in st
                .ports
                .values()
                .filter(|p| p.proto == PROTO_TCP && listening.tcp.contains(&p.port))
            {
                let syn5 = p.syn_since(min_now - 4);
                if cfg.auth_ports.contains(&p.port) && syn5 >= th.brute_force_syn_5m {
                    f.push(Finding {
                        kind: "brute_force",
                        score: if syn5 >= th.brute_force_syn_5m * 5 {
                            85
                        } else {
                            62
                        },
                        summary: format!(
                            "{} connection attempts to {} in 5 min",
                            syn5,
                            port_label(p.port)
                        ),
                    });
                } else if syn5 >= th.conn_flood_syn_5m {
                    f.push(Finding {
                        kind: "conn_flood",
                        score: 70,
                        summary: format!(
                            "{} new connections to {} in 5 min",
                            syn5,
                            port_label(p.port)
                        ),
                    });
                }
            }

            if st.rate.syn_ps >= th.syn_flood_pps {
                f.push(Finding {
                    kind: "syn_flood",
                    score: 90,
                    summary: format!("SYN flood: {:.0} SYN/s", st.rate.syn_ps),
                });
            } else if st.rate.in_pps >= th.flood_pps {
                f.push(Finding {
                    kind: "flood",
                    score: 85,
                    summary: format!("Packet flood: {:.0} packets/s inbound", st.rate.in_pps),
                });
            }
            if st.rate.icmp_ps >= th.icmp_flood_pps {
                f.push(Finding {
                    kind: "icmp_flood",
                    score: 60,
                    summary: format!("ICMP flood: {:.0} echo requests/s", st.rate.icmp_ps),
                });
            }

            if !st.feeds.is_empty() {
                if st.total.in_packets > 0 {
                    // Listed scanners ping and poke closed ports all day; only
                    // reaching a real service is worth a review on its own.
                    let mut reached: Vec<&PortState> = st
                        .ports
                        .values()
                        .filter(|p| {
                            (p.proto == PROTO_TCP || p.proto == PROTO_UDP)
                                && listening.has(p.proto, p.port)
                        })
                        .collect();
                    reached.sort_by_key(|p| p.port);
                    let reached_service = !reached.is_empty();
                    f.push(Finding {
                        kind: "threat_feed",
                        score: if reached_service { 45 } else { 25 },
                        summary: if reached_service {
                            let services: Vec<String> = reached
                                .iter()
                                .take(4)
                                .map(|p| service_label(p.proto, p.port, listeners))
                                .collect();
                            let mut s = format!(
                                "Listed on {} · reached {}",
                                listed_on(&st.feed_hits),
                                services.join(", ")
                            );
                            if let Some(r) = st.requests.back() {
                                s.push_str(&format!(" · last request {}", clip(&r.what, 80)));
                            }
                            s
                        } else {
                            format!(
                                "Listed on {} (only pinged or probed closed ports)",
                                listed_on(&st.feed_hits)
                            )
                        },
                    });
                } else if st.total.packets > 0 {
                    f.push(Finding {
                        kind: "outbound_to_listed",
                        score: 50,
                        summary: format!(
                            "This host opened a connection to an address listed on {} — check which process",
                            listed_on(&st.feed_hits)
                        ),
                    });
                }
            }
            let hits: Vec<&InboundRequest> =
                st.exploits.iter().filter(|r| r.ts >= now - 3600).collect();
            // The most severe request is the example (the latest of equals).
            if let Some(last) = hits.iter().max_by_key(|r| r.exploit.map_or(0, |s| s.score)) {
                let mut sigs: Vec<&crate::exploits::Signature> =
                    hits.iter().filter_map(|r| r.exploit).collect();
                sigs.sort_by_key(|s| std::cmp::Reverse(s.score));
                let mut names: Vec<String> = Vec::new();
                for s in &sigs {
                    if !names.contains(&s.label()) {
                        names.push(s.label());
                    }
                }
                let recon = sigs.iter().all(|s| s.recon());
                let top = sigs.iter().map(|s| s.score).max().unwrap_or(0);
                let more = if names.len() > 2 {
                    format!(" (+{} more)", names.len() - 2)
                } else {
                    String::new()
                };
                let shown = names.iter().take(2).cloned().collect::<Vec<_>>().join("; ");
                f.push(Finding {
                    kind: if recon {
                        "recon_probe"
                    } else {
                        "exploit_attempt"
                    },
                    score: (top + 5 * (names.len() as u32).saturating_sub(1)).min(90),
                    summary: format!(
                        "{}{shown}{more} — {} to {}",
                        if recon { "" } else { "Exploit attempt: " },
                        clip(&last.what, 100),
                        match &last.served_by {
                            Some(who) =>
                                service_label_with(PROTO_TCP, last.port, Some(who.clone())),
                            None => service_label(PROTO_TCP, last.port, listeners),
                        }
                    ),
                });
            }
            if st.ipopt_last >= now - 3600 {
                f.push(Finding {
                    kind: "exploit_attempt",
                    score: 85,
                    summary: format!(
                        "Exploit attempt: CVE-2026-98432 Linux TCP use-after-free — {} SYN(s) carrying IPv4 options ({})",
                        st.total.ipopt_syn,
                        ipopt_names(st.ipopt_kinds)
                    ),
                });
            }
            if let Some(cc) = &st.geo.country_code
                && st.total.in_packets > 0
                && cfg
                    .watch_countries
                    .iter()
                    .any(|w| w.eq_ignore_ascii_case(cc))
            {
                f.push(Finding {
                    kind: "watched_country",
                    score: 15,
                    summary: format!("From watched country {cc}"),
                });
            }

            let failed10 = st.ssh_failed_within(now, 600);
            if failed10 >= 5 || st.ssh.invalid_users.len() >= 3 {
                let users: Vec<&str> = st
                    .ssh
                    .invalid_users
                    .iter()
                    .take(5)
                    .map(String::as_str)
                    .collect();
                f.push(Finding {
                    kind: "ssh_bruteforce",
                    score: if failed10 >= 30 { 85 } else { 65 },
                    summary: {
                        let mut parts = Vec::new();
                        if failed10 > 0 {
                            parts.push(format!("{failed10} failed logins in 10 min"));
                        }
                        if !users.is_empty() {
                            let n = st.ssh.invalid_users.len();
                            let more = if n > users.len() {
                                format!(", +{}", n - users.len())
                            } else {
                                String::new()
                            };
                            parts.push(format!(
                                "{n} nonexistent usernames tried ({}{more})",
                                users.join(", ")
                            ));
                        }
                        format!("SSH: {}", parts.join(", "))
                    },
                });
            }
            for (_, flag) in &st.ssh.flags {
                if !f.iter().any(|x| x.kind == flag.kind) {
                    f.push(flag.clone());
                }
            }

            f.sort_by_key(|x| std::cmp::Reverse(x.score));
            let mut score = f.first().map_or(0, |x| x.score);
            for extra in f.iter().skip(1) {
                score += extra.score / 4;
            }
            st.score = score.min(100);
            st.findings = f;
        }
    }

    fn subject<'a>(st: &'a IpState) -> Subject<'a> {
        Subject {
            ip: st.ip,
            score: st.score,
            kinds: st.kinds(),
            country: st.geo.country_code.as_deref(),
            asn: st.geo.asn,
            ports: st.ports.values().map(|p| p.port).collect(),
            in_feed: !st.feeds.is_empty(),
            ssh_failed: st.ssh.failed_total,
        }
    }

    /// The policy rule (if any) that applies to a source right now.
    pub fn rule_for(&self, st: &IpState) -> Option<&Rule> {
        policy::decide(&self.user_rules, &self.default_rules, &Self::subject(st))
    }

    /// Ban/review decisions for active, public, not-yet-handled sources.
    pub fn decisions(&self, now: i64) -> Vec<Decision> {
        let mut out = Vec::new();
        for st in self.states.values() {
            if st.allowlisted || st.banned || !is_public(st.ip) || now - st.last_activity() > 600 {
                continue;
            }
            if st.findings.is_empty() && self.user_rules.is_empty() {
                continue;
            }
            let Some(rule) = self.rule_for(st) else {
                continue;
            };
            if matches!(rule.action, Action::Ban | Action::Review) {
                let reasons: Vec<&str> = st.findings.iter().map(|f| f.summary.as_str()).collect();
                out.push(Decision {
                    ip: st.ip,
                    rule: rule.clone(),
                    urgent: st.findings.iter().any(|f| {
                        matches!(
                            f.kind,
                            "login_after_failures" | "new_login_location" | "outbound_to_listed"
                        )
                    }),
                    reason: if reasons.is_empty() {
                        rule.description.clone()
                    } else {
                        format!("{} — {}", rule.description, reasons.join("; "))
                    },
                });
            }
        }
        out
    }

    /// /24s (or /64s) with several flagged sources: candidates for a range ban.
    pub fn subnet_candidates(&self) -> Vec<(IpNet, Vec<&IpState>)> {
        let min = self.cfg.ban.subnet_min_sources.max(2);
        let mut groups: BTreeMap<IpNet, Vec<&IpState>> = BTreeMap::new();
        for st in self.states.values() {
            if st.score >= self.cfg.ban.review_score && !st.allowlisted && is_public(st.ip) {
                groups.entry(neighbourhood(st.ip)).or_default().push(st);
            }
        }
        groups
            .into_iter()
            .filter(|(net, v)| v.len() >= min && !self.bans.contains_key(net))
            .collect()
    }

    /// Findings that are new, worse, or still active after 5 minutes.
    pub fn alerts_due(&mut self, now: i64) -> Vec<AlertDue> {
        let mut out = Vec::new();
        for st in self.states.values_mut() {
            if st.allowlisted {
                continue;
            }
            for f in &st.findings {
                let due = match st.reported.get(f.kind) {
                    None => true,
                    Some((score, ts)) => f.score > *score || now - ts >= 300,
                };
                if due {
                    st.reported.insert(f.kind, (f.score, now));
                    out.push(AlertDue {
                        ip: st.ip.to_string(),
                        kind: f.kind,
                        score: f.score,
                        summary: f.summary.clone(),
                        location: st.location.clone(),
                    });
                }
            }
        }
        out
    }

    /// Sources that sent SYNs with IPv4 options since they were last reported, at most
    /// hourly each. Unlike findings this includes allowlisted, private and banned
    /// sources: the kernel bug is reachable from anywhere a SYN can come from.
    pub fn ipopt_alerts_due(&mut self, now: i64) -> Vec<IpoptAlert> {
        let mut out = Vec::new();
        for st in self.states.values_mut() {
            if st.ipopt_last > st.ipopt_alerted && now - st.ipopt_alerted >= 3600 {
                st.ipopt_alerted = now;
                out.push(IpoptAlert {
                    ip: st.ip,
                    location: st.location.clone(),
                    syn: st.total.ipopt_syn,
                    options: ipopt_names(st.ipopt_kinds),
                    allowlisted: st.allowlisted,
                    banned: st.banned,
                });
            }
        }
        out
    }

    pub fn take_hour_deltas(&mut self) -> Vec<HourDeltaOwned> {
        let mut out = Vec::new();
        for st in self.states.values_mut() {
            let d = std::mem::take(&mut st.pending_hour);
            if (d.in_packets > 0 || d.blocked > 0) && !st.allowlisted {
                out.push(HourDeltaOwned {
                    ip: st.ip.to_string(),
                    country: st.geo.country_code.clone().unwrap_or_else(|| "--".into()),
                    location: st.location.clone(),
                    delta: d,
                    score: st.score,
                });
            }
        }
        out
    }

    /// Forgets quiet sources and stale port entries.
    pub fn prune(&mut self, now: i64) {
        self.states.retain(|_, st| {
            st.banned
                || !st.findings.is_empty()
                || now - st.last_seen.max(st.last_activity()) < 7200
        });
        for st in self.states.values_mut() {
            st.ports.retain(|_, p| now - p.last_seen < 3600);
        }
        if self.states.len() > MAX_STATES {
            let mut by_age: Vec<(i64, IpAddr)> =
                self.states.values().map(|s| (s.last_seen, s.ip)).collect();
            by_age.sort();
            for (_, ip) in by_age.into_iter().take(self.states.len() - MAX_STATES) {
                self.states.remove(&ip);
            }
        }
    }

    /// Sources that the LLM should look at: flagged, not banned, not allowlisted.
    pub fn flagged(&self, now: i64, limit: usize) -> Vec<&IpState> {
        let mut v: Vec<&IpState> = self
            .states
            .values()
            .filter(|s| {
                s.score > 0 && !s.banned && !s.allowlisted && now - s.last_activity() < 3600
            })
            .collect();
        v.sort_by_key(|s| std::cmp::Reverse(s.score));
        v.truncate(limit);
        v
    }
}

/// "80 (HTTP, temps)": the port, its usual service and who serves it here.
fn service_label(proto: u8, port: u16, listeners: &HashMap<(u8, u16), Listener>) -> String {
    let name = |o: &Owner| {
        o.container
            .clone()
            .or_else(|| o.unit.clone())
            .unwrap_or_else(|| o.comm.clone())
    };
    // Without the flow's own owner, name the port's owner only when nobody else shares the port.
    let who = listeners.get(&(proto, port)).and_then(|l| {
        let mut names: BTreeSet<String> = l.by_addr.values().map(name).collect();
        names.extend(l.owner.as_ref().map(name));
        if names.len() == 1 {
            names.pop_first()
        } else {
            None
        }
    });
    service_label_with(proto, port, who)
}

fn service_label_with(proto: u8, port: u16, who: Option<String>) -> String {
    let who = who.filter(|w| !w.is_empty());
    let name = if proto == PROTO_TCP {
        service_name(port)
    } else {
        None
    };
    let unit = if proto == PROTO_UDP { "udp" } else { "tcp" };
    match (name, who) {
        (Some(n), Some(w)) => format!("{port} ({n}, {w})"),
        (Some(n), None) => format!("{port} ({n})"),
        (None, Some(w)) => format!("{port}/{unit} ({w})"),
        (None, None) => format!("{port}/{unit}"),
    }
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use netwatch_common::{FlowKey, FlowStats, INIT_LOCAL, INIT_REMOTE};

    use super::*;
    use crate::util::{boot_now_ns, ip_to_key, now_unix};

    const HOST: &str = "192.0.2.10";
    const RESOLVER: &str = "198.51.100.53";
    const SCANNER: &str = "203.0.113.9";
    /// Source ports Hickory may pick that sit above the kernel's 32768-60999 range.
    const CLIENT_PORTS: [u16; 3] = [61537, 63659, 65395];

    /// What the kernel maps list: per-source and per-probe counters.
    type Totals = (Vec<([u8; 16], SrcStats)>, Vec<(ProbeKey, ProbeStats)>);

    fn engine() -> Engine {
        let geo = Geo::open(
            Path::new("/nonexistent/city.mmdb"),
            Path::new("/nonexistent/asn.mmdb"),
        );
        Engine::new(Arc::new(Config::default()), geo, (32768, 60999))
    }

    /// The kernel flow map lists a UDP flow this host's `lport` -> `remote`:53.
    fn flow(e: &mut Engine, lport: u16, remote: &str, initiator: u8) {
        let ns = boot_now_ns();
        let key = FlowKey {
            local: ip_to_key(HOST.parse().unwrap()),
            remote: ip_to_key(remote.parse().unwrap()),
            ifindex: 2,
            lport,
            rport: 53,
            proto: PROTO_UDP,
            _pad: [0; 3],
        };
        let st = FlowStats {
            initiator,
            first_seen_ns: ns,
            last_seen_ns: ns,
            pkts_out: 1,
            bytes_out: 60,
            ..Default::default()
        };
        e.flows
            .observe(vec![(key, st)], &[], &BootClock::new(), now_unix(), 1.0);
    }

    /// The XDP program counted `packets` UDP packets from `src` to local `port`.
    fn hits(src: &str, ports: &[u16], packets: u64) -> Vec<(ProbeKey, ProbeStats)> {
        let ns = boot_now_ns();
        ports
            .iter()
            .map(|&port| {
                let k = ProbeKey {
                    addr: ip_to_key(src.parse().unwrap()),
                    port,
                    proto: PROTO_UDP,
                    _pad: 0,
                };
                (
                    k,
                    ProbeStats {
                        packets,
                        bytes: packets * 80,
                        syn: 0,
                        first_seen_ns: ns,
                        last_seen_ns: ns,
                    },
                )
            })
            .collect()
    }

    /// The kernel's all-time counters for `src`: `syn` connections to TCP `port`, five packets each.
    fn tcp_totals(src: &str, port: u16, syn: u64) -> Totals {
        let ns = boot_now_ns();
        let addr = ip_to_key(src.parse().unwrap());
        let packets = syn * 5;
        let s = SrcStats {
            packets,
            bytes: packets * 60,
            in_packets: packets,
            in_bytes: packets * 60,
            syn,
            first_seen_ns: ns,
            last_seen_ns: ns,
            ..Default::default()
        };
        let k = ProbeKey {
            addr,
            port,
            proto: PROTO_TCP,
            _pad: 0,
        };
        let p = ProbeStats {
            packets,
            bytes: packets * 60,
            syn,
            first_seen_ns: ns,
            last_seen_ns: ns,
        };
        (vec![(addr, s)], vec![(k, p)])
    }

    /// One daemon tick (5 s) that reads `totals` from the kernel maps.
    fn tick(e: &mut Engine, totals: &Totals, now: i64) {
        e.prune(now);
        e.observe_sources(totals.0.clone(), now, 5.0);
        e.observe_probes(totals.1.clone(), now);
        e.evaluate(now);
    }

    fn kinds(e: &mut Engine, ip: &str) -> Vec<&'static str> {
        let now = now_unix();
        let ip: IpAddr = ip.parse().unwrap();
        e.state(ip, now).last_inbound = now;
        e.evaluate(now);
        e.states[&ip].findings.iter().map(|f| f.kind).collect()
    }

    #[test]
    fn a_syn_with_ip_options_is_a_cve_2026_98432_exploit_attempt() {
        let mut e = engine();
        let ip: IpAddr = SCANNER.parse().unwrap();
        let t0 = now_unix();
        let mut totals = tcp_totals(SCANNER, 443, 1);
        tick(&mut e, &totals, t0);
        assert!(!e.states[&ip].kinds().contains(&"exploit_attempt"));

        totals.0[0].1.ipopt_syn = 1;
        totals.0[0].1.ipopt_kinds = IPOPT_TS;
        totals.0[0].1.packets += 1;
        tick(&mut e, &totals, t0 + 5);
        let st = &e.states[&ip];
        let f = st
            .findings
            .iter()
            .find(|f| f.kind == "exploit_attempt")
            .expect("finding");
        assert!(
            f.summary.contains("CVE-2026-98432") && f.summary.contains("Timestamp"),
            "{}",
            f.summary
        );
        assert_eq!(
            e.rule_for(st).map(|r| r.id.as_str()),
            Some("default:exploit")
        );

        // It stays an hour, then expires with the source's other findings.
        tick(&mut e, &totals, t0 + 3000);
        assert!(e.states[&ip].kinds().contains(&"exploit_attempt"));
        tick(&mut e, &totals, t0 + 3700);
        assert!(
            !e.states
                .get(&ip)
                .is_some_and(|s| s.kinds().contains(&"exploit_attempt"))
        );
    }

    #[test]
    fn the_cve_2026_98432_trigger_alerts_even_from_an_allowlisted_source() {
        let mut e = engine();
        e.set_allow(vec!["100.64.0.0/10".parse().unwrap()]);
        let tailnet = "100.101.102.103";
        let ip: IpAddr = tailnet.parse().unwrap();
        let t0 = now_unix();
        let mut totals = tcp_totals(tailnet, 22, 1);
        tick(&mut e, &totals, t0);
        assert!(e.states[&ip].allowlisted);
        assert!(e.ipopt_alerts_due(t0).is_empty());

        let send = |totals: &mut Totals| {
            totals.0[0].1.ipopt_syn += 1;
            totals.0[0].1.ipopt_kinds = IPOPT_RR;
            totals.0[0].1.packets += 1;
            totals.0[0].1.in_packets += 1;
        };
        send(&mut totals);
        tick(&mut e, &totals, t0 + 5);
        let due = e.ipopt_alerts_due(t0 + 5);
        assert_eq!(due.len(), 1);
        assert!(due[0].allowlisted && due[0].options == "Record Route" && due[0].syn == 1);
        // Allowlisted: no ban proposal, so this alert is the only notice.
        assert!(e.decisions(t0 + 5).iter().all(|d| d.ip != ip));

        // More SYNs within the hour don't repeat it; after an hour they do.
        send(&mut totals);
        tick(&mut e, &totals, t0 + 60);
        assert!(e.ipopt_alerts_due(t0 + 60).is_empty());
        send(&mut totals);
        tick(&mut e, &totals, t0 + 3700);
        let due = e.ipopt_alerts_due(t0 + 3700);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].syn, 3);
        // Silence after that alerts no more.
        tick(&mut e, &totals, t0 + 7400);
        assert!(e.ipopt_alerts_due(t0 + 7400).is_empty());
    }

    #[test]
    fn a_forgotten_source_is_not_counted_again_from_the_kernel_totals() {
        let mut e = engine();
        let ip: IpAddr = SCANNER.parse().unwrap();
        let t0 = now_unix();
        let burst = tcp_totals(SCANNER, 80, 1077);
        tick(&mut e, &burst, t0);
        assert!(e.states[&ip].findings.iter().any(|f| f.kind == "syn_flood"));

        // The kernel keeps listing the same totals while the source is quiet: its
        // findings expire after an hour and the source is forgotten after two.
        for t in (t0 + 5..t0 + 3 * 3600).step_by(300) {
            tick(&mut e, &burst, t);
        }
        assert!(!e.states.contains_key(&ip));

        // When it comes back, only what it sent since counts.
        tick(&mut e, &tcp_totals(SCANNER, 80, 1080), t0 + 3 * 3600);
        let st = &e.states[&ip];
        assert_eq!(st.total.syn, 3);
        assert_eq!(st.ports[&(PROTO_TCP, 80)].syn, 3);
        assert!(st.rate.syn_ps < 1.0);
        assert!(
            !st.findings
                .iter()
                .any(|f| f.kind == "syn_flood" || f.kind == "conn_flood")
        );
    }

    #[test]
    fn dns_answers_to_client_ports_above_the_ephemeral_range_are_not_probes() {
        let mut e = engine();
        for p in CLIENT_PORTS {
            flow(&mut e, p, RESOLVER, INIT_LOCAL);
        }
        e.observe_probes(hits(RESOLVER, &CLIENT_PORTS, 1), now_unix());
        assert!(
            e.states[&RESOLVER.parse::<IpAddr>().unwrap()]
                .ports
                .values()
                .all(|p| p.reply)
        );
        assert_eq!(kinds(&mut e, RESOLVER), Vec::<&str>::new());

        // The verdict is kept after the flows are gone, and for later packets.
        e.flows.active.clear();
        e.observe_probes(hits(RESOLVER, &CLIENT_PORTS, 2), now_unix());
        assert_eq!(kinds(&mut e, RESOLVER), Vec::<&str>::new());
    }

    #[test]
    fn the_same_ports_probed_by_a_stranger_still_alert() {
        let mut e = engine();
        // The resolver's flows exist; the scanner never had a conversation with us.
        for p in CLIENT_PORTS {
            flow(&mut e, p, RESOLVER, INIT_LOCAL);
        }
        e.observe_probes(hits(SCANNER, &CLIENT_PORTS, 1), now_unix());
        assert_eq!(kinds(&mut e, SCANNER), ["closed_probe"]);
    }

    #[test]
    fn a_resolver_is_not_exempt_for_ports_we_never_queried_from() {
        let mut e = engine();
        flow(&mut e, CLIENT_PORTS[0], RESOLVER, INIT_LOCAL);
        // Answers for the one port we used, plus a sweep of others (source port 53 or not).
        let mut probes = hits(RESOLVER, &CLIENT_PORTS[..1], 1);
        probes.extend(hits(RESOLVER, &[1111, 2222, 3333], 1));
        e.observe_probes(probes, now_unix());
        assert_eq!(kinds(&mut e, RESOLVER), ["closed_probe"]);
        let st = &e.states[&RESOLVER.parse::<IpAddr>().unwrap()];
        assert!(st.ports[&(PROTO_UDP, CLIENT_PORTS[0])].reply);
        assert!(!st.ports[&(PROTO_UDP, 1111)].reply);
    }

    #[test]
    fn only_flows_this_host_opened_explain_inbound_udp() {
        let mut e = engine();
        // A remote that contacted us first is not answering anything.
        for p in CLIENT_PORTS {
            flow(&mut e, p, SCANNER, INIT_REMOTE);
        }
        e.observe_probes(hits(SCANNER, &CLIENT_PORTS, 1), now_unix());
        assert_eq!(kinds(&mut e, SCANNER), ["closed_probe"]);
    }

    /// sshd's log of one brute-force run, as journald hands it over.
    fn ssh_log(e: &mut Engine, lines: &[&str]) -> u64 {
        let now = now_unix();
        for l in lines {
            let ev = crate::ssh::parse(now, false, l).unwrap();
            e.observe_ssh(&ev, &[]);
        }
        let ip: IpAddr = SCANNER.parse().unwrap();
        e.states[&ip].ssh_failed_within(now, 3600)
    }

    #[test]
    fn counts_failed_ssh_attempts_on_servers_without_passwords() {
        // Keys only: sshd never logs "Failed password", one "Invalid user" per try.
        let mut e = engine();
        let n = ssh_log(
            &mut e,
            &[
                "Invalid user admin from 203.0.113.9 port 40001",
                "Invalid user oracle from 203.0.113.9 port 40002",
                "Connection closed by authenticating user root 203.0.113.9 port 40003 [preauth]",
            ],
        );
        assert_eq!(n, 2);

        // Passwords: each connection logs "Invalid user" once, then a line per
        // password it tried; existing users only get the "Failed password" lines.
        let mut e = engine();
        let n = ssh_log(
            &mut e,
            &[
                "Invalid user admin from 203.0.113.9 port 40001",
                "Invalid user admin from 203.0.113.9 port 40004",
                "Failed password for invalid user admin from 203.0.113.9 port 40001 ssh2",
                "Failed password for invalid user admin from 203.0.113.9 port 40004 ssh2",
                "Failed password for invalid user admin from 203.0.113.9 port 40001 ssh2",
                "Failed password for invalid user admin from 203.0.113.9 port 40001 ssh2",
                "Failed password for root from 203.0.113.9 port 40002 ssh2",
                "Failed password for root from 203.0.113.9 port 40002 ssh2",
                // Gave up before trying a password.
                "Invalid user guest from 203.0.113.9 port 40005",
            ],
        );
        assert_eq!(n, 7);

        // A long username list keeps counting one per password.
        let mut e = engine();
        let lines: Vec<String> = (0..300)
            .flat_map(|i| {
                let port = 20000 + i;
                [
                    format!("Invalid user u{i} from 203.0.113.9 port {port}"),
                    format!(
                        "Failed password for invalid user u{i} from 203.0.113.9 port {port} ssh2"
                    ),
                ]
            })
            .collect();
        let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
        assert_eq!(ssh_log(&mut e, &lines), 300);
    }
}
