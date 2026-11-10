// Contract between the netwatch daemon (read-only HTTP API on 127.0.0.1) and the UI.
// All timestamps are unix seconds. The API exposes GET endpoints only.

export interface GeoInfo {
  country_code: string | null;
  country: string | null;
  city: string | null;
  lat: number | null;
  lon: number | null;
  asn: number | null;
  as_org: string | null;
}

export type Level = "info" | "warn" | "critical";

/** One detection on a source, e.g. kind "port_scan", "ssh_bruteforce", "threat_feed". */
export interface Finding {
  kind: string;
  score: number; // 0-100
  summary: string;
}

export interface Rates {
  in_pps: number;
  in_bps: number; // bits per second
  syn_ps: number;
}

export interface SshCounts {
  failed: number;
  invalid_users: number;
  accepted: number;
}

/** GET /api/sources?sort=score|syn|in_bytes|in_pps|ports|last_seen&limit=100&q=<ip/country/asn substring>&flagged=1 */
export interface Source {
  ip: string;
  geo: GeoInfo;
  first_seen: number;
  last_seen: number;
  packets: number;
  bytes: number;
  in_packets: number;
  in_bytes: number;
  syn: number;
  udp_in: number;
  icmp_in: number;
  blocked: number;
  rate: Rates;
  ports: number; // distinct local ports touched in the last hour
  score: number;
  findings: Finding[];
  feeds: string[]; // threat feeds listing this IP
  /** Why it is listed: the range each feed lists it under, and what the feed means. */
  feed_hits?: FeedHit[];
  allowlisted: boolean;
  banned: boolean;
  ssh: SshCounts;
}

export interface FeedHit {
  name: string;
  range: string; // e.g. "185.93.89.0/24"
  about: string; // one line on what the feed lists; may be empty
}

export interface PortTouch {
  proto: "tcp" | "udp" | "icmp" | "icmp6" | "ip";
  port: number;
  service: string | null;
  listening: boolean;
  first_seen: number;
  last_seen: number;
  packets: number;
  syn: number;
}

export interface HourPoint {
  hour: number;
  in_packets: number;
  in_bytes: number;
  syn: number;
  blocked: number;
  max_score: number;
}

/** GET /api/sources/{ip} (404 if unknown) */
export interface SourceDetail extends Source {
  port_touches: PortTouch[];
  alerts: Alert[];
  history: HourPoint[]; // last 7 days, hourly
  ssh_events: SshEvent[];
  ban: Ban | null;
  proposals: Proposal[];
  /** Active flows first, then finished flows from the last 7 days (newest first). */
  flows: FlowRow[];
  /** Names this IP currently resolves from, per DNS answers seen by netwatch. */
  dns_names: string[];
}

/** GET /api/alerts?since=&limit=&ip= */
export interface Alert {
  id: number;
  ip: string;
  kind: string;
  score: number;
  summary: string;
  location: string; // e.g. "CN AS4134 Chinanet"
  first_ts: number;
  last_ts: number;
  count: number;
}

/** GET /api/bans */
export interface Ban {
  target: string; // IP or CIDR
  created: number;
  expires: number | null; // null = permanent
  reason: string;
  source: "manual" | "auto" | "policy" | "llm";
  /** Packets from the target that hit the ban since daemon start (absent from daemons before 0.1.4). */
  matched?: number;
  /** Of those, how many were dropped: all of them, or 0 in a dry run (`drop_banned = false`). */
  dropped: number;
}

/** GET /api/proposals?status=pending|all — actions waiting for a human (approve via CLI). */
export interface Proposal {
  id: number;
  created: number;
  target: string;
  action: "ban" | "unban" | "allow" | "review";
  ttl_secs: number | null;
  reason: string;
  source: "rules" | "llm";
  confidence: number; // 0-1
  status: "pending" | "approved" | "rejected" | "applied" | "expired";
  decided_at: number | null;
  approve_cmd: string; // e.g. "sudo netwatch approve 12"
}

/** GET /api/insights */
export interface Insight {
  level: Level;
  title: string;
  detail: string;
  action: string | null; // suggested shell command, shown copyable
}

/** GET /api/ssh?since=&limit=&ip= */
export interface SshEvent {
  ts: number;
  kind: "accepted" | "failed" | "invalid_user" | "preauth_close" | "tailscale_login";
  user: string | null;
  ip: string;
  method: string | null; // password | publickey | tailscale
  location: string;
}

export interface SeriesPoint {
  ts: number;
  pps: number;
  in_pps: number;
  syn_pps: number;
  dropped_pps: number;
}

/** GET /api/overview */
export interface Overview {
  host: string;
  version: string;
  interface: string;
  /** Linux: XDP mode. macOS: "capture" (/dev/bpf), "capture+pf" when pf drops bans. */
  attach_mode: "driver" | "skb" | "capture" | "capture+pf";
  /** Where the daemon runs (absent from older daemons, which are all Linux). */
  platform?: "linux" | "macos";
  mode: "observe" | "enforce";
  drop_banned: boolean;
  started_at: number;
  now: number;
  /** `bps` is bits per second (rx + tx of the XDP interface, from sysfs counters). */
  rates: { pps: number; bps: number; in_pps: number; syn_pps: number; dropped_pps: number };
  totals: {
    packets: number;
    bytes: number;
    in_packets: number;
    syn: number;
    blocked: number;
    dropped: number;
    events_lost: number;
    /** IPv4 TCP SYNs carrying IP options (CVE-2026-98432 trigger), and how many were dropped. */
    ipopt_syn?: number;
    ipopt_dropped?: number;
  };
  counts: {
    sources_tracked: number;
    sources_active_10m: number;
    flagged: number;
    bans_active: number;
    proposals_pending: number;
    ssh_failed_1h: number;
  };
  llm: LlmStatus;
  geo_db: boolean;
  feeds: { name: string; entries: number; about?: string }[];
  series: SeriesPoint[]; // last 30 min, one point per tick
  flows: OverviewFlows;
  /** Interfaces with flow tracking or XDP attached. */
  interfaces: OverviewInterface[];
}

export interface OverviewFlows {
  active: number;
  in: number;
  out: number;
  tcp: number;
  udp: number;
  rate_in_bps: number; // bits per second, summed over active flows
  rate_out_bps: number;
  listeners: number; // exposed listeners, not counting UDP sockets seen acting as DNS clients
  series: FlowMinute[];
  sock_events_lost: number;
}

export interface OverviewInterface {
  name: string;
  kind: IfKind;
  rx_bps: number; // bits per second
  tx_bps: number;
  xdp: boolean;
  flows: boolean;
}

export interface CountryAgg {
  country_code: string;
  country: string;
  sources: number;
  flagged: number;
  syn: number;
  in_packets: number;
}

export interface AsnAgg {
  asn: number;
  org: string;
  sources: number;
  flagged: number;
  syn: number;
}

export interface PortAgg {
  proto: string;
  port: number;
  service: string | null;
  listening: boolean;
  sources: number;
  syn: number;
}

export interface HistoryRow {
  ip: string;
  location: string;
  in_packets: number;
  in_bytes: number;
  syn: number;
  blocked: number;
  max_score: number;
  hours: number;
  last_hour: number;
}

/** GET /api/summary?window=1h|24h|7d */
export interface Summary {
  window: string;
  countries: CountryAgg[];
  asns: AsnAgg[];
  ports: PortAgg[];
  top_history: HistoryRow[];
}

/** GET /api/events?limit=200 — newest first; one per new (source, port) pair seen by XDP. */
export interface ProbeEvent {
  ts: number;
  ip: string;
  proto: string;
  port: number;
  service: string | null;
  tcp_flags: number;
  ttl: number;
  location: string;
}

export interface PolicyRule {
  id: string;
  description: string;
  action: "ban" | "review" | "ignore" | "never_ban";
  ttl_secs: number | null;
  when: Record<string, unknown>; // structured conditions, displayed as JSON
  enabled: boolean;
}

/** GET /api/policy — natural-language policy and the rules compiled from it. */
export interface Policy {
  text: string | null;
  rules: PolicyRule[];
  defaults: PolicyRule[]; // built-in rules, always shown
  compiled_at: number | null;
  compiled_by: string | null; // model name
  set_cmd: string; // e.g. "sudo netwatch policy set 'ban ssh brute force for a week...'"
}

export interface LlmStatus {
  enabled: boolean;
  model: string | null;
  base_url: string | null;
  calls_today: number;
  tokens_today: number;
  budget_tokens_day: number;
  last_run: number | null;
}

export interface LlmRun {
  ts: number;
  kind: "analyze" | "compile_policy";
  model: string;
  prompt_tokens: number;
  completion_tokens: number;
  summary: string;
  proposals: number;
}

/** GET /api/llm */
export interface LlmInfo extends LlmStatus {
  runs: LlmRun[];
}

// ---------------------------------------------------------------------------
// Flows (conversations), interfaces, listeners, DNS, connection events

/** Who opened the conversation. */
export type FlowDir = "in" | "out" | "unknown";

/**
 * Parsed first-payload metadata (`dissect::AppMeta`). Every field may be null
 * or absent; the whole object is null when nothing was recognised.
 */
export interface AppMeta {
  proto?: "tls" | "http" | "ssh" | null;
  sni?: string | null;
  alpn?: string | null;
  http_method?: string | null;
  http_host?: string | null;
  http_path?: string | null;
  user_agent?: string | null;
  http_status?: number | null;
  server?: string | null;
  ssh_client?: string | null;
  ssh_server?: string | null;
  dns_qname?: string | null;
  /** A known exploit in what the client sent (name), and its CVE when it has one. */
  exploit?: string | null;
  cve?: string | null;
}

/**
 * One conversation, active (from memory) or finished (from the store).
 * GET /api/flows?view=active|history|all&window=&ip=&port=&process=&dir=&iface=&proto=&q=&sort=bytes|rate|last|first|retrans&limit=
 * `process=` matches the process name, container or systemd unit exactly.
 */
export interface FlowRow {
  iface: string;
  proto: string; // tcp, udp, icmp, ...
  local: string;
  lport: number;
  remote: string;
  rport: number;
  dir: FlowDir;
  first_seen: number;
  last_seen: number;
  bytes_in: number;
  bytes_out: number;
  pkts_in: number;
  pkts_out: number;
  /** TCP: established, syn_sent, failed, closed, time_wait, unanswered (a SYN no TCP packet answered: dropped, or refused with ICMP), ...; non-TCP: "active". */
  state: string;
  connect_ms: number | null;
  retrans: number;
  rst_sent: number;
  rst_recv: number;
  pid: number | null;
  process: string | null;
  exe: string | null;
  container: string | null;
  /** systemd service (without ".service") when the process isn't in a container. */
  unit: string | null;
  /**
   * The process on the remote end when it is on this host too (another container,
   * or a host process such as docker-proxy), found while the flow was active.
   */
  remote_pid: number | null;
  remote_process: string | null;
  remote_container: string | null;
  remote_unit: string | null;
  /** Name the remote address was resolved from (DNS seen by netwatch), or the TLS SNI. */
  remote_name: string | null;
  app: AppMeta | null;
  country: string | null; // ISO code; null for private remotes
  asn: number | null;
  as_org: string | null;
  /** The port that identifies the service: local for inbound, remote for outbound. */
  service_port: number;
  service: string | null;
  active: boolean;
  /** Bytes per second over the last tick (0 for finished flows). */
  rate_in: number;
  rate_out: number;
}

/**
 * Everything this host and its containers connected out to at one remote address.
 * GET /api/destinations?window=&scope=public|all&unnamed=true&q=&sort=flows|bytes|last|first&limit=
 */
export interface Destination {
  remote: string;
  /** DNS name or TLS SNI seen for it; null if it was reached without either. */
  name: string | null;
  country: string | null;
  asn: number | null;
  as_org: string | null;
  flows: number;
  /** Flows still open. */
  active: number;
  failed: number;
  bytes_in: number;
  bytes_out: number;
  first_seen: number;
  last_seen: number;
  /** "tcp/443", sorted. */
  ports: string[];
  /** Who connected: "container/process", "unit/process" or "process". */
  processes: string[];
}

export interface Destinations {
  window: string;
  /** Remotes in scope, before the search and "no name" filters. */
  destinations: number;
  /** Of those, reached without a DNS name or TLS SNI. */
  unnamed: number;
  /** Rows matching the filters, before the limit. */
  matched: number;
  rows: Destination[];
}

export type DestinationSort = "flows" | "bytes" | "last" | "first";

export type FlowView = "active" | "history" | "all";
export type FlowSort = "bytes" | "rate" | "last" | "first" | "retrans";

/** One minute of flow activity (last 60 minutes, oldest first). */
export interface FlowMinute {
  ts: number;
  new_in: number;
  new_out: number;
  failed: number;
  dns: number;
  bytes_in: number;
  bytes_out: number;
}

/** A ranked group in /api/flows/summary. */
export interface FlowGroup {
  /**
   * remotes: the IP; processes: "container/process" or "unit/process" (container wins), "process",
   * "container/?" or "unknown";
   * services: "<port>/<proto> <dir>" e.g. "443/tcp out"; countries: ISO code or "--".
   */
  key: string;
  /** remotes: DNS name; processes: exe path; services: service name. */
  label: string | null;
  flows: number;
  active: number;
  bytes_in: number;
  bytes_out: number;
  rate_bps: number; // bits per second
  failed: number;
  retrans: number;
  last_seen: number;
  remotes: number; // distinct remotes
  country: string | null; // remotes only
  as_org: string | null; // remotes only
}

/** GET /api/flows/summary?window=5m|15m|1h|6h|24h|7d|30d — active flows plus finished ones in the window. */
export interface FlowsSummary {
  window: string;
  flows: number;
  active: number;
  inbound: number;
  outbound: number;
  failed: number;
  /** Bytes moved within the window (not each flow's lifetime). */
  bytes_in: number;
  bytes_out: number;
  /** Where the byte totals start: the window rounded down to the minute, or to the hour beyond 1h. */
  bytes_since: number;
  listeners: number; // all listening sockets
  truncated: boolean; // history capped at 100k flows
  top_remotes: FlowGroup[];
  top_processes: FlowGroup[];
  top_services: FlowGroup[];
  top_countries: FlowGroup[];
  /** Always the last 60 minutes, regardless of `window`. */
  series: FlowMinute[];
}

export type IfKind = "ethernet" | "bridge" | "tunnel" | "loopback" | "other";

/** `IfStat` with the `IfInfo` fields flattened in, plus `active_flows`. */
export interface IfStat {
  name: string;
  ifindex: number;
  kind: IfKind;
  up: boolean;
  mac: string | null;
  addrs: string[]; // "addr/prefix"
  rx_bytes: number;
  tx_bytes: number;
  rx_packets: number;
  tx_packets: number;
  rx_dropped: number;
  tx_dropped: number;
  rx_errors: number;
  tx_errors: number;
  rx_bps: number; // bits per second
  tx_bps: number;
  rx_pps: number;
  tx_pps: number;
  /** Flow programs (TC) attached. */
  flows: boolean;
  /** The XDP program (accounting and bans) runs here. */
  xdp: boolean;
  active_flows: number;
}

/** GET /api/interfaces */
export interface InterfacesInfo {
  interfaces: IfStat[];
  /** Whether the flow (TC) programs loaded at all. */
  flow_programs: boolean;
  tracepoints: { name: string; attached: boolean }[];
  /** Configured `flow_interfaces` patterns: exact names or prefixes ending in "*". */
  patterns: string[];
  sample_dns: boolean;
  sample_tcp_payload: boolean;
}

/** GET /api/listeners — one per (proto, port). */
export interface Listener {
  proto: string; // tcp | udp
  port: number;
  service: string | null;
  addrs: string[]; // bound addresses
  /** Bound to something other than loopback. */
  exposed: boolean;
  /** The port is inside the kernel's automatic source-port range. Says nothing about client or server: see `role`. */
  ephemeral: boolean;
  /** From observed traffic: a UDP socket that sent DNS queries is a client; unknown sockets are treated like services. */
  role: "unknown" | "client" | "server";
  /** Why `role` is what it is, e.g. "sent DNS queries to 192.0.2.53:53". */
  role_reason: string;
  pid: number | null;
  process: string | null;
  exe: string | null;
  container: string | null;
  /** systemd service (without ".service") when the process isn't in a container. */
  unit: string | null;
  since: number;
  active_flows: number; // active inbound flows to this port
  remotes: number;
  public_remotes: number;
  age_secs: number;
}

/** One DNS query (and its answer, if seen). */
export interface DnsQuery {
  ts: number;
  iface: string;
  client: string;
  server: string;
  /** out: this host asked; in: someone asked this host. */
  dir: string;
  qname: string;
  qtype: string; // A, AAAA, HTTPS, TYPE<n>, ...
  /** NOERROR, NXDOMAIN, SERVFAIL, REFUSED, FORMERR, NOTIMP, OTHER, or TIMEOUT (no answer seen). */
  rcode: string;
  answers: string[];
  latency_ms: number | null;
}

export interface DnsTopName {
  qname: string;
  queries: number;
  nxdomain: number;
  clients: number;
  last_ts: number;
}

/** GET /api/dns?window=&q=&rcode=&limit= */
export interface DnsInfo {
  queries: DnsQuery[];
  top: DnsTopName[];
}

export type ConnEventKind = "connect_failed" | "listen" | "unlisten";

/** GET /api/conn_events?window=&kind=&limit= — newest first. */
export interface ConnEvent {
  ts: number;
  kind: ConnEventKind | (string & {});
  proto: string;
  local: string;
  lport: number;
  remote: string | null;
  rport: number | null;
  pid: number | null;
  process: string | null;
  container: string | null;
  /** systemd service (without ".service") when the process isn't in a container. */
  unit: string | null;
  detail: string;
}

/** GET /api/timeline?window=24h|7d&limit= — one lane per flagged source, highest score first. */
export interface Timeline {
  since: number;
  now: number;
  rows: TimelineRow[];
}

export interface TimelineRow {
  ip: string;
  geo: GeoInfo;
  score: number;
  findings: Finding[];
  allowlisted: boolean;
  status: "banned" | "ban proposed" | "watching";
  ssh_accepted: number;
  first_seen: number;
  last_seen: number;
  hours: { hour: number; in_packets: number; syn: number; blocked: number }[];
  /** Oldest first, inside the window. */
  events: TimelineEvent[];
  ban: Ban | null;
}

export interface TimelineEvent {
  ts: number;
  kind: "finding" | "proposal" | "ban" | "login";
  label: string;
  /** The finding's kind (ssh_bruteforce, port_scan, ...), for findings. */
  finding?: string;
}
