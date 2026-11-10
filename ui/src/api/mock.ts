// Fixture data for `npm run dev:mock` (VITE_MOCK=1). Loaded via dynamic import
// from client.ts only in mock mode, so none of this ships in production builds.
import pkg from "../../package.json";
import { ApiError } from "./client";
import type {
  Alert,
  AppMeta,
  AsnAgg,
  Ban,
  ConnEvent,
  CountryAgg,
  Destination,
  Destinations,
  DnsInfo,
  DnsQuery,
  DnsTopName,
  FlowDir,
  FlowGroup,
  FlowMinute,
  FlowRow,
  FlowsSummary,
  IfStat,
  InterfacesInfo,
  Listener,
  GeoInfo,
  HistoryRow,
  HourPoint,
  Insight,
  LlmInfo,
  LlmRun,
  LlmStatus,
  Overview,
  Policy,
  PolicyRule,
  PortAgg,
  PortTouch,
  ProbeEvent,
  Proposal,
  SeriesPoint,
  Source,
  SourceDetail,
  SshEvent,
  Summary,
} from "./types";

// ---------------------------------------------------------------------------
// helpers

const now = () => Math.floor(Date.now() / 1000);
const BOOT = now() - (3 * 86400 + 4 * 3600 + 17 * 60);

function rng(seed: number) {
  let s = seed >>> 0 || 1;
  return () => {
    s ^= s << 13;
    s ^= s >>> 17;
    s ^= s << 5;
    return ((s >>> 0) % 1_000_000) / 1_000_000;
  };
}
function hash(str: string): number {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) h = Math.imul(h ^ str.charCodeAt(i), 16777619);
  return h >>> 0;
}

function geo(cc: string | null, country: string | null, city: string | null, asn: number | null, org: string | null, lat: number | null = null, lon: number | null = null): GeoInfo {
  return { country_code: cc, country, city, lat, lon, asn, as_org: org };
}
const loc = (g: GeoInfo) => [g.country_code, g.asn ? `AS${g.asn}` : null, g.as_org].filter(Boolean).join(" ") || "unknown";

const SERVICES: Record<number, string> = {
  22: "ssh",
  23: "telnet",
  25: "smtp",
  53: "dns",
  80: "http",
  123: "ntp",
  443: "https",
  445: "microsoft-ds",
  1433: "ms-sql",
  2375: "docker",
  3306: "mysql",
  3389: "rdp",
  5060: "sip",
  5432: "postgresql",
  5900: "vnc",
  6379: "redis",
  8080: "http-alt",
  8443: "https-alt",
  9200: "elasticsearch",
  11211: "memcached",
  27017: "mongodb",
};
const LISTENING = new Set([22, 80, 443]);

// ---------------------------------------------------------------------------
// sources

interface SourceSeed {
  ip: string;
  geo: GeoInfo;
  ageH: number; // first seen, hours ago
  lastS: number; // last seen, seconds ago
  inPackets: number;
  syn: number;
  ports: number;
  pps: number;
  findings: { kind: string; score: number; summary: string }[];
  feeds?: string[];
  allowlisted?: boolean;
  banned?: boolean;
  ssh?: { failed: number; invalid_users: number; accepted: number };
  udp?: number;
  icmp?: number;
}

const SEEDS: SourceSeed[] = [
  {
    ip: "218.92.0.112",
    geo: geo("CN", "China", "Nanjing", 4134, "CHINANET-BACKBONE", 32.06, 118.78),
    ageH: 52,
    lastS: 14,
    inPackets: 48_210,
    syn: 9_840,
    ports: 1,
    pps: 6.2,
    findings: [
      { kind: "ssh_bruteforce", score: 92, summary: "1,284 failed SSH logins in 1h (root, admin, ubuntu, …)" },
      { kind: "threat_feed", score: 70, summary: "Listed by blocklist.de and firehol_level1" },
    ],
    feeds: ["blocklist_de", "firehol_level1"],
    banned: true,
    ssh: { failed: 1284, invalid_users: 311, accepted: 0 },
  },
  {
    ip: "61.177.172.140",
    geo: geo("CN", "China", "Lianyungang", 4134, "CHINANET-BACKBONE", 34.6, 119.22),
    ageH: 6,
    lastS: 42,
    inPackets: 6_904,
    syn: 1_210,
    ports: 1,
    pps: 2.1,
    findings: [{ kind: "ssh_bruteforce", score: 81, summary: "204 failed SSH logins in 1h, 37 invalid users" }],
    feeds: ["blocklist_de"],
    ssh: { failed: 204, invalid_users: 37, accepted: 0 },
  },
  {
    ip: "121.36.212.9",
    geo: geo("CN", "China", "Beijing", 55990, "Huawei Cloud Service data center", 39.9, 116.4),
    ageH: 2,
    lastS: 95,
    inPackets: 3_120,
    syn: 3_002,
    ports: 412,
    pps: 4.4,
    findings: [{ kind: "port_scan", score: 74, summary: "SYN scan of 412 distinct ports in 10m" }],
  },
  {
    ip: "47.92.101.33",
    geo: geo("CN", "China", "Zhangjiakou", 37963, "Hangzhou Alibaba Advertising Co.,Ltd.", 40.8, 114.88),
    ageH: 20,
    lastS: 610,
    inPackets: 980,
    syn: 960,
    ports: 38,
    pps: 0.3,
    findings: [{ kind: "port_scan", score: 48, summary: "Probed 38 ports incl. redis, docker, elasticsearch" }],
  },
  {
    ip: "193.163.125.14",
    geo: geo("RU", "Russia", "Saint Petersburg", 49505, "JSC Selectel", 59.94, 30.31),
    ageH: 30,
    lastS: 8,
    inPackets: 22_410,
    syn: 21_880,
    ports: 1_870,
    pps: 11.9,
    findings: [
      { kind: "port_scan", score: 88, summary: "SYN scan of 1,870 ports in 1h" },
      { kind: "threat_feed", score: 60, summary: "Listed by firehol_level1" },
    ],
    feeds: ["firehol_level1"],
    banned: true,
  },
  {
    ip: "45.141.84.126",
    geo: geo("RU", "Russia", "Moscow", 206728, "Media Land LLC", 55.75, 37.62),
    ageH: 4,
    lastS: 160,
    inPackets: 1_402,
    syn: 1_380,
    ports: 6,
    pps: 0.9,
    findings: [{ kind: "rdp_probe", score: 57, summary: "Repeated SYN to 3389 and 5900 (RDP/VNC)" }],
    feeds: ["spamhaus_drop"],
  },
  {
    ip: "162.142.125.221",
    geo: geo("US", "United States", "Ann Arbor", 398324, "CENSYS-ARIN-01", 42.28, -83.74),
    ageH: 70,
    lastS: 1_250,
    inPackets: 860,
    syn: 840,
    ports: 96,
    pps: 0.05,
    findings: [{ kind: "port_scan", score: 35, summary: "Research scanner (Censys), 96 ports over 24h" }],
  },
  {
    ip: "64.62.197.18",
    geo: geo("US", "United States", "Fremont", 6939, "HURRICANE", 37.55, -121.98),
    ageH: 40,
    lastS: 3_400,
    inPackets: 210,
    syn: 140,
    ports: 22,
    pps: 0.0,
    findings: [{ kind: "udp_probe", score: 22, summary: "Shadowserver-style UDP probes (ntp, memcached, dns)" }],
    udp: 70,
  },
  {
    ip: "159.89.48.201",
    geo: geo("US", "United States", "Clifton", 14061, "DIGITALOCEAN-ASN", 40.86, -74.16),
    ageH: 1,
    lastS: 22,
    inPackets: 5_820,
    syn: 2_900,
    ports: 3,
    pps: 3.7,
    findings: [{ kind: "http_flood", score: 63, summary: "Sustained 3.7 pps to 80/443 with 50% SYN" }],
  },
  {
    ip: "3.84.27.190",
    geo: geo("US", "United States", "Ashburn", 14618, "AMAZON-AES", 39.04, -77.49),
    ageH: 12,
    lastS: 300,
    inPackets: 410,
    syn: 12,
    ports: 1,
    pps: 0.1,
    findings: [],
  },
  {
    ip: "172.70.214.88",
    geo: geo("US", "United States", "San Francisco", 13335, "CLOUDFLARENET", 37.77, -122.42),
    ageH: 76,
    lastS: 2,
    inPackets: 412_900,
    syn: 8_900,
    ports: 1,
    pps: 38.4,
    findings: [],
    allowlisted: true,
  },
  {
    ip: "162.158.90.41",
    geo: geo("DE", "Germany", "Frankfurt am Main", 13335, "CLOUDFLARENET", 50.11, 8.68),
    ageH: 76,
    lastS: 5,
    inPackets: 288_400,
    syn: 6_100,
    ports: 1,
    pps: 21.7,
    findings: [],
    allowlisted: true,
  },
  {
    ip: "198.51.100.23",
    geo: geo("ES", "Spain", "Madrid", 3352, "TELEFONICA_DE_ESPANA", 40.42, -3.7),
    ageH: 9,
    lastS: 1_900,
    inPackets: 3_400,
    syn: 3,
    ports: 1,
    pps: 0.0,
    findings: [],
    ssh: { failed: 0, invalid_users: 0, accepted: 2 },
  },
  {
    ip: "100.88.14.3",
    geo: geo(null, null, null, null, null),
    ageH: 50,
    lastS: 640,
    inPackets: 1_120,
    syn: 2,
    ports: 1,
    pps: 0.0,
    findings: [],
    ssh: { failed: 0, invalid_users: 0, accepted: 1 },
  },
  {
    ip: "2001:db8:85a3::8a2e:370:7334",
    geo: geo("NL", "Netherlands", "Amsterdam", 60781, "LeaseWeb Netherlands B.V.", 52.37, 4.9),
    ageH: 3,
    lastS: 420,
    inPackets: 640,
    syn: 600,
    ports: 18,
    pps: 0.2,
    findings: [{ kind: "port_scan", score: 41, summary: "IPv6 SYN scan of 18 ports" }],
  },
];

function buildSource(s: SourceSeed): Source {
  const t = now();
  const jitter = 1 + 0.15 * Math.sin(t / 37 + hash(s.ip));
  const in_bytes = s.inPackets * (s.allowlisted ? 820 : s.ssh?.failed ? 140 : 62);
  const pps = s.pps * jitter;
  return {
    ip: s.ip,
    geo: s.geo,
    first_seen: t - s.ageH * 3600,
    last_seen: t - s.lastS,
    packets: Math.round(s.inPackets * 1.6),
    bytes: Math.round(in_bytes * 1.8),
    in_packets: s.inPackets,
    in_bytes,
    syn: s.syn,
    udp_in: s.udp ?? 0,
    icmp_in: s.icmp ?? Math.round(s.inPackets * 0.002),
    blocked: s.banned ? Math.round(s.inPackets * 0.7) : 0,
    rate: { in_pps: pps, in_bps: pps * (in_bytes / Math.max(1, s.inPackets)) * 8, syn_ps: pps * (s.syn / Math.max(1, s.inPackets)) },
    ports: s.ports,
    score: s.findings.reduce((m, f) => Math.max(m, f.score), 0),
    findings: s.findings,
    feeds: s.feeds ?? [],
    allowlisted: !!s.allowlisted,
    banned: !!s.banned,
    ssh: s.ssh ?? { failed: 0, invalid_users: 0, accepted: 0 },
  };
}

function allSources(): Source[] {
  return SEEDS.map(buildSource);
}

// ---------------------------------------------------------------------------
// alerts, bans, proposals, ssh, events

function alerts(): Alert[] {
  const t = now();
  let id = 140;
  const out: Alert[] = [];
  for (const s of SEEDS) {
    for (const f of s.findings) {
      out.push({
        id: id++,
        ip: s.ip,
        kind: f.kind,
        score: f.score,
        summary: f.summary,
        location: loc(s.geo),
        first_ts: t - s.ageH * 3600 + 600,
        last_ts: t - s.lastS,
        count: 1 + (hash(s.ip + f.kind) % 40),
      });
    }
  }
  return out.sort((a, b) => b.last_ts - a.last_ts);
}

function bans(): Ban[] {
  const t = now();
  return [
    { target: "218.92.0.112", created: t - 50 * 3600, expires: t - 50 * 3600 + 7 * 86400, reason: "ssh_bruteforce score 92 (policy rule ssh-bruteforce-week)", source: "policy", dropped: 33_740 },
    { target: "193.163.125.14", created: t - 26 * 3600, expires: t + 22 * 3600, reason: "port_scan score 88, approved LLM proposal #31", source: "llm", dropped: 15_310 },
    { target: "45.148.10.0/24", created: t - 9 * 86400, expires: null, reason: "Known malicious hosting range (operator)", source: "manual", dropped: 4_102 },
    { target: "185.224.128.17", created: t - 3 * 3600, expires: t + 21 * 3600, reason: "threat_feed + port_scan", source: "auto", dropped: 0 },
  ];
}

function proposals(): Proposal[] {
  const t = now();
  const p = (o: Omit<Proposal, "approve_cmd">): Proposal => ({ ...o, approve_cmd: `sudo netwatch approve ${o.id}` });
  return [
    p({ id: 42, created: t - 240, target: "61.177.172.140", action: "ban", ttl_secs: 7 * 86400, reason: "SSH brute force from CHINANET (204 failures/h, 37 invalid users). Same /16 as active ban 218.92.0.112.", source: "llm", confidence: 0.91, status: "pending", decided_at: null }),
    p({ id: 41, created: t - 900, target: "121.36.212.9", action: "ban", ttl_secs: 86400, reason: "SYN scan of 412 ports in 10m from a cloud provider.", source: "rules", confidence: 0.8, status: "pending", decided_at: null }),
    p({ id: 40, created: t - 1_800, target: "159.89.48.201", action: "review", ttl_secs: null, reason: "Sustained HTTP SYN load from DigitalOcean; could be a misbehaving client or a flood.", source: "llm", confidence: 0.55, status: "pending", decided_at: null }),
    p({ id: 39, created: t - 3_600, target: "162.142.125.0/24", action: "allow", ttl_secs: null, reason: "Censys research scanner; low risk, reduce noise.", source: "llm", confidence: 0.62, status: "pending", decided_at: null }),
    p({ id: 31, created: t - 27 * 3600, target: "193.163.125.14", action: "ban", ttl_secs: 2 * 86400, reason: "Port scan of 1,870 ports, listed by firehol_level1.", source: "llm", confidence: 0.94, status: "applied", decided_at: t - 26 * 3600 }),
    p({ id: 28, created: t - 40 * 3600, target: "64.62.197.18", action: "ban", ttl_secs: 86400, reason: "UDP probes to amplification ports.", source: "rules", confidence: 0.6, status: "rejected", decided_at: t - 39 * 3600 }),
    p({ id: 25, created: t - 60 * 3600, target: "203.0.113.50", action: "unban", ttl_secs: null, reason: "Ban expired-equivalent: no traffic for 72h.", source: "llm", confidence: 0.7, status: "expired", decided_at: null }),
    p({ id: 22, created: t - 70 * 3600, target: "198.51.100.23", action: "allow", ttl_secs: null, reason: "Operator's home IP (accepted publickey logins).", source: "llm", confidence: 0.88, status: "approved", decided_at: t - 69 * 3600 }),
  ];
}

function insights(): Insight[] {
  return [
    { level: "critical", title: "SSH brute force from CHINANET /16 is ongoing", detail: "61.177.172.140 made 204 failed logins in the last hour. 218.92.0.112 in the same network is already banned. Proposal #42 is pending.", action: "sudo netwatch approve 42" },
    { level: "warn", title: "4 proposed action(s) waiting for approval", detail: "Rules and the LLM propose; nothing is applied in observe mode until you approve.", action: "netwatch proposals" },
    { level: "warn", title: "Redis and Docker ports are being probed", detail: "6 sources touched 6379/2375 in the last 24h. Neither is listening, but confirm the firewall blocks them on every interface.", action: null },
    { level: "info", title: "Cloudflare traffic allowlisted", detail: "2 Cloudflare edge IPs account for 91% of inbound bytes; they are excluded from scoring.", action: null },
    { level: "info", title: "9 source(s) would be banned automatically in enforce mode", detail: "Set mode = \"enforce\" in the config once you trust the proposals.", action: "netwatch proposals" },
  ];
}

function sshEvents(): SshEvent[] {
  const t = now();
  const out: SshEvent[] = [];
  const r = rng(7);
  const users = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "git", "user", "deploy", "pi"];
  for (let i = 0; i < 60; i++) {
    const s = r() < 0.65 ? SEEDS[0] : SEEDS[1];
    const u = users[Math.floor(r() * users.length)];
    const k: SshEvent["kind"] = r() < 0.25 ? "invalid_user" : r() < 0.1 ? "preauth_close" : "failed";
    out.push({ ts: t - Math.floor(i * 47 + r() * 30) - 10, kind: k, user: k === "preauth_close" ? null : u, ip: s.ip, method: k === "preauth_close" ? null : "password", location: loc(s.geo) });
  }
  out.push({ ts: t - 1_900, kind: "accepted", user: "alice", ip: "198.51.100.23", method: "publickey", location: loc(SEEDS[12].geo) });
  out.push({ ts: t - 30_000, kind: "accepted", user: "alice", ip: "198.51.100.23", method: "publickey", location: loc(SEEDS[12].geo) });
  out.push({ ts: t - 640, kind: "tailscale_login", user: "alice@github", ip: "100.88.14.3", method: "tailscale", location: "tailnet" });
  out.push({ ts: t - 2_600, kind: "failed", user: "root", ip: "45.141.84.126", method: "password", location: loc(SEEDS[5].geo) });
  return out.sort((a, b) => b.ts - a.ts);
}

function events(limit: number): ProbeEvent[] {
  const t = now();
  const out: ProbeEvent[] = [];
  const scanners = SEEDS.filter((s) => s.findings.length && !s.allowlisted);
  // New events appear every ~4s so the live feed visibly moves.
  const head = Math.floor(t / 4);
  for (let i = 0; i < limit; i++) {
    const k = head - i;
    const r = rng(k * 2654435761);
    const s = scanners[Math.floor(r() * scanners.length)];
    const ports = s.ssh?.failed ? [22] : [22, 23, 80, 443, 445, 1433, 2375, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017, 11211, 123, 53];
    const port = ports[Math.floor(r() * ports.length)];
    const udp = s.udp && r() < 0.6;
    const p = udp ? [123, 11211, 53, 5060][Math.floor(r() * 4)] : port;
    out.push({
      ts: k * 4 - Math.floor(r() * 3),
      ip: s.ip,
      proto: udp ? "udp" : "tcp",
      port: p,
      service: SERVICES[p] ?? null,
      tcp_flags: udp ? 0 : 0x02,
      ttl: [44, 48, 52, 112, 238][Math.floor(r() * 5)],
      location: loc(s.geo),
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// overview

function series(): SeriesPoint[] {
  const t = now();
  const out: SeriesPoint[] = [];
  // One point per 10s tick for 30 minutes.
  const step = 10;
  const start = Math.floor(t / step) * step - 179 * step;
  for (let i = 0; i < 180; i++) {
    const ts = start + i * step;
    const r = rng(ts);
    const base = 70 + 18 * Math.sin(ts / 300) + 8 * Math.sin(ts / 47);
    const burst = ts % 900 > 600 && ts % 900 < 700 ? 60 * Math.sin(((ts % 900) - 600) / 31.8) : 0;
    const in_pps = Math.max(0, base + burst + r() * 10);
    const syn_pps = Math.max(0, 6 + burst * 0.8 + r() * 4);
    const dropped_pps = Math.max(0, 12 + 6 * Math.sin(ts / 120) + r() * 3);
    out.push({ ts, pps: in_pps * 1.55 + r() * 6, in_pps, syn_pps, dropped_pps });
  }
  return out;
}

function llmStatus(): LlmStatus {
  return { enabled: true, model: "qwen3:14b", base_url: "http://127.0.0.1:11434/v1", calls_today: 14, tokens_today: 82_100, budget_tokens_day: 200_000, last_run: now() - 420 };
}

function overview(): Overview {
  const t = now();
  const s = series();
  const last = s[s.length - 1];
  return {
    host: "edge-01",
    version: pkg.version,
    interface: "eno1",
    attach_mode: "driver",
    mode: "observe",
    drop_banned: true,
    started_at: BOOT,
    now: t,
    rates: { pps: last.pps, bps: last.pps * 610 * 8, in_pps: last.in_pps, syn_pps: last.syn_pps, dropped_pps: last.dropped_pps },
    totals: { packets: 41_822_390, bytes: 31_408_811_200, in_packets: 26_120_334, syn: 1_904_221, blocked: 52_152, dropped: 51_906, events_lost: 3 },
    counts: { sources_tracked: 2_314, sources_active_10m: 187, flagged: 11, bans_active: 4, proposals_pending: 4, ssh_failed_1h: 1_488 },
    llm: llmStatus(),
    geo_db: true,
    feeds: [
      { name: "firehol_level1", entries: 4_512 },
      { name: "blocklist_de", entries: 27_903 },
      { name: "spamhaus_drop", entries: 1_402 },
    ],
    series: s,
    flows: overviewFlows(),
    interfaces: interfaces()
      .interfaces.filter((i) => i.flows || i.xdp)
      .map((i) => ({ name: i.name, kind: i.kind, rx_bps: i.rx_bps, tx_bps: i.tx_bps, xdp: i.xdp, flows: i.flows })),
  };
}

// ---------------------------------------------------------------------------
// source detail

function history(s: SourceSeed): HourPoint[] {
  const t = now();
  const hourNow = Math.floor(t / 3600) * 3600;
  const r = rng(hash(s.ip));
  const out: HourPoint[] = [];
  const score = s.findings.reduce((m, f) => Math.max(m, f.score), 0);
  for (let h = 167; h >= 0; h--) {
    if (h > s.ageH) continue; // sparse: no rows before first seen
    const hour = hourNow - h * 3600;
    if (r() < 0.15 && !s.allowlisted) continue; // quiet hours
    const daily = 0.6 + 0.4 * Math.sin((hour / 3600 / 24) * Math.PI * 2);
    const in_packets = Math.round((s.inPackets / Math.max(1, Math.min(168, s.ageH))) * daily * (0.5 + r()));
    const syn = Math.round(in_packets * (s.syn / Math.max(1, s.inPackets)));
    out.push({ hour, in_packets, in_bytes: in_packets * 90, syn, blocked: s.banned && h < 50 ? Math.round(in_packets * 0.9) : 0, max_score: Math.round(score * (0.6 + 0.4 * r())) });
  }
  return out;
}

function portTouches(s: SourceSeed): PortTouch[] {
  const t = now();
  const r = rng(hash(s.ip) + 3);
  const candidates = s.ssh?.failed || s.ssh?.accepted ? [22] : s.allowlisted ? [443] : s.ip === "159.89.48.201" ? [80, 443, 8080] : Object.keys(SERVICES).map(Number);
  const n = Math.min(candidates.length, Math.max(1, Math.min(s.ports, 24)));
  const out: PortTouch[] = [];
  for (let i = 0; i < n; i++) {
    const port = candidates[i];
    const udp = !!s.udp && [53, 123, 11211, 5060].includes(port);
    const packets = Math.round(1 + r() * (s.inPackets / n));
    out.push({
      proto: udp ? "udp" : "tcp",
      port,
      service: SERVICES[port] ?? null,
      listening: LISTENING.has(port) && !udp,
      first_seen: t - Math.round(s.ageH * 3600 * (0.5 + r() * 0.5)),
      last_seen: t - s.lastS - Math.round(r() * 600),
      packets,
      syn: udp ? 0 : Math.round(packets * (s.syn / Math.max(1, s.inPackets))),
    });
  }
  return out.sort((a, b) => b.packets - a.packets);
}

function detail(ip: string): SourceDetail {
  const seed = SEEDS.find((s) => s.ip === ip);
  const t = now();
  const flows = [...activeFlows(t).filter((f) => f.remote === ip || f.local === ip), ...historyFlows(t).filter((f) => f.remote === ip || f.local === ip).slice(0, 200)];
  const name = REMOTES[ip]?.name;
  const dns_names = name ? [name] : [];
  if (!seed) {
    // Not a tracked source, but the store remembers conversations with it.
    if (!flows.length) throw new ApiError(404, `${ip} has not been seen`);
    const r = REMOTES[ip];
    const g = r && isPublicIp(ip) ? geo(r.cc, COUNTRY_NAMES[r.cc ?? ""] ?? r.cc, null, r.asn, r.org) : geo(null, null, null, null, null);
    return {
      ip,
      geo: g,
      first_seen: 0,
      last_seen: 0,
      packets: 0,
      bytes: 0,
      in_packets: 0,
      in_bytes: 0,
      syn: 0,
      udp_in: 0,
      icmp_in: 0,
      blocked: 0,
      rate: { in_pps: 0, in_bps: 0, syn_ps: 0 },
      ports: 0,
      score: 0,
      findings: [],
      feeds: [],
      allowlisted: false,
      banned: false,
      ssh: { failed: 0, invalid_users: 0, accepted: 0 },
      port_touches: [],
      alerts: [],
      history: [],
      ssh_events: [],
      ban: null,
      proposals: [],
      flows,
      dns_names,
    };
  }
  const base = buildSource(seed);
  return {
    ...base,
    port_touches: portTouches(seed),
    alerts: alerts().filter((a) => a.ip === ip),
    history: history(seed),
    ssh_events: sshEvents().filter((e) => e.ip === ip).slice(0, 50),
    ban: bans().find((b) => b.target === ip) ?? null,
    proposals: proposals().filter((p) => p.target === ip),
    flows,
    dns_names,
  };
}

// ---------------------------------------------------------------------------
// summary

function summary(window: string): Summary {
  const scale = window === "1h" ? 0.04 : window === "7d" ? 4.5 : 1;
  const sources = allSources();
  const byCc = new Map<string, CountryAgg>();
  const byAsn = new Map<number, AsnAgg>();
  for (const s of sources) {
    const cc = s.geo.country_code ?? "??";
    const c = byCc.get(cc) ?? { country_code: cc, country: s.geo.country ?? "Unknown", sources: 0, flagged: 0, syn: 0, in_packets: 0 };
    c.sources += 1;
    c.flagged += s.score > 0 ? 1 : 0;
    c.syn += s.syn;
    c.in_packets += s.in_packets;
    byCc.set(cc, c);
    if (s.geo.asn) {
      const a = byAsn.get(s.geo.asn) ?? { asn: s.geo.asn, org: s.geo.as_org ?? "", sources: 0, flagged: 0, syn: 0 };
      a.sources += 1;
      a.flagged += s.score > 0 ? 1 : 0;
      a.syn += s.syn;
      byAsn.set(s.geo.asn, a);
    }
  }
  // Pad with a long tail so tables look realistic.
  const extra: [string, string, number][] = [
    ["BR", "Brazil", 31],
    ["IN", "India", 27],
    ["VN", "Vietnam", 19],
    ["KR", "South Korea", 14],
    ["GB", "United Kingdom", 12],
    ["FR", "France", 9],
    ["IR", "Iran", 6],
  ];
  const mult = (n: number) => Math.max(1, Math.round(n * scale));
  const countries = [...byCc.values()].map((c) => ({ ...c, sources: mult(c.sources * 18), flagged: mult(c.flagged * 3), syn: mult(c.syn), in_packets: mult(c.in_packets) }));
  for (const [cc, name, n] of extra) countries.push({ country_code: cc, country: name, sources: mult(n), flagged: mult(n / 6), syn: mult(n * 410), in_packets: mult(n * 700) });
  const asns = [...byAsn.values()].map((a) => ({ ...a, sources: mult(a.sources * 9), flagged: mult(a.flagged * 2), syn: mult(a.syn) }));
  asns.push({ asn: 9829, org: "National Internet Backbone", sources: mult(22), flagged: mult(4), syn: mult(8_400) });
  asns.push({ asn: 7552, org: "Viettel Group", sources: mult(17), flagged: mult(3), syn: mult(6_100) });
  const ports: PortAgg[] = Object.entries(SERVICES).map(([p, svc]) => {
    const port = Number(p);
    const r = rng(port + 11);
    const udp = [53, 123, 11211, 5060].includes(port);
    return { proto: udp ? "udp" : "tcp", port, service: svc, listening: LISTENING.has(port), sources: mult(5 + r() * (port === 22 ? 400 : 120)), syn: udp ? 0 : mult(200 + r() * (port === 22 ? 40_000 : 9_000)) };
  });
  const top_history: HistoryRow[] = SEEDS.filter((s) => !s.allowlisted)
    .map((s) => {
      const b = buildSource(s);
      return { ip: s.ip, location: loc(s.geo), in_packets: mult(b.in_packets), in_bytes: mult(b.in_bytes), syn: mult(b.syn), blocked: mult(b.blocked), max_score: b.score, hours: Math.min(window === "1h" ? 1 : window === "7d" ? 168 : 24, s.ageH), last_hour: Math.floor((now() - s.lastS) / 3600) * 3600 };
    })
    .sort((a, b) => b.in_packets - a.in_packets);
  return {
    window,
    countries: countries.sort((a, b) => b.sources - a.sources),
    asns: asns.sort((a, b) => b.sources - a.sources),
    ports: ports.sort((a, b) => b.sources - a.sources),
    top_history,
  };
}

// ---------------------------------------------------------------------------
// policy, llm

const defaults: PolicyRule[] = [
  { id: "default-never-ban-allowlist", description: "Never ban allowlisted networks (Cloudflare, tailnet, operator IPs)", action: "never_ban", ttl_secs: null, when: { allowlisted: true }, enabled: true },
  { id: "default-never-ban-private", description: "Never ban RFC1918 / CGNAT / loopback sources", action: "never_ban", ttl_secs: null, when: { cidr_in: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8"] }, enabled: true },
  { id: "default-review-high-score", description: "Propose review for any source scoring 60 or more", action: "review", ttl_secs: null, when: { score_gte: 60 }, enabled: true },
];

function policy(): Policy {
  const text =
    "Ban SSH brute force for a week. Ban port scanners for a day if they also appear on a threat feed. Never ban Cloudflare or my home IP. Anything from research scanners like Censys or Shodan: just ignore.";
  return {
    text,
    rules: [
      { id: "ssh-bruteforce-week", description: "SSH brute force: ban for 7 days", action: "ban", ttl_secs: 7 * 86400, when: { finding: "ssh_bruteforce", score_gte: 70 }, enabled: true },
      { id: "scan-plus-feed-day", description: "Port scanners on a threat feed: ban for 1 day", action: "ban", ttl_secs: 86400, when: { finding: "port_scan", feeds_any: true }, enabled: true },
      { id: "never-ban-cloudflare", description: "Never ban Cloudflare", action: "never_ban", ttl_secs: null, when: { asn_in: [13335] }, enabled: true },
      { id: "never-ban-home", description: "Never ban the operator's home IP", action: "never_ban", ttl_secs: null, when: { ip_in: ["198.51.100.23"] }, enabled: true },
      { id: "ignore-research-scanners", description: "Ignore research scanners (Censys, Shodan)", action: "ignore", ttl_secs: null, when: { asn_in: [398324, 10439], as_org_matches: "(?i)censys|shodan" }, enabled: false },
    ],
    defaults,
    compiled_at: now() - 3 * 86400,
    compiled_by: "qwen3:14b",
    set_cmd: `sudo netwatch policy set '${text.replace(/'/g, "'\\''")}'`,
  };
}

function llm(): LlmInfo {
  const t = now();
  const runs: LlmRun[] = [];
  const r = rng(99);
  for (let i = 0; i < 14; i++) {
    runs.push({
      ts: t - 420 - i * 1800,
      kind: i === 13 ? "compile_policy" : "analyze",
      model: "qwen3:14b",
      prompt_tokens: Math.round(3500 + r() * 2500),
      completion_tokens: Math.round(300 + r() * 700),
      summary:
        i === 0
          ? "SSH brute force from 61.177.172.140 (CHINANET); proposed 7d ban. Huawei Cloud SYN scan; proposed 1d ban."
          : i === 13
            ? "Compiled policy into 5 rules (2 ban, 2 never_ban, 1 ignore)."
            : ["No new threats beyond existing bans.", "Censys scanner activity; suggested allowlist.", "DigitalOcean HTTP load flagged for review.", "Quiet period; nothing to propose."][i % 4],
      proposals: i === 0 ? 2 : i % 3 === 0 ? 1 : 0,
    });
  }
  return { ...llmStatus(), runs };
}

// ---------------------------------------------------------------------------
// flows, interfaces, listeners, dns, connection events

const HOST4 = "203.0.113.10";
const HOST6 = "2001:db8:1::10";
const TS4 = "100.101.102.103";

const COUNTRY_NAMES: Record<string, string> = { US: "United States", DE: "Germany", NL: "Netherlands", FI: "Finland", GB: "United Kingdom", CH: "Switzerland", IE: "Ireland", CN: "China", RU: "Russia", ES: "Spain" };

interface Rem {
  cc: string | null;
  asn: number | null;
  org: string | null;
  name?: string;
}
const REMOTES: Record<string, Rem> = {
  "172.70.214.88": { cc: "US", asn: 13335, org: "CLOUDFLARENET" },
  "162.158.90.41": { cc: "DE", asn: 13335, org: "CLOUDFLARENET" },
  "198.51.100.23": { cc: "ES", asn: 3352, org: "TELEFONICA_DE_ESPANA" },
  "218.92.0.112": { cc: "CN", asn: 4134, org: "CHINANET-BACKBONE" },
  "61.177.172.140": { cc: "CN", asn: 4134, org: "CHINANET-BACKBONE" },
  "121.36.212.9": { cc: "CN", asn: 55990, org: "Huawei Cloud Service data center" },
  "47.92.101.33": { cc: "CN", asn: 37963, org: "Hangzhou Alibaba Advertising Co.,Ltd." },
  "159.89.48.201": { cc: "US", asn: 14061, org: "DIGITALOCEAN-ASN" },
  "193.163.125.14": { cc: "RU", asn: 49505, org: "JSC Selectel" },
  "140.82.121.4": { cc: "US", asn: 36459, org: "GITHUB", name: "github.com" },
  "104.16.27.34": { cc: "US", asn: 13335, org: "CLOUDFLARENET", name: "registry.npmjs.org" },
  "54.236.113.205": { cc: "US", asn: 14618, org: "AMAZON-AES", name: "registry-1.docker.io" },
  "9.9.9.9": { cc: "CH", asn: 19281, org: "Quad9" },
  "162.159.200.1": { cc: "US", asn: 13335, org: "CLOUDFLARENET", name: "time.cloudflare.com" },
  "149.137.128.10": { cc: "NL", asn: 40401, org: "BACKBLAZE", name: "s3.eu-central-003.backblazeb2.com" },
  "3.120.10.20": { cc: "DE", asn: 16509, org: "AMAZON-02", name: "derp4.tailscale.com" },
  "95.217.10.44": { cc: "FI", asn: 24940, org: "Hetzner Online GmbH", name: "db.backup.example.com" },
  "45.33.32.156": { cc: "US", asn: 63949, org: "Akamai Connected Cloud", name: "legacy-api.example.com" },
  "91.189.91.83": { cc: "GB", asn: 41231, org: "Canonical Group Limited", name: "archive.ubuntu.com" },
  "34.117.59.81": { cc: "US", asn: 396982, org: "GOOGLE-CLOUD-PLATFORM", name: "ingest.temps.sh" },
  "2a00:1450:4003:80e::200e": { cc: "IE", asn: 15169, org: "GOOGLE", name: "www.google.com" },
  "100.64.0.7": { cc: null, asn: null, org: null, name: "nas.tail1234.ts.net" },
  "100.88.14.3": { cc: null, asn: null, org: null, name: "laptop.tail1234.ts.net" },
};

function isPublicIp(ip: string): boolean {
  if (ip.includes(":")) return !/^(::1$|fe80:|fc|fd|2001:db8:)/i.test(ip);
  const [a, b] = ip.split(".").map(Number);
  if (a === 10 || a === 127 || a === 0) return false;
  if (a === 172 && b >= 16 && b < 32) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b < 128) return false;
  if ((a === 203 && b === 0) || (a === 198 && b === 51)) return false; // documentation ranges: this host
  return true;
}

interface Owner {
  pid: number;
  comm: string;
  exe: string | null;
  container?: string;
  unit?: string;
}
const O = {
  caddy: { pid: 1840, comm: "caddy", exe: "/usr/bin/caddy", container: "caddy" },
  sshd: { pid: 912, comm: "sshd", exe: "/usr/sbin/sshd", unit: "ssh" },
  nginx: { pid: 2210, comm: "nginx", exe: "/usr/sbin/nginx", container: "web" },
  git: { pid: 30122, comm: "git", exe: "/usr/bin/git" },
  restic: { pid: 4410, comm: "restic", exe: "/usr/local/bin/restic", unit: "restic-backup" },
  tailscaled: { pid: 801, comm: "tailscaled", exe: "/usr/sbin/tailscaled", unit: "tailscaled" },
  resolved: { pid: 655, comm: "systemd-resolve", exe: "/usr/lib/systemd/systemd-resolved", unit: "systemd-resolved" },
  chrony: { pid: 700, comm: "chronyd", exe: "/usr/sbin/chronyd", unit: "chrony" },
  backup: { pid: 5120, comm: "backup-agent", exe: "/opt/backup/bin/backup-agent", unit: "pg-backup" },
  temps: { pid: 1522, comm: "3bfc539f45d2620", exe: "/opt/temps/bin/3bfc539f45d2620e81c4", unit: "temps-agent" },
  prometheus: { pid: 2930, comm: "prometheus", exe: "/bin/prometheus", container: "prometheus" },
  grafana: { pid: 3120, comm: "grafana", exe: "/usr/share/grafana/bin/grafana", container: "grafana" },
  node: { pid: 3301, comm: "node", exe: "/usr/local/bin/node", container: "app" },
  watchtower: { pid: 2788, comm: "watchtower", exe: "/watchtower", container: "watchtower" },
  postgres: { pid: 2650, comm: "postgres", exe: "/usr/lib/postgresql/16/bin/postgres", container: "db" },
  curl: { pid: 41877, comm: "curl", exe: "/usr/bin/curl" },
  apt: { pid: 38110, comm: "http", exe: "/usr/lib/apt/methods/http", unit: "apt-daily-upgrade" },
  redis: { pid: 1180, comm: "redis-server", exe: "/usr/bin/redis-server", unit: "redis-server" },
  dockerProxy: { pid: 2101, comm: "docker-proxy", exe: "/usr/bin/docker-proxy", unit: "docker" },
  avahi: { pid: 640, comm: "avahi-daemon", exe: "/usr/sbin/avahi-daemon", unit: "avahi-daemon" },
} satisfies Record<string, Owner>;

const EXTRA_SERVICES: Record<number, string> = { 3000: "grafana", 9090: "prometheus", 9229: "node-inspect", 41641: "tailscale", 5353: "mdns", 323: "chrony" };
const serviceName = (port: number) => SERVICES[port] ?? EXTRA_SERVICES[port] ?? null;

interface FlowSeed {
  iface: string;
  proto: "tcp" | "udp";
  local: string;
  lport: number;
  remote: string;
  rport: number;
  dir: FlowDir;
  age: number; // first seen, seconds ago
  idle?: number; // last seen, seconds ago
  bin: number;
  bout: number;
  rin?: number; // bytes/s while active
  rout?: number;
  state?: string;
  connect_ms?: number | null;
  retrans?: number;
  rst_sent?: number;
  rst_recv?: number;
  owner?: Owner;
  /** Owner of the remote end when it is on this host. */
  peer?: Owner;
  app?: AppMeta | null;
}

function mkFlow(f: FlowSeed, active: boolean, t: number): FlowRow {
  const r = REMOTES[f.remote];
  const pub = isPublicIp(f.remote);
  const sp = f.dir === "in" ? f.lport : f.rport;
  const jit = active ? Math.max(0, 1 + 0.35 * Math.sin(t / 11 + (hash(f.remote + f.rport) % 97))) : 0;
  const grow = active ? t % 600 : 0;
  const bytes_in = Math.round(f.bin + (f.rin ?? 0) * grow);
  const bytes_out = Math.round(f.bout + (f.rout ?? 0) * grow);
  const per = f.proto === "udp" ? 140 : 1100;
  return {
    iface: f.iface,
    proto: f.proto,
    local: f.local,
    lport: f.lport,
    remote: f.remote,
    rport: f.rport,
    dir: f.dir,
    first_seen: t - f.age,
    last_seen: t - (f.idle ?? (active ? 1 : 0)),
    bytes_in,
    bytes_out,
    pkts_in: bytes_in ? Math.max(1, Math.round(bytes_in / per)) : 0,
    pkts_out: bytes_out ? Math.max(1, Math.round(bytes_out / per)) : 0,
    state: f.state ?? (f.proto === "tcp" ? "established" : "active"),
    connect_ms: f.connect_ms ?? null,
    retrans: f.retrans ?? 0,
    rst_sent: f.rst_sent ?? 0,
    rst_recv: f.rst_recv ?? 0,
    pid: f.owner?.pid ?? null,
    process: f.owner?.comm ?? null,
    exe: f.owner?.exe ?? null,
    container: f.owner?.container ?? null,
    unit: f.owner?.container ? null : (f.owner?.unit ?? null),
    remote_pid: f.peer?.pid ?? null,
    remote_process: f.peer?.comm ?? null,
    remote_container: f.peer?.container ?? null,
    remote_unit: f.peer?.container ? null : (f.peer?.unit ?? null),
    remote_name: r?.name ?? f.app?.sni ?? null,
    app: f.app ?? null,
    country: pub ? (r?.cc ?? null) : null,
    asn: pub ? (r?.asn ?? null) : null,
    as_org: pub ? (r?.org ?? null) : null,
    service_port: sp,
    service: serviceName(sp),
    active,
    rate_in: active ? (f.rin ?? 0) * jit : 0,
    rate_out: active ? (f.rout ?? 0) * jit : 0,
  };
}

const UA_CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
const SSH_SERVER = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5";

const ACTIVE_SEEDS: FlowSeed[] = [
  { iface: "eno1", proto: "tcp", local: HOST4, lport: 443, remote: "172.70.214.88", rport: 51234, dir: "in", age: 412, bin: 1_840_000, bout: 42_300_000, rin: 9_000, rout: 310_000, owner: O.caddy, app: { proto: "tls", sni: "app.example.com", alpn: "h2" } },
  { iface: "eno1", proto: "tcp", local: HOST4, lport: 443, remote: "162.158.90.41", rport: 40122, dir: "in", age: 1_210, bin: 920_000, bout: 18_700_000, rin: 4_100, rout: 120_000, owner: O.caddy, app: { proto: "tls", sni: "grafana.example.com", alpn: "h2" } },
  { iface: "eno1", proto: "tcp", local: HOST4, lport: 22, remote: "198.51.100.23", rport: 50522, dir: "in", age: 1_900, bin: 310_000, bout: 2_400_000, rin: 120, rout: 900, owner: O.sshd, connect_ms: 38.2, app: { proto: "ssh", ssh_client: "SSH-2.0-OpenSSH_9.7", ssh_server: SSH_SERVER } },
  { iface: "eno1", proto: "tcp", local: HOST4, lport: 22, remote: "218.92.0.112", rport: 44120, dir: "in", age: 9, bin: 2_900, bout: 3_400, rin: 300, rout: 340, owner: O.sshd, app: { proto: "ssh", ssh_client: "SSH-2.0-libssh_0.9.6", ssh_server: SSH_SERVER } },
  {
    iface: "eno1", proto: "tcp", local: HOST4, lport: 80, remote: "159.89.48.201", rport: 38812, dir: "in", age: 3, idle: 2, bin: 610, bout: 540, state: "time_wait", owner: O.nginx,
    app: { proto: "http", http_method: "GET", http_host: HOST4, http_path: "/wp-login.php?redirect_to=%2Fwp-admin%2F&reauth=1", user_agent: `${UA_CHROME} zgrab/0.x`, http_status: 404, server: "nginx/1.25.3" },
  },
  { iface: "eno1", proto: "tcp", local: HOST4, lport: 3389, remote: "193.163.125.14", rport: 61000, dir: "in", age: 2, bin: 60, bout: 40, state: "closed", rst_sent: 1 },
  { iface: "eno1", proto: "tcp", local: HOST4, lport: 6379, remote: "47.92.101.33", rport: 53120, dir: "in", age: 4, bin: 60, bout: 0, state: "unanswered" },
  { iface: "eno1", proto: "tcp", local: HOST4, lport: 443, remote: "121.36.212.9", rport: 47712, dir: "in", age: 1, bin: 60, bout: 60, state: "syn_recv", owner: O.caddy },
  { iface: "eno1", proto: "tcp", local: HOST4, lport: 48812, remote: "140.82.121.4", rport: 443, dir: "out", age: 6, bin: 3_800_000, bout: 41_000, rin: 640_000, rout: 2_000, connect_ms: 18.4, owner: O.git, app: { proto: "tls", sni: "github.com", alpn: "http/1.1" } },
  { iface: "eno1", proto: "tcp", local: HOST4, lport: 50110, remote: "149.137.128.10", rport: 443, dir: "out", age: 1_420, bin: 9_400_000, bout: 1_240_000_000, rin: 6_000, rout: 9_200_000, connect_ms: 31.9, retrans: 37, owner: O.restic, app: { proto: "tls", sni: "s3.eu-central-003.backblazeb2.com", alpn: "h2" } },
  { iface: "eno1", proto: "tcp", local: HOST4, lport: 39220, remote: "34.117.59.81", rport: 443, dir: "out", age: 3_300, bin: 81_000, bout: 1_900_000, rin: 20, rout: 600, connect_ms: 12.1, owner: O.temps, app: { proto: "tls", sni: "ingest.temps.sh", alpn: "h2" } },
  { iface: "eno1", proto: "udp", local: HOST4, lport: 41641, remote: "3.120.10.20", rport: 41641, dir: "out", age: 5_400, bin: 210_000, bout: 190_000, rin: 90, rout: 80, owner: O.tailscaled },
  { iface: "eno1", proto: "udp", local: HOST4, lport: 53114, remote: "9.9.9.9", rport: 53, dir: "out", age: 1, bin: 180, bout: 64, owner: O.resolved, app: { dns_qname: "registry-1.docker.io" } },
  { iface: "eno1", proto: "udp", local: HOST4, lport: 45002, remote: "162.159.200.1", rport: 123, dir: "out", age: 4, bin: 90, bout: 90, owner: O.chrony },
  { iface: "eno1", proto: "tcp", local: HOST4, lport: 52230, remote: "95.217.10.44", rport: 5432, dir: "out", age: 7, idle: 7, bin: 40, bout: 60, state: "failed", connect_ms: 2.1, rst_recv: 1, owner: O.backup },
  { iface: "eno1", proto: "tcp", local: HOST6, lport: 52144, remote: "2a00:1450:4003:80e::200e", rport: 443, dir: "out", age: 21, bin: 64_000, bout: 3_100, rin: 900, rout: 40, connect_ms: 9.7, owner: O.curl, app: { proto: "tls", sni: "www.google.com", alpn: "h2" } },
  { iface: "tailscale0", proto: "tcp", local: TS4, lport: 22, remote: "100.88.14.3", rport: 60122, dir: "in", age: 640, bin: 840_000, bout: 6_200_000, rin: 300, rout: 4_200, owner: O.sshd, app: { proto: "ssh", ssh_client: "SSH-2.0-OpenSSH_9.7", ssh_server: SSH_SERVER } },
  {
    iface: "tailscale0", proto: "tcp", local: TS4, lport: 41822, remote: "100.64.0.7", rport: 8080, dir: "out", age: 14, bin: 48_000, bout: 1_400, rin: 3_200, rout: 90, connect_ms: 4.4, owner: O.prometheus,
    app: { proto: "http", http_method: "GET", http_host: "nas.tail1234.ts.net:8080", http_path: "/metrics", user_agent: "Prometheus/2.51.0", http_status: 200, server: "node_exporter" },
  },
  { iface: "tailscale0", proto: "tcp", local: TS4, lport: 3000, remote: "100.88.14.3", rport: 60488, dir: "in", age: 380, bin: 120_000, bout: 3_900_000, rin: 200, rout: 9_000, owner: O.grafana, app: { proto: "http", http_method: "GET", http_host: "grafana.tail1234.ts.net", http_path: "/api/ds/query?ds_type=prometheus", user_agent: "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0", http_status: 200, server: "Grafana" } },
  { iface: "docker0", proto: "tcp", local: "172.17.0.3", lport: 39012, remote: "104.16.27.34", rport: 443, dir: "out", age: 33, bin: 12_400_000, bout: 88_000, rin: 410_000, rout: 2_500, connect_ms: 7.8, owner: O.node, app: { proto: "tls", sni: "registry.npmjs.org", alpn: "h2" } },
  { iface: "br-3f1c2a9e7b10", proto: "tcp", local: "172.18.0.5", lport: 51234, remote: "54.236.113.205", rport: 443, dir: "out", age: 4, bin: 8_100, bout: 1_900, rin: 2_000, rout: 400, connect_ms: 96.3, owner: O.watchtower, app: { proto: "tls", sni: "registry-1.docker.io", alpn: "http/1.1" } },
  { iface: "br-3f1c2a9e7b10", proto: "tcp", local: "172.18.0.2", lport: 5432, remote: "172.18.0.4", rport: 44310, dir: "in", age: 7_200, bin: 3_200_000, bout: 41_000_000, rin: 300, rout: 5_800, owner: O.postgres, peer: O.grafana },
  // A host client reaching the published port through docker-proxy.
  { iface: "br-3f1c2a9e7b10", proto: "tcp", local: "172.18.0.2", lport: 5432, remote: "172.18.0.1", rport: 51476, dir: "in", age: 95, bin: 18_000, bout: 240_000, rin: 40, rout: 900, owner: O.postgres, peer: O.dockerProxy },
];

function activeFlows(t: number): FlowRow[] {
  return ACTIVE_SEEDS.map((f) => mkFlow(f, true, t));
}

const HTTP_PATHS = ["/.env", "/wp-login.php", "/phpmyadmin/index.php", "/cgi-bin/luci/;stok=/locale", "/.git/config", "/actuator/health", "/boaform/admin/formLogin", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/"];
const HTTP_UAS = [UA_CHROME, "curl/8.5.0", "python-requests/2.31.0", "Mozilla/5.0 zgrab/0.x", "Go-http-client/1.1", "masscan/1.3 (https://github.com/robertdavidgraham/masscan)"];
const DNS_NAMES = ["github.com", "registry.npmjs.org", "registry-1.docker.io", "ingest.temps.sh", "archive.ubuntu.com", "s3.eu-central-003.backblazeb2.com", "time.cloudflare.com", "api.github.com", "objects.githubusercontent.com", "wpad.home.arpa"];
const OUTBOUND: { owner: Owner; iface: string; local: string; remote: string; rport: number; app: AppMeta }[] = [
  { owner: O.git, iface: "eno1", local: HOST4, remote: "140.82.121.4", rport: 443, app: { proto: "tls", sni: "github.com", alpn: "http/1.1" } },
  { owner: O.node, iface: "docker0", local: "172.17.0.3", remote: "104.16.27.34", rport: 443, app: { proto: "tls", sni: "registry.npmjs.org", alpn: "h2" } },
  { owner: O.watchtower, iface: "br-3f1c2a9e7b10", local: "172.18.0.5", remote: "54.236.113.205", rport: 443, app: { proto: "tls", sni: "registry-1.docker.io", alpn: "http/1.1" } },
  { owner: O.curl, iface: "eno1", local: HOST6, remote: "2a00:1450:4003:80e::200e", rport: 443, app: { proto: "tls", sni: "www.google.com", alpn: "h2" } },
  { owner: O.temps, iface: "eno1", local: HOST4, remote: "34.117.59.81", rport: 443, app: { proto: "tls", sni: "ingest.temps.sh", alpn: "h2" } },
  {
    owner: O.apt, iface: "eno1", local: HOST4, remote: "91.189.91.83", rport: 80,
    app: { proto: "http", http_method: "GET", http_host: "archive.ubuntu.com", http_path: "/ubuntu/dists/noble-updates/InRelease", user_agent: "Debian APT-HTTP/1.3 (2.7.14)", http_status: 200, server: "Apache/2.4.29 (Ubuntu)" },
  },
];

type Template = (r: () => number, ago: number) => FlowSeed;
const pick = <T,>(r: () => number, xs: readonly T[]): T => xs[Math.floor(r() * xs.length)];
const eph = (r: () => number) => 32768 + Math.floor(r() * 28000);

const TEMPLATES: [number, Template][] = [
  // SSH brute force
  [18, (r, ago) => { const d = 2 + r() * 10; return { iface: "eno1", proto: "tcp", local: HOST4, lport: 22, remote: pick(r, ["218.92.0.112", "61.177.172.140"]), rport: eph(r), dir: "in", age: ago + d, idle: ago, bin: 2_000 + r() * 2_000, bout: 3_000 + r() * 2_000, state: "closed", owner: O.sshd, app: { proto: "ssh", ssh_client: pick(r, ["SSH-2.0-libssh_0.9.6", "SSH-2.0-Go", "SSH-2.0-paramiko_3.4.0"]), ssh_server: SSH_SERVER } }; }],
  // HTTP scanning
  [10, (r, ago) => ({ iface: "eno1", proto: "tcp", local: HOST4, lport: 80, remote: pick(r, ["159.89.48.201", "47.92.101.33", "193.163.125.14"]), rport: eph(r), dir: "in", age: ago + 1, idle: ago, bin: 300 + r() * 600, bout: 400 + r() * 300, state: "closed", owner: O.nginx, app: { proto: "http", http_method: pick(r, ["GET", "GET", "POST", "HEAD"]), http_host: HOST4, http_path: pick(r, HTTP_PATHS), user_agent: pick(r, HTTP_UAS), http_status: pick(r, [404, 404, 404, 400, 301]), server: "nginx/1.25.3" } })],
  // outbound TLS / HTTP
  [22, (r, ago) => { const o = pick(r, OUTBOUND); const d = 1 + r() * 300; return { iface: o.iface, proto: "tcp", local: o.local, lport: eph(r), remote: o.remote, rport: o.rport, dir: "out", age: ago + d, idle: ago, bin: 20_000 + r() * 8_000_000, bout: 2_000 + r() * 60_000, state: "closed", connect_ms: 5 + r() * 90, owner: o.owner, app: o.app }; }],
  // DNS
  [20, (r, ago) => ({ iface: "eno1", proto: "udp", local: HOST4, lport: eph(r), remote: "9.9.9.9", rport: 53, dir: "out", age: ago, idle: ago, bin: 80 + r() * 300, bout: 50 + r() * 30, owner: O.resolved, app: { dns_qname: pick(r, DNS_NAMES) } })],
  // failed connects
  [5, (r, ago) => (r() < 0.6
    ? { iface: "eno1", proto: "tcp", local: HOST4, lport: eph(r), remote: "95.217.10.44", rport: 5432, dir: "out", age: ago, idle: ago, bin: 40, bout: 60, state: "failed", connect_ms: 1.5 + r() * 2, rst_recv: 1, owner: O.backup }
    : { iface: "eno1", proto: "tcp", local: HOST4, lport: eph(r), remote: "45.33.32.156", rport: 8443, dir: "out", age: ago + 21, idle: ago, bin: 0, bout: 360, state: "failed", connect_ms: 21_000 + r() * 500, retrans: 5, owner: O.curl })],
  // tailscale SSH sessions
  [3, (r, ago) => { const d = 600 + r() * 7200; return { iface: "tailscale0", proto: "tcp", local: TS4, lport: 22, remote: "100.88.14.3", rport: eph(r), dir: "in", age: ago + d, idle: ago, bin: 200_000 + r() * 2e6, bout: 1e6 + r() * 2e7, state: "closed", connect_ms: 3 + r() * 4, owner: O.sshd, app: { proto: "ssh", ssh_client: "SSH-2.0-OpenSSH_9.7", ssh_server: SSH_SERVER } }; }],
  // nightly backup upload
  [2, (r, ago) => ({ iface: "eno1", proto: "tcp", local: HOST4, lport: eph(r), remote: "149.137.128.10", rport: 443, dir: "out", age: ago + 1800 + r() * 1800, idle: ago, bin: 9e6, bout: 1.5e9 + r() * 2e9, state: "closed", connect_ms: 30 + r() * 10, retrans: 10 + Math.floor(r() * 70), owner: O.restic, app: { proto: "tls", sni: "s3.eu-central-003.backblazeb2.com", alpn: "h2" } })],
  // CDN edge to caddy
  [15, (r, ago) => ({ iface: "eno1", proto: "tcp", local: HOST4, lport: 443, remote: pick(r, ["172.70.214.88", "162.158.90.41"]), rport: eph(r), dir: "in", age: ago + 5 + r() * 300, idle: ago, bin: 4_000 + r() * 400_000, bout: 20_000 + r() * 9e6, state: "closed", owner: O.caddy, app: { proto: "tls", sni: pick(r, ["app.example.com", "grafana.example.com", "example.com"]), alpn: "h2" } })],
  // SYN scans answered with RST
  [15, (r, ago) => ({ iface: "eno1", proto: "tcp", local: HOST4, lport: pick(r, [23, 445, 1433, 2375, 3306, 3389, 5900, 6379, 8080, 9200, 27017]), remote: pick(r, ["121.36.212.9", "193.163.125.14", "47.92.101.33"]), rport: eph(r), dir: "in", age: ago, idle: ago, bin: 60, bout: 40, state: "closed", rst_sent: 1 })],
];
const TEMPLATE_TOTAL = TEMPLATES.reduce((a, [w]) => a + w, 0);

function historyFlows(t: number): FlowRow[] {
  const out: FlowRow[] = [];
  // Anchored to the minute so rows keep their identity between polls.
  const t0 = Math.floor(t / 60) * 60;
  for (let i = 0; i < 320; i++) {
    const r = rng(i * 7919 + 13);
    let w = r() * TEMPLATE_TOTAL;
    let tpl = TEMPLATES[0][1];
    for (const [wt, f] of TEMPLATES) {
      if ((w -= wt) < 0) {
        tpl = f;
        break;
      }
    }
    const ago = 20 + Math.floor(Math.pow(r(), 1.8) * 7 * 86400) + (t - t0);
    const seed = tpl(r, ago);
    out.push(mkFlow({ ...seed, bin: Math.round(seed.bin), bout: Math.round(seed.bout), age: Math.round(seed.age) }, false, t));
  }
  return out.sort((a, b) => b.last_seen - a.last_seen);
}

function windowSecs(w: string | null, def: number): number {
  const m: Record<string, number> = { "5m": 300, "15m": 900, "1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400 };
  return (w && m[w]) || def;
}

function flowMatches(f: FlowRow, q: URLSearchParams): boolean {
  const eq = (k: string, have: string) => {
    const v = q.get(k);
    return !v || v === have;
  };
  if (!eq("dir", f.dir) || !eq("iface", f.iface) || !eq("proto", f.proto)) return false;
  const ip = q.get("ip");
  if (ip && f.remote !== ip && f.local !== ip) return false;
  const port = q.get("port");
  if (port && f.lport !== Number(port) && f.rport !== Number(port)) return false;
  const p = q.get("process");
  if (p && f.process !== p && f.container !== p && f.unit !== p) return false;
  const needle = (q.get("q") ?? "").toLowerCase();
  if (needle) {
    const hay = [f.remote, f.local, f.remote_name, f.process, f.container, f.unit, f.as_org, f.country, f.service, JSON.stringify(f.app ?? null)];
    if (!hay.some((h) => h && h.toLowerCase().includes(needle))) return false;
  }
  return true;
}

function flows(q: URLSearchParams): FlowRow[] {
  const t = now();
  const view = q.get("view") ?? "active";
  const limit = Math.min(Number(q.get("limit")) || 500, 10_000);
  let rows: FlowRow[] = [];
  if (view !== "history") rows = rows.concat(activeFlows(t).filter((f) => flowMatches(f, q)));
  if (view !== "active") {
    const since = t - windowSecs(q.get("window"), 3600);
    rows = rows.concat(historyFlows(t).filter((f) => f.last_seen >= since && flowMatches(f, q)));
  }
  const key: Record<string, (f: FlowRow) => number> = {
    rate: (f) => f.rate_in + f.rate_out,
    last: (f) => f.last_seen,
    first: (f) => f.first_seen,
    retrans: (f) => f.retrans,
    bytes: (f) => f.bytes_in + f.bytes_out,
  };
  const k = key[q.get("sort") ?? "bytes"] ?? key.bytes;
  rows.sort((a, b) => k(b) - k(a));
  return rows.slice(0, limit);
}

function destinations(q: URLSearchParams): Destinations {
  const t = now();
  const w = q.get("window") ?? "24h";
  const since = t - windowSecs(w, 3600);
  const by = new Map<string, Destination>();
  for (const f of [...activeFlows(t), ...historyFlows(t).filter((f) => f.last_seen >= since)]) {
    if (f.dir !== "out") continue;
    let d = by.get(f.remote);
    if (!d) {
      d = { remote: f.remote, name: null, country: null, asn: null, as_org: null, flows: 0, active: 0, failed: 0, bytes_in: 0, bytes_out: 0, first_seen: f.first_seen, last_seen: 0, ports: [], processes: [] };
      by.set(f.remote, d);
    }
    d.name ??= f.remote_name;
    d.country ??= f.country;
    d.asn ??= f.asn;
    d.as_org ??= f.as_org;
    d.flows++;
    d.active += f.active ? 1 : 0;
    d.failed += f.state === "failed" ? 1 : 0;
    d.bytes_in += f.bytes_in;
    d.bytes_out += f.bytes_out;
    d.first_seen = Math.min(d.first_seen, f.first_seen);
    d.last_seen = Math.max(d.last_seen, f.last_seen);
    const port = `${f.proto}/${f.rport}`;
    if (!d.ports.includes(port)) d.ports = [...d.ports, port].sort();
    const prefix = f.container ?? f.unit;
    const who = prefix ? `${prefix}/${f.process ?? "?"}` : (f.process ?? "unknown");
    if (!d.processes.includes(who)) d.processes = [...d.processes, who].sort();
  }
  let rows = [...by.values()].filter((d) => q.get("scope") === "all" || isPublicIp(d.remote));
  const total = rows.length;
  const unnamed = rows.filter((d) => !d.name).length;
  if (q.get("unnamed") === "true") rows = rows.filter((d) => !d.name);
  const needle = (q.get("q") ?? "").trim().toLowerCase();
  if (needle) rows = rows.filter((d) => [d.remote, d.name, d.as_org, d.country, ...d.ports, ...d.processes].some((h) => h?.toLowerCase().includes(needle)));
  const key: Record<string, (d: Destination) => number> = {
    bytes: (d) => d.bytes_in + d.bytes_out,
    last: (d) => d.last_seen,
    first: (d) => d.first_seen,
    flows: (d) => d.flows,
  };
  const k = key[q.get("sort") ?? "flows"] ?? key.flows;
  rows.sort((a, b) => k(b) - k(a));
  return { window: w, destinations: total, unnamed, matched: rows.length, rows: rows.slice(0, Number(q.get("limit")) || 500) };
}

function flowSeries(): FlowMinute[] {
  const t = now();
  const m0 = Math.floor(t / 60) * 60;
  const out: FlowMinute[] = [];
  for (let i = 59; i >= 0; i--) {
    const ts = m0 - i * 60;
    const r = rng(ts + 5);
    const burst = (ts / 60) % 17 < 2 ? 40 : 0;
    const new_in = Math.round(18 + 8 * Math.sin(ts / 600) + r() * 10 + burst);
    const new_out = Math.round(30 + 10 * Math.sin(ts / 900 + 1) + r() * 12);
    out.push({
      ts,
      new_in,
      new_out,
      failed: r() < 0.25 ? 1 + Math.floor(r() * 3) : 0,
      dns: Math.round(new_out * 1.3 + r() * 8),
      bytes_in: Math.round(2.4e7 + r() * 1.5e7),
      bytes_out: Math.round(4.1e8 + r() * 2e8),
    });
  }
  return out;
}

function flowsSummary(window: string | null): FlowsSummary {
  const t = now();
  const w = window ?? "1h";
  const since = t - windowSecs(w, 3600);
  const act = activeFlows(t);
  const past = historyFlows(t).filter((f) => f.last_seen >= since);
  const by: Map<string, { g: FlowGroup; remotes: Set<string> }>[] = [new Map(), new Map(), new Map(), new Map()];
  let total_in = 0;
  let total_out = 0;
  let failed = 0;
  let n_in = 0;
  let n_out = 0;
  for (const f of [...act, ...past]) {
    total_in += f.bytes_in;
    total_out += f.bytes_out;
    if (f.state === "failed") failed++;
    if (f.dir === "in") n_in++;
    else if (f.dir === "out") n_out++;
    const prefix = f.container ?? f.unit;
    const proc = prefix && f.process ? `${prefix}/${f.process}` : f.process ? f.process : prefix ? `${prefix}/?` : "unknown";
    const keys = [f.remote, proc, `${f.service_port}/${f.proto} ${f.dir}`, f.country ?? "--"];
    keys.forEach((k, i) => {
      let e = by[i].get(k);
      if (!e) {
        e = { g: { key: k, label: null, flows: 0, active: 0, bytes_in: 0, bytes_out: 0, rate_bps: 0, failed: 0, retrans: 0, last_seen: 0, remotes: 0, country: null, as_org: null }, remotes: new Set() };
        by[i].set(k, e);
      }
      const g = e.g;
      g.flows++;
      g.active += f.active ? 1 : 0;
      g.bytes_in += f.bytes_in;
      g.bytes_out += f.bytes_out;
      g.rate_bps += (f.rate_in + f.rate_out) * 8;
      g.failed += f.state === "failed" ? 1 : 0;
      g.retrans += f.retrans;
      g.last_seen = Math.max(g.last_seen, f.last_seen);
      e.remotes.add(f.remote);
      if (i === 0) {
        g.label ??= f.remote_name;
        g.country ??= f.country;
        g.as_org ??= f.as_org;
      } else if (i === 1) g.label ??= f.exe;
      else if (i === 2) g.label ??= f.service;
    });
  }
  const top = (m: Map<string, { g: FlowGroup; remotes: Set<string> }>) =>
    [...m.values()]
      .map(({ g, remotes }) => ({ ...g, remotes: remotes.size }))
      .sort((a, b) => b.bytes_in + b.bytes_out - (a.bytes_in + a.bytes_out))
      .slice(0, 25);
  return {
    window: w,
    flows: act.length + past.length,
    active: act.length,
    inbound: n_in,
    outbound: n_out,
    failed,
    bytes_in: total_in,
    bytes_out: total_out,
    bytes_since: windowSecs(w, 3600) > 3600 ? since - (since % 3600) : since - (since % 60),
    listeners: listenerSeeds().length,
    truncated: false,
    top_remotes: top(by[0]),
    top_processes: top(by[1]),
    top_services: top(by[2]),
    top_countries: top(by[3]),
    series: flowSeries(),
  };
}

function overviewFlows() {
  const act = activeFlows(now());
  return {
    active: act.length,
    in: act.filter((f) => f.dir === "in").length,
    out: act.filter((f) => f.dir === "out").length,
    tcp: act.filter((f) => f.proto === "tcp").length,
    udp: act.filter((f) => f.proto === "udp").length,
    rate_in_bps: act.reduce((a, f) => a + f.rate_in, 0) * 8,
    rate_out_bps: act.reduce((a, f) => a + f.rate_out, 0) * 8,
    listeners: listenerSeeds().filter((l) => l.exposed && l.role !== "client").length,
    series: flowSeries(),
    sock_events_lost: 0,
  };
}

// interfaces

function interfaces(): InterfacesInfo {
  const t = now();
  const act = activeFlows(t);
  const up = t - BOOT;
  const mk = (
    name: string,
    ifindex: number,
    kind: IfStat["kind"],
    o: { up?: boolean; mac?: string | null; addrs: string[]; rx: number; tx: number; flows?: boolean; xdp?: boolean; drops?: number; errs?: number },
  ): IfStat => {
    const j = 1 + 0.2 * Math.sin(t / 9 + ifindex);
    const rx_bps = o.up === false ? 0 : o.rx * j;
    const tx_bps = o.up === false ? 0 : o.tx * j;
    return {
      name,
      ifindex,
      kind,
      up: o.up ?? true,
      mac: o.mac ?? null,
      addrs: o.addrs,
      rx_bytes: Math.round((o.rx / 8) * up * 0.6),
      tx_bytes: Math.round((o.tx / 8) * up * 0.6),
      rx_packets: Math.round((o.rx / 8 / 900) * up * 0.6),
      tx_packets: Math.round((o.tx / 8 / 900) * up * 0.6),
      rx_dropped: o.drops ?? 0,
      tx_dropped: 0,
      rx_errors: o.errs ?? 0,
      tx_errors: 0,
      rx_bps,
      tx_bps,
      rx_pps: rx_bps / 8 / 900,
      tx_pps: tx_bps / 8 / 900,
      flows: o.flows ?? false,
      xdp: o.xdp ?? false,
      active_flows: act.filter((f) => f.iface === name).length,
    };
  };
  return {
    interfaces: [
      mk("lo", 1, "loopback", { addrs: ["127.0.0.1/8", "::1/128"], rx: 2.1e6, tx: 2.1e6 }),
      mk("eno1", 2, "ethernet", { mac: "3c:ec:ef:12:34:56", addrs: [`${HOST4}/24`, `${HOST6}/64`, "fe80::3eec:efff:fe12:3456/64"], rx: 48e6, tx: 96e6, flows: true, xdp: true, drops: 1_204 }),
      mk("eno2", 3, "ethernet", { up: false, mac: "3c:ec:ef:12:34:57", addrs: [], rx: 0, tx: 0 }),
      mk("tailscale0", 4, "tunnel", { addrs: [`${TS4}/32`, "fd7a:115c:a1e0::6f01:6667/128"], rx: 1.9e6, tx: 7.4e6, flows: true }),
      mk("docker0", 5, "bridge", { mac: "02:42:9c:1e:44:01", addrs: ["172.17.0.1/16"], rx: 0.4e6, tx: 3.6e6, flows: true }),
      mk("br-3f1c2a9e7b10", 6, "bridge", { mac: "02:42:1f:7a:20:b3", addrs: ["172.18.0.1/16"], rx: 0.9e6, tx: 1.2e6, flows: true }),
      mk("veth8c1d2e3", 7, "ethernet", { mac: "6a:1f:0e:9d:42:11", addrs: [], rx: 0.3e6, tx: 3.1e6 }),
    ],
    flow_programs: true,
    tracepoints: [
      { name: "sock:inet_sock_set_state", attached: true },
      { name: "tcp:tcp_retransmit_skb", attached: true },
      { name: "tcp:tcp_send_reset", attached: true },
      { name: "tcp:tcp_receive_reset", attached: false },
    ],
    patterns: ["tailscale*", "wg*", "docker0", "br-*"],
    sample_dns: true,
    sample_tcp_payload: true,
  };
}

// listeners

interface ListenerSeed {
  proto: "tcp" | "udp";
  port: number;
  addrs: string[];
  owner: Owner | null;
  sinceAgo?: number;
  ephemeral?: boolean;
  /** Defaults to "server" for TCP, "unknown" for UDP. */
  role?: Listener["role"];
  reason?: string;
  exposed: boolean;
}

function listenerSeeds(): ListenerSeed[] {
  return [
    { proto: "tcp", port: 22, addrs: ["0.0.0.0", "::"], owner: O.sshd, exposed: true },
    { proto: "tcp", port: 80, addrs: ["0.0.0.0", "::"], owner: O.dockerProxy, exposed: true },
    { proto: "tcp", port: 443, addrs: ["0.0.0.0", "::"], owner: O.caddy, exposed: true },
    { proto: "tcp", port: 3000, addrs: [TS4], owner: O.grafana, sinceAgo: 1_800, exposed: true },
    { proto: "tcp", port: 5432, addrs: ["127.0.0.1"], owner: O.postgres, exposed: false },
    { proto: "tcp", port: 53, addrs: ["127.0.0.53", "127.0.0.54"], owner: O.resolved, exposed: false },
    { proto: "udp", port: 53, addrs: ["127.0.0.53", "127.0.0.54"], owner: O.resolved, role: "server", reason: "receives DNS queries from 127.0.0.1:41873", exposed: false },
    { proto: "tcp", port: 6379, addrs: ["127.0.0.1", "::1"], owner: O.redis, exposed: false },
    { proto: "tcp", port: 9090, addrs: ["127.0.0.1"], owner: O.prometheus, exposed: false },
    { proto: "tcp", port: 7070, addrs: ["127.0.0.1"], owner: O.temps, sinceAgo: 52_000, exposed: false },
    { proto: "udp", port: 323, addrs: ["127.0.0.1", "::1"], owner: O.chrony, exposed: false },
    { proto: "udp", port: 41641, addrs: ["0.0.0.0", "::"], owner: O.tailscaled, exposed: true },
    { proto: "udp", port: 5353, addrs: ["0.0.0.0", "::"], owner: O.avahi, exposed: true },
    { proto: "udp", port: 48211, addrs: ["0.0.0.0"], owner: O.node, sinceAgo: 600, ephemeral: true, role: "client", reason: "sent DNS queries to 10.0.0.2:53", exposed: true },
    { proto: "udp", port: 39544, addrs: ["0.0.0.0"], owner: O.tailscaled, sinceAgo: 5_400, ephemeral: true, exposed: true },
    { proto: "udp", port: 5300, addrs: ["0.0.0.0"], owner: O.node, sinceAgo: 90, role: "client", reason: "sent DNS queries to 10.0.0.2:53", exposed: true },
    { proto: "udp", port: 51102, addrs: ["127.0.0.1"], owner: null, sinceAgo: 40, ephemeral: true, exposed: false },
  ];
}

function listeners(): Listener[] {
  const t = now();
  const act = activeFlows(t).filter((f) => f.dir === "in");
  return listenerSeeds()
    .map((l) => {
      const hits = act.filter((f) => f.proto === l.proto && f.lport === l.port);
      const remotes = new Set(hits.map((f) => f.remote));
      const since = l.sinceAgo ? t - l.sinceAgo : BOOT + 20;
      return {
        proto: l.proto,
        port: l.port,
        service: serviceName(l.port),
        addrs: l.addrs,
        exposed: l.exposed,
        ephemeral: !!l.ephemeral,
        role: l.role ?? (l.proto === "tcp" ? "server" : "unknown"),
        role_reason: l.reason ?? (l.proto === "tcp" ? "accepts TCP connections" : "no DNS client or server traffic seen"),
        pid: l.owner?.pid ?? null,
        process: l.owner?.comm ?? null,
        exe: l.owner?.exe ?? null,
        container: l.owner?.container ?? null,
        unit: l.owner?.container ? null : (l.owner?.unit ?? null),
        since,
        active_flows: hits.length,
        remotes: remotes.size,
        public_remotes: [...remotes].filter(isPublicIp).length,
        age_secs: t - since,
      };
    })
    .sort((a, b) => (a.proto === b.proto ? a.port - b.port : a.proto < b.proto ? -1 : 1));
}

// dns

const DNS_POOL: { name: string; w: number; answers: string[]; rcode?: string; client?: "tail" | "docker" }[] = [
  { name: "github.com", w: 9, answers: ["140.82.121.4"] },
  { name: "api.github.com", w: 5, answers: ["140.82.121.6"] },
  { name: "registry.npmjs.org", w: 8, answers: ["104.16.27.34", "104.16.30.34"], client: "docker" },
  { name: "registry-1.docker.io", w: 6, answers: ["54.236.113.205", "3.219.239.5"] },
  { name: "ingest.temps.sh", w: 10, answers: ["34.117.59.81"] },
  { name: "s3.eu-central-003.backblazeb2.com", w: 3, answers: ["149.137.128.10"] },
  { name: "time.cloudflare.com", w: 2, answers: ["162.159.200.1", "162.159.200.123"] },
  { name: "archive.ubuntu.com", w: 2, answers: ["91.189.91.83", "185.125.190.36"] },
  { name: "www.google.com", w: 3, answers: ["2a00:1450:4003:80e::200e"] },
  { name: "db.backup.example.com", w: 4, answers: ["95.217.10.44"] },
  { name: "legacy-api.example.com", w: 1, answers: [], rcode: "TIMEOUT" },
  { name: "wpad.home.arpa", w: 4, answers: [], rcode: "NXDOMAIN" },
  { name: "telemetry.old-vendor.invalid", w: 2, answers: [], rcode: "NXDOMAIN", client: "docker" },
  { name: "broken-dnssec.example.com", w: 1, answers: [], rcode: "SERVFAIL" },
  { name: "nas.tail1234.ts.net", w: 5, answers: ["100.64.0.7"], client: "tail" },
  { name: "laptop.tail1234.ts.net", w: 1, answers: ["100.88.14.3"], client: "tail" },
];
const DNS_TOTAL = DNS_POOL.reduce((a, d) => a + d.w, 0);

function dnsAll(t: number): DnsQuery[] {
  const out: DnsQuery[] = [];
  const head = Math.floor(t / 9);
  // One query every ~9s for the last ~2.5 days.
  for (let i = 0; i < 24_000; i++) {
    const k = head - i;
    const r = rng(k * 2246822519 + 7);
    let w = r() * DNS_TOTAL;
    let d = DNS_POOL[0];
    for (const x of DNS_POOL) {
      if ((w -= x.w) < 0) {
        d = x;
        break;
      }
    }
    const v6 = d.answers.some((a) => a.includes(":"));
    const where = d.client === "tail" ? { iface: "tailscale0", client: TS4, server: "100.100.100.100" } : d.client === "docker" ? { iface: "docker0", client: "172.17.0.3", server: "9.9.9.9" } : { iface: "eno1", client: HOST4, server: "9.9.9.9" };
    const rcode = d.rcode ?? "NOERROR";
    out.push({
      ts: k * 9 - Math.floor(r() * 8),
      ...where,
      dir: "out",
      qname: d.name,
      qtype: v6 ? "AAAA" : r() < 0.15 ? "HTTPS" : "A",
      rcode,
      answers: rcode === "NOERROR" ? d.answers : [],
      latency_ms: rcode === "TIMEOUT" ? null : d.client === "tail" ? 0.4 + r() : r() < 0.7 ? 0.8 + r() * 2 : 9 + r() * 40,
    });
  }
  return out;
}

function dns(q: URLSearchParams): DnsInfo {
  const t = now();
  const since = t - windowSecs(q.get("window"), 3600);
  const inWin = dnsAll(t).filter((d) => d.ts >= since);
  const needle = q.get("q") ?? "";
  const rc = q.get("rcode") ?? "";
  const limit = Math.min(Number(q.get("limit")) || 500, 10_000);
  const queries = inWin
    .filter((d) => !needle || d.qname.includes(needle) || d.client === needle || d.server === needle || d.answers.some((a) => a.includes(needle)))
    .filter((d) => !rc || d.rcode === rc)
    .slice(0, limit);
  const agg = new Map<string, DnsTopName & { cs: Set<string> }>();
  for (const d of inWin) {
    const a = agg.get(d.qname) ?? { qname: d.qname, queries: 0, nxdomain: 0, clients: 0, last_ts: 0, cs: new Set<string>() };
    a.queries++;
    if (d.rcode === "NXDOMAIN") a.nxdomain++;
    a.cs.add(d.client);
    a.last_ts = Math.max(a.last_ts, d.ts);
    agg.set(d.qname, a);
  }
  const top: DnsTopName[] = [...agg.values()]
    .map(({ cs, ...rest }) => ({ ...rest, clients: cs.size }))
    .sort((a, b) => b.queries - a.queries)
    .slice(0, 50);
  return { queries, top };
}

// connection events

function connEvents(q: URLSearchParams): ConnEvent[] {
  const t = now();
  const since = t - windowSecs(q.get("window"), 86400);
  const kind = q.get("kind");
  const limit = Math.min(Number(q.get("limit")) || 500, 5000);
  const ev = (ts: number, kind: string, o: Owner | null, local: string, lport: number, remote: string | null, rport: number | null, detail: string): ConnEvent => ({
    ts,
    kind,
    proto: "tcp",
    local,
    lport,
    remote,
    rport,
    pid: o?.pid ?? null,
    process: o?.comm ?? null,
    container: o?.container ?? null,
    unit: o?.container ? null : (o?.unit ?? null),
    detail,
  });
  const label = (o: Owner) => (o.container ? `${o.comm} (${o.pid}, container ${o.container})` : o.unit ? `${o.comm} (${o.pid}, ${o.unit}.service)` : `${o.comm} (${o.pid})`);
  const out: ConnEvent[] = [];
  // backup-agent retries every 15 minutes against a refusing server
  const q15 = Math.floor(t / 900) * 900;
  for (let i = 0; i < 4 * 24 * 3; i++) {
    const ts = q15 - i * 900 + 7;
    out.push(ev(ts, "connect_failed", O.backup, HOST4, 40000 + ((i * 37) % 20000), "95.217.10.44", 5432, `${label(O.backup)} could not connect to 95.217.10.44:5432 (refused after ${(1.5 + (i % 3) * 0.4).toFixed(0)} ms)`));
  }
  for (let i = 0; i < 6; i++) {
    const ts = t - 1_000 - i * 11_000;
    out.push(ev(ts, "connect_failed", O.curl, HOST4, 51000 + i, "45.33.32.156", 8443, `${label(O.curl)} could not connect to 45.33.32.156:8443 (timed out after 21 s)`));
  }
  out.push(ev(t - 1_800, "listen", O.grafana, TS4, 3000, null, null, `${label(O.grafana)} listening on ${TS4}:3000`));
  out.push(ev(t - 5_400, "unlisten", O.node, "0.0.0.0", 9229, null, null, `${label(O.node)} stopped listening on port 9229`));
  out.push(ev(t - 9_000, "listen", O.node, "0.0.0.0", 9229, null, null, `${label(O.node)} listening on 0.0.0.0:9229`));
  out.push(ev(t - 52_000, "listen", O.temps, "127.0.0.1", 7070, null, null, `${label(O.temps)} listening on 127.0.0.1:7070`));
  out.push(ev(t - 86_000, "unlisten", O.redis, "::1", 6380, null, null, `${label(O.redis)} stopped listening on port 6380`));
  return out
    .filter((e) => e.ts >= since && (!kind || e.kind === kind))
    .sort((a, b) => b.ts - a.ts)
    .slice(0, limit);
}

// ---------------------------------------------------------------------------
// router

const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((res, rej) => {
    const id = setTimeout(res, ms);
    signal?.addEventListener("abort", () => {
      clearTimeout(id);
      rej(new DOMException("aborted", "AbortError"));
    });
  });

export async function mockGet(path: string, signal?: AbortSignal): Promise<unknown> {
  await sleep(80 + Math.random() * 120, signal);
  const url = new URL(path, "http://mock");
  const q = url.searchParams;
  const p = url.pathname.replace(/\/+$/, "");
  const limit = Number(q.get("limit")) || undefined;

  if (p === "/api/overview") return overview();
  if (p === "/api/sources") {
    let list = allSources();
    const needle = (q.get("q") ?? "").toLowerCase();
    if (needle) list = list.filter((s) => [s.ip, s.geo.country_code, s.geo.country, s.geo.as_org, s.geo.asn ? `as${s.geo.asn}` : ""].some((v) => v && String(v).toLowerCase().includes(needle)));
    if (q.get("flagged") === "1") list = list.filter((s) => s.score > 0);
    const key = q.get("sort") ?? "score";
    const val: Record<string, (s: Source) => number> = {
      score: (s) => s.score,
      syn: (s) => s.syn,
      in_bytes: (s) => s.in_bytes,
      in_pps: (s) => s.rate.in_pps,
      ports: (s) => s.ports,
      last_seen: (s) => s.last_seen,
    };
    const f = val[key] ?? val.score;
    list.sort((a, b) => f(b) - f(a));
    return list.slice(0, limit ?? 100);
  }
  if (p.startsWith("/api/sources/")) return detail(decodeURIComponent(p.slice("/api/sources/".length)));
  if (p === "/api/alerts") {
    let a = alerts();
    const ip = q.get("ip");
    if (ip) a = a.filter((x) => x.ip === ip);
    return a.slice(0, limit ?? 200);
  }
  if (p === "/api/bans") return bans().map((b) => ({ ...b, matched: b.dropped }));
  if (p === "/api/proposals") {
    const all = proposals();
    return q.get("status") === "all" ? all : all.filter((x) => x.status === "pending");
  }
  if (p === "/api/insights") return insights();
  if (p === "/api/ssh") {
    let e = sshEvents();
    const ip = q.get("ip");
    if (ip) e = e.filter((x) => x.ip === ip);
    return e.slice(0, limit ?? 200);
  }
  if (p === "/api/summary") return summary(q.get("window") ?? "24h");
  if (p === "/api/events") return events(Math.min(limit ?? 200, 500));
  if (p === "/api/policy") return policy();
  if (p === "/api/llm") return llm();
  if (p === "/api/flows") return flows(q);
  if (p === "/api/flows/summary") return flowsSummary(q.get("window"));
  if (p === "/api/destinations") return destinations(q);
  if (p === "/api/interfaces") return interfaces();
  if (p === "/api/listeners") return listeners();
  if (p === "/api/dns") return dns(q);
  if (p === "/api/conn_events") return connEvents(q);
  // Aggregates, built from the endpoints above (mock-views.ts).
  if (p === "/api/timeline") return (await import("./mock-views")).mockTimeline((x) => mockGet(x), q);
  throw new ApiError(404, `mock: no fixture for ${p}`);
}
