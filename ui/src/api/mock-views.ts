// Demo-data versions of the aggregate endpoints (/api/timeline, /api/flows/graph),
// built from the other mock endpoints the way the daemon builds them from its
// state, so the demo stays consistent with the pages it links to.
import type { FlowGraph, FlowRow, GraphEdge, GraphHalf, GraphNode, Source, SourceDetail, Timeline } from "./types";
import { rowFromDetail } from "../lib/timeline";

type Get = (path: string) => Promise<unknown>;

export async function mockTimeline(get: Get, q: URLSearchParams): Promise<Timeline> {
  const now = Math.floor(Date.now() / 1000);
  const since = now - (q.get("window") === "24h" ? 86_400 : 7 * 86_400);
  const limit = Math.min(50, Math.max(1, Number(q.get("limit")) || 20));
  const all = ((await get(`/api/sources?flagged=1&sort=score&limit=100`)) as Source[]).filter((s) => !s.allowlisted && s.score > 0 && s.last_seen >= since);
  const flagged = all.slice(0, limit);
  const details = (await Promise.all(flagged.map((s) => get(`/api/sources/${encodeURIComponent(s.ip)}`).catch(() => null)))) as (SourceDetail | null)[];
  const rows = details.filter((d): d is SourceDetail => !!d).map((d) => rowFromDetail(d, since));
  return { since, now, total: all.length, rows };
}

// ---------------------------------------------------------------------------
// /api/flows/graph: the same grouping and folding as the daemon (api.rs).

const COLUMN = 9;
const HOSTILE = 4;
type Side = [key: string, label: string, sub: string, filter: GraphNode["filter"]];

// As flow_failure in api.rs: a failed connect that kept retrying for 3 s or more timed out.
const failure = (f: FlowRow): GraphEdge["reason"] => (f.state === "unanswered" ? "unanswered" : f.state === "failed" ? (f.last_seen - f.first_seen >= 3 ? "timed out" : "refused") : null);
const ownerOf = (f: FlowRow) => f.container ?? f.unit ?? f.process ?? null;
const shortName = (n: string) => (n.endsWith(".ts.net") && n.includes(".tail") ? n.slice(0, n.indexOf(".tail")) : n);

function halfGraph(rows: FlowRow[], sideA: (f: FlowRow) => Side, sideB: (f: FlowRow) => Side, hostile: Set<string>, more: string): GraphHalf {
  const na = new Map<string, GraphNode>(), nb = new Map<string, GraphNode>(), ed = new Map<string, GraphEdge>();
  const bump = (m: Map<string, GraphNode>, [key, label, sub, filter]: Side, f: FlowRow, bad: boolean, hot: boolean) => {
    const n = m.get(key) ?? { key, label, sub, flows: 0, bytes: 0, failed: 0, hostile: false, folded: 0, filter };
    n.flows++;
    n.bytes += f.bytes_in + f.bytes_out;
    n.failed += bad ? 1 : 0;
    n.hostile ||= hot;
    m.set(key, n);
  };
  for (const f of rows) {
    const why = failure(f), hot = hostile.has(f.remote), a = sideA(f), b = sideB(f);
    bump(na, a, f, !!why, hot);
    bump(nb, b, f, !!why, hot);
    const k = `${a[0]}\u0000${b[0]}`;
    const e = ed.get(k) ?? { a: a[0], b: b[0], flows: 0, bytes: 0, failed: 0, hostile: false, reason: null };
    e.flows++;
    e.bytes += f.bytes_in + f.bytes_out;
    if (why) {
      e.failed++;
      e.reason ??= why;
    }
    e.hostile ||= hot;
    ed.set(k, e);
  }
  const fold = (m: Map<string, GraphNode>, key: string): [GraphNode[], Map<string, string>] => {
    const v = [...m.values()].sort((x, y) => y.failed - x.failed || y.bytes - x.bytes || x.key.localeCompare(y.key));
    const map = new Map(v.map((n) => [n.key, n.key]));
    if (v.length <= COLUMN) return [v, map];
    const rest = v.splice(COLUMN - 1);
    const o: GraphNode = { key, label: `${rest.length} more`, sub: "folded", flows: 0, bytes: 0, failed: 0, hostile: false, folded: rest.length, filter: null };
    for (const n of rest) {
      o.flows += n.flows;
      o.bytes += n.bytes;
      o.failed += n.failed;
      o.hostile ||= n.hostile;
      map.set(n.key, key);
    }
    return [[...v, o], map];
  };
  const [left, ma] = fold(na, `more:${more}:a`);
  const [right, mb] = fold(nb, `more:${more}:b`);
  const edges = new Map<string, GraphEdge>();
  for (const e of ed.values()) {
    const a = ma.get(e.a)!, b = mb.get(e.b)!, k = `${a}\u0000${b}`;
    const x = edges.get(k) ?? { a, b, flows: 0, bytes: 0, failed: 0, hostile: false, reason: null };
    x.flows += e.flows;
    x.bytes += e.bytes;
    x.failed += e.failed;
    x.hostile ||= e.hostile;
    x.reason ??= e.reason;
    edges.set(k, x);
  }
  const es = [...edges.values()];
  const pos = new Map(left.map((n, i) => [n.key, i]));
  const bary = (k: string) => {
    let sum = 0, w = 0;
    for (const e of es.filter((x) => x.b === k)) {
      const wt = Math.max(1, Math.log1p(e.bytes));
      sum += (pos.get(e.a) ?? 0) * wt;
      w += wt;
    }
    return w ? sum / w : 0;
  };
  right.sort((x, y) => Number(x.folded > 0) - Number(y.folded > 0) || y.failed - x.failed || bary(x.key) - bary(y.key));
  return { left, right, edges: es };
}

export async function mockFlowGraph(get: Get, q: URLSearchParams): Promise<FlowGraph> {
  const window = q.get("window") === "5m" ? "5m" : q.get("window") === "24h" ? "24h" : "1h";
  const secs = window === "5m" ? 300 : window === "24h" ? 86_400 : 3_600;
  const rows = (await get(`/api/flows?view=all&window=${window}&limit=10000`)) as FlowRow[];
  const hostile = new Set(((await get("/api/sources?flagged=1&limit=500")) as Source[]).filter((s) => s.score > 0 && !s.allowlisted).map((s) => s.ip));
  const inbound = rows.filter((f) => f.dir === "in");
  const by = new Map<string, number>();
  for (const f of inbound) if (hostile.has(f.remote)) by.set(f.remote, (by.get(f.remote) ?? 0) + f.bytes_in + f.bytes_out);
  const shown = new Set([...by.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, HOSTILE).map(([ip]) => ip));
  const remote = (f: FlowRow): Side => {
    const local = f.remote_container ?? f.remote_process;
    if (local) return [`local:${local}`, local, "on this host", { dir: "in", ip: f.remote }];
    if (hostile.has(f.remote)) return shown.has(f.remote) ? [`ip:${f.remote}`, f.remote, f.as_org ?? "unknown network", { dir: "in", ip: f.remote }] : ["hostile:other", "other flagged sources", "score above 0", null];
    if (f.remote_name) return [`name:${f.remote_name}`, shortName(f.remote_name), f.remote, { dir: "in", ip: f.remote }];
    if (f.as_org) return [`org:${f.as_org}`, f.as_org, f.country ?? "", { dir: "in", q: f.as_org }];
    return [`ip:${f.remote}`, f.remote, "no network info", { dir: "in", ip: f.remote }];
  };
  const service = (f: FlowRow): Side => {
    const o = ownerOf(f);
    return o ? [`svc:${f.proto}/${f.lport}`, `${f.service ?? f.lport} · ${o}`, `${f.proto}/${f.lport}`, { dir: "in", port: f.lport }] : ["svc:closed", "closed ports", "nothing listening", null];
  };
  const program = (f: FlowRow): Side => {
    const [o, kind] = f.container ? [f.container, "container"] : f.unit ? [f.unit, "systemd unit"] : f.process ? [f.process, "process"] : [null, ""];
    return o ? [`prog:${o}`, o, kind, { dir: "out", process: o }] : ["prog:unknown", "unknown process", "ended before netwatch saw it", null];
  };
  const dest = (f: FlowRow): Side => {
    const sub = `${f.proto}/${f.rport}${f.as_org ? ` · ${f.as_org}` : ""}`;
    return f.remote_name ? [`dest:${f.remote_name}`, shortName(f.remote_name), sub, { dir: "out", q: f.remote_name }] : [`dest:${f.remote}`, f.remote, sub, { dir: "out", ip: f.remote }];
  };
  const now = Math.floor(Date.now() / 1000);
  return {
    since: now - secs,
    now,
    flows: rows.length,
    active: rows.filter((f) => f.active).length,
    truncated: false,
    inbound: halfGraph(inbound, remote, service, hostile, "in"),
    outbound: halfGraph(
      rows.filter((f) => f.dir === "out"),
      program,
      dest,
      hostile,
      "out",
    ),
  };
}
