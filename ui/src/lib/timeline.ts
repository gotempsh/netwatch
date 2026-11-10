// A source's detail as one timeline row: the same shape /api/timeline returns,
// so the source page draws its lane with the code the Threats timeline uses.
import type { SourceDetail, TimelineEvent, TimelineRow } from "../api/types";
import { hourToTs } from "./format";

export function rowFromDetail(d: SourceDetail, since: number): TimelineRow {
  const events: TimelineEvent[] = [
    ...d.alerts.filter((a) => a.first_ts >= since).map((a) => ({ ts: a.first_ts, kind: "finding" as const, label: a.summary, finding: a.kind })),
    ...d.proposals.filter((p) => p.created >= since).map((p) => ({ ts: p.created, kind: "proposal" as const, label: `${p.action} proposed (#${p.id}, ${p.status})` })),
    ...(d.ban && d.ban.created >= since ? [{ ts: d.ban.created, kind: "ban" as const, label: `banned (${d.ban.source}): ${d.ban.reason}` }] : []),
    ...d.ssh_events.filter((e) => e.kind === "accepted" && e.ts >= since).map((e) => ({ ts: e.ts, kind: "login" as const, label: e.user ? `SSH login accepted as ${e.user}` : "SSH login accepted" })),
  ].sort((a, b) => a.ts - b.ts);
  const pending = d.proposals.some((p) => p.status === "pending" && p.action === "ban");
  return {
    ip: d.ip,
    geo: d.geo,
    score: d.score,
    findings: d.findings,
    allowlisted: d.allowlisted,
    status: d.banned ? "banned" : pending ? "ban proposed" : "watching",
    ssh_accepted: d.ssh.accepted,
    first_seen: d.first_seen,
    last_seen: d.last_seen,
    hours: d.history.map((h) => ({ hour: hourToTs(h.hour), in_packets: h.in_packets, syn: h.syn, blocked: h.blocked })).filter((h) => h.hour >= since - (since % 3600)),
    events,
    ban: d.ban ? { ...d.ban, matched: d.ban.matched ?? d.ban.dropped } : null,
  };
}
