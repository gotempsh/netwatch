// Demo-data versions of the aggregate endpoints (/api/timeline, /api/flows/graph),
// built from the other mock endpoints the way the daemon builds them from its
// state, so the demo stays consistent with the pages it links to.
import type { Source, SourceDetail, Timeline, TimelineEvent } from "./types";

type Get = (path: string) => Promise<unknown>;

export async function mockTimeline(get: Get, q: URLSearchParams): Promise<Timeline> {
  const now = Math.floor(Date.now() / 1000);
  const since = now - (q.get("window") === "24h" ? 86_400 : 7 * 86_400);
  const limit = Math.min(50, Math.max(1, Number(q.get("limit")) || 20));
  const flagged = ((await get(`/api/sources?flagged=1&sort=score&limit=100`)) as Source[]).filter((s) => !s.allowlisted).slice(0, limit);
  const details = (await Promise.all(flagged.map((s) => get(`/api/sources/${encodeURIComponent(s.ip)}`).catch(() => null)))) as (SourceDetail | null)[];
  const rows = details.filter((d): d is SourceDetail => !!d).map((d) => {
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
      status: d.banned ? ("banned" as const) : pending ? ("ban proposed" as const) : ("watching" as const),
      ssh_accepted: d.ssh.accepted,
      first_seen: d.first_seen,
      last_seen: d.last_seen,
      hours: d.history.filter((h) => h.hour >= since - (since % 3600)).map((h) => ({ hour: h.hour, in_packets: h.in_packets, syn: h.syn, blocked: h.blocked })),
      events,
      ban: d.ban ? { ...d.ban, matched: d.ban.matched ?? d.ban.dropped } : null,
    };
  });
  return { since, now, rows };
}
