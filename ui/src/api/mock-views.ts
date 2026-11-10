// Demo-data versions of the aggregate endpoints (/api/timeline, /api/flows/graph),
// built from the other mock endpoints the way the daemon builds them from its
// state, so the demo stays consistent with the pages it links to.
import type { Source, SourceDetail, Timeline } from "./types";
import { rowFromDetail } from "../lib/timeline";

type Get = (path: string) => Promise<unknown>;

export async function mockTimeline(get: Get, q: URLSearchParams): Promise<Timeline> {
  const now = Math.floor(Date.now() / 1000);
  const since = now - (q.get("window") === "24h" ? 86_400 : 7 * 86_400);
  const limit = Math.min(50, Math.max(1, Number(q.get("limit")) || 20));
  const flagged = ((await get(`/api/sources?flagged=1&sort=score&limit=100`)) as Source[]).filter((s) => !s.allowlisted).slice(0, limit);
  const details = (await Promise.all(flagged.map((s) => get(`/api/sources/${encodeURIComponent(s.ip)}`).catch(() => null)))) as (SourceDetail | null)[];
  const rows = details.filter((d): d is SourceDetail => !!d).map((d) => rowFromDetail(d, since));
  return { since, now, rows };
}
