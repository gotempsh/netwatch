// A source as one lane of the attack timeline (see Lanes in viz.tsx).
import type { TimelineRow } from "../api/types";
import { hourToTs } from "../lib/format";
import { sourceHref } from "../lib/router";
import { Flag, KindChip, kindLabel, scoreTone } from "./ui";
import type { Lane } from "./viz";

export function statusText(r: Pick<TimelineRow, "status" | "ban">, drops: boolean): string {
  if (r.status === "banned") return drops ? "banned" : "banned, counted";
  return r.status;
}

export function laneFor(r: TimelineRow, drops: boolean, opts: { compact?: boolean } = {}): Lane {
  const top = [...r.findings].sort((a, b) => b.score - a.score)[0];
  return {
    key: r.ip,
    label: (
      <a className="lane-name" href={sourceHref(r.ip)}>
        <span className={`score-dot tone-${scoreTone(r.score)}`}>{r.score}</span>
        <span className="lane-ip mono">{r.ip}</span>
        {!opts.compact && (
          <span className="lane-sub">
            <Flag cc={r.geo.country_code} title={r.geo.country} /> {r.geo.as_org ?? "unknown network"}
          </span>
        )}
      </a>
    ),
    side: (
      <span className="lane-side">
        {top && <KindChip kind={top.kind} score={top.score} title={top.summary} />}
        <span className={r.ssh_accepted ? "hot" : "muted"}>{r.ssh_accepted ? `${r.ssh_accepted} logins` : statusText(r, drops)}</span>
      </span>
    ),
    cells: r.hours.map((h) => ({ ts: hourToTs(h.hour), v: h.in_packets })),
    events: r.events
      .filter((e) => e.kind !== "ban")
      .map((e) => ({
        ts: e.ts,
        kind: e.kind === "finding" ? ("finding" as const) : e.kind === "proposal" ? ("proposal" as const) : ("login" as const),
        label: e.kind === "finding" && e.finding ? `${kindLabel(e.finding)} raised` : e.label,
      })),
    ban: r.ban ? { from: r.ban.created, to: r.ban.expires, drops } : null,
  };
}
