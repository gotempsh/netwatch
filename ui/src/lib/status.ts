// What the Status page lists as needing you: the daemon's insights, plus
// outbound connections that keep failing, merged into one ordered list where
// each item says what is wrong, why it matters, the command and the evidence.
import type { ConnEvent, Destination, Insight, Listener, Proposal } from "../api/types";
import type { Sev } from "../components/viz";
import { sourceHref } from "./router";

export interface Issue {
  key: string;
  sev: Sev;
  title: string;
  consequence: string;
  fix: string | null;
  fixNote?: string;
  /** Short label for the verdict's "Start here" when this is the first issue. */
  next?: string;
  evidence?: { href: string; label: string };
}

export interface FailGroup {
  /** systemd unit, container or process that tried to connect. */
  owner: string;
  unit: string | null;
  container: string | null;
  remote: string;
  rport: number;
  name: string | null;
  count: number;
  first: number;
  last: number;
  refused: number;
  timedOut: number;
  /** The remote never accepted a connection in the window (from /api/destinations). */
  neverConnected: boolean;
}

/** Outbound connects that failed at least this often in the window become an issue. */
export const FAIL_MIN = 3;

export function failGroups(events: ConnEvent[], dests: Destination[]): FailGroup[] {
  const m = new Map<string, FailGroup>();
  for (const e of events) {
    if (e.kind !== "connect_failed" || !e.remote) continue;
    // Same order as the host map's program boxes, so the evidence link lands on one.
    const owner = e.container ?? e.unit ?? e.process ?? "an unknown process";
    const k = `${owner}|${e.remote}|${e.rport}`;
    let g = m.get(k);
    if (!g) {
      const d = dests.find((x) => x.remote === e.remote);
      g = { owner, unit: e.unit, container: e.container, remote: e.remote, rport: e.rport ?? 0, name: d?.name ?? null, count: 0, first: e.ts, last: e.ts, refused: 0, timedOut: 0, neverConnected: !!d && d.failed >= d.flows };
      m.set(k, g);
    }
    g.count++;
    g.first = Math.min(g.first, e.ts);
    g.last = Math.max(g.last, e.ts);
    if (/refused/.test(e.detail)) g.refused++;
    else if (/timed out/.test(e.detail)) g.timedOut++;
  }
  return [...m.values()].filter((g) => g.count >= FAIL_MIN).sort((a, b) => b.count - a.count);
}

const failWord = (g: FailGroup) => (g.refused === g.count ? "refused" : g.timedOut === g.count ? "timed out" : "failed");

/** Where an insight's evidence lives in the UI, from the command it suggests. */
function evidenceFor(action: string | null, proposals: Proposal[]): Issue["evidence"] {
  if (!action) return undefined;
  const id = Number(action.match(/approve (\d+)/)?.[1] ?? NaN);
  const p = proposals.find((x) => x.id === id);
  if (p) return p.target.includes("/") ? { href: "#/bans", label: `Proposal #${p.id}` } : { href: sourceHref(p.target), label: `What ${p.target} did` };
  if (/netwatch proposals/.test(action)) return { href: "#/bans", label: "Review proposals" };
  if (/netwatch bans/.test(action)) return { href: "#/bans", label: "Active bans" };
  const port = action.match(/sources --port (\d+)/)?.[1];
  if (port) return { href: `#/threats/sources?q=${port}`, label: `Sources on port ${port}` };
  if (/netwatch (top|sources)/.test(action)) return { href: "#/threats/sources", label: "Sources" };
  return undefined;
}

function fmtAgo(secs: number): string {
  if (secs < 90) return "just now";
  if (secs < 5400) return `${Math.round(secs / 60)} min ago`;
  if (secs < 129_600) return `${Math.round(secs / 3600)} h ago`;
  return `${Math.round(secs / 86400)} days ago`;
}

export function deriveIssues(insights: Insight[], proposals: Proposal[], fails: FailGroup[], now: number, platform: "linux" | "macos" | undefined): { issues: Issue[]; notes: string[] } {
  const issues: Issue[] = [];
  const notes: string[] = [];

  for (const i of insights) {
    if (i.level === "info") {
      notes.push(i.title.replace(/\.$/, ""));
      continue;
    }
    const id = Number(i.action?.match(/approve (\d+)/)?.[1] ?? NaN);
    const p = proposals.find((x) => x.id === id);
    issues.push({
      key: `insight-${i.title}`,
      sev: i.level === "critical" ? "critical" : "warn",
      title: i.title,
      consequence: i.detail,
      fix: i.action,
      fixNote: p ? `approves proposal #${p.id}: ${p.action} ${p.target}` : undefined,
      next: p ? `${p.action === "ban" ? "Ban" : p.action === "allow" ? "Allow" : "Review"} ${p.target} (proposal #${p.id})` : undefined,
      evidence: evidenceFor(i.action, proposals),
    });
  }

  for (const g of fails) {
    const target = `${g.name ?? g.remote}:${g.rport}`;
    const fix = g.unit ? (platform === "macos" ? null : `systemctl status ${g.unit}`) : g.container ? `docker logs --tail 50 ${g.container}` : null;
    issues.push({
      key: `fail-${g.owner}-${g.remote}-${g.rport}`,
      sev: "warn",
      title: `${g.owner} can't reach ${target}`,
      consequence: `${g.count} connection attempts in the last 24 h ${g.count === 1 ? "was" : "were"} ${failWord(g)}${g.neverConnected ? " and none got through" : ""}, the latest ${fmtAgo(now - g.last)}.`,
      fix,
      fixNote: fix ? undefined : "No command to run: check what calls it.",
      evidence: { href: `#/traffic?window=24h&node=${encodeURIComponent(`prog:${g.owner}`)}`, label: `Where ${g.owner} connects` },
    });
  }

  const order: Record<Sev, number> = { critical: 0, warn: 1, ok: 2 };
  issues.sort((a, b) => order[a.sev] - order[b.sev]);
  return { issues, notes };
}

/** Bound only to Tailscale's CGNAT range or its ULA prefix: reachable from your tailnet, not the internet. */
export const tailnetOnly = (l: Listener) => l.addrs.length > 0 && l.addrs.every((a) => /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(a) || a.toLowerCase().startsWith("fd7a:115c:a1e0"));

/** What a missing tracepoint costs, for the sensor line. */
export const TRACEPOINT_LOSS: Record<string, string> = {
  "sock:inet_sock_set_state": "connection states and failed connects aren't recorded",
  "tcp:tcp_retransmit_skb": "retransmits aren't counted per connection",
  "tcp:tcp_send_reset": "resets this host sends aren't attributed to a process",
  "tcp:tcp_receive_reset": "resets sent by remotes aren't attributed to a process",
};
