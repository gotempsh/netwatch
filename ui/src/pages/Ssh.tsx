import { useMemo, useState } from "react";
import type { SshEvent } from "../api/types";
import { usePoll } from "../api/client";
import { Badge, Card, Empty, IpLink, Location, PanelState, RelTime, Segmented, type Tone } from "../components/ui";
import { fmtInt } from "../lib/format";

const KIND: Record<SshEvent["kind"], { label: string; tone: Tone }> = {
  accepted: { label: "accepted", tone: "good" },
  tailscale_login: { label: "tailscale login", tone: "accent" },
  failed: { label: "failed", tone: "critical" },
  invalid_user: { label: "invalid user", tone: "serious" },
  preauth_close: { label: "pre-auth close", tone: "muted" },
};
const isFailure = (k: SshEvent["kind"]) => k === "failed" || k === "invalid_user" || k === "preauth_close";

export function SshTable({ events, showIp = true }: { events: SshEvent[]; showIp?: boolean }) {
  return (
    <table className="tbl tbl-compact">
      <thead>
        <tr>
          <th>Time</th>
          <th>Result</th>
          <th>User</th>
          <th>Method</th>
          {showIp && <th>IP</th>}
          {showIp && <th>Location</th>}
        </tr>
      </thead>
      <tbody>
        {events.map((e, i) => {
          const k = KIND[e.kind] ?? { label: e.kind, tone: "neutral" as Tone };
          const ok = e.kind === "accepted" || e.kind === "tailscale_login";
          return (
            <tr key={`${e.ts}-${e.ip}-${i}`} className={ok ? "row-accepted" : ""}>
              <td className="nowrap">
                <RelTime ts={e.ts} />
              </td>
              <td className="nowrap">
                <Badge tone={k.tone}>{k.label}</Badge>
              </td>
              <td className="mono">{e.user ?? <span className="muted">–</span>}</td>
              <td>{e.method ?? <span className="muted">–</span>}</td>
              {showIp && (
                <td>
                  <IpLink ip={e.ip} />
                </td>
              )}
              {showIp && (
                <td className="ellipsis loc-cell">
                  <Location text={e.location} />
                </td>
              )}
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

interface Agg {
  ip: string;
  location: string;
  failed: number;
  invalid: number;
  preauth: number;
  users: Set<string>;
  last: number;
}

export default function Ssh() {
  const res = usePoll<SshEvent[]>("/api/ssh?limit=1000", 10_000);
  const [filter, setFilter] = useState<"all" | "failures" | "logins">("all");
  const events = res.data ?? [];

  const agg = useMemo(() => {
    const m = new Map<string, Agg>();
    for (const e of events) {
      if (!isFailure(e.kind)) continue;
      const a = m.get(e.ip) ?? { ip: e.ip, location: e.location, failed: 0, invalid: 0, preauth: 0, users: new Set<string>(), last: 0 };
      if (e.kind === "failed") a.failed++;
      else if (e.kind === "invalid_user") a.invalid++;
      else a.preauth++;
      if (e.user) a.users.add(e.user);
      a.last = Math.max(a.last, e.ts);
      m.set(e.ip, a);
    }
    return [...m.values()].sort((a, b) => b.failed + b.invalid - (a.failed + a.invalid));
  }, [events]);

  const logins = events.filter((e) => !isFailure(e.kind));
  const shown = filter === "all" ? events : filter === "failures" ? events.filter((e) => isFailure(e.kind)) : logins;

  return (
    <div className="page">
      <div className="page-head">
        <h1>SSH logins</h1>
        <span className="muted small">
          {fmtInt(events.length)} events loaded · {fmtInt(logins.length)} successful logins · {fmtInt(agg.length)} IPs with failures
        </span>
      </div>
      <div className="grid-2 grid-wide-right">
        <Card title="Failures by IP" sub="From the events loaded" flush>
          {agg.length ? (
            <div className="scroll-y" style={{ maxHeight: 640 }}>
              <table className="tbl tbl-compact">
                <thead>
                  <tr>
                    <th>IP</th>
                    <th className="num">Failed</th>
                    <th className="num" title="Invalid user">Invalid</th>
                    <th className="num" title="Closed before authentication">Pre-auth</th>
                    <th>Users tried</th>
                    <th>Last</th>
                  </tr>
                </thead>
                <tbody>
                  {agg.map((a) => (
                    <tr key={a.ip}>
                      <td>
                        <IpLink ip={a.ip} />
                        <div className="muted small ellipsis" title={a.location}>
                          {a.location}
                        </div>
                      </td>
                      <td className="num">{fmtInt(a.failed)}</td>
                      <td className="num">{fmtInt(a.invalid)}</td>
                      <td className="num">{fmtInt(a.preauth)}</td>
                      <td className="small mono" title={[...a.users].join(", ")}>
                        <div className="ellipsis users-cell">
                          {[...a.users].slice(0, 6).join(", ")}
                          {a.users.size > 6 ? ` +${a.users.size - 6}` : ""}
                        </div>
                      </td>
                      <td className="nowrap">
                        <RelTime ts={a.last} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty>No failed SSH attempts.</Empty>
          )}
        </Card>
        <Card
          title="Events"
          flush
          actions={
            <Segmented
              label="Event filter"
              value={filter}
              onChange={setFilter}
              options={[
                { value: "all", label: "All" },
                { value: "failures", label: "Failures" },
                { value: "logins", label: "Logins" },
              ]}
            />
          }
        >
          <PanelState loading={res.loading} error={res.error} empty={!shown.length} emptyText="No SSH events." />
          {shown.length > 0 && (
            <div className="scroll-y" style={{ maxHeight: 640 }}>
              <SshTable events={shown} />
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
