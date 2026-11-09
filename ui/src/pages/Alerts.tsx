import { useEffect, useRef, useState } from "react";
import type { Alert } from "../api/types";
import { apiPath, usePoll } from "../api/client";
import { Card, IpLink, KindChip, Location, PanelState, RelTime, ScoreMeter, Segmented } from "../components/ui";
import { fmtInt } from "../lib/format";
import { useQueryState } from "../lib/router";

export function AlertsTable({ alerts, showIp = true }: { alerts: Alert[]; showIp?: boolean }) {
  return (
    <div className="scroll-x">
      <table className="tbl">
        <thead>
          <tr>
            <th>Kind</th>
            <th>Score</th>
            {showIp && <th>IP</th>}
            {showIp && <th>Location</th>}
            <th>Summary</th>
            <th>First</th>
            <th>Last</th>
            <th className="num">Count</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a) => (
            <tr key={a.id}>
              <td className="nowrap">
                <KindChip kind={a.kind} score={a.score} />
              </td>
              <td>
                <ScoreMeter score={a.score} />
              </td>
              {showIp && (
                <td>
                  <IpLink ip={a.ip} />
                </td>
              )}
              {showIp && (
                <td className="ellipsis loc-cell">
                  <Location text={a.location} />
                </td>
              )}
              <td className="summary-cell">{a.summary}</td>
              <td className="nowrap">
                <RelTime ts={a.first_ts} />
              </td>
              <td className="nowrap">
                <RelTime ts={a.last_ts} />
              </td>
              <td className="num">{fmtInt(a.count)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const WINDOWS = [
  { value: "1h", label: "1h", secs: 3600 },
  { value: "24h", label: "24h", secs: 86400 },
  { value: "7d", label: "7d", secs: 7 * 86400 },
  { value: "all", label: "All", secs: 0 },
];

export default function Alerts() {
  const [query, setQuery] = useQueryState();
  const ip = query.get("ip") ?? "";
  const win = query.get("since") ?? "24h";
  const secs = WINDOWS.find((w) => w.value === win)?.secs ?? 86400;
  // `since` is quantised to the minute so the poll path stays stable between ticks.
  const since = secs ? Math.floor((Date.now() / 1000 - secs) / 60) * 60 : null;

  const [text, setText] = useState(ip);
  const pushed = useRef(ip);
  useEffect(() => {
    if (ip !== pushed.current) {
      pushed.current = ip;
      setText(ip);
    }
  }, [ip]);
  useEffect(() => {
    const next = text.trim();
    if (next === pushed.current) return;
    const id = setTimeout(() => {
      pushed.current = next;
      setQuery({ ip: next });
    }, 400);
    return () => clearTimeout(id);
  }, [text, setQuery]);

  const res = usePoll<Alert[]>(apiPath("/api/alerts", { since, limit: 500, ip: ip || null }), 10_000);
  const rows = res.data ?? [];

  return (
    <div className="page">
      <div className="page-head">
        <h1>Alerts</h1>
        <div className="filters">
          <Segmented label="Time window" value={win} options={WINDOWS.map(({ value, label }) => ({ value, label }))} onChange={(v) => setQuery({ since: v === "24h" ? null : v })} />
          <input type="search" className="input" placeholder="Exact IP…" value={text} onChange={(e) => setText(e.target.value)} aria-label="Filter by IP" />
        </div>
      </div>
      <Card flush>
        <div className={res.stale ? "dim" : ""}>{rows.length > 0 && <AlertsTable alerts={rows} />}</div>
        <PanelState loading={res.loading} error={res.error} empty={!rows.length && !res.stale} emptyText="No alerts in this window." />
        {rows.length > 0 && <div className="table-foot muted small">{rows.length} alerts</div>}
      </Card>
    </div>
  );
}
