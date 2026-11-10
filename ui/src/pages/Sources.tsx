import { useEffect, useRef, useState } from "react";
import type { Source } from "../api/types";
import { apiPath, usePoll } from "../api/client";
import { Card, FindingChips, Flag, IpLink, PanelState, RelTime, ScoreMeter, Segmented, SortTh, SourceFlags } from "../components/ui";
import { fmtBits, fmtBytes, fmtCompact, fmtInt, fmtRate } from "../lib/format";
import { navigate, sourceHref, useQueryState } from "../lib/router";

export type SourceSort = "score" | "syn" | "in_bytes" | "in_pps" | "ports" | "last_seen";
const SORTS: SourceSort[] = ["score", "syn", "in_bytes", "in_pps", "ports", "last_seen"];

export default function Sources() {
  const [query, setQuery] = useQueryState();
  const sortParam = query.get("sort") as SourceSort | null;
  const sort: SourceSort = sortParam && SORTS.includes(sortParam) ? sortParam : "score";
  const q = query.get("q") ?? "";
  const flagged = query.get("flagged") === "1";
  // Sources that touched one local port (Status links here from a probed-port insight).
  const port = Number(query.get("port")) || null;
  const limit = Number(query.get("limit")) || 100;

  // Debounce the text filter so typing doesn't spam the daemon.
  const [text, setText] = useState(q);
  const pushed = useRef(q);
  useEffect(() => {
    // Only adopt external changes (back/forward, links), not our own echo.
    if (q !== pushed.current) {
      pushed.current = q;
      setText(q);
    }
  }, [q]);
  useEffect(() => {
    const next = text.trim();
    if (next === pushed.current) return;
    const id = setTimeout(() => {
      pushed.current = next;
      setQuery({ q: next });
    }, 300);
    return () => clearTimeout(id);
  }, [text, setQuery]);

  const path = apiPath("/api/sources", { sort, limit, q: q || null, flagged, port });
  const res = usePoll<Source[]>(path, 5000);
  const rows = res.data ?? [];

  return (
    <div className="page">
      <div className="page-head">
        <h1>Sources</h1>
        <div className="filters">
          <input type="search" className="input" placeholder="Filter by IP, country or ASN…" value={text} onChange={(e) => setText(e.target.value)} aria-label="Filter sources" />
          {port && (
            <span className="filter-chip">
              port {port}
              <button type="button" aria-label="Clear the port filter" onClick={() => setQuery({ port: null })}>
                ×
              </button>
            </span>
          )}
          <label className="toggle">
            <input type="checkbox" checked={flagged} onChange={(e) => setQuery({ flagged: e.target.checked })} />
            Flagged only
          </label>
          <Segmented
            label="Row limit"
            value={String(limit)}
            options={["100", "250", "1000"].map((v) => ({ value: v, label: v }))}
            onChange={(v) => setQuery({ limit: v === "100" ? null : v })}
          />
        </div>
      </div>
      <Card flush>
        <div className={`scroll-x ${res.stale ? "dim" : ""}`}>
          <table className="tbl tbl-hover">
            <thead>
              <tr>
                <th>IP</th>
                <th>Country</th>
                <th>ASN / org</th>
                <SortTh k="score" label="Score" sort={sort} onSort={(k) => setQuery({ sort: k === "score" ? null : k })} />
                <th>Findings</th>
                <SortTh k="ports" label="Ports" sort={sort} onSort={(k) => setQuery({ sort: k })} align="right" title="Distinct local ports touched in the last hour" />
                <SortTh k="syn" label="SYN" sort={sort} onSort={(k) => setQuery({ sort: k })} align="right" />
                <SortTh k="in_bytes" label="Inbound" sort={sort} onSort={(k) => setQuery({ sort: k })} align="right" />
                <SortTh k="in_pps" label="Rate" sort={sort} onSort={(k) => setQuery({ sort: k })} align="right" />
                <SortTh k="last_seen" label="Last seen" sort={sort} onSort={(k) => setQuery({ sort: k })} />
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((s) => (
                <tr
                  key={s.ip}
                  className={`clickable ${s.allowlisted ? "row-allow" : ""}`}
                  tabIndex={0}
                  onClick={() => navigate(sourceHref(s.ip))}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") navigate(sourceHref(s.ip));
                  }}
                >
                  <td>
                    <IpLink ip={s.ip} />
                  </td>
                  <td className="nowrap">
                    <Flag cc={s.geo.country_code} title={s.geo.country} /> <span title={[s.geo.city, s.geo.country].filter(Boolean).join(", ")}>{s.geo.country_code ?? "–"}</span>
                  </td>
                  <td className="ellipsis asn-cell" title={s.geo.as_org ?? undefined}>
                    {s.geo.asn ? <span className="mono muted">AS{s.geo.asn} </span> : null}
                    {s.geo.as_org ?? (s.geo.asn ? "" : <span className="muted">–</span>)}
                  </td>
                  <td>
                    <ScoreMeter score={s.score} />
                  </td>
                  <td>
                    <FindingChips findings={s.findings} />
                  </td>
                  <td className="num">{fmtInt(s.ports)}</td>
                  <td className="num">{fmtCompact(s.syn)}</td>
                  <td className="num" title={`${fmtInt(s.in_packets)} packets`}>
                    {fmtBytes(s.in_bytes)}
                  </td>
                  <td className="num" title={`${fmtBits(s.rate.in_bps)}, ${fmtRate(s.rate.syn_ps, " SYN/s")}`}>
                    {fmtRate(s.rate.in_pps, " pps")}
                  </td>
                  <td className="nowrap">
                    <RelTime ts={s.last_seen} />
                  </td>
                  <td>
                    <SourceFlags banned={s.banned} allowlisted={s.allowlisted} feeds={s.feeds} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <PanelState loading={res.loading} error={res.error} empty={!rows.length && !res.stale} emptyText={q || flagged ? "No sources match the filter." : "No sources tracked yet."} />
        {rows.length > 0 && (
          <div className="table-foot muted small">
            {rows.length} row{rows.length === 1 ? "" : "s"}
            {rows.length >= limit ? ` (limit ${limit}; refine the filter or raise the limit)` : ""}
          </div>
        )}
      </Card>
    </div>
  );
}
