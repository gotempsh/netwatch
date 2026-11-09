import type { DnsInfo, DnsQuery } from "../api/types";
import { dnsPath, usePoll, type FlowWindow } from "../api/client";
import { Badge, BarCell, Card, Empty, FilterInput, PanelState, RelTime, Segmented, Select, type Tone } from "../components/ui";
import { fmtAbsolute, fmtClockSec, fmtInt, fmtMs } from "../lib/format";
import { useQueryState } from "../lib/router";
import { FLOW_WINDOWS, parseWindow } from "./Connections";

const RCODES = ["NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "TIMEOUT", "FORMERR", "NOTIMP", "OTHER"];

function rcodeTone(rc: string): Tone {
  if (rc === "NOERROR") return "muted";
  if (rc === "NXDOMAIN") return "warning";
  if (rc === "SERVFAIL" || rc === "TIMEOUT") return "critical";
  return "serious";
}

export function RcodeBadge({ rcode }: { rcode: string }) {
  return <Badge tone={rcodeTone(rcode)}>{rcode}</Badge>;
}

function DnsTable({ rows, onFilter }: { rows: DnsQuery[]; onFilter: (q: string) => void }) {
  const ipBtn = (ip: string, what: string) => (
    <button type="button" className="proc-link mono" title={`Filter by ${what} ${ip}`} onClick={() => onFilter(ip)}>
      {ip}
    </button>
  );
  return (
    <table className="tbl tbl-compact tbl-hover">
      <thead>
        <tr>
          <th>Time</th>
          <th>Client</th>
          <th>Server</th>
          <th>Type</th>
          <th>Name</th>
          <th>Result</th>
          <th className="num">Latency</th>
          <th>Answers</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => {
          const bad = r.rcode === "NXDOMAIN" || r.rcode === "SERVFAIL" || r.rcode === "TIMEOUT";
          return (
            <tr key={`${r.ts}-${r.client}-${r.qname}-${r.qtype}-${i}`} className={bad ? (r.rcode === "NXDOMAIN" ? "row-warn" : "row-failed") : ""}>
              <td className="mono muted nowrap" title={fmtAbsolute(r.ts)}>
                {fmtClockSec(r.ts)}
              </td>
              <td className="nowrap" title={`${r.dir === "in" ? "Asked this host" : "This host asked"} · ${r.iface}`}>
                {ipBtn(r.client, "client")}
              </td>
              <td className="nowrap">{ipBtn(r.server, "server")}</td>
              <td className="mono small">{r.qtype}</td>
              <td>
                <button type="button" className="proc-link mono trunc qname-cell" title={`${r.qname}\nClick to filter by this name.`} onClick={() => onFilter(r.qname)}>
                  {r.qname}
                </button>
              </td>
              <td>
                <RcodeBadge rcode={r.rcode} />
              </td>
              <td className="num">{r.latency_ms != null ? fmtMs(r.latency_ms) : <span className="muted">–</span>}</td>
              <td className="mono small">
                {r.answers.length ? (
                  <span className="trunc answers-cell" title={r.answers.join("\n")}>
                    {r.answers.join(", ")}
                  </span>
                ) : (
                  <span className="muted">–</span>
                )}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

export default function Dns() {
  const [query, setQuery] = useQueryState();
  const win = parseWindow(query.get("window"), "1h");
  const q = query.get("q") ?? "";
  const rcode = query.get("rcode") ?? "";
  const limit = Number(query.get("limit")) || 500;
  const res = usePoll<DnsInfo>(dnsPath({ window: win, q: q || null, rcode: rcode || null, limit }), 10_000);
  const rows = res.data?.queries ?? [];
  const top = res.data?.top ?? [];
  const maxTop = Math.max(0, ...top.map((t) => t.queries));
  const failures = rows.filter((r) => r.rcode !== "NOERROR").length;

  return (
    <div className="page">
      <div className="page-head">
        <h1>DNS</h1>
        {res.data && (
          <span className="muted small">
            {fmtInt(rows.length)} queries loaded · {fmtInt(failures)} not NOERROR
          </span>
        )}
        <div className="filters">
          <FilterInput value={q} onCommit={(v) => setQuery({ q: v })} placeholder="Name, client, server or answer…" label="Filter DNS queries" />
          <Select
            label="Response code"
            value={rcode}
            onChange={(v) => setQuery({ rcode: v })}
            options={[{ value: "", label: "Any result" }, ...RCODES.map((r) => ({ value: r, label: r }))]}
          />
          <Segmented<FlowWindow> label="Time window" value={win} options={FLOW_WINDOWS} onChange={(v) => setQuery({ window: v === "1h" ? null : v })} />
        </div>
      </div>
      <div className="grid-2 grid-wide-left">
        <Card title="Query log" sub="Newest first" flush>
          {rows.length > 0 && (
            <div className={`scroll-y ${res.stale ? "dim" : ""}`} style={{ maxHeight: 720 }}>
              <DnsTable rows={rows} onFilter={(v) => setQuery({ q: v })} />
            </div>
          )}
          <PanelState loading={res.loading} error={res.error} empty={!rows.length && !res.stale} emptyText={q || rcode ? "No queries match the filters." : "No DNS queries in this window."} />
          {rows.length > 0 && (
            <div className="table-foot muted small">
              {fmtInt(rows.length)} queries{rows.length >= limit ? ` (limit ${limit}; refine the filter)` : ""}
            </div>
          )}
        </Card>
        <Card title="Top names" sub={`Most queried over ${win} (unfiltered)`} flush>
          {top.length ? (
            <div className={`scroll-y ${res.stale ? "dim" : ""}`} style={{ maxHeight: 720 }}>
              <table className="tbl tbl-compact tbl-hover">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th className="bar-col">Queries</th>
                    <th className="num">NXDOMAIN</th>
                    <th className="num">Clients</th>
                    <th>Last</th>
                  </tr>
                </thead>
                <tbody>
                  {top.map((t) => (
                    <tr key={t.qname} className={t.nxdomain > 0 && t.nxdomain === t.queries ? "row-warn" : ""}>
                      <td>
                        <button type="button" className="proc-link mono trunc qname-cell" title={`${t.qname}\nClick to filter by this name.`} onClick={() => setQuery({ q: t.qname })}>
                          {t.qname}
                        </button>
                      </td>
                      <td>
                        <BarCell value={t.queries} max={maxTop} label={fmtInt(t.queries)} />
                      </td>
                      <td className="num">{t.nxdomain > 0 ? <Badge tone="warning">{fmtInt(t.nxdomain)}</Badge> : <span className="muted">0</span>}</td>
                      <td className="num">{fmtInt(t.clients)}</td>
                      <td className="nowrap">
                        <RelTime ts={t.last_ts} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            !res.loading && <Empty>No names yet.</Empty>
          )}
        </Card>
      </div>
    </div>
  );
}
