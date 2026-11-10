// Traffic › Map: the host in the middle. Left, who connects in and to which
// service; right, which program connects out and to whom. Line width is bytes,
// dashed red is failing, orange comes from a flagged source. Clicking a node
// lists its connections; the choice lives in the URL (#/traffic?node=...).
import { useMemo, useState } from "react";
import type { FlowGraph, FlowRow, GraphHalf, GraphNode, Overview } from "../api/types";
import { flowsPath, usePoll } from "../api/client";
import { PanelState, RelTime, Segmented } from "../components/ui";
import { SevIcon, useWidth } from "../components/viz";
import { fmtBytes, fmtInt } from "../lib/format";
import { href, useQueryState } from "../lib/router";

const ROW = 40;
const WINDOWS = [
  { value: "5m", label: "5 min" },
  { value: "1h", label: "1 hour" },
  { value: "24h", label: "24 hours" },
] as const;
type Win = (typeof WINDOWS)[number]["value"];

function Half({ data, rows, focus, setFocus, pick, side, label }: { data: GraphHalf; rows: number; focus: string | null; setFocus: (k: string | null) => void; pick: (n: GraphNode) => void; side: "in" | "out"; label: string }) {
  const [ref, w] = useWidth<HTMLDivElement>();
  const nodeW = Math.min(210, Math.max(118, w * 0.4));
  const h = Math.max(1, rows) * ROW + 8;
  const maxCh = Math.floor((nodeW - 18) / 6.8);
  const yOf = (list: GraphNode[], i: number) => (h - list.length * ROW) / 2 + i * ROW + ROW / 2;
  const maxB = Math.max(1, ...data.edges.map((e) => e.bytes));
  const width = (b: number) => 1.5 + 7 * (Math.log1p(b) / Math.log1p(maxB));
  const lit = new Set<string>();
  if (focus) {
    lit.add(focus);
    for (const e of data.edges)
      if (e.a === focus || e.b === focus) {
        lit.add(e.a);
        lit.add(e.b);
      }
  }
  const clip = (s: string) => (s.length > maxCh ? `${s.slice(0, maxCh - 1)}…` : s);
  // On a phone the count goes before the byte total does.
  const fit = (s: string, short: string) => (s.length > maxCh ? short : s);
  const node = (n: GraphNode, x: number, y: number, first: boolean) => (
    <g
      key={n.key}
      className={`map-node ${n.failed ? "bad-node" : ""} ${lit.has(n.key) ? "lit" : ""}`}
      transform={`translate(${x},${y - 16})`}
      tabIndex={0}
      role="button"
      aria-label={`${n.label}${n.sub ? `, ${n.sub}` : ""}: ${fmtInt(n.flows)} connections, ${fmtBytes(n.bytes)}${n.failed ? `, ${fmtInt(n.failed)} failed` : ""}`}
      onPointerEnter={() => setFocus(n.key)}
      onPointerLeave={() => setFocus(null)}
      onFocus={() => setFocus(n.key)}
      onBlur={() => setFocus(null)}
      onClick={() => pick(n)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          pick(n);
        }
      }}
    >
      <title>{`${n.label}\n${n.sub}`}</title>
      <rect className="n" width={nodeW} height={32} rx={5} />
      <text x={9} y={14} className={n.hostile && side === "in" && first ? "hostile" : ""}>
        {clip(n.label)}
      </text>
      <text x={9} y={27} className={n.failed ? "bad" : "sub"}>
        {n.failed ? `${fmtInt(n.failed)} of ${fmtInt(n.flows)} failed` : fit(`${fmtInt(n.flows)} conn · ${fmtBytes(n.bytes)}`, fmtBytes(n.bytes))}
      </text>
    </g>
  );
  const xr = w - nodeW;
  // Too narrow for "timed out ×2" between the columns; the box says it already.
  const edgeLabels = xr - nodeW >= 110;
  return (
    <div ref={ref} className="map-half">
      {w > 0 && (
        <svg width={w} height={h} role="group" aria-label={label}>
          {[...data.edges]
            .sort((a, b) => Number(a.failed > 0) - Number(b.failed > 0))
            .map((e) => {
              const y1 = yOf(data.left, data.left.findIndex((n) => n.key === e.a));
              const y2 = yOf(data.right, data.right.findIndex((n) => n.key === e.b));
              const x1 = nodeW,
                x2 = xr,
                mx = (x1 + x2) / 2;
              const on = focus && (e.a === focus || e.b === focus);
              return (
                <g key={`${e.a}→${e.b}`}>
                  <path d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} className={`map-edge ${e.failed ? "bad" : e.hostile ? "hostile" : ""} ${on ? "lit" : ""}`} strokeWidth={e.failed ? 2 : width(e.bytes)} />
                  {e.failed > 0 && edgeLabels && (
                    <text x={mx} y={(y1 + y2) / 2 - 5} textAnchor="middle" className="map-edge-label">
                      {e.reason ?? "failed"} ×{fmtInt(e.failed)}
                    </text>
                  )}
                </g>
              );
            })}
          {data.left.map((n, i) => node(n, 0, yOf(data.left, i), true))}
          {data.right.map((n, i) => node(n, xr, yOf(data.right, i), false))}
        </svg>
      )}
    </div>
  );
}

function EdgeTable({ g }: { g: FlowGraph }) {
  const name = (half: GraphHalf, k: string) => [...half.left, ...half.right].find((n) => n.key === k)?.label ?? k;
  const rows = [
    ...g.inbound.edges.map((e) => ({ dir: "in", a: name(g.inbound, e.a), b: name(g.inbound, e.b), e })),
    ...g.outbound.edges.map((e) => ({ dir: "out", a: name(g.outbound, e.a), b: name(g.outbound, e.b), e })),
  ].sort((x, y) => y.e.failed - x.e.failed || y.e.bytes - x.e.bytes);
  return (
    <div className="scroll-y" style={{ maxHeight: 420 }}>
      <table className="tbl tbl-compact">
        <thead>
          <tr>
            <th>From</th>
            <th>To</th>
            <th className="num">Connections</th>
            <th className="num">Bytes</th>
            <th>Failing</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(({ dir, a, b, e }) => (
            <tr key={`${dir}${e.a}${e.b}`} className={e.failed ? "tr-bad" : ""}>
              <td>{dir === "in" ? a : `${a} (this host)`}</td>
              <td>{dir === "in" ? `${b} (this host)` : b}</td>
              <td className="num">{fmtInt(e.flows)}</td>
              <td className="num">{fmtBytes(e.bytes)}</td>
              <td>{e.failed ? `${e.reason ?? "failed"} ×${fmtInt(e.failed)}` : <span className="muted">–</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const owner = (f: FlowRow) => f.container ?? f.unit ?? f.process ?? "unknown process";
const failWord = (f: FlowRow) => (f.state === "unanswered" ? "unanswered" : (f.connect_ms ?? 0) >= 3000 ? "timed out" : "refused");

export default function TrafficMap() {
  const [q, setQ] = useQueryState();
  const win: Win = (WINDOWS.find((w) => w.value === q.get("window"))?.value ?? "1h") as Win;
  const picked = q.get("node");
  const [hover, setHover] = useState<string | null>(null);
  const [table, setTable] = useState(false);
  const ov = usePoll<Overview>("/api/overview", 10_000);
  const g = usePoll<FlowGraph>(`/api/flows/graph?window=${win}`, 15_000);
  const all = useMemo(() => (g.data ? [...g.data.inbound.left, ...g.data.inbound.right, ...g.data.outbound.left, ...g.data.outbound.right] : []), [g.data]);
  const pickedNode = all.find((n) => n.key === picked) ?? null;
  const filter = pickedNode?.filter ?? null;
  const list = usePoll<FlowRow[]>(flowsPath({ view: "all", window: win, sort: filter ? "last" : "bytes", limit: 15, ...(filter ?? {}) }), 15_000);

  const data = g.data;
  if (!data)
    return (
      <div className="page roomy">
        <h1>Who talks to whom</h1>
        <PanelState loading={g.loading} error={g.error} />
      </div>
    );

  const rows = Math.max(data.inbound.left.length, data.inbound.right.length, data.outbound.left.length, data.outbound.right.length);
  const failing = data.outbound.left.filter((n) => n.failed > 0 && !n.folded);
  const focus = hover ?? picked;
  const pick = (n: GraphNode) => setQ({ node: n.key === picked ? null : n.key });
  const span = WINDOWS.find((w) => w.value === win)!.label;
  const empty = data.flows === 0;

  return (
    <div className="page roomy">
      <div className="title-row">
        <div>
          <h1>Who talks to whom</h1>
          <p className="title-verdict">
            <b>{fmtInt(data.active)}</b> open connections, <b>{fmtInt(data.flows)}</b> in the last {span}
            {data.truncated ? " (the most recent ones)" : ""}.{" "}
            {failing.length ? (
              <b className="hot">
                {failing.length} program{failing.length === 1 ? " can't" : "s can't"} connect: {failing.map((n) => n.label).join(", ")}.
              </b>
            ) : empty ? null : (
              "Every program reached what it asked for."
            )}
          </p>
        </div>
        <Segmented label="Window" value={win} onChange={(v) => setQ({ window: v === "1h" ? null : v, node: null })} options={WINDOWS.map((w) => ({ value: w.value, label: w.label }))} />
      </div>

      {empty ? (
        <p className="muted">No connections in the last {span}. Try a longer window.</p>
      ) : (
        <section className={`host-map ${focus ? "has-focus" : ""}`} aria-label={`Who talks to whom, last ${span}`}>
          <div className="map-head">
            <div className="lane-legend">
              <span>line width: bytes</span>
              <span>
                <svg width="22" height="8" aria-hidden>
                  <path d="M1,4 H21" className="map-edge hostile" strokeWidth="3" />
                </svg>
                from a flagged source
              </span>
              <span>
                <svg width="22" height="8" aria-hidden>
                  <path d="M1,4 H21" className="map-edge bad" strokeWidth="2" />
                </svg>
                failing
              </span>
              <span>click a box to list its connections</span>
            </div>
            <button type="button" className="link-btn" onClick={() => setTable(!table)}>
              {table ? "Map" : "Table"}
            </button>
          </div>
          {table ? (
            <EdgeTable g={data} />
          ) : (
            <div className="map-grid">
              <div className="map-side">
                <div className="map-cols">
                  <span>Connects to us</span>
                  <span>Service on this host</span>
                </div>
                {data.inbound.left.length ? <Half data={data.inbound} rows={rows} focus={focus} setFocus={setHover} pick={pick} side="in" label="Inbound: who connects to which service" /> : <p className="muted small map-none">Nothing connected in.</p>}
              </div>
              <div className="map-spine" aria-hidden>
                <span>{ov.data?.host ?? "this host"}</span>
              </div>
              <div className="map-side">
                <div className="map-cols">
                  <span>Program on this host</span>
                  <span>Connects to</span>
                </div>
                {data.outbound.left.length ? <Half data={data.outbound} rows={rows} focus={focus} setFocus={setHover} pick={pick} side="out" label="Outbound: which program connects to whom" /> : <p className="muted small map-none">Nothing connected out.</p>}
              </div>
            </div>
          )}
        </section>
      )}

      <section className="section">
        <div className="section-head">
          <h2>{pickedNode ? `Connections: ${pickedNode.label}` : "Busiest connections"}</h2>
          {pickedNode && (
            <span className="filter-chip">
              {pickedNode.label}
              <button type="button" aria-label="Clear the filter" onClick={() => setQ({ node: null })}>
                ×
              </button>
            </span>
          )}
          <a className="small" href={href("/traffic/connections", { view: "all", window: win, ...(filter ?? {}) })}>
            All of them in Connections
          </a>
        </div>
        {pickedNode && !filter && <p className="muted small">This box groups several addresses, so there is no single filter for it: open Connections to search.</p>}
        <div className="panel flush-panel">
          <PanelState loading={list.loading} error={list.error} empty={!!list.data && list.data.length === 0} emptyText={`No connections in the last ${span}.`} />
          {list.data && list.data.length > 0 && (
            <table className="tbl tbl-compact">
              <thead>
                <tr>
                  <th>Program</th>
                  <th>Remote</th>
                  <th className="hide-sm">Port</th>
                  <th className="num">Bytes</th>
                  <th>State</th>
                  <th className="hide-sm">Last</th>
                </tr>
              </thead>
              <tbody>
                {list.data.map((f, i) => (
                  <tr key={`${f.remote}${f.rport}${f.lport}${f.first_seen}${i}`} className={f.state === "failed" || f.state === "unanswered" ? "tr-bad" : ""}>
                    <td className="nowrap">{f.dir === "in" ? (f.container ?? f.unit ?? f.process ?? <span className="muted">nothing listening</span>) : owner(f)}</td>
                    <td className="clip-cell">
                      <span className="mono" title={f.remote_name ? `${f.remote_name} ${f.remote}` : f.remote}>{f.remote_name ?? f.remote}</span>
                      {f.remote_name && <span className="muted mono small hide-sm"> {f.remote}</span>}
                    </td>
                    <td className="mono hide-sm">
                      {f.dir} {f.proto}/{f.service_port}
                    </td>
                    <td className="num">{fmtBytes(f.bytes_in + f.bytes_out)}</td>
                    <td>
                      {f.state === "failed" || f.state === "unanswered" ? (
                        <span className="inline-sev">
                          <SevIcon sev="critical" size={12} /> {failWord(f)}
                        </span>
                      ) : f.active ? (
                        "open"
                      ) : (
                        f.state
                      )}
                    </td>
                    <td className="hide-sm">
                      <RelTime ts={f.last_seen} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>
    </div>
  );
}
