import { useMemo } from "react";
import type { ConnEvent, FlowGroup, FlowRow, FlowSort, FlowsSummary, FlowView, InterfacesInfo } from "../api/types";
import { connEventsPath, flowsPath, flowsSummaryPath, interfacesPath, usePoll, type FlowWindow } from "../api/client";
import { StatTile, TimeChart, type ChartSeries } from "../components/charts";
import { AppCell, DirArrow, FlowState, HostPort, ProcessCell, RemoteCell, RetransCell } from "../components/domain";
import { Badge, Card, FilterInput, Flag, IpLink, LevelTag, PanelState, RankedList, RelTime, Segmented, Select, SortTh, type RankItem, type Tone } from "../components/ui";
import { fmtAbsolute, fmtBitrate, fmtBytes, fmtClock, fmtClockSec, fmtCompact, fmtDayHour, fmtDuration, fmtInt } from "../lib/format";
import { useQueryState } from "../lib/router";

// ---------------------------------------------------------------------------
// Shared bits

export const FLOW_WINDOWS: { value: FlowWindow; label: string }[] = [
  { value: "15m", label: "15m" },
  { value: "1h", label: "1h" },
  { value: "6h", label: "6h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
  { value: "30d", label: "30d" },
];
const WINDOW_VALUES = new Set<string>(["5m", ...FLOW_WINDOWS.map((w) => w.value)]);
export function parseWindow(v: string | null, def: FlowWindow): FlowWindow {
  return v && WINDOW_VALUES.has(v) ? (v as FlowWindow) : def;
}

const SORTS: FlowSort[] = ["bytes", "rate", "last", "first", "retrans"];
const VIEWS: FlowView[] = ["active", "history", "all"];

const rowKey = (f: FlowRow, i: number) => `${f.iface}|${f.proto}|${f.local}|${f.lport}|${f.remote}|${f.rport}|${f.first_seen}|${f.active ? 1 : 0}|${i}`;

// ---------------------------------------------------------------------------
// Flows table (also used on the source detail page)

export function FlowsTable({
  rows,
  mode,
  sort,
  onSort,
  onProcess,
}: {
  rows: FlowRow[];
  /** live: active flows; history: finished; all: both (rate for active rows, duration for finished). */
  mode: "live" | "history" | "all";
  sort?: FlowSort;
  onSort?: (k: FlowSort) => void;
  onProcess?: (name: string) => void;
}) {
  const h = (k: FlowSort, label: string, title?: string, align?: "left" | "right") =>
    sort && onSort ? (
      <SortTh k={k} label={label} sort={sort} onSort={onSort} title={title} align={align} />
    ) : (
      <th className={align === "right" ? "num" : undefined} title={title}>
        {label}
      </th>
    );
  return (
    <table className="tbl tbl-compact tbl-hover flows-tbl">
      <thead>
        <tr>
          <th title="Direction: ← inbound, → outbound" className="dir-col">
            Dir
          </th>
          <th>Proto</th>
          <th>Local</th>
          <th>Remote</th>
          <th>Process</th>
          <th>State</th>
          {h("bytes", "Bytes in / out", "Sort by total bytes (descending)", "right")}
          {mode === "live" && h("rate", "Rate", "Sort by current rate (descending)", "right")}
          {mode === "history" && <th className="num">Duration</th>}
          {mode === "all" && h("rate", "Rate / duration", "Rate for active flows, duration for finished ones; sorts by rate", "right")}
          {h("first", "Started", "Sort by start time (newest first)")}
          {mode !== "live" && h("last", "Last", "Sort by last activity (newest first)")}
          {h("retrans", "Retr / RST", "Sort by TCP retransmissions (descending)")}
          <th>Iface</th>
          <th>App</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((f, i) => {
          const rate = f.rate_in + f.rate_out;
          const rateCell = (
            <td className="num" title={`in ${fmtBitrate(f.rate_in)} · out ${fmtBitrate(f.rate_out)}`}>
              {rate > 0 ? fmtBitrate(rate) : <span className="muted">idle</span>}
            </td>
          );
          const durCell = (
            <td className="num" title={`${fmtAbsolute(f.first_seen)} → ${fmtAbsolute(f.last_seen)}`}>
              {fmtDuration(f.last_seen - f.first_seen)}
            </td>
          );
          return (
            <tr key={rowKey(f, i)} className={`${f.state === "failed" ? "row-failed" : ""} ${mode === "all" && f.active ? "row-active" : ""}`}>
              <td className="dir-col">
                <DirArrow dir={f.dir} />
              </td>
              <td className="nowrap">
                <span className="mono">{f.proto}</span>
                {f.service && (
                  <div className="muted small" title={`Service port ${f.service_port}`}>
                    {f.service}
                  </div>
                )}
              </td>
              <td className="nowrap">
                <HostPort ip={f.local} port={f.lport} />
              </td>
              <td className="remote-col">
                <RemoteCell ip={f.remote} port={f.rport} name={f.remote_name} country={f.country} asn={f.asn} asOrg={f.as_org} />
                {(f.remote_process || f.remote_container || f.remote_unit) && (
                  <div className="remote-sub small" title="Process on the remote end (on this host)">
                    <ProcessCell
                      process={f.remote_process}
                      container={f.remote_container}
                      unit={f.remote_unit}
                      pid={f.remote_pid}
                      exe={null}
                      onFilter={onProcess}
                    />
                  </div>
                )}
              </td>
              <td className="proc-col">
                <ProcessCell process={f.process} container={f.container} unit={f.unit} pid={f.pid} exe={f.exe} onFilter={onProcess} />
              </td>
              <td className="nowrap">
                <FlowState state={f.state} connectMs={f.connect_ms} />
              </td>
              <td className="num bytes-cell" title={`${fmtInt(f.pkts_in)} packets in · ${fmtInt(f.pkts_out)} packets out`}>
                <div>
                  <span className="muted small">↓</span> {fmtBytes(f.bytes_in)}
                </div>
                <div>
                  <span className="muted small">↑</span> {fmtBytes(f.bytes_out)}
                </div>
              </td>
              {mode === "live" && rateCell}
              {mode === "history" && durCell}
              {mode === "all" && (f.active ? rateCell : durCell)}
              <td className="nowrap">
                <RelTime ts={f.first_seen} />
              </td>
              {mode !== "live" && <td className="nowrap">{f.active ? <Badge tone="good">active</Badge> : <RelTime ts={f.last_seen} />}</td>}
              <td>
                <RetransCell retrans={f.retrans} rstSent={f.rst_sent} rstRecv={f.rst_recv} />
              </td>
              <td className="mono small nowrap">{f.iface}</td>
              <td className="app-col">
                <AppCell app={f.app} />
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

// ---------------------------------------------------------------------------
// Summary strip

/** "c/p" -> c, "u/p" -> u, "c/?" -> c, "p" -> p, "unknown" -> null (the API matches process, container or unit). */
function processFilter(key: string): string | null {
  if (key === "unknown") return null;
  const i = key.indexOf("/");
  return i > 0 ? key.slice(0, i) : key;
}

function parseService(key: string): { port: number; proto: string; dir: string } | null {
  const m = /^(\d+)\/(\S+) (\S+)$/.exec(key);
  return m ? { port: Number(m[1]), proto: m[2], dir: m[3] } : null;
}

const total = (g: FlowGroup) => g.bytes_in + g.bytes_out;
const groupTitle = (g: FlowGroup) =>
  `${fmtInt(g.flows)} flows (${fmtInt(g.active)} active) · ↓ ${fmtBytes(g.bytes_in)} ↑ ${fmtBytes(g.bytes_out)}` +
  (g.remotes > 1 ? ` · ${fmtInt(g.remotes)} remotes` : "") +
  (g.failed ? ` · ${fmtInt(g.failed)} failed` : "") +
  (g.retrans ? ` · ${fmtInt(g.retrans)} retrans` : "");

function SummaryStrip({ s, dim, onFilter }: { s: FlowsSummary; dim: boolean; onFilter: (patch: Record<string, string | number | null>) => void }) {
  const x = useMemo(() => s.series.map((p) => p.ts), [s.series]);
  const series: ChartSeries[] = useMemo(
    () => [
      { key: "new_out", label: "New outbound", slot: 1, values: s.series.map((p) => p.new_out) },
      { key: "new_in", label: "New inbound", slot: 2, values: s.series.map((p) => p.new_in) },
      { key: "failed", label: "Failed", slot: 4, values: s.series.map((p) => p.failed) },
    ],
    [s.series],
  );
  const tail = (k: "new_in" | "new_out" | "failed" | "bytes_in" | "bytes_out") => s.series.map((p) => p[k]);

  const remotes: RankItem[] = s.top_remotes.map((g) => ({
    key: g.key,
    label: (
      <>
        <Flag cc={g.country} /> <span className="mono">{g.key}</span>
      </>
    ),
    sub: g.label ?? g.as_org ?? undefined,
    value: total(g),
    valueLabel: fmtBytes(total(g)),
    title: `${g.label ? `${g.label}\n` : ""}${g.as_org ? `${g.as_org}\n` : ""}${groupTitle(g)}\nClick to filter by this IP.`,
    onClick: () => onFilter({ ip: g.key }),
  }));
  const processes: RankItem[] = s.top_processes.map((g) => {
    const f = processFilter(g.key);
    return {
      key: g.key,
      label: <span className="mono">{g.key}</span>,
      sub: g.label ?? undefined,
      value: total(g),
      valueLabel: fmtBytes(total(g)),
      title: `${g.label ? `${g.label}\n` : ""}${groupTitle(g)}${f ? `\nClick to filter by ${f}.` : ""}`,
      onClick: f ? () => onFilter({ process: f }) : undefined,
    };
  });
  const services: RankItem[] = s.top_services.map((g) => {
    const p = parseService(g.key);
    return {
      key: g.key,
      label: (
        <>
          {p && <span className="dir-inline">{p.dir === "in" ? "←" : p.dir === "out" ? "→" : "↔"}</span>} {g.label ?? (p ? String(p.port) : g.key)}
        </>
      ),
      sub: <span className="mono">{g.key}</span>,
      value: total(g),
      valueLabel: fmtBytes(total(g)),
      title: `${groupTitle(g)}\nClick to filter by this port, protocol and direction.`,
      onClick: p ? () => onFilter({ port: p.port, proto: p.proto, dir: p.dir }) : undefined,
    };
  });
  const countries: RankItem[] = s.top_countries.map((g) => {
    const known = /^[A-Za-z]{2}$/.test(g.key);
    return {
      key: g.key,
      label: known ? (
        <>
          <Flag cc={g.key} /> {g.key}
        </>
      ) : (
        <span className="muted">private / unknown</span>
      ),
      sub: `${fmtInt(g.remotes)} remote${g.remotes === 1 ? "" : "s"}`,
      value: total(g),
      valueLabel: fmtBytes(total(g)),
      title: `${groupTitle(g)}${known ? "\nClick to search for this country code." : ""}`,
      onClick: known ? () => onFilter({ q: g.key }) : undefined,
    };
  });

  // Beyond an hour the byte totals start on a whole hour; say which.
  const hourly = !["5m", "15m", "1h"].includes(s.window);
  const bytesSpan = hourly && s.bytes_since ? `since ${fmtDayHour(s.bytes_since)}` : `in ${s.window}`;

  return (
    <div className={`stack ${dim ? "dim" : ""}`}>
      <div className="tiles">
        <StatTile label="Active flows" value={fmtCompact(s.active)} context="open right now" />
        <StatTile label={`Flows (${s.window})`} value={fmtCompact(s.flows)} context={s.truncated ? "history truncated at 100k" : "active + finished"} />
        <StatTile label="Inbound" value={fmtCompact(s.inbound)} context="remote connected to us" trend={tail("new_in")} />
        <StatTile label="Outbound" value={fmtCompact(s.outbound)} context="we connected out" trend={tail("new_out")} />
        <StatTile
          label="Failed connects"
          value={fmtCompact(s.failed)}
          status={s.failed > 0 ? <LevelTag level="warn" label="Check" /> : undefined}
          context={s.failed > 0 ? undefined : "none"}
          trend={tail("failed")}
        />
        <StatTile label="Received" value={fmtBytes(s.bytes_in)} context={bytesSpan} trend={tail("bytes_in")} />
        <StatTile label="Sent" value={fmtBytes(s.bytes_out)} context={bytesSpan} trend={tail("bytes_out")} />
        <StatTile label="Listening sockets" value={fmtCompact(s.listeners)} context="incl. loopback" href="#/exposure" />
      </div>
      <div className="grid-2 grid-wide-right">
        <Card title="New flows per minute" sub="Last 60 minutes">
          <TimeChart x={x} series={series} yFormat={fmtCompact} xFormat={fmtClock} height={170} ariaLabel="New inbound, new outbound and failed flows per minute, last 60 minutes" dim={dim} />
        </Card>
        <Card title="Top talkers" sub={`By bytes over ${s.window}. Click an entry to filter.`}>
          <div className="rank-grid">
            <div>
              <h3 className="rank-title">Remotes</h3>
              <RankedList items={remotes} />
            </div>
            <div>
              <h3 className="rank-title">Processes</h3>
              <RankedList items={processes} />
            </div>
            <div>
              <h3 className="rank-title">Services</h3>
              <RankedList items={services} />
            </div>
            <div>
              <h3 className="rank-title">Countries</h3>
              <RankedList items={countries} />
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Connection events

const EVENT_META: Record<string, { label: string; tone: Tone }> = {
  connect_failed: { label: "connect failed", tone: "critical" },
  listen: { label: "listen", tone: "accent" },
  unlisten: { label: "unlisten", tone: "muted" },
};

export function ConnEventsTable({ events, onProcess }: { events: ConnEvent[]; onProcess?: (name: string) => void }) {
  return (
    <table className="tbl tbl-compact">
      <thead>
        <tr>
          <th>Time</th>
          <th>Event</th>
          <th>Local</th>
          <th>Remote</th>
          <th>Process</th>
          <th>Detail</th>
        </tr>
      </thead>
      <tbody>
        {events.map((e, i) => {
          const m = EVENT_META[e.kind] ?? { label: e.kind.replace(/_/g, " "), tone: "neutral" as Tone };
          return (
            <tr key={`${e.ts}-${e.kind}-${e.lport}-${i}`} className={e.kind === "connect_failed" ? "row-failed" : ""}>
              <td className="nowrap mono muted" title={fmtAbsolute(e.ts)}>
                {fmtClockSec(e.ts)}
                <div className="small">
                  <RelTime ts={e.ts} />
                </div>
              </td>
              <td className="nowrap">
                <Badge tone={m.tone}>{m.label}</Badge> <span className="mono muted small">{e.proto}</span>
              </td>
              <td className="nowrap">
                <HostPort ip={e.local} port={e.lport} />
              </td>
              <td className="nowrap">
                {e.remote ? (
                  <>
                    <IpLink ip={e.remote} />
                    {e.rport != null && <span className="mono muted">:{e.rport}</span>}
                  </>
                ) : (
                  <span className="muted">–</span>
                )}
              </td>
              <td>
                <ProcessCell process={e.process} container={e.container} unit={e.unit} pid={e.pid} exe={null} onFilter={onProcess} />
              </td>
              <td className="summary-cell">{e.detail}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function ConnEventsCard({ window, kind, onKind, onProcess }: { window: FlowWindow; kind: string; onKind: (k: string) => void; onProcess: (p: string) => void }) {
  const res = usePoll<ConnEvent[]>(connEventsPath({ window, kind: kind === "all" ? null : kind, limit: 300 }), 10_000);
  const rows = res.data ?? [];
  return (
    <Card
      title="Connection events"
      sub={`Failed connects and listening sockets opened or closed, last ${window}`}
      flush
      actions={
        <Segmented
          label="Event kind"
          value={kind}
          onChange={onKind}
          options={[
            { value: "all", label: "All" },
            { value: "connect_failed", label: "Failed" },
            { value: "listen", label: "Listen" },
            { value: "unlisten", label: "Unlisten" },
          ]}
        />
      }
    >
      <PanelState loading={res.loading} error={res.error} empty={!rows.length && !res.stale} emptyText="No connection events in this window." />
      {rows.length > 0 && (
        <div className={`scroll-y ${res.stale ? "dim" : ""}`} style={{ maxHeight: 420 }}>
          <ConnEventsTable events={rows} onProcess={onProcess} />
        </div>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Page

export default function Connections() {
  const [query, setQuery] = useQueryState();
  const viewParam = query.get("view") as FlowView | null;
  const view: FlowView = viewParam && VIEWS.includes(viewParam) ? viewParam : "active";
  const sortParam = query.get("sort") as FlowSort | null;
  const sort: FlowSort = sortParam && SORTS.includes(sortParam) ? sortParam : "bytes";
  const win = parseWindow(query.get("window"), "1h");
  const q = query.get("q") ?? "";
  const ip = query.get("ip") ?? "";
  const portRaw = query.get("port") ?? "";
  const port = /^\d{1,5}$/.test(portRaw) ? Number(portRaw) : null;
  const process = query.get("process") ?? "";
  const dir = query.get("dir") ?? "";
  const iface = query.get("iface") ?? "";
  const proto = query.get("proto") ?? "";
  const limit = Number(query.get("limit")) || 500;
  const evKind = query.get("ev") ?? "all";

  const path = flowsPath({
    view,
    window: view === "active" ? null : win,
    q: q || null,
    ip: ip || null,
    port,
    process: process || null,
    dir: dir === "in" || dir === "out" || dir === "unknown" ? dir : null,
    iface: iface || null,
    proto: proto || null,
    sort,
    limit,
  });
  const res = usePoll<FlowRow[]>(path, view === "active" ? 5000 : 15_000);
  const sum = usePoll<FlowsSummary>(flowsSummaryPath(win), 10_000);
  const ifs = usePoll<InterfacesInfo>(interfacesPath(), 60_000);
  const rows = res.data ?? [];

  const ifaceOptions = useMemo(() => {
    const names = (ifs.data?.interfaces ?? []).filter((i) => i.flows || i.xdp).map((i) => i.name);
    if (iface && !names.includes(iface)) names.push(iface);
    return [{ value: "", label: "Any interface" }, ...names.map((n) => ({ value: n, label: n }))];
  }, [ifs.data, iface]);

  const filtered = !!(q || ip || port != null || process || dir || iface || proto);
  const setProcess = (p: string) => setQuery({ process: p });
  const mode = view === "active" ? "live" : view;

  return (
    <div className="page">
      <div className="page-head">
        <h1>Connections</h1>
        <div className="filters">
          <Segmented<FlowView>
            label="View"
            value={view}
            onChange={(v) => setQuery(v === "history" && sort === "rate" ? { view: v, sort: null } : { view: v === "active" ? null : v })}
            options={[
              { value: "active", label: "Live" },
              { value: "history", label: "History" },
              { value: "all", label: "All" },
            ]}
          />
          <Segmented<FlowWindow> label="Time window" value={win} options={FLOW_WINDOWS} onChange={(v) => setQuery({ window: v === "1h" ? null : v })} />
        </div>
      </div>
      <p className="muted small page-note">
        {view === "active" ? "Live view shows open conversations; the window applies to the summary." : `Showing ${view === "all" ? "open conversations plus " : ""}flows active within the last ${win}.`}
      </p>

      {sum.data ? <SummaryStrip s={sum.data} dim={sum.stale} onFilter={(patch) => setQuery(patch)} /> : <PanelState loading={sum.loading} error={sum.error} />}

      <Card flush>
        <div className="filters filter-bar">
          <FilterInput value={q} onCommit={(v) => setQuery({ q: v })} placeholder="Search IP, name, process, SNI, host, ASN…" label="Free-text filter" className="input-wide" />
          <FilterInput value={ip} onCommit={(v) => setQuery({ ip: v })} placeholder="Exact IP" label="IP filter" className="input-narrow" />
          <FilterInput value={portRaw} onCommit={(v) => setQuery({ port: v })} placeholder="Port" label="Port filter" className="input-port" type="text" />
          <FilterInput value={process} onCommit={(v) => setQuery({ process: v })} placeholder="Process, container or unit" label="Process filter" className="input-narrow" />
          <Segmented
            label="Direction"
            value={dir === "in" || dir === "out" ? dir : ""}
            onChange={(v) => setQuery({ dir: v })}
            options={[
              { value: "", label: "Both" },
              { value: "in", label: "← In" },
              { value: "out", label: "Out →" },
            ]}
          />
          <Select label="Interface" value={iface} onChange={(v) => setQuery({ iface: v })} options={ifaceOptions} />
          <Select
            label="Protocol"
            value={proto}
            onChange={(v) => setQuery({ proto: v })}
            options={[
              { value: "", label: "Any proto" },
              { value: "tcp", label: "TCP" },
              { value: "udp", label: "UDP" },
              { value: "icmp", label: "ICMP" },
            ]}
          />
          {filtered && (
            <button type="button" className="link-btn" onClick={() => setQuery({ q: null, ip: null, port: null, process: null, dir: null, iface: null, proto: null })}>
              Clear filters
            </button>
          )}
          <span className="spacer" />
          <Segmented label="Row limit" value={String(limit)} options={["500", "2000", "5000"].map((v) => ({ value: v, label: v }))} onChange={(v) => setQuery({ limit: v === "500" ? null : v })} />
        </div>
        {rows.length > 0 && (
          <div className={`scroll-x ${res.stale ? "dim" : ""}`}>
            <FlowsTable rows={rows} mode={mode} sort={sort} onSort={(k) => setQuery({ sort: k === "bytes" ? null : k })} onProcess={setProcess} />
          </div>
        )}
        <PanelState
          loading={res.loading}
          error={res.error}
          empty={!rows.length && !res.stale}
          emptyText={filtered ? "No flows match the filters." : view === "active" ? "No open conversations right now." : "No flows in this window."}
        />
        {rows.length > 0 && (
          <div className="table-foot muted small">
            {fmtInt(rows.length)} flow{rows.length === 1 ? "" : "s"}
            {rows.length >= limit ? ` (limit ${limit}; refine the filters or raise the limit)` : ""}
            {res.updatedAt ? (
              <>
                {" "}
                · updated <RelTime ts={res.updatedAt / 1000} />
              </>
            ) : null}
          </div>
        )}
      </Card>

      <ConnEventsCard window={win} kind={evKind} onKind={(k) => setQuery({ ev: k === "all" ? null : k })} onProcess={setProcess} />
    </div>
  );
}
