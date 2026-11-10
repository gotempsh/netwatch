import type { Destination, Destinations as DestinationsData, DestinationSort } from "../api/types";
import { destinationsPath, usePoll, type FlowWindow } from "../api/client";
import { Badge, Card, FilterInput, Flag, IpLink, PanelState, RelTime, Segmented, SortTh } from "../components/ui";
import { fmtAbsolute, fmtBytes, fmtInt } from "../lib/format";
import { href, useQueryState } from "../lib/router";
import { FLOW_WINDOWS, parseWindow } from "./Connections";

const SORTS: DestinationSort[] = ["flows", "bytes", "last", "first"];
/** Chips shown per cell before "+N". */
const SHOWN = 4;

function More({ items }: { items: string[] }) {
  const rest = items.length - SHOWN;
  return rest > 0 ? (
    <span className="muted small" title={items.slice(SHOWN).join("\n")}>
      +{rest}
    </span>
  ) : null;
}

function Row({ d, win }: { d: Destination; win: FlowWindow }) {
  const net = [d.asn ? `AS${d.asn}` : null, d.as_org].filter(Boolean).join(" ");
  const flowsHref = href("/traffic/connections", { view: "all", window: win, ip: d.remote, dir: "out" });
  return (
    <tr className={d.failed === d.flows ? "row-failed" : ""}>
      <td className="remote-col">
        <span className="remote-cell">
          <span className="nowrap">
            <Flag cc={d.country} title={net || undefined} /> <IpLink ip={d.remote} />
          </span>
          <span className="remote-sub small">
            {d.name ? (
              <span className="remote-name" title={d.name}>
                {d.name}
              </span>
            ) : (
              <Badge tone="warning" title="No DNS answer or TLS SNI named this address: it was reached by IP. Lookups netwatch can't see (DNS over HTTPS, names cached before it started) also end up here.">
                no name
              </Badge>
            )}
            {net && <span className="muted"> · {net}</span>}
          </span>
        </span>
      </td>
      <td>
        <span className="chips">
          {d.ports.slice(0, SHOWN).map((p) => (
            <span key={p} className="mono small">
              {p}
            </span>
          ))}
          <More items={d.ports} />
        </span>
      </td>
      <td className="proc-col">
        <span className="chips">
          {d.processes.slice(0, SHOWN).map((p) => (
            <a key={p} className="proc-link mono small" href={href("/traffic/connections", { view: "all", window: win, ip: d.remote, dir: "out", process: p === "unknown" ? null : p.split("/")[0] })} title={`Connections from ${p} to ${d.remote}`}>
              {p}
            </a>
          ))}
          <More items={d.processes} />
        </span>
      </td>
      <td className="num">
        <a href={flowsHref} title="Show these connections">
          {fmtInt(d.flows)}
        </a>
        {(d.active > 0 || d.failed > 0) && (
          <div className="small">
            {d.active > 0 && <span className="muted">{fmtInt(d.active)} open</span>}
            {d.active > 0 && d.failed > 0 && <span className="muted"> · </span>}
            {d.failed > 0 && <span className="error-text">{fmtInt(d.failed)} failed</span>}
          </div>
        )}
      </td>
      <td className="num bytes-cell">
        <div>
          <span className="muted small">↑</span> {fmtBytes(d.bytes_out)}
        </div>
        <div>
          <span className="muted small">↓</span> {fmtBytes(d.bytes_in)}
        </div>
      </td>
      <td className="nowrap" title={fmtAbsolute(d.first_seen)}>
        <RelTime ts={d.first_seen} />
      </td>
      <td className="nowrap" title={fmtAbsolute(d.last_seen)}>
        {d.active > 0 ? <Badge tone="good">open</Badge> : <RelTime ts={d.last_seen} />}
      </td>
    </tr>
  );
}

export default function Destinations() {
  const [query, setQuery] = useQueryState();
  const win = parseWindow(query.get("window"), "24h");
  const scope = query.get("scope") === "all" ? "all" : "public";
  const unnamed = query.get("unnamed") === "1";
  const q = query.get("q") ?? "";
  const sortParam = query.get("sort") as DestinationSort | null;
  const sort: DestinationSort = sortParam && SORTS.includes(sortParam) ? sortParam : "flows";
  const limit = Number(query.get("limit")) || 500;

  const res = usePoll<DestinationsData>(destinationsPath({ window: win, scope, unnamed, q: q || null, sort, limit }), 15_000);
  const d = res.data;
  const rows = d?.rows ?? [];
  const h = (k: DestinationSort, label: string, title: string, align?: "left" | "right") => (
    <SortTh k={k} label={label} sort={sort} onSort={(v) => setQuery({ sort: v === "flows" ? null : v })} title={title} align={align} />
  );

  return (
    <div className="page">
      <div className="page-head">
        <h1>Destinations</h1>
        {d && (
          <span className="muted small">
            {fmtInt(d.destinations)} {scope === "public" ? "internet " : ""}addresses · {fmtInt(d.unnamed)} without a name
          </span>
        )}
        <div className="filters">
          <Segmented<FlowWindow> label="Time window" value={win} options={FLOW_WINDOWS} onChange={(v) => setQuery({ window: v === "24h" ? null : v })} />
        </div>
      </div>
      <p className="muted small page-note">
        Every address this host and its containers connected out to, one row per address. Click the count to see the connections.
      </p>

      <Card flush>
        <div className="filters filter-bar">
          <FilterInput value={q} onCommit={(v) => setQuery({ q: v })} placeholder="Search IP, name, network, port, process…" label="Free-text filter" className="input-wide" />
          <Segmented
            label="Scope"
            value={scope}
            onChange={(v) => setQuery({ scope: v === "public" ? null : v })}
            options={[
              { value: "public", label: "Internet" },
              { value: "all", label: "Incl. private" },
            ]}
          />
          <label className="toggle" title="Addresses no DNS answer or TLS SNI named: reached by IP">
            <input type="checkbox" checked={unnamed} onChange={(e) => setQuery({ unnamed: e.target.checked })} />
            No name only
          </label>
          <span className="spacer" />
          <Segmented label="Row limit" value={String(limit)} options={["500", "2000", "5000"].map((v) => ({ value: v, label: v }))} onChange={(v) => setQuery({ limit: v === "500" ? null : v })} />
        </div>
        {rows.length > 0 && (
          <div className={`scroll-x ${res.stale ? "dim" : ""}`}>
            <table className="tbl tbl-compact tbl-hover">
              <thead>
                <tr>
                  <th>Remote</th>
                  <th>Ports</th>
                  <th>Connected by</th>
                  {h("flows", "Connections", "Sort by number of connections", "right")}
                  {h("bytes", "Sent / received", "Sort by bytes in both directions", "right")}
                  {h("first", "First", "Sort by first connection (newest first)")}
                  {h("last", "Last", "Sort by last activity (newest first)")}
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <Row key={r.remote} d={r} win={win} />
                ))}
              </tbody>
            </table>
          </div>
        )}
        <PanelState
          loading={res.loading}
          error={res.error}
          empty={!rows.length && !res.stale}
          emptyText={q || unnamed ? "No destinations match the filters." : "No outbound connections in this window."}
        />
        {d && rows.length > 0 && (
          <div className="table-foot muted small">
            {fmtInt(rows.length)} of {fmtInt(d.matched)} destination{d.matched === 1 ? "" : "s"}
            {rows.length < d.matched ? ` (limit ${limit}; refine the filters or raise the limit)` : ""}
            {res.updatedAt ? (
              <>
                {" "}
                · updated <RelTime ts={res.updatedAt / 1000} />
              </>
            ) : null}
          </div>
        )}
      </Card>
    </div>
  );
}
