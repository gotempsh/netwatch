import type { Listener } from "../api/types";
import { listenersPath, usePoll } from "../api/client";
import { ProcessCell } from "../components/domain";
import { Badge, Card, PanelState, RelTime } from "../components/ui";
import { fmtAbsolute, fmtDuration, fmtInt } from "../lib/format";
import { href, useQueryState } from "../lib/router";
import { NetworkTabs } from "./Interfaces";

function Exposure({ l }: { l: Listener }) {
  return l.exposed ? (
    <Badge tone="serious" title="Bound to a non-loopback address: reachable from the network (subject to the firewall)">
      exposed
    </Badge>
  ) : (
    <Badge tone="muted" title="Bound to loopback only">
      loopback only
    </Badge>
  );
}

export default function Listeners() {
  const [query, setQuery] = useQueryState();
  const showClients = query.get("clients") === "1";
  const exposedOnly = query.get("exposed") === "1";
  const res = usePoll<Listener[]>(listenersPath(), 10_000);
  const all = res.data ?? [];
  const hiddenClients = all.filter((l) => l.role === "client").length;
  const rows = all.filter((l) => (showClients || l.role !== "client") && (!exposedOnly || l.exposed));
  const exposed = all.filter((l) => l.exposed && l.role !== "client").length;

  return (
    <div className="page">
      <div className="page-head">
        <h1>Network</h1>
        <NetworkTabs active="listeners" />
        <span className="muted small">
          {fmtInt(all.length)} listening sockets · {fmtInt(exposed)} exposed
        </span>
        <div className="filters">
          <label className="toggle">
            <input type="checkbox" checked={exposedOnly} onChange={(e) => setQuery({ exposed: e.target.checked })} />
            Exposed only
          </label>
          <label className="toggle" title="UDP sockets seen sending DNS queries: resolver source ports, not services">
            <input type="checkbox" checked={showClients} onChange={(e) => setQuery({ clients: e.target.checked })} />
            Show DNS clients{hiddenClients ? ` (${hiddenClients})` : ""}
          </label>
        </div>
      </div>
      <Card flush>
        {rows.length > 0 && (
          <div className={`scroll-x ${res.stale ? "dim" : ""}`}>
            <table className="tbl tbl-hover">
              <thead>
                <tr>
                  <th>Port</th>
                  <th>Service</th>
                  <th>Exposure</th>
                  <th>Bound to</th>
                  <th>Process</th>
                  <th>Executable</th>
                  <th className="num" title="Active inbound flows to this port">
                    Active flows
                  </th>
                  <th className="num" title="Distinct remotes with an active inbound flow / of which public">
                    Remotes / public
                  </th>
                  <th>Listening for</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((l) => (
                  <tr key={`${l.proto}/${l.port}`} className={l.exposed ? "row-listening" : ""}>
                    <td className="mono nowrap">
                      {l.port}/{l.proto}
                      {l.proto === "udp" && l.role !== "unknown" && (
                        <>
                          {" "}
                          <Badge tone="muted" title={l.role_reason}>
                            {l.role}
                          </Badge>
                        </>
                      )}
                    </td>
                    <td>{l.service ?? <span className="muted">–</span>}</td>
                    <td>
                      <Exposure l={l} />
                    </td>
                    <td className="mono small addr-cell">
                      {l.addrs.length ? (
                        l.addrs.map((a) => (
                          <div key={a} className="ellipsis" title={a}>
                            {a}
                          </div>
                        ))
                      ) : (
                        <span className="muted">–</span>
                      )}
                    </td>
                    <td>
                      <ProcessCell process={l.process} container={l.container} unit={l.unit} pid={l.pid} exe={l.exe} />
                    </td>
                    <td className="mono small">
                      {l.exe ? (
                        <span className="trunc exe-cell" title={l.exe}>
                          {l.exe}
                        </span>
                      ) : (
                        <span className="muted">–</span>
                      )}
                    </td>
                    <td className="num">
                      {l.active_flows > 0 ? <a href={href("/connections", { port: l.port, proto: l.proto, dir: "in" })}>{fmtInt(l.active_flows)}</a> : <span className="muted">0</span>}
                    </td>
                    <td className="num">
                      {fmtInt(l.remotes)} <span className="muted">/</span> {l.public_remotes > 0 ? <strong>{fmtInt(l.public_remotes)}</strong> : <span className="muted">0</span>}
                    </td>
                    <td className="nowrap" title={`Since ${fmtAbsolute(l.since)}`}>
                      {fmtDuration(l.age_secs)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <PanelState loading={res.loading} error={res.error} empty={!rows.length} emptyText={all.length ? "No listeners match the filters." : "No listening sockets seen yet."} />
        {rows.length > 0 && (
          <div className="table-foot muted small">
            {fmtInt(rows.length)} shown
            {!showClients && hiddenClients > 0 ? ` · ${hiddenClients} DNS clients hidden` : ""}
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
