import type { InterfacesInfo, IfStat } from "../api/types";
import { interfacesPath, usePoll } from "../api/client";
import { Check, IfKindBadge } from "../components/domain";
import { Badge, Card, Empty, PanelState, RelTime } from "../components/ui";
import { fmtBits, fmtBytes, fmtCompact, fmtInt, fmtRate } from "../lib/format";
import { href } from "../lib/router";

function Attachments({ i }: { i: Pick<IfStat, "xdp" | "flows"> }) {
  if (!i.xdp && !i.flows) return <span className="muted small">not monitored</span>;
  return (
    <span className="chips">
      {i.xdp && (
        <Badge tone="accent" title="XDP program: packet accounting, detections and bans">
          XDP
        </Badge>
      )}
      {i.flows && (
        <Badge tone="good" title="TC flow programs: every conversation recorded">
          flows
        </Badge>
      )}
    </span>
  );
}

function errTitle(i: IfStat) {
  return `rx dropped ${fmtInt(i.rx_dropped)} · tx dropped ${fmtInt(i.tx_dropped)}\nrx errors ${fmtInt(i.rx_errors)} · tx errors ${fmtInt(i.tx_errors)}`;
}

export default function Interfaces() {
  const res = usePoll<InterfacesInfo>(interfacesPath(), 5000);
  const d = res.data;
  const list = d?.interfaces ?? [];
  const maxRate = Math.max(0, ...list.map((i) => i.rx_bps + i.tx_bps));

  return (
    <div className="page">
      <div className="page-head">
        <h1>Interfaces & sensor</h1>
      </div>
      {!d && <PanelState loading={res.loading} error={res.error} />}
      {d && (
        <div className={`stack ${res.stale ? "dim" : ""}`}>
          <Card flush title="Interfaces" sub="Throughput from kernel counters; flows are counted per interface they were seen on">
            {list.length ? (
              <div className="scroll-x">
                <table className="tbl tbl-hover if-tbl">
                  <thead>
                    <tr>
                      <th>Interface</th>
                      <th>Kind</th>
                      <th>State</th>
                      <th>Monitoring</th>
                      <th>MAC</th>
                      <th>Addresses</th>
                      <th className="bar-col">RX + TX</th>
                      <th className="num">RX</th>
                      <th className="num">TX</th>
                      <th className="num">Total RX / TX</th>
                      <th className="num" title="Dropped + errors, both directions">
                        Drops / errors
                      </th>
                      <th className="num">Active flows</th>
                    </tr>
                  </thead>
                  <tbody>
                    {list.map((i) => {
                      const drops = i.rx_dropped + i.tx_dropped;
                      const errs = i.rx_errors + i.tx_errors;
                      const rate = i.rx_bps + i.tx_bps;
                      const w = maxRate > 0 ? Math.max(rate > 0 ? 1.5 : 0, (rate / maxRate) * 100) : 0;
                      return (
                        <tr key={i.name} className={i.up ? "" : "row-closed"}>
                          <td className="nowrap">
                            <span className="mono">{i.name}</span> <span className="muted small">#{i.ifindex}</span>
                          </td>
                          <td>
                            <IfKindBadge kind={i.kind} />
                          </td>
                          <td>{i.up ? <Badge tone="good">up</Badge> : <Badge tone="muted">down</Badge>}</td>
                          <td>
                            <Attachments i={i} />
                          </td>
                          <td className="mono small nowrap">{i.mac ?? <span className="muted">–</span>}</td>
                          <td className="mono small addr-cell">
                            {i.addrs.length ? (
                              i.addrs.map((a) => (
                                <div key={a} className="ellipsis" title={a}>
                                  {a}
                                </div>
                              ))
                            ) : (
                              <span className="muted">–</span>
                            )}
                          </td>
                          <td>
                            <span className="barcell" title={fmtBits(rate)}>
                              <span className="barcell-track" aria-hidden>
                                <span className="barcell-fill" style={{ width: `${w}%` }} />
                              </span>
                            </span>
                          </td>
                          <td className="num" title={fmtRate(i.rx_pps, " pps")}>
                            {fmtBits(i.rx_bps)}
                          </td>
                          <td className="num" title={fmtRate(i.tx_pps, " pps")}>
                            {fmtBits(i.tx_bps)}
                          </td>
                          <td className="num" title={`${fmtInt(i.rx_packets)} packets received · ${fmtInt(i.tx_packets)} sent`}>
                            {fmtBytes(i.rx_bytes)} <span className="muted">/</span> {fmtBytes(i.tx_bytes)}
                          </td>
                          <td className="num" title={errTitle(i)}>
                            {drops || errs ? (
                              <span className={errs ? "error-text" : ""}>
                                {fmtCompact(drops)} / {fmtCompact(errs)}
                              </span>
                            ) : (
                              <span className="muted">0 / 0</span>
                            )}
                          </td>
                          <td className="num">
                            {i.active_flows > 0 ? <a href={href("/traffic/connections", { iface: i.name })}>{fmtInt(i.active_flows)}</a> : <span className="muted">{i.flows ? "0" : "–"}</span>}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <Empty>No interfaces reported.</Empty>
            )}
          </Card>

          <div className="grid-3">
            <Card title="Kernel programs">
              <dl className="kv">
                <dt>Flow programs (TC)</dt>
                <dd>
                  <Check ok={d.flow_programs} /> {d.flow_programs ? "loaded" : <span className="error-text">not loaded: flows are not recorded</span>}
                </dd>
                <dt>XDP interface</dt>
                <dd className="mono">{list.find((i) => i.xdp)?.name ?? <span className="muted">none</span>}</dd>
              </dl>
            </Card>
            <Card title="Tracepoints" sub="TCP state and socket events for process attribution">
              {d.tracepoints.length ? (
                <ul className="check-list">
                  {d.tracepoints.map((t) => (
                    <li key={t.name}>
                      <Check ok={t.attached} label={t.attached ? "attached" : "failed to attach"} />
                      <span className="mono">{t.name}</span>
                      {!t.attached && <span className="muted small">not attached</span>}
                    </li>
                  ))}
                </ul>
              ) : (
                <Empty>No tracepoints configured.</Empty>
              )}
            </Card>
            <Card title="Configuration" sub="flow_interfaces patterns and payload sampling">
              <dl className="kv">
                <dt>Patterns</dt>
                <dd>
                  {d.patterns.length ? (
                    <span className="chips">
                      {d.patterns.map((p) => (
                        <span key={p} className="chip mono">
                          {p}
                        </span>
                      ))}
                    </span>
                  ) : (
                    <span className="muted">only the XDP interface</span>
                  )}
                </dd>
                <dt>DNS sampling</dt>
                <dd>
                  <Check ok={d.sample_dns} /> {d.sample_dns ? "on: queries logged, remotes named" : "off"}
                </dd>
                <dt>TCP payload sampling</dt>
                <dd>
                  <Check ok={d.sample_tcp_payload} /> {d.sample_tcp_payload ? "on: TLS SNI, HTTP and SSH banners" : "off"}
                </dd>
              </dl>
            </Card>
          </div>
          {res.updatedAt && (
            <p className="muted small footnote">
              Updated <RelTime ts={res.updatedAt / 1000} />.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
