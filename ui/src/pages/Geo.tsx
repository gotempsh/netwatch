import type { Summary } from "../api/types";
import { usePoll } from "../api/client";
import { Badge, BarCell, Card, Flag, IpLink, Location, PanelState, RelTime, ScoreMeter, Segmented } from "../components/ui";
import { fmtBytes, fmtCompact, fmtInt, hourToTs } from "../lib/format";
import { useQueryState } from "../lib/router";

type Win = "1h" | "24h" | "7d";

export default function Geo() {
  const [query, setQuery] = useQueryState();
  const w = query.get("window");
  const win: Win = w === "1h" || w === "7d" ? w : "24h";
  const res = usePoll<Summary>(`/api/summary?window=${win}`, 30_000);
  const s = res.data;
  const dim = res.stale ? "dim" : "";

  const maxC = Math.max(0, ...(s?.countries ?? []).map((c) => c.sources));
  const maxA = Math.max(0, ...(s?.asns ?? []).map((a) => a.sources));
  const maxP = Math.max(0, ...(s?.ports ?? []).map((p) => p.sources));

  return (
    <div className="page">
      <div className="page-head">
        <h1>Countries & networks</h1>
        <div className="filters">
          <Segmented<Win>
            label="Window"
            value={win}
            onChange={(v) => setQuery({ window: v === "24h" ? null : v })}
            options={[
              { value: "1h", label: "Last hour" },
              { value: "24h", label: "24 hours" },
              { value: "7d", label: "7 days" },
            ]}
          />
        </div>
      </div>
      {!s && <PanelState loading={res.loading} error={res.error} />}
      {s && (
        <div className={`stack ${dim}`}>
          <div className="grid-2">
            <Card title="Countries" sub="Bars: distinct sources" flush>
              <div className="scroll-y" style={{ maxHeight: 460 }}>
                <table className="tbl tbl-compact">
                  <thead>
                    <tr>
                      <th>Country</th>
                      <th className="bar-col">Sources</th>
                      <th className="num">Flagged</th>
                      <th className="num">SYN</th>
                      <th className="num">Inbound pkts</th>
                    </tr>
                  </thead>
                  <tbody>
                    {s.countries.map((c) => (
                      <tr key={c.country_code}>
                        <td className="nowrap">
                          <Flag cc={c.country_code} title={c.country} /> {c.country} <span className="muted small">{c.country_code}</span>
                        </td>
                        <td>
                          <BarCell value={c.sources} max={maxC} label={fmtInt(c.sources)} />
                        </td>
                        <td className="num">{c.flagged ? fmtInt(c.flagged) : <span className="muted">0</span>}</td>
                        <td className="num">{fmtCompact(c.syn)}</td>
                        <td className="num">{fmtCompact(c.in_packets)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
            <Card title="Networks (ASN)" sub="Bars: distinct sources" flush>
              <div className="scroll-y" style={{ maxHeight: 460 }}>
                <table className="tbl tbl-compact">
                  <thead>
                    <tr>
                      <th>ASN</th>
                      <th>Organisation</th>
                      <th className="bar-col">Sources</th>
                      <th className="num">Flagged</th>
                      <th className="num">SYN</th>
                    </tr>
                  </thead>
                  <tbody>
                    {s.asns.map((a) => (
                      <tr key={a.asn}>
                        <td className="mono">
                          <a href={`#/threats/sources?q=${encodeURIComponent(`AS${a.asn}`)}`}>AS{a.asn}</a>
                        </td>
                        <td className="ellipsis asn-cell" title={a.org}>
                          {a.org}
                        </td>
                        <td>
                          <BarCell value={a.sources} max={maxA} label={fmtInt(a.sources)} />
                        </td>
                        <td className="num">{a.flagged ? fmtInt(a.flagged) : <span className="muted">0</span>}</td>
                        <td className="num">{fmtCompact(a.syn)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          </div>
          <div className="grid-2 grid-wide-right">
            <Card title="Ports" sub="Listening services highlighted" flush>
              <div className="scroll-y" style={{ maxHeight: 520 }}>
                <table className="tbl tbl-compact">
                  <thead>
                    <tr>
                      <th>Port</th>
                      <th>Service</th>
                      <th>State</th>
                      <th className="bar-col">Sources</th>
                      <th className="num">SYN</th>
                    </tr>
                  </thead>
                  <tbody>
                    {s.ports.map((p) => (
                      <tr key={`${p.proto}/${p.port}`} className={p.listening ? "row-listening" : "row-closed"}>
                        <td className="mono">
                          {p.port}/{p.proto}
                        </td>
                        <td>{p.service ?? <span className="muted">–</span>}</td>
                        <td>{p.listening ? <Badge tone="serious">listening</Badge> : <span className="muted small">closed</span>}</td>
                        <td>
                          <BarCell value={p.sources} max={maxP} label={fmtInt(p.sources)} />
                        </td>
                        <td className="num">{fmtCompact(p.syn)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
            <Card title="Top sources by history" sub={`Hourly rollups over the ${win} window`} flush>
              <div className="scroll-y" style={{ maxHeight: 520 }}>
                <table className="tbl tbl-compact">
                  <thead>
                    <tr>
                      <th>IP</th>
                      <th>Location</th>
                      <th>Max score</th>
                      <th className="num">Inbound</th>
                      <th className="num">SYN</th>
                      <th className="num">Blocked</th>
                      <th className="num" title="Hours with activity">Hours</th>
                      <th>Last active</th>
                    </tr>
                  </thead>
                  <tbody>
                    {s.top_history.map((h) => (
                      <tr key={h.ip}>
                        <td>
                          <IpLink ip={h.ip} />
                        </td>
                        <td className="ellipsis loc-cell">
                          <Location text={h.location} />
                        </td>
                        <td>
                          <ScoreMeter score={h.max_score} />
                        </td>
                        <td className="num" title={`${fmtInt(h.in_packets)} packets`}>
                          {fmtBytes(h.in_bytes)}
                        </td>
                        <td className="num">{fmtCompact(h.syn)}</td>
                        <td className="num">{fmtCompact(h.blocked)}</td>
                        <td className="num">{fmtInt(h.hours)}</td>
                        <td className="nowrap">
                          <RelTime ts={hourToTs(h.last_hour)} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          </div>
        </div>
      )}
    </div>
  );
}
