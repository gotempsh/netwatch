import { useMemo } from "react";
import type { SourceDetail as Detail } from "../api/types";
import { usePoll } from "../api/client";
import { TimeChart, type ChartSeries } from "../components/charts";
import { BanExpiry, BanSourceBadge, ProposalList, banCmd, unbanCmd } from "../components/domain";
import { AlertsTable } from "./Alerts";
import { SshTable } from "./Ssh";
import { Badge, Card, Command, Empty, Flag, KindChip, PanelState, RelTime, ScoreMeter, SourceFlags } from "../components/ui";
import { useNow } from "../lib/clock";
import { fmtBits, fmtBytes, fmtCompact, fmtDayHour, fmtInt, fmtRate, hourToTs } from "../lib/format";
import { href } from "../lib/router";
import { FlowsTable } from "./Connections";

function KV({ k, children }: { k: string; children: React.ReactNode }) {
  return (
    <>
      <dt>{k}</dt>
      <dd>{children}</dd>
    </>
  );
}

function HistoryChart({ d }: { d: Detail }) {
  const now = useNow();
  const hourNow = Math.floor(now / 3600);
  const { x, series } = useMemo(() => {
    // Fill the full 7-day hourly grid; hours with no row are zero.
    const end = hourNow * 3600;
    const start = end - 167 * 3600;
    const byHour = new Map(d.history.map((h) => [Math.floor(hourToTs(h.hour) / 3600) * 3600, h]));
    const x: number[] = [];
    const inP: number[] = [];
    const syn: number[] = [];
    const blk: number[] = [];
    for (let t = start; t <= end; t += 3600) {
      const h = byHour.get(t);
      x.push(t);
      inP.push(h?.in_packets ?? 0);
      syn.push(h?.syn ?? 0);
      blk.push(h?.blocked ?? 0);
    }
    const series: ChartSeries[] = [
      { key: "in", label: "Inbound packets", slot: 2, values: inP },
      { key: "syn", label: "SYN", slot: 3, values: syn },
      { key: "blocked", label: "Blocked", slot: 4, values: blk },
    ];
    return { x, series };
  }, [d.history, hourNow]);
  const peak = d.history.reduce((m, h) => Math.max(m, h.max_score), 0);
  return (
    <Card title="Last 7 days" sub={`Packets per hour · peak hourly score ${peak}`}>
      {d.history.length ? (
        <TimeChart x={x} series={series} yFormat={fmtCompact} xFormat={fmtDayHour} height={160} ariaLabel={`Hourly inbound, SYN and blocked packets for ${d.ip}, last 7 days`} />
      ) : (
        <Empty>No hourly history yet.</Empty>
      )}
    </Card>
  );
}

function ConnectionsSection({ d }: { d: Detail }) {
  const flows = d.flows ?? [];
  const names = d.dns_names ?? [];
  const active = flows.filter((f) => f.active).length;
  return (
    <Card
      title={`Connections (${flows.length})`}
      sub={`${active} active · finished flows from the last 7 days, newest first`}
      flush
      actions={
        <a className="small" href={href("/connections", { view: "all", ip: d.ip, window: "7d" })}>
          Open in Connections
        </a>
      }
    >
      <div className="dns-names">
        <span className="muted small">DNS names: </span>
        {names.length ? (
          names.map((n) => (
            <span key={n} className="chip mono" title="This IP was resolved from this name (DNS answers seen by netwatch)">
              {n}
            </span>
          ))
        ) : (
          <span className="muted small">none seen</span>
        )}
      </div>
      {flows.length ? (
        <div className="scroll-y scroll-x" style={{ maxHeight: 480 }}>
          <FlowsTable rows={flows} mode="all" />
        </div>
      ) : (
        <Empty>No conversations recorded with this IP.</Empty>
      )}
    </Card>
  );
}

export default function SourceDetail({ ip }: { ip: string }) {
  const res = usePoll<Detail>(`/api/sources/${encodeURIComponent(ip)}`, 10_000);
  const d = res.stale ? undefined : res.data;

  if (!d) {
    const notFound = res.error?.status === 404;
    return (
      <div className="page">
        <p className="crumbs">
          <a href="#/sources">Sources</a> /
        </p>
        <h1 className="mono">{ip}</h1>
        {notFound ? (
          <Card>
            <Empty>This IP is not tracked by the daemon (no traffic seen, or it aged out).</Empty>
            <div className="hint-row">
              <span className="muted small">To ban it anyway, run on the server:</span>
              <Command cmd={banCmd(ip)} />
            </div>
          </Card>
        ) : (
          <PanelState loading={!res.error} error={res.error} />
        )}
      </div>
    );
  }

  const g = d.geo;
  const listening = d.port_touches.filter((p) => p.listening).length;
  return (
    <div className="page">
      <p className="crumbs">
        <a href="#/sources">Sources</a> /
      </p>
      <div className="page-head">
        <h1 className="mono detail-ip">
          <Flag cc={g.country_code} title={g.country} /> {d.ip}
        </h1>
        <SourceFlags banned={d.banned} allowlisted={d.allowlisted} feeds={d.feeds} />
        <span className="muted small">
          first seen <RelTime ts={d.first_seen} /> · last seen <RelTime ts={d.last_seen} />
        </span>
      </div>

      <div className="grid-3">
        <Card title="Location & network">
          <dl className="kv">
            <KV k="Country">
              {g.country ? (
                <>
                  <Flag cc={g.country_code} /> {g.country} <span className="muted">({g.country_code})</span>
                </>
              ) : (
                <span className="muted">unknown</span>
              )}
            </KV>
            <KV k="City">{g.city ?? <span className="muted">–</span>}</KV>
            <KV k="Coordinates">{g.lat != null && g.lon != null ? <span className="mono">{g.lat.toFixed(2)}, {g.lon.toFixed(2)}</span> : <span className="muted">–</span>}</KV>
            <KV k="ASN">{g.asn ? <span className="mono">AS{g.asn}</span> : <span className="muted">–</span>}</KV>
            <KV k="Organisation">{g.as_org ?? <span className="muted">–</span>}</KV>
          </dl>
        </Card>

        <Card title="Score & findings">
          <div className="score-row">
            <ScoreMeter score={d.score} wide />
          </div>
          {d.findings.length ? (
            <ul className="finding-list">
              {d.findings.map((f) => (
                <li key={f.kind}>
                  <KindChip kind={f.kind} score={f.score} />
                  <span className="num muted">{f.score}</span>
                  <span>{f.summary}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">No findings.</p>
          )}
          <div className="feeds">
            <span className="muted small">Threat feeds: </span>
            {d.feeds.length === 0 && <span className="muted small">not listed</span>}
            {d.feed_hits?.length
              ? d.feed_hits.map((h) => (
                  <div key={h.name} className="feed-hit">
                    <Badge tone="serious">{h.name}</Badge>
                    {h.range && <span className="mono small" title="The listed range that contains this address">{h.range}</span>}
                    {h.about && <span className="muted small">{h.about}</span>}
                  </div>
                ))
              : d.feeds.map((f) => <Badge key={f} tone="serious">{f}</Badge>)}
          </div>
        </Card>

        <Card title="Ban status">
          {d.ban ? (
            <>
              <dl className="kv">
                <KV k="Target">
                  <span className="mono">{d.ban.target}</span>
                </KV>
                <KV k="Source">
                  <BanSourceBadge source={d.ban.source} />
                </KV>
                <KV k="Created">
                  <RelTime ts={d.ban.created} />
                </KV>
                <KV k="Expires">
                  <BanExpiry ban={d.ban} />
                </KV>
                {d.ban.dropped > 0 || !d.ban.matched ? <KV k="Dropped">{fmtInt(d.ban.dropped)} packets</KV> : <KV k="Matched">{fmtInt(d.ban.matched)} packets, not dropped (dry run)</KV>}
                <KV k="Reason">{d.ban.reason}</KV>
              </dl>
              <div className="hint-row">
                <span className="muted small">To lift the ban, run on the server:</span>
                <Command cmd={unbanCmd(d.ban.target)} />
              </div>
            </>
          ) : (
            <>
              <p className="muted">{d.banned ? "Covered by a ban on a wider range." : "Not banned."}</p>
              {d.allowlisted ? (
                <p className="small">
                  <Badge tone="good">allowlisted</Badge> Policy will never ban this source.
                </p>
              ) : (
                !d.banned && (
                  <div className="hint-row">
                    <span className="muted small">To ban it, run on the server:</span>
                    <Command cmd={banCmd(d.ip)} />
                  </div>
                )
              )}
            </>
          )}
        </Card>
      </div>

      <Card title="Traffic counters" className="counters">
        <dl className="kv kv-grid">
          <KV k="Inbound">
            {fmtInt(d.in_packets)} pkts · {fmtBytes(d.in_bytes)}
          </KV>
          <KV k="Total">
            {fmtInt(d.packets)} pkts · {fmtBytes(d.bytes)}
          </KV>
          <KV k="SYN">{fmtInt(d.syn)}</KV>
          <KV k="UDP in">{fmtInt(d.udp_in)}</KV>
          <KV k="ICMP in">{fmtInt(d.icmp_in)}</KV>
          <KV k="Blocked">{fmtInt(d.blocked)}</KV>
          <KV k="Rate now">
            {fmtRate(d.rate.in_pps, " pps")} · {fmtBits(d.rate.in_bps)} · {fmtRate(d.rate.syn_ps, " SYN/s")}
          </KV>
          <KV k="SSH">
            {fmtInt(d.ssh.failed)} failed · {fmtInt(d.ssh.invalid_users)} invalid users · {fmtInt(d.ssh.accepted)} accepted
          </KV>
        </dl>
      </Card>

      <HistoryChart d={d} />

      <ConnectionsSection d={d} />

      <div className="grid-2">
        <Card title={`Ports touched (${d.port_touches.length})`} sub={listening ? `${listening} hit a listening service` : "None hit a listening service"} flush>
          {d.port_touches.length ? (
            <div className="scroll-y" style={{ maxHeight: 420 }}>
              <table className="tbl tbl-compact">
                <thead>
                  <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>State</th>
                    <th className="num">Packets</th>
                    <th className="num">SYN</th>
                    <th>First</th>
                    <th>Last</th>
                  </tr>
                </thead>
                <tbody>
                  {d.port_touches.map((p) => (
                    <tr key={`${p.proto}/${p.port}`} className={p.listening ? "row-listening" : "row-closed"}>
                      <td className="mono">
                        {p.port}/{p.proto}
                      </td>
                      <td>{p.service ?? <span className="muted">–</span>}</td>
                      <td>{p.listening ? <Badge tone="serious">listening</Badge> : <span className="muted small">closed</span>}</td>
                      <td className="num">{fmtInt(p.packets)}</td>
                      <td className="num">{fmtInt(p.syn)}</td>
                      <td className="nowrap">
                        <RelTime ts={p.first_seen} />
                      </td>
                      <td className="nowrap">
                        <RelTime ts={p.last_seen} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty>No port touches recorded.</Empty>
          )}
        </Card>
        <Card title={`SSH events (${d.ssh_events.length})`} flush>
          {d.ssh_events.length ? (
            <div className="scroll-y" style={{ maxHeight: 420 }}>
              <SshTable events={d.ssh_events} showIp={false} />
            </div>
          ) : (
            <Empty>No SSH activity from this source.</Empty>
          )}
        </Card>
      </div>

      <Card title={`Alerts (${d.alerts.length})`} flush>
        {d.alerts.length ? <AlertsTable alerts={d.alerts} showIp={false} /> : <Empty>No alerts.</Empty>}
      </Card>

      <Card title={`Proposals (${d.proposals.length})`}>
        {d.proposals.length ? <ProposalList proposals={d.proposals} showTarget={false} /> : <Empty>No proposals for this source.</Empty>}
      </Card>
      {res.updatedAt && (
        <p className="muted small footnote">
          Updated <RelTime ts={res.updatedAt / 1000} />.
        </p>
      )}
    </div>
  );
}
