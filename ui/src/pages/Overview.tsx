import { useMemo } from "react";
import type { Insight, Overview as OverviewData, ProbeEvent, Proposal } from "../api/types";
import { usePoll } from "../api/client";
import { TimeChart, type ChartSeries } from "../components/charts";
import { Sparkline, StatTile } from "../components/charts";
import { IfKindBadge, InsightList, ProposalList } from "../components/domain";
import { bansDrop, modeChip } from "../lib/mode";
import { Badge, Card, Flag, IpLink, PanelState, RelTime, LevelTag } from "../components/ui";
import { useNow } from "../lib/clock";
import { ccFromLocation, fmtAbsolute, fmtBits, fmtClockSec, fmtCompact, fmtDuration, fmtInt, fmtRate, fmtTcpFlags, pct } from "../lib/format";

const ATTACH_TITLE: Record<OverviewData["attach_mode"], string> = {
  driver: "Native driver mode",
  skb: "Generic (skb) mode: works everywhere, slower than native driver mode",
  capture: "Packets read with /dev/bpf; pf is unavailable, so bans are only counted",
  "capture+pf": "Packets read with /dev/bpf; bans dropped by pf (anchor com.apple/netwatch)",
};

function HeaderFact({ label, children, title }: { label: string; children: React.ReactNode; title?: string }) {
  return (
    <div className="fact" title={title}>
      <div className="fact-label">{label}</div>
      <div className="fact-value">{children}</div>
    </div>
  );
}

function StatusHeader({ o }: { o: OverviewData }) {
  const now = useNow();
  const mac = o.platform === "macos";
  const llm = o.llm;
  const used = pct(llm.tokens_today, llm.budget_tokens_day);
  return (
    <div className="status-header card">
      <HeaderFact label="Host">
        <span className="mono">{o.host}</span> <span className="muted small">v{o.version}</span>
      </HeaderFact>
      <HeaderFact label="Interface">
        <span className="mono">{o.interface}</span>
      </HeaderFact>
      <HeaderFact label={mac ? "Capture" : "XDP attach"} title={ATTACH_TITLE[o.attach_mode]}>
        <Badge tone={o.attach_mode === "driver" || o.attach_mode === "capture+pf" ? "good" : "warning"}>{o.attach_mode}</Badge>
      </HeaderFact>
      <HeaderFact label="Mode" title={modeChip(o).title}>
        <Badge tone={o.mode === "enforce" ? "critical" : "accent"}>{modeChip(o).label}</Badge>
      </HeaderFact>
      <HeaderFact label="Drop banned" title={`Whether ${mac ? "pf" : "XDP"} drops packets from banned sources`}>
        <Badge tone={o.drop_banned ? "good" : "muted"}>{o.drop_banned ? "yes" : "no"}</Badge>
      </HeaderFact>
      <HeaderFact label="Uptime" title={`Started ${fmtAbsolute(o.started_at)}`}>
        {fmtDuration(now - o.started_at)}
      </HeaderFact>
      <HeaderFact label="Feeds" title={o.feeds.map((f) => `${f.name}: ${fmtInt(f.entries)}${f.about ? ` — ${f.about}` : ""}`).join("\n") || "No threat feeds loaded"}>
        {o.feeds.length} <span className="muted small">({fmtCompact(o.feeds.reduce((a, f) => a + f.entries, 0))} entries)</span>
        {!o.geo_db && (
          <>
            {" "}
            <Badge tone="warning" title="GeoIP database missing: countries and ASNs unavailable">
              no GeoIP
            </Badge>
          </>
        )}
      </HeaderFact>
      {o.totals.events_lost > 0 && (
        <HeaderFact label="Events lost" title="Ring buffer events dropped by the kernel side">
          <Badge tone="warning">{fmtInt(o.totals.events_lost)}</Badge>
        </HeaderFact>
      )}
      <HeaderFact label="LLM" title={llm.base_url ?? undefined}>
        {llm.enabled ? (
          <span className="llm-fact">
            <span className="mono">{llm.model ?? "?"}</span>
            <span className="meter-track small" aria-hidden title={`${used.toFixed(0)}% of daily budget`}>
              <span className={`meter-fill ${used >= 90 ? "tone-critical" : used >= 70 ? "tone-warning" : ""}`} style={{ width: `${used}%` }} />
            </span>
            <span className="small">
              {fmtCompact(llm.tokens_today)} / {fmtCompact(llm.budget_tokens_day)} tok
            </span>
          </span>
        ) : (
          <Badge tone="muted">disabled</Badge>
        )}
      </HeaderFact>
    </div>
  );
}

function FlowsCard({ o }: { o: OverviewData }) {
  const mac = o.platform === "macos";
  const f = o.flows;
  const trend = useMemo(() => (f?.series ?? []).map((m) => m.new_in + m.new_out), [f?.series]);
  if (!f) return null;
  return (
    <Card
      title="Connections"
      sub="Open conversations on monitored interfaces"
      actions={
        <a href="#/connections" className="small">
          All connections
        </a>
      }
    >
      <div className="fact-row">
        <HeaderFact label="Active flows" title={`${fmtInt(f.tcp)} TCP · ${fmtInt(f.udp)} UDP`}>
          <a href="#/connections">{fmtInt(f.active)}</a>{" "}
          <span className="muted small">
            <a href="#/connections?dir=in">← {fmtInt(f.in)} in</a> · <a href="#/connections?dir=out">{fmtInt(f.out)} out →</a>
          </span>
        </HeaderFact>
        <HeaderFact label="Rate in / out" title="Summed over active flows">
          {fmtBits(f.rate_in_bps)} <span className="muted">/</span> {fmtBits(f.rate_out_bps)}
        </HeaderFact>
        <HeaderFact label="Exposed listeners" title="Listening on a non-loopback address (ephemeral UDP excluded)">
          <a href="#/listeners?exposed=1">{fmtInt(f.listeners)}</a>
        </HeaderFact>
        {f.sock_events_lost > 0 && (
          <HeaderFact label="Socket events lost" title="Tracepoint events dropped by the kernel side; some flows may lack process attribution">
            <Badge tone="warning">{fmtInt(f.sock_events_lost)}</Badge>
          </HeaderFact>
        )}
      </div>
      {trend.length > 1 && (
        <div className="fact-spark" title="New flows per minute, last 60 minutes">
          <Sparkline values={trend} label="New flows per minute, last 60 minutes" />
        </div>
      )}
      {o.interfaces?.length > 0 && (
        <div className="scroll-x tbl-inset">
          <table className="tbl tbl-compact">
            <thead>
              <tr>
                <th>Interface</th>
                <th>Kind</th>
                <th>Monitoring</th>
                <th className="num">RX</th>
                <th className="num">TX</th>
              </tr>
            </thead>
            <tbody>
              {o.interfaces.map((i) => (
                <tr key={i.name}>
                  <td className="mono">
                    <a href={`#/connections?iface=${encodeURIComponent(i.name)}`}>{i.name}</a>
                  </td>
                  <td>
                    <IfKindBadge kind={i.kind} />
                  </td>
                  <td className="small">{[i.xdp ? (mac ? "accounting" : "XDP") : null, i.flows ? "flows" : null].filter(Boolean).join(" + ") || <span className="muted">–</span>}</td>
                  <td className="num">{fmtBits(i.rx_bps)}</td>
                  <td className="num">{fmtBits(i.tx_bps)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="card-foot-link small">
        <a href="#/interfaces">Interface details</a>
      </div>
    </Card>
  );
}

function LiveFeed() {
  const ev = usePoll<ProbeEvent[]>("/api/events?limit=40", 3000);
  const rows = ev.data ?? [];
  return (
    <Card title="Live probe feed" sub="New (source, port) pairs, newest first" flush className="live-feed">
      <PanelState loading={ev.loading} error={ev.error} empty={!rows.length} emptyText="No probes yet." />
      {rows.length > 0 && (
        <div className="scroll-y feed-scroll">
          <table className="tbl tbl-compact">
            <thead>
              <tr>
                <th>Time</th>
                <th>Source</th>
                <th>Port</th>
                <th>Flags</th>
                <th className="num" title="IP TTL as received">TTL</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e, i) => (
                <tr key={`${e.ts}-${e.ip}-${e.port}-${i}`}>
                  <td className="mono muted nowrap" title={fmtAbsolute(e.ts)}>
                    {fmtClockSec(e.ts)}
                  </td>
                  <td className="feed-src">
                    <span className="nowrap">
                      <Flag cc={ccFromLocation(e.location)} title={e.location} /> <IpLink ip={e.ip} />
                    </span>
                    <div className="muted small ellipsis" title={e.location}>
                      {e.location}
                    </div>
                  </td>
                  <td className="mono nowrap">
                    {e.port}/{e.proto}
                    {e.service && <div className="muted small">{e.service}</div>}
                  </td>
                  <td className="mono small">{e.proto === "tcp" ? fmtTcpFlags(e.tcp_flags) : "–"}</td>
                  <td className="num">{e.ttl}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

export default function Overview() {
  const ov = usePoll<OverviewData>("/api/overview", 5000);
  const ins = usePoll<Insight[]>("/api/insights", 15_000);
  const props = usePoll<Proposal[]>("/api/proposals?status=pending", 10_000);
  const o = ov.data;
  // A proposal an insight already carries (its approve command is the insight's action) shows once, there.
  const otherProps = (props.data ?? []).filter((p) => !ins.data?.some((i) => i.action === p.approve_cmd));

  const s = o?.series ?? [];
  const x = useMemo(() => s.map((p) => p.ts), [s]);
  const volume: ChartSeries[] = useMemo(
    () => [
      { key: "pps", label: "All packets", slot: 1, values: s.map((p) => p.pps) },
      { key: "in_pps", label: "Inbound", slot: 2, values: s.map((p) => p.in_pps) },
    ],
    [s],
  );
  const hostile: ChartSeries[] = useMemo(
    () => [
      { key: "syn_pps", label: "SYN", slot: 3, values: s.map((p) => p.syn_pps) },
      { key: "dropped_pps", label: "Dropped", slot: 4, values: s.map((p) => p.dropped_pps) },
    ],
    [s],
  );
  const tail = (k: "in_pps" | "syn_pps" | "dropped_pps") => s.slice(-36).map((p) => p[k]);
  const ppsFmt = (n: number) => fmtCompact(n);

  if (!o) {
    return (
      <div className="page">
        <h1>Overview</h1>
        <PanelState loading={ov.loading} error={ov.error} />
        {ov.error && <div className="empty">Waiting for the daemon…</div>}
      </div>
    );
  }

  const c = o.counts;
  return (
    <div className="page">
      <StatusHeader o={o} />

      <div className="tiles">
        <StatTile label="Inbound packets/s" value={fmtCompact(o.rates.in_pps)} context={`${fmtCompact(o.rates.pps)} pps total · ${fmtBits(o.rates.bps)}`} trend={tail("in_pps")} />
        <StatTile label="SYN/s" value={fmtCompact(o.rates.syn_pps)} context={`${fmtCompact(o.totals.syn)} since start`} trend={tail("syn_pps")} />
        <StatTile
          label="Dropped/s"
          value={fmtCompact(o.rates.dropped_pps)}
          context={bansDrop(o) ? `${fmtCompact(o.totals.dropped)} since start` : "bans counted, not dropped"}
          trend={tail("dropped_pps")}
        />
        <StatTile label="Active sources (10m)" value={fmtCompact(c.sources_active_10m)} context={`${fmtCompact(c.sources_tracked)} tracked`} href="#/sources?sort=last_seen" />
        <StatTile label="Flagged sources" value={fmtCompact(c.flagged)} context="score above 0" href="#/sources?flagged=1" />
        <StatTile label="Active bans" value={fmtCompact(c.bans_active)} context={`${fmtCompact(o.totals.blocked)} pkts matched`} href="#/bans" />
        <StatTile label="Pending proposals" value={fmtCompact(c.proposals_pending)} status={c.proposals_pending > 0 ? <LevelTag level="warn" label="Needs review" /> : undefined} context={c.proposals_pending > 0 ? undefined : "none"} href="#/bans" />
        <StatTile label="SSH failures (1h)" value={fmtCompact(c.ssh_failed_1h)} context="failed + invalid user" href="#/ssh" />
      </div>

      <div className="grid-2">
        <Card title="Packets per second" sub="All packets vs inbound, last 30 minutes">
          <TimeChart x={x} series={volume} yFormat={ppsFmt} xFormat={fmtClockSec} height={170} ariaLabel="Packets per second, all versus inbound, last 30 minutes" dim={ov.stale} />
        </Card>
        <Card title="SYN and dropped per second" sub="Last 30 minutes">
          <TimeChart x={x} series={hostile} yFormat={ppsFmt} xFormat={fmtClockSec} height={170} ariaLabel="SYN and dropped packets per second, last 30 minutes" dim={ov.stale} />
        </Card>
      </div>

      <div className="grid-2 grid-wide-left">
        <div className="stack">
          <Card title="Insights" sub="What the daemon thinks deserves attention">
            <PanelState loading={ins.loading} error={ins.error} empty={!ins.data?.length} emptyText="No insights right now." />
            {ins.data && ins.data.length > 0 && <InsightList insights={ins.data} />}
          </Card>
          <Card
            title={otherProps.length < (props.data?.length ?? 0) ? `Other pending proposals${otherProps.length ? ` (${otherProps.length})` : ""}` : `Pending proposals${otherProps.length ? ` (${otherProps.length})` : ""}`}
            sub="Approve on the server with the command shown"
            actions={
              <a href="#/bans" className="small">
                All proposals
              </a>
            }
          >
            <PanelState loading={props.loading} error={props.error} empty={!otherProps.length} emptyText={props.data?.length ? "The only pending proposal is in the insights above." : "Nothing waiting for a decision."} />
            {otherProps.length > 0 && <ProposalList proposals={otherProps} />}
          </Card>
        </div>
        <div className="stack">
          <FlowsCard o={o} />
          <LiveFeed />
        </div>
      </div>

      <p className="muted small footnote">
        Totals since start: {fmtInt(o.totals.packets)} packets ({fmtCompact(o.totals.in_packets)} inbound), {fmtRate(o.rates.pps, " pps")} now. Updated <RelTime ts={o.now} />.
      </p>
    </div>
  );
}
