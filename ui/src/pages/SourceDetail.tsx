// One source as a story: the verdict (is it handled? did it get in?), its last
// seven days as a lane, what it did in sentences, and the raw tables behind
// disclosures for when you need the evidence.
import { useMemo, type ReactNode } from "react";
import type { SourceDetail as Detail, Overview, Source } from "../api/types";
import { usePoll } from "../api/client";
import { BanSourceBadge, ProposalList, banCmd, unbanCmd } from "../components/domain";
import { AlertsTable } from "./Alerts";
import { SshTable } from "./Ssh";
import { FlowsTable } from "./Connections";
import { Command, Empty, Flag, KindChip, PanelState, RelTime, kindLabel } from "../components/ui";
import { LaneLegend, Lanes, SevIcon, type Sev } from "../components/viz";
import { laneFor } from "../components/timeline";
import { useNow } from "../lib/clock";
import { fmtBits, fmtBytes, fmtDayHour, fmtDuration, fmtInt, fmtRate, fmtRelative } from "../lib/format";
import { bansDrop, banMatched, dryRun } from "../lib/mode";
import { href, sourceHref } from "../lib/router";
import { rowFromDetail } from "../lib/timeline";

function count<T>(xs: T[], key: (x: T) => string | null | undefined): [string, number][] {
  const m = new Map<string, number>();
  for (const x of xs) {
    const k = key(x);
    if (k) m.set(k, (m.get(k) ?? 0) + 1);
  }
  return [...m.entries()].sort((a, b) => b[1] - a[1]);
}

function Fact({ sev, title, children }: { sev: Sev; title: ReactNode; children?: ReactNode }) {
  return (
    <div className="fact">
      <SevIcon sev={sev} size={14} />
      <div>
        <b>{title}</b>
        {children && <span>{children}</span>}
      </div>
    </div>
  );
}

function Evidence({ title, sub, children }: { title: string; sub?: string; children: ReactNode }) {
  return (
    <details className="evidence">
      <summary>
        {title}
        {sub && <span>{sub}</span>}
      </summary>
      <div className="evidence-body">{children}</div>
    </details>
  );
}

function KV({ k, children }: { k: string; children: ReactNode }) {
  return (
    <>
      <dt>{k}</dt>
      <dd>{children}</dd>
    </>
  );
}

export default function SourceDetail({ ip }: { ip: string }) {
  const now = useNow();
  const res = usePoll<Detail>(`/api/sources/${encodeURIComponent(ip)}`, 10_000);
  const ov = usePoll<Overview>("/api/overview", 30_000);
  const d = res.stale ? undefined : res.data;
  const peers = usePoll<Source[]>(d?.geo.asn ? `/api/sources?q=as${d.geo.asn}&flagged=1&limit=20` : null, 60_000);

  const since = now - 7 * 86400;
  const row = useMemo(() => (d ? rowFromDetail(d, since) : null), [d, since]);

  if (!d || !row) {
    const notFound = res.error?.status === 404;
    return (
      <div className="page roomy">
        <a className="crumb" href="#/threats">
          Threats
        </a>
        <h1 className="src-ip">{ip}</h1>
        {notFound ? (
          <>
            <p className="muted">netwatch hasn't seen {ip}: no traffic, or it aged out after 7 days.</p>
            <div className="next">
              <span className="next-label">To ban it anyway, run on the server</span>
              <Command cmd={banCmd(ip)} />
            </div>
          </>
        ) : (
          <PanelState loading={!res.error} error={res.error} />
        )}
      </div>
    );
  }

  const drops = !ov.data || bansDrop(ov.data);
  const dry = ov.data ? dryRun(ov.data) : null;
  const top = [...d.findings].sort((a, b) => b.score - a.score)[0];
  const active = now - d.last_seen < 600;
  const pending = d.proposals.find((p) => p.status === "pending");
  const gotIn = d.ssh.accepted > 0;
  const sev: Sev = gotIn ? "critical" : d.banned && drops ? "ok" : d.score >= 60 ? "warn" : "ok";
  const what = top ? kindLabel(top.kind) : null;
  const title = gotIn
    ? `Logged in over SSH ${d.ssh.accepted === 1 ? "once" : `${d.ssh.accepted} times`}`
    : d.allowlisted
      ? "Allowlisted: never scored or banned"
      : d.ban
        ? `Banned ${fmtRelative(d.ban.created, now)}${what ? ` for ${what}` : ""}${active ? ", still trying" : ""}`
        : d.banned
          ? `Banned with its range${what ? ` for ${what}` : ""}`
          : pending
            ? `${what ?? "Flagged"}; a ${pending.action} is proposed and waits for you`
            : what
              ? `${what}, not banned`
              : "Nothing suspicious";
  const next = pending
    ? { label: `Approve the proposed ${pending.action} (#${pending.id})`, cmd: pending.approve_cmd }
    : d.ban && dry
      ? { label: `This ban only counts because ${dry.why}. ${dry.fix}`, cmd: dry.cmd }
      : !d.banned && !d.allowlisted && d.score >= 60
        ? { label: "To ban it, run on the server", cmd: banCmd(d.ip) }
        : null;

  const sshFlows = d.flows.filter((f) => f.app?.ssh_client);
  const clients = count(sshFlows, (f) => f.app?.ssh_client?.replace(/^SSH-2\.0-/, ""));
  const users = count(
    d.ssh_events.filter((e) => e.kind !== "accepted"),
    (e) => e.user,
  );
  const targets = count(d.flows, (f) => `${f.process ?? f.app?.proto ?? "?"} on ${f.local}:${f.lport}`);
  const peerList = (peers.data ?? []).filter((s) => s.ip !== d.ip && s.geo.asn === d.geo.asn);
  const lane = laneFor(row, drops);
  const synLane = { ...lane, key: `${d.ip}-syn`, label: <span className="muted small">SYN per hour</span>, side: null, events: [], ban: null, cells: row.hours.map((h) => ({ ts: h.hour, v: h.syn })) };
  const story = [
    { ts: d.first_seen, text: "First packet seen" },
    ...row.events.map((e) => ({ ts: e.ts, text: e.kind === "finding" && e.finding ? `${kindLabel(e.finding)} raised: ${e.label}` : e.label })),
    { ts: d.last_seen, text: "Last packet seen" },
  ]
    .filter((e) => e.ts > 0)
    .sort((a, b) => a.ts - b.ts);
  const listening = d.port_touches.filter((p) => p.listening).length;
  const where = [d.geo.city, d.geo.country].filter(Boolean).join(", ");

  return (
    <div className="page roomy">
      <div className="src-head">
        <a className="crumb" href="#/threats">
          Threats
        </a>
        <h1 className="src-ip">{d.ip}</h1>
        <p className="src-where">
          <Flag cc={d.geo.country_code} title={d.geo.country} /> {where || "Unknown location"}
          {d.geo.asn ? ` · AS${d.geo.asn} ${d.geo.as_org ?? ""}` : ""} · first seen <RelTime ts={d.first_seen} />
        </p>
      </div>

      <section className={`verdict sev-${sev} verdict-block`}>
        <div className="verdict-top">
          <div className="verdict-main">
            <SevIcon sev={sev} size={22} />
            <div>
              <h2 className="verdict-title">{title}</h2>
              <p className="verdict-sub">
                Score {d.score} · {d.findings.map((f) => kindLabel(f.kind)).join(", ") || "no findings"} · last packet <RelTime ts={d.last_seen} />
              </p>
            </div>
          </div>
          {(next || d.ban) && (
            <div className="next">
              {next && (
                <>
                  <span className="next-label">{next.label}</span>
                  <Command cmd={next.cmd} />
                </>
              )}
              {d.ban && (
                <span className="muted small">
                  To lift the ban: <span className="mono">{unbanCmd(d.ban.target)}</span>
                </span>
              )}
            </div>
          )}
        </div>
        <div className="facts">
          <Fact sev={gotIn ? "critical" : "ok"} title={gotIn ? `Got in: ${fmtInt(d.ssh.accepted)} accepted logins` : "Never got in"}>
            {fmtInt(d.ssh.failed)} failed logins, {fmtInt(d.ssh.invalid_users)} invalid users, {fmtInt(d.ssh.accepted)} accepted
          </Fact>
          {d.ban ? (
            <Fact sev={drops ? "ok" : "warn"} title={drops ? `Ban dropped ${fmtInt(d.ban.dropped)} packets` : `Ban matched ${fmtInt(banMatched(d.ban))} packets, dropped none`}>
              {d.ban.target !== d.ip ? `banned as part of ${d.ban.target} · ` : ""}
              {dry ? `${dry.why}, so they went through · ` : ""}
              {d.ban.expires ? `expires in ${fmtDuration(Math.max(0, d.ban.expires - now))}` : "permanent"}
            </Fact>
          ) : (
            <Fact sev={d.banned ? "ok" : d.score >= 60 ? "warn" : "ok"} title={d.banned ? "Covered by a wider ban" : d.allowlisted ? "Allowlisted" : "Not banned"}>
              {pending ? `proposal #${pending.id} waits for you` : d.allowlisted ? "policy never bans it" : undefined}
            </Fact>
          )}
          {d.feeds.length > 0 && (
            <Fact sev="warn" title={`On ${d.feeds.length} threat feed${d.feeds.length === 1 ? "" : "s"}`}>
              {d.feeds.join(", ")}
            </Fact>
          )}
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2 className="section-title">Last 7 days</h2>
          <LaneLegend dryRun={!drops} />
        </div>
        {row.hours.length ? <Lanes lanes={[{ ...lane, label: <span className="muted small">Packets per hour</span> }, synLane]} from={since} to={now} labelW={120} head="" /> : <Empty>No hourly history yet: it fills in after the first full hour.</Empty>}
        <ol className="story">
          {story.map((e, i) => (
            <li key={i}>
              <time className="muted tabular" dateTime={new Date(e.ts * 1000).toISOString()}>
                {fmtDayHour(e.ts)}
              </time>
              <span>{e.text}</span>
            </li>
          ))}
        </ol>
      </section>

      <section className="section">
        <h2>What it did</h2>
        <ul className="did">
          <li>
            <span className="did-k">Ports</span>
            <div>
              {d.port_touches.length === 0 ? (
                <span className="muted">No ports touched.</span>
              ) : (
                <>
                  {d.port_touches.length} port{d.port_touches.length === 1 ? "" : "s"}, {listening ? `${listening} with a service listening` : "none with a service listening"}:{" "}
                  {[...d.port_touches]
                    .sort((a, b) => Number(b.listening) - Number(a.listening) || b.packets - a.packets)
                    .slice(0, 6)
                    .map((p, i) => (
                      <span key={`${p.proto}${p.port}`}>
                        {i ? ", " : ""}
                        <span className="mono">
                          {p.port}/{p.proto}
                        </span>
                        {p.service ? ` ${p.service}` : ""} ({p.listening ? "open" : "closed"}, {fmtInt(p.packets)} packets)
                      </span>
                    ))}
                  {d.port_touches.length > 6 ? ` and ${d.port_touches.length - 6} more` : ""}
                </>
              )}
            </div>
          </li>
          <li>
            <span className="did-k">Connections</span>
            <div>
              {d.flows.length === 0 ? (
                <span className="muted">No connections recorded.</span>
              ) : (
                <>
                  {d.flows.length} connection{d.flows.length === 1 ? "" : "s"}, {targets.length === 1 ? "all to " : "mostly to "}
                  <span className="mono">{targets[0]?.[0]}</span>.
                  {clients.length > 0 && (
                    <>
                      {" "}
                      Client software:
                      <div className="chipsline">
                        {clients.map(([k, n]) => (
                          <span key={k} className="count-chip">
                            {k}
                            <i>×{n}</i>
                          </span>
                        ))}
                      </div>
                    </>
                  )}
                </>
              )}
            </div>
          </li>
          {users.length > 0 && (
            <li>
              <span className="did-k">Usernames tried</span>
              <div className="chipsline flush">
                {users.slice(0, 24).map(([k, n]) => (
                  <span key={k} className="count-chip">
                    {k}
                    <i>×{n}</i>
                  </span>
                ))}
              </div>
            </li>
          )}
          {(d.feed_hits ?? []).length > 0 && (
            <li>
              <span className="did-k">Why it is listed</span>
              <div>
                {(d.feed_hits ?? []).map((h) => (
                  <div key={h.name}>
                    <b>{h.name}</b> lists <span className="mono">{h.range}</span>
                    {h.about ? `: ${h.about}` : ""}
                  </div>
                ))}
              </div>
            </li>
          )}
          {d.geo.asn && (
            <li>
              <span className="did-k">Same network</span>
              <div>
                {peerList.length ? (
                  peerList.map((s, i) => (
                    <span key={s.ip}>
                      {i ? " · " : ""}
                      <a className="mono" href={sourceHref(s.ip)}>
                        {s.ip}
                      </a>{" "}
                      {s.findings[0] && <KindChip kind={s.findings[0].kind} score={s.score} />} {s.banned ? "banned" : "not banned"}
                    </span>
                  ))
                ) : (
                  <span className="muted">No other flagged sources in AS{d.geo.asn}.</span>
                )}
              </div>
            </li>
          )}
        </ul>
      </section>

      <section className="section">
        <h2 className="sr-only">Evidence</h2>
        <Evidence title="Connections" sub={`${d.flows.length} · active first, then the last 7 days`}>
          <p className="evidence-note">
            {(d.dns_names ?? []).length ? (
              <>
                Resolved from <span className="mono">{d.dns_names.join(", ")}</span>.{" "}
              </>
            ) : null}
            <a href={href("/traffic/connections", { view: "all", ip: d.ip, window: "7d" })}>Open in Connections</a>
          </p>
          {d.flows.length ? (
            <div className="scroll-y scroll-x" style={{ maxHeight: 480 }}>
              <FlowsTable rows={d.flows} mode="all" />
            </div>
          ) : (
            <Empty>No conversations recorded with this IP.</Empty>
          )}
        </Evidence>
        <Evidence title="Ports touched" sub={`${d.port_touches.length}`}>
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
                      <td>{p.listening ? "listening" : <span className="muted">closed</span>}</td>
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
        </Evidence>
        <Evidence title="SSH attempts" sub={`${d.ssh_events.length} most recent`}>
          {d.ssh_events.length ? (
            <div className="scroll-y" style={{ maxHeight: 420 }}>
              <SshTable events={d.ssh_events} showIp={false} />
            </div>
          ) : (
            <Empty>No SSH activity from this source.</Empty>
          )}
        </Evidence>
        <Evidence title="Alerts and proposals" sub={`${d.alerts.length} alert${d.alerts.length === 1 ? "" : "s"} · ${d.proposals.length} proposal${d.proposals.length === 1 ? "" : "s"}`}>
          {d.alerts.length ? <AlertsTable alerts={d.alerts} showIp={false} /> : <Empty>No alerts.</Empty>}
          {d.proposals.length > 0 && (
            <div className="evidence-pad">
              <ProposalList proposals={d.proposals} showTarget={false} />
            </div>
          )}
        </Evidence>
        <Evidence title="Counters and ban" sub="since the daemon started">
          <dl className="kv kv-grid evidence-pad">
            <KV k="Inbound">
              {fmtInt(d.in_packets)} pkts · {fmtBytes(d.in_bytes)}
            </KV>
            <KV k="Total">
              {fmtInt(d.packets)} pkts · {fmtBytes(d.bytes)}
            </KV>
            <KV k="SYN">{fmtInt(d.syn)}</KV>
            <KV k="UDP / ICMP in">
              {fmtInt(d.udp_in)} / {fmtInt(d.icmp_in)}
            </KV>
            <KV k="Hit a ban">{fmtInt(d.blocked)}</KV>
            <KV k="Rate now">
              {fmtRate(d.rate.in_pps, " pps")} · {fmtBits(d.rate.in_bps)} · {fmtRate(d.rate.syn_ps, " SYN/s")}
            </KV>
            {d.ban && (
              <>
                <KV k="Ban">
                  <span className="mono">{d.ban.target}</span> <BanSourceBadge source={d.ban.source} /> · {d.ban.reason}
                </KV>
                <KV k="Ban age">{fmtDuration(now - d.ban.created)}</KV>
              </>
            )}
            <KV k="Coordinates">{d.geo.lat != null && d.geo.lon != null ? <span className="mono">{d.geo.lat.toFixed(2)}, {d.geo.lon.toFixed(2)}</span> : <span className="muted">–</span>}</KV>
          </dl>
        </Evidence>
      </section>
    </div>
  );
}
