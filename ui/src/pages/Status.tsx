// Status: is this host OK? One verdict, then what needs you (problem,
// consequence, command, evidence), then three questions a self-hoster asks:
// who is knocking, who does this host talk to, what can the internet reach.
import { useMemo } from "react";
import type { ConnEvent, Destinations, Insight, InterfacesInfo, Listener, Overview, Proposal, Source, Summary } from "../api/types";
import { connEventsPath, destinationsPath, useConnectivity, usePoll } from "../api/client";
import { Command, KindChip, PanelState, RelTime, scoreTone } from "../components/ui";
import { BandChart, SevIcon, type Sev } from "../components/viz";
import { fmtBytes, fmtDuration, fmtInt } from "../lib/format";
import { useNow } from "../lib/clock";
import { sourceHref } from "../lib/router";
import { bansDrop } from "../lib/mode";
import { deriveIssues, failGroups, tailnetOnly, TRACEPOINT_LOSS, type Issue } from "../lib/status";

const SEV_WORD: Record<Sev, string> = { critical: "Act now", warn: "Check", ok: "Fine" };

function serviceCmd(o: Overview) {
  return o.platform === "macos" ? "sudo launchctl print system/dev.netwatch" : "systemctl status netwatch";
}

function Verdict({ issues, o, down, lastOk }: { issues: Issue[]; o: Overview; down: boolean; lastOk: number | null }) {
  if (down)
    return (
      <section className="verdict sev-critical" aria-live="polite">
        <div className="verdict-main">
          <SevIcon sev="critical" size={22} />
          <div>
            <h1 className="verdict-title">netwatch is not answering</h1>
            <p className="verdict-sub">
              {lastOk ? (
                <>
                  What you see is from <RelTime ts={lastOk / 1000} />.{" "}
                </>
              ) : null}
              The page retries on its own; until it answers, nothing here is current.
            </p>
          </div>
        </div>
        <div className="next">
          <span className="next-label">Check the service on the server</span>
          <Command cmd={serviceCmd(o)} />
        </div>
      </section>
    );
  const crit = issues.filter((i) => i.sev === "critical");
  const warn = issues.filter((i) => i.sev === "warn");
  const sev: Sev = crit.length ? "critical" : warn.length ? "warn" : "ok";
  const first = crit[0] ?? warn[0];
  const parts = [crit.length && `${crit.length} now`, warn.length && `${warn.length} to check`].filter(Boolean);
  const drops = bansDrop(o);
  return (
    <section className={`verdict sev-${sev}`} aria-live="polite">
      <div className="verdict-main">
        <SevIcon sev={sev} size={22} />
        <div>
          <h1 className="verdict-title">{sev === "ok" ? "All quiet. Nothing needs you." : `Needs you: ${parts.join(", ")}`}</h1>
          <p className="verdict-sub">
            {sev === "ok" ? (
              <>
                {fmtInt(o.counts.flagged)} flagged sources, {o.counts.bans_active} bans {drops ? "dropping their traffic" : "counting (dry run)"}. {o.host} up {fmtDuration(o.now - o.started_at)}, updated <RelTime ts={o.now} />.
              </>
            ) : (
              <>
                {o.host} up {fmtDuration(o.now - o.started_at)} · watching {o.interfaces.length} interface{o.interfaces.length === 1 ? "" : "s"} · updated <RelTime ts={o.now} />
              </>
            )}
          </p>
        </div>
      </div>
      {first?.fix && (
        <div className="next">
          <span className="next-label">Start here: {first.next ?? first.title}</span>
          <Command cmd={first.fix} />
        </div>
      )}
    </section>
  );
}

function IssueRow({ i }: { i: Issue }) {
  return (
    <li className={`issue sev-${i.sev}`}>
      <div className="issue-sev">
        <SevIcon sev={i.sev} />
        <span>{SEV_WORD[i.sev]}</span>
      </div>
      <div className="issue-body">
        <h3>{i.title}</h3>
        <p>{i.consequence}</p>
        {i.evidence && (
          <a className="issue-link" href={i.evidence.href}>
            {i.evidence.label}
          </a>
        )}
      </div>
      <div className="issue-fix">
        {i.fix && <Command cmd={i.fix} />}
        {i.fixNote && <span className="muted small">{i.fixNote}</span>}
      </div>
    </li>
  );
}

function sourceStatus(s: Source, pendingFor: Set<string>, drops: boolean) {
  if (s.banned) return drops ? "banned" : "banned, counted";
  if (pendingFor.has(s.ip)) return "ban proposed";
  if (s.allowlisted) return "allowlisted";
  return "watching";
}

export default function Status() {
  const now = useNow();
  const conn = useConnectivity();
  const ov = usePoll<Overview>("/api/overview", 5000);
  const ins = usePoll<Insight[]>("/api/insights", 15_000);
  const props = usePoll<Proposal[]>("/api/proposals?status=pending", 10_000);
  const ev = usePoll<ConnEvent[]>(connEventsPath({ window: "24h", kind: "connect_failed", limit: 2000 }), 30_000);
  const dest = usePoll<Destinations>(destinationsPath({ window: "24h", sort: "bytes", limit: 50 }), 30_000);
  const lis = usePoll<Listener[]>("/api/listeners", 30_000);
  const sum = usePoll<Summary>("/api/summary?window=24h", 30_000);
  const src = usePoll<Source[]>("/api/sources?flagged=1&sort=score&limit=100", 15_000);
  const ifs = usePoll<InterfacesInfo>("/api/interfaces", 60_000);

  const fails = useMemo(() => failGroups(ev.data ?? [], dest.data?.rows ?? []), [ev.data, dest.data]);
  const derived = useMemo(() => (ins.data && props.data ? deriveIssues(ins.data, props.data, fails, now, ov.data?.platform) : null), [ins.data, props.data, fails, now, ov.data?.platform]);

  const chart = useMemo(() => {
    const s = ov.data?.series ?? [];
    const syn = s.map((p) => p.syn_pps);
    const synMed = [...syn].sort((a, b) => a - b)[Math.floor(syn.length / 2)] ?? 0;
    const marks: { ts: number; label: string }[] = [];
    syn.forEach((v, i) => {
      if (synMed > 0 && v > synMed * 3 && (i === 0 || syn[i - 1] <= synMed * 3) && marks.length < 2) marks.push({ ts: s[i].ts, label: `SYN burst ×${Math.round(v / synMed)}` });
    });
    return { x: s.map((p) => p.ts), y: s.map((p) => p.in_pps), marks };
  }, [ov.data]);

  const o = ov.data;
  if (!o || !derived)
    return (
      <div className="page roomy">
        <h1 className="sr-only">Status</h1>
        <PanelState loading={ov.loading || ins.loading} error={ov.error ?? ins.error} />
      </div>
    );

  const down = !conn.reachable;
  const issues = derived.issues;
  const drops = bansDrop(o);
  const hostile = src.data ?? [];
  const gotIn = hostile.filter((s) => s.ssh.accepted > 0);
  const pendingFor = new Set((props.data ?? []).filter((p) => p.action === "ban").map((p) => p.target));
  const exposed = (lis.data ?? []).filter((l) => l.exposed && l.role !== "client");
  const probes = (l: Listener) => sum.data?.ports.find((p) => p.port === l.port && p.proto === l.proto)?.sources ?? 0;
  const failing = new Set(fails.map((g) => g.remote));
  const outRows = [
    ...fails.slice(0, 3).map((g) => ({ key: `f-${g.owner}-${g.remote}-${g.rport}`, bad: true, who: g.owner, to: `${g.name ?? g.remote}:${g.rport}`, what: `${g.refused === g.count ? "refused" : g.timedOut === g.count ? "timed out" : "failed"} ×${g.count}` })),
    ...(dest.data?.rows ?? [])
      .filter((d) => !failing.has(d.remote) && d.failed < d.flows)
      .slice(0, Math.max(0, 6 - Math.min(3, fails.length)))
      .map((d) => ({ key: d.remote, bad: false, who: d.processes[0]?.split("/").pop() ?? "unknown", to: d.name ?? d.remote, what: fmtBytes(d.bytes_in + d.bytes_out) })),
  ];
  const missing = (ifs.data?.tracepoints ?? []).filter((t) => !t.attached);
  const mac = o.platform === "macos";

  return (
    <div className={`page roomy ${down ? "stale" : ""}`}>
      <Verdict issues={issues} o={o} down={down} lastOk={conn.lastOk} />

      {issues.length > 0 && !down && (
        <section className="section" aria-labelledby="needs-you">
          <h2 id="needs-you" className="sr-only">
            What needs you
          </h2>
          <ol className="issues">
            {issues.map((i) => (
              <IssueRow key={i.key} i={i} />
            ))}
          </ol>
          {derived.notes.length > 0 && <p className="notes">Also noted: {derived.notes.join(" · ")}.</p>}
        </section>
      )}

      <section className="pillars">
        <div className="pillar">
          <h2>Who is knocking</h2>
          <p className="pillar-verdict">
            <b>{fmtInt(o.counts.flagged)}</b> flagged sources · <b>{o.counts.bans_active}</b> bans · <b className={gotIn.length ? "hot" : ""}>{gotIn.length}</b> logged in
          </p>
          {src.data && hostile.length === 0 && <p className="muted small">No flagged sources right now.</p>}
          <ul className="mini-rows">
            {hostile.slice(0, 5).map((s) => (
              <li key={s.ip} className={s.ssh.accepted ? "mini-row-bad" : ""}>
                <span className={`score-dot tone-${scoreTone(s.score)}`}>{s.score}</span>
                <span className="mini-row-main">
                  <a className="mono" href={sourceHref(s.ip)}>
                    {s.ip}
                  </a>{" "}
                  {s.findings[0] && <KindChip kind={s.findings[0].kind} score={s.findings[0].score} title={s.findings[0].summary} />}
                </span>
                <span className={`mini-row-val ${s.ssh.accepted ? "hot" : "muted"}`}>{s.ssh.accepted ? `${s.ssh.accepted} logins` : sourceStatus(s, pendingFor, drops)}</span>
              </li>
            ))}
          </ul>
          <a className="more-link" href="#/threats/sources">
            All sources
          </a>
        </div>
        <div className="pillar">
          <h2>Who this host talks to</h2>
          <p className="pillar-verdict">
            <b>{dest.data ? fmtInt(dest.data.destinations) : "–"}</b> internet destinations in 24 h · <b className={fails.length ? "hot" : ""}>{fails.length}</b> failing
          </p>
          {dest.data && outRows.length === 0 && <p className="muted small">No outbound connections in the last 24 h.</p>}
          <ul className="mini-rows">
            {outRows.map((r) => (
              <li key={r.key} className={r.bad ? "mini-row-bad" : ""}>
                <SevIcon sev={r.bad ? "warn" : "ok"} size={12} />
                <span className="mini-row-main">
                  <span className="mini-row-who">{r.who}</span>
                  <span className="mini-arrow" aria-label="to">
                    →
                  </span>
                  <span className="mono mini-row-to">{r.to}</span>
                </span>
                <span className={`mini-row-val tabular ${r.bad ? "hot" : "muted"}`}>{r.what}</span>
              </li>
            ))}
          </ul>
          <a className="more-link" href="#/traffic/destinations">
            All destinations
          </a>
        </div>
        <div className="pillar">
          <h2>What the internet can reach</h2>
          <p className="pillar-verdict">
            <b>{exposed.filter((l) => !tailnetOnly(l)).length}</b> open ports · <b>{exposed.filter(tailnetOnly).length}</b> tailnet only
          </p>
          {lis.data && exposed.length === 0 && <p className="muted small">Nothing listens beyond loopback.</p>}
          <ul className="mini-rows">
            {[...exposed]
              .sort((a, b) => probes(b) - probes(a))
              .slice(0, 6)
              .map((l) => (
                <li key={`${l.proto}${l.port}`}>
                  <span className="mono mini-port">
                    {l.port}/{l.proto}
                  </span>
                  <span className="mini-row-main">
                    <span className="mini-row-who">{l.service ?? "unknown"}</span>
                    <span className="muted"> · {l.container ?? l.unit ?? l.process ?? "?"}</span>
                    {tailnetOnly(l) && <span className="tag-chip">tailnet only</span>}
                  </span>
                  <span className="mini-row-val tabular muted">{probes(l) ? `${fmtInt(probes(l))} probing` : "not probed"}</span>
                </li>
              ))}
          </ul>
          <a className="more-link" href="#/exposure">
            Listening ports
          </a>
        </div>
      </section>

      <section className="section">
        <div className="section-head">
          <h2>Inbound traffic</h2>
          <span className="muted small">packets per second, last 30 minutes</span>
        </div>
        {chart.x.length > 1 ? <BandChart x={chart.x} y={chart.y} marks={chart.marks} unit="pkt/s" label="Inbound packets per second over the last 30 minutes" /> : <p className="muted small">The chart fills in during the first minutes after netwatch starts.</p>}
      </section>

      <footer className="sensor">
        <SevIcon sev={missing.length ? "warn" : "ok"} size={12} />
        <span>
          Sensor: {mac ? `packet capture (${o.attach_mode})` : `XDP (${o.attach_mode})`} on {o.interface}, flows on {o.interfaces.filter((i) => i.flows).length} interface{o.interfaces.filter((i) => i.flows).length === 1 ? "" : "s"}, {o.feeds.length} threat feed{o.feeds.length === 1 ? "" : "s"} ({fmtInt(o.feeds.reduce((a, f) => a + f.entries, 0))} entries).
          {missing.map((t) => (
            <span key={t.name}>
              {" "}
              <b>{t.name} isn't attached</b>: {TRACEPOINT_LOSS[t.name] ?? "what it records is missing"}.
            </span>
          ))}
{" "}
          <a href="#/exposure/interfaces">Interfaces & sensor</a>
        </span>
      </footer>
    </div>
  );
}
