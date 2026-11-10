// Threats › Timeline: every flagged source as one lane over the last day or week,
// so "when did it start, did it get in, is it handled?" is one look, not a table.
import { useMemo } from "react";
import type { Overview, Timeline } from "../api/types";
import { usePoll } from "../api/client";
import { PanelState, Segmented } from "../components/ui";
import { LaneLegend, Lanes } from "../components/viz";
import { laneFor } from "../components/timeline";
import { fmtInt } from "../lib/format";
import { bansDrop } from "../lib/mode";
import { useQueryState } from "../lib/router";

export default function Threats() {
  const [q, setQ] = useQueryState();
  const win = q.get("window") === "24h" ? "24h" : "7d";
  const ov = usePoll<Overview>("/api/overview", 10_000);
  const tl = usePoll<Timeline>(`/api/timeline?window=${win}&limit=20`, 30_000);
  const rows = useMemo(() => tl.data?.rows ?? [], [tl.data]);

  const groups = useMemo(() => {
    const m = new Map<string, { org: string; asn: number | null; n: number; banned: number; top: number; kinds: Set<string> }>();
    for (const r of rows) {
      const k = r.geo.as_org ?? "Unknown network";
      const g = m.get(k) ?? { org: k, asn: r.geo.asn, n: 0, banned: 0, top: 0, kinds: new Set<string>() };
      g.n++;
      if (r.status === "banned") g.banned++;
      g.top = Math.max(g.top, r.score);
      r.findings.forEach((f) => g.kinds.add(f.kind.replace(/_/g, " ")));
      m.set(k, g);
    }
    return [...m.values()].filter((g) => g.n > 1 || g.banned).sort((a, b) => b.n - a.n || b.top - a.top).slice(0, 4);
  }, [rows]);

  const drops = !ov.data || bansDrop(ov.data);
  const banned = rows.filter((r) => r.status === "banned").length;
  const proposed = rows.filter((r) => r.status === "ban proposed").length;
  const gotIn = rows.filter((r) => r.ssh_accepted > 0);

  return (
    <div className="page roomy">
      <div className="title-row">
        <div>
          <h1>Attack timeline</h1>
          {tl.data && (
            <p className="title-verdict">
              <b>{fmtInt(rows.length)}</b> flagged source{rows.length === 1 ? "" : "s"} in the last {win === "7d" ? "7 days" : "24 hours"}, <b>{banned}</b> banned{drops ? "" : " (counted, not dropped)"}, <b>{proposed}</b> with a ban waiting for you.{" "}
              {gotIn.length ? (
                <b className="hot">
                  {gotIn.length} logged in: {gotIn.map((r) => r.ip).join(", ")}.
                </b>
              ) : (
                <>
                  <b>None logged in</b> over SSH.
                </>
              )}
            </p>
          )}
        </div>
        <Segmented
          label="Window"
          value={win}
          onChange={(v) => setQ({ window: v === "7d" ? null : v })}
          options={[
            { value: "24h", label: "24 hours" },
            { value: "7d", label: "7 days" },
          ]}
        />
      </div>

      {groups.length > 0 && (
        <section aria-labelledby="by-network">
          <h2 id="by-network" className="sr-only">
            By network
          </h2>
          <div className="groups">
            {groups.map((g) => (
              <div className="group" key={g.org}>
                <h3>
                  <a href={`#/threats/sources?q=${encodeURIComponent(g.asn ? `AS${g.asn}` : g.org)}`}>{g.org}</a> {g.asn && <span className="muted mono small">AS{g.asn}</span>}
                </h3>
                <p>
                  {g.n} source{g.n === 1 ? "" : "s"} · {g.banned} banned · {[...g.kinds].slice(0, 2).join(", ")}
                </p>
              </div>
            ))}
          </div>
        </section>
      )}

      <section className="panel">
        <div className="panel-head">
          <h2 className="section-title">Sources, highest score first</h2>
          <LaneLegend dryRun={!drops} />
        </div>
        <PanelState loading={tl.loading} error={tl.error} empty={!!tl.data && rows.length === 0} emptyText={`No flagged sources in the last ${win === "7d" ? "7 days" : "24 hours"}.`} />
        {tl.data && rows.length > 0 && <Lanes lanes={rows.map((r) => laneFor(r, drops))} from={tl.data.since} to={tl.data.now} />}
      </section>
    </div>
  );
}
