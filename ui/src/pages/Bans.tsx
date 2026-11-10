import type { Ban, Overview, Proposal } from "../api/types";
import { usePoll } from "../api/client";
import { BanExpiry, BanSourceBadge, ProposalList, TargetLink, unbanCmd } from "../components/domain";
import { Card, Command, CopyButton, PanelState, RelTime, Segmented } from "../components/ui";
import { fmtInt } from "../lib/format";
import { useQueryState } from "../lib/router";
import { banMatched, bansDrop } from "../lib/mode";

const STATUSES = ["pending", "all", "approved", "applied", "rejected", "expired"] as const;
type StatusFilter = (typeof STATUSES)[number];

export default function Bans() {
  const [query, setQuery] = useQueryState();
  const sp = query.get("status") as StatusFilter | null;
  const status: StatusFilter = sp && STATUSES.includes(sp) ? sp : "pending";

  const bans = usePoll<Ban[]>("/api/bans", 10_000);
  const ov = usePoll<Overview>("/api/overview", 30_000);
  const drops = !ov.data || bansDrop(ov.data);
  // The API only distinguishes pending|all; narrower statuses are filtered here.
  const props = usePoll<Proposal[]>(`/api/proposals?status=${status === "pending" ? "pending" : "all"}`, 10_000);
  const shown = (props.data ?? []).filter((p) => status === "all" || p.status === status);
  const banRows = [...(bans.data ?? [])].sort((a, b) => b.created - a.created);

  return (
    <div className="page">
      <div className="page-head">
        <h1>Bans & proposals</h1>
        <span className="muted small">Read-only. Ban, unban and approve with the netwatch CLI on the server.</span>
      </div>

      <Card title={`Active bans${banRows.length ? ` (${banRows.length})` : ""}`} flush actions={<Command cmd="sudo netwatch ban <ip-or-cidr>" hint="Template: replace the placeholder" />}>
        <PanelState loading={bans.loading} error={bans.error} empty={!banRows.length} emptyText="No active bans." />
        {banRows.length > 0 && (
          <div className="scroll-x">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Source</th>
                  <th>Reason</th>
                  <th>Created</th>
                  <th>Expires</th>
                  <th className="num" title={drops ? "Packets dropped since daemon start" : "Packets that hit the ban since daemon start; a dry run lets them through"}>
                    {drops ? "Dropped" : "Matched, not dropped"}
                  </th>
                  <th>Unban</th>
                </tr>
              </thead>
              <tbody>
                {banRows.map((b) => (
                  <tr key={b.target}>
                    <td>
                      <TargetLink target={b.target} />
                    </td>
                    <td>
                      <BanSourceBadge source={b.source} />
                    </td>
                    <td className="summary-cell">{b.reason}</td>
                    <td className="nowrap">
                      <RelTime ts={b.created} />
                    </td>
                    <td className="nowrap">
                      <BanExpiry ban={b} />
                    </td>
                    <td className="num">{fmtInt(drops ? b.dropped : banMatched(b))}</td>
                    <td className="nowrap">
                      <code className="inline-cmd">{unbanCmd(b.target)}</code> <CopyButton text={unbanCmd(b.target)} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card
        title="Proposals"
        sub="Actions suggested by rules or the LLM, waiting for a human"
        actions={<Segmented label="Proposal status" value={status} onChange={(v) => setQuery({ status: v === "pending" ? null : v })} options={STATUSES.map((s) => ({ value: s, label: s }))} />}
      >
        <div className={props.stale ? "dim" : ""}>{shown.length > 0 && <ProposalList proposals={shown} />}</div>
        <PanelState loading={props.loading} error={props.error} empty={!shown.length && !props.stale} emptyText={status === "pending" ? "Nothing waiting for a decision." : `No ${status === "all" ? "" : status + " "}proposals.`} />
      </Card>
    </div>
  );
}
