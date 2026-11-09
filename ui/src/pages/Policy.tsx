import type { LlmInfo, Policy as PolicyData, PolicyRule } from "../api/types";
import { usePoll } from "../api/client";
import { ActionBadge } from "../components/domain";
import { Badge, Card, Command, Empty, PanelState, RelTime } from "../components/ui";
import { fmtAbsolute, fmtCompact, fmtInt, fmtTtl, pct } from "../lib/format";

function compactJson(v: unknown): string {
  try {
    return JSON.stringify(v, null, 0)
      .replace(/":/g, '": ')
      .replace(/,"/g, ', "');
  } catch {
    return String(v);
  }
}

function RulesTable({ rules }: { rules: PolicyRule[] }) {
  return (
    <div className="scroll-x">
      <table className="tbl">
        <thead>
          <tr>
            <th>Rule</th>
            <th>Action</th>
            <th>TTL</th>
            <th>When</th>
            <th>Enabled</th>
          </tr>
        </thead>
        <tbody>
          {rules.map((r) => (
            <tr key={r.id} className={r.enabled ? "" : "row-disabled"}>
              <td>
                <div className="mono small muted">{r.id}</div>
                <div>{r.description}</div>
              </td>
              <td>
                <ActionBadge action={r.action} />
              </td>
              <td className="nowrap">{r.action === "ban" ? fmtTtl(r.ttl_secs) : <span className="muted">–</span>}</td>
              <td>
                <code className="json">{compactJson(r.when)}</code>
              </td>
              <td>{r.enabled ? <Badge tone="good">on</Badge> : <Badge tone="muted">off</Badge>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Policy() {
  const pol = usePoll<PolicyData>("/api/policy", 30_000);
  const llm = usePoll<LlmInfo>("/api/llm", 15_000);
  const p = pol.data;
  const l = llm.data;
  const used = l ? pct(l.tokens_today, l.budget_tokens_day) : 0;

  return (
    <div className="page">
      <div className="page-head">
        <h1>Policy & AI</h1>
      </div>

      <Card
        title="Policy"
        sub={
          p?.compiled_at ? (
            <>
              Compiled <RelTime ts={p.compiled_at} />
              {p.compiled_by ? (
                <>
                  {" "}
                  by <span className="mono">{p.compiled_by}</span>
                </>
              ) : null}
            </>
          ) : (
            "Natural-language policy, compiled into rules by the LLM"
          )
        }
      >
        {!p && <PanelState loading={pol.loading} error={pol.error} />}
        {p && (
          <>
            {p.text ? <blockquote className="policy-text">{p.text}</blockquote> : <Empty>No policy set. Only the built-in defaults apply.</Empty>}
            <div className="hint-row">
              <span className="muted small">To change the policy, run on the server:</span>
              <Command cmd={p.set_cmd} />
            </div>
          </>
        )}
      </Card>

      {p && (
        <>
          <Card title={`Compiled rules (${p.rules.length})`} flush>
            {p.rules.length ? <RulesTable rules={p.rules} /> : <Empty>No compiled rules.</Empty>}
          </Card>
          <Card title={`Built-in default rules (${p.defaults.length})`} sub="Always applied" flush>
            {p.defaults.length ? <RulesTable rules={p.defaults} /> : <Empty>No defaults reported.</Empty>}
          </Card>
        </>
      )}

      <Card title="LLM" sub={l?.base_url ? <span className="mono">{l.base_url}</span> : undefined}>
        {!l && <PanelState loading={llm.loading} error={llm.error} />}
        {l && (
          <div className="llm-summary">
            <div className="fact">
              <div className="fact-label">Status</div>
              <div className="fact-value">{l.enabled ? <Badge tone="good">enabled</Badge> : <Badge tone="muted">disabled</Badge>}</div>
            </div>
            <div className="fact">
              <div className="fact-label">Model</div>
              <div className="fact-value mono">{l.model ?? "–"}</div>
            </div>
            <div className="fact">
              <div className="fact-label">Calls today</div>
              <div className="fact-value">{fmtInt(l.calls_today)}</div>
            </div>
            <div className="fact fact-wide">
              <div className="fact-label">Tokens today</div>
              <div className="fact-value llm-fact">
                <span className="meter-track" aria-hidden>
                  <span className={`meter-fill ${used >= 90 ? "tone-critical" : used >= 70 ? "tone-warning" : ""}`} style={{ width: `${used}%` }} />
                </span>
                <span>
                  {fmtInt(l.tokens_today)} / {fmtInt(l.budget_tokens_day)} ({used.toFixed(0)}%)
                </span>
              </div>
            </div>
            <div className="fact">
              <div className="fact-label">Last run</div>
              <div className="fact-value">
                <RelTime ts={l.last_run} />
              </div>
            </div>
          </div>
        )}
      </Card>

      {l && (
        <Card title={`Runs (${l.runs.length})`} flush>
          {l.runs.length ? (
            <div className="scroll-x">
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Kind</th>
                    <th>Model</th>
                    <th className="num" title="Prompt + completion tokens">Tokens</th>
                    <th className="num">Proposals</th>
                    <th>Summary</th>
                  </tr>
                </thead>
                <tbody>
                  {l.runs.map((r, i) => (
                    <tr key={`${r.ts}-${i}`}>
                      <td className="nowrap" title={fmtAbsolute(r.ts)}>
                        <RelTime ts={r.ts} />
                      </td>
                      <td>
                        <Badge tone={r.kind === "compile_policy" ? "accent" : "neutral"}>{r.kind.replace(/_/g, " ")}</Badge>
                      </td>
                      <td className="mono small">{r.model}</td>
                      <td className="num" title={`${fmtInt(r.prompt_tokens)} prompt + ${fmtInt(r.completion_tokens)} completion`}>
                        {fmtCompact(r.prompt_tokens + r.completion_tokens)}
                        <span className="muted small">
                          {" "}
                          ({fmtCompact(r.prompt_tokens)}+{fmtCompact(r.completion_tokens)})
                        </span>
                      </td>
                      <td className="num">{r.proposals ? fmtInt(r.proposals) : <span className="muted">0</span>}</td>
                      <td className="summary-cell">{r.summary}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty>No LLM runs yet.</Empty>
          )}
        </Card>
      )}
    </div>
  );
}
