// Domain widgets shared between pages.
import type { AppMeta, Ban, FlowDir, Insight, Proposal } from "../api/types";
import { fmtHostPort, fmtInt, fmtMs, fmtTtl } from "../lib/format";
import { href } from "../lib/router";
import { Badge, Command, Flag, IpLink, LevelTag, RelTime, type Tone } from "./ui";

export function TargetLink({ target }: { target: string }) {
  // Bans and proposals store single addresses as /32 or /128; those open the source page.
  const [addr, len] = target.split("/");
  const single = len === undefined || (len === "32" && !addr.includes(":")) || (len === "128" && addr.includes(":"));
  return single ? <IpLink ip={addr} /> : <span className="mono">{target}</span>;
}

const ACTION_TONE: Record<string, Tone> = {
  ban: "critical",
  unban: "neutral",
  allow: "good",
  review: "warning",
  ignore: "muted",
  never_ban: "good",
};
export function ActionBadge({ action }: { action: string }) {
  return <Badge tone={ACTION_TONE[action] ?? "neutral"}>{action.replace(/_/g, " ")}</Badge>;
}

const STATUS_TONE: Record<Proposal["status"], Tone> = {
  pending: "warning",
  approved: "accent",
  applied: "good",
  rejected: "muted",
  expired: "muted",
};
export function ProposalStatus({ status }: { status: Proposal["status"] }) {
  return <Badge tone={STATUS_TONE[status] ?? "neutral"}>{status}</Badge>;
}

export function Confidence({ value }: { value: number }) {
  const pct = Math.round(Math.max(0, Math.min(1, value)) * 100);
  return (
    <span className="confidence" title={`Confidence ${pct}%`}>
      <span className="meter-track small" aria-hidden>
        <span className="meter-fill conf" style={{ width: `${pct}%` }} />
      </span>
      <span className="num">{pct}%</span>
    </span>
  );
}

export function ProposalItem({ p, showTarget = true }: { p: Proposal; showTarget?: boolean }) {
  return (
    <li className="proposal">
      <div className="proposal-head">
        <span className="proposal-id mono muted">#{p.id}</span>
        <ActionBadge action={p.action} />
        {showTarget && <TargetLink target={p.target} />}
        {p.action === "ban" && <span className="muted">for {fmtTtl(p.ttl_secs)}</span>}
        <span className="spacer" />
        <Badge tone="neutral" title="Who proposed it">
          {p.source === "llm" ? "LLM" : "rules"}
        </Badge>
        <Confidence value={p.confidence} />
        <ProposalStatus status={p.status} />
      </div>
      <p className="proposal-reason">{p.reason}</p>
      <div className="proposal-foot">
        <span className="muted small">
          proposed <RelTime ts={p.created} />
          {p.decided_at ? (
            <>
              {" "}
              · decided <RelTime ts={p.decided_at} />
            </>
          ) : null}
        </span>
        {p.status === "pending" && <Command cmd={p.approve_cmd} hint="Run on the server to approve" />}
      </div>
    </li>
  );
}

export function ProposalList({ proposals, showTarget = true }: { proposals: Proposal[]; showTarget?: boolean }) {
  return (
    <ul className="proposal-list">
      {proposals.map((p) => (
        <ProposalItem key={p.id} p={p} showTarget={showTarget} />
      ))}
    </ul>
  );
}

export function InsightList({ insights }: { insights: Insight[] }) {
  const order = { critical: 0, warn: 1, info: 2 } as const;
  const sorted = [...insights].sort((a, b) => (order[a.level] ?? 3) - (order[b.level] ?? 3));
  return (
    <ul className="insight-list">
      {sorted.map((i, idx) => (
        <li key={`${i.title}-${idx}`} className={`insight level-${i.level}`}>
          <div className="insight-head">
            <LevelTag level={i.level} />
            <strong>{i.title}</strong>
          </div>
          <p>{i.detail}</p>
          {i.action && <Command cmd={i.action} />}
        </li>
      ))}
    </ul>
  );
}

const BAN_SOURCE_LABEL: Record<Ban["source"], string> = { manual: "manual", auto: "auto", policy: "policy", llm: "LLM" };

export function BanSourceBadge({ source }: { source: Ban["source"] }) {
  return <Badge tone={source === "manual" ? "neutral" : source === "llm" ? "accent" : "muted"}>{BAN_SOURCE_LABEL[source] ?? source}</Badge>;
}

export function BanExpiry({ ban }: { ban: Ban }) {
  return ban.expires == null ? <Badge tone="serious">permanent</Badge> : <RelTime ts={ban.expires} />;
}

export function DroppedCount({ n }: { n: number }) {
  return <span className="num">{fmtInt(n)}</span>;
}

export const banCmd = (target: string) => `sudo netwatch ban ${target}`;
export const unbanCmd = (target: string) => `sudo netwatch unban ${target}`;

// ---------------------------------------------------------------------------
// Flows

const DIR_META: Record<FlowDir, { arrow: string; label: string }> = {
  in: { arrow: "←", label: "inbound: the remote side connected to us" },
  out: { arrow: "→", label: "outbound: this host or a local container connected out" },
  unknown: { arrow: "↔", label: "direction unknown (flow seen mid-conversation)" },
};

export function DirArrow({ dir }: { dir: string }) {
  const m = DIR_META[dir as FlowDir] ?? DIR_META.unknown;
  return (
    <span className={`dir dir-${dir}`} title={m.label} aria-label={dir}>
      {m.arrow}
    </span>
  );
}

const STATE_TONE: Record<string, Tone> = {
  established: "good",
  active: "accent",
  failed: "critical",
  syn_sent: "warning",
  unanswered: "warning",
  syn_recv: "warning",
  new_syn_recv: "warning",
  listen: "accent",
};

export function FlowState({ state, connectMs }: { state: string; connectMs?: number | null }) {
  const tone = STATE_TONE[state] ?? "muted";
  return (
    <span className="flow-state">
      <Badge tone={tone} title={connectMs != null ? `${state.replace(/_/g, " ")}; handshake ${fmtMs(connectMs)}` : undefined}>
        {state.replace(/_/g, " ")}
      </Badge>
      {connectMs != null && <span className="muted small num">{fmtMs(connectMs)}</span>}
    </span>
  );
}

export interface AppSummary {
  tag: string; // TLS, HTTP, SSH, DNS
  text: string;
  title: string;
  status?: number | null;
}

/** One-line summary of the dissected first payload; null when there is nothing to show. */
export function appSummary(app: AppMeta | null | undefined): AppSummary | null {
  if (!app) return null;
  const lines = (pairs: [string, string | number | null | undefined][]) =>
    pairs
      .filter(([, v]) => v != null && v !== "")
      .map(([k, v]) => `${k}: ${v}`)
      .join("\n");
  if (app.proto === "http" || app.http_method || app.http_status != null) {
    const target = `${app.http_host ?? ""}${app.http_path ?? ""}`;
    const text = [app.http_method, target].filter(Boolean).join(" ") || (app.http_status != null ? "response" : "HTTP");
    return {
      tag: "HTTP",
      text,
      status: app.http_status,
      title: lines([
        ["Method", app.http_method],
        ["Host", app.http_host],
        ["Path", app.http_path],
        ["User-Agent", app.user_agent],
        ["Status", app.http_status],
        ["Server", app.server],
      ]),
    };
  }
  if (app.proto === "tls" || app.sni) {
    return {
      tag: "TLS",
      text: app.sni ?? "no SNI",
      title: lines([
        ["SNI", app.sni ?? "(none)"],
        ["ALPN", app.alpn],
      ]),
    };
  }
  if (app.proto === "ssh" || app.ssh_client || app.ssh_server) {
    return {
      tag: "SSH",
      text: app.ssh_client ?? app.ssh_server ?? "SSH",
      title: lines([
        ["Client", app.ssh_client],
        ["Server", app.ssh_server],
      ]),
    };
  }
  if (app.dns_qname) return { tag: "DNS", text: app.dns_qname, title: `Last query: ${app.dns_qname}` };
  if (app.exploit) return { tag: "RAW", text: "payload", title: "Unrecognised plaintext payload" };
  return null;
}

export function AppCell({ app }: { app: AppMeta | null | undefined }) {
  const s = appSummary(app);
  if (!s) return <span className="muted">–</span>;
  const st = s.status;
  return (
    <span className="app-cell" title={s.title}>
      {app?.exploit && (
        <Badge tone="critical" title={`Known exploit: ${app.exploit}`}>
          {app.cve ?? "exploit"}
        </Badge>
      )}
      <span className={`app-tag app-${s.tag.toLowerCase()}`}>{s.tag}</span>
      <span className="app-text">{s.text}</span>
      {app?.alpn && s.tag === "TLS" && <span className="muted small">{app.alpn}</span>}
      {st != null && <Badge tone={st >= 500 ? "critical" : st >= 400 ? "warning" : st >= 300 ? "muted" : "good"}>{st}</Badge>}
    </span>
  );
}

/**
 * Process owner as "container/process" or "unit/process" (container wins over the
 * systemd unit). Each part filters connections by it when clicked.
 */
export function ProcessCell({
  process,
  container,
  unit,
  pid,
  exe,
  onFilter,
}: {
  process: string | null;
  container: string | null;
  unit?: string | null;
  pid: number | null;
  exe: string | null;
  onFilter?: (name: string) => void;
}) {
  const prefix = container ?? unit ?? null;
  if (!process && !prefix) return <span className="muted">–</span>;
  const procTitle = [exe ?? process, pid != null ? `pid ${pid}` : null].filter(Boolean).join("\n");
  const link = (name: string, cls: string, t: string) =>
    onFilter ? (
      <button type="button" className={`proc-link ${cls}`} title={`${t}\nClick to filter.`} onClick={(e) => (e.stopPropagation(), onFilter(name))}>
        {name}
      </button>
    ) : (
      <a className={`proc-link ${cls}`} title={`${t}\nClick to show its connections.`} href={href("/traffic/connections", { process: name })} onClick={(e) => e.stopPropagation()}>
        {name}
      </a>
    );
  return (
    <span className="proc-cell">
      {prefix &&
        link(prefix, container ? "proc-prefix proc-container" : "proc-prefix proc-unit", container ? `Container ${container}` : `Service or app ${unit} (systemd unit on Linux, app bundle on macOS)`)}
      {prefix && <span className="muted">/</span>}
      {process ? link(process, "mono", procTitle) : <span className="muted" title="Process unknown">?</span>}
    </span>
  );
}

/** Remote endpoint: flag, IP (links to source detail), port, then resolved name and network. */
export function RemoteCell({
  ip,
  port,
  name,
  country,
  asn,
  asOrg,
}: {
  ip: string;
  port?: number | null;
  name?: string | null;
  country?: string | null;
  asn?: number | null;
  asOrg?: string | null;
}) {
  const net = [country, asn ? `AS${asn}` : null, asOrg].filter(Boolean).join(" ");
  const sub = [name, net].filter(Boolean).join(" · ");
  const v6 = ip.includes(":");
  return (
    <span className="remote-cell">
      <span className="nowrap">
        <Flag cc={country} title={net || undefined} /> {v6 && port ? <span className="mono muted">[</span> : null}
        <IpLink ip={ip} />
        {port ? <span className="mono muted">{v6 ? `]:${port}` : `:${port}`}</span> : null}
      </span>
      {sub && (
        <span className="remote-sub small" title={sub}>
          {name && <span className="remote-name">{name}</span>}
          {name && net && <span className="muted"> · </span>}
          {net && <span className="muted">{net}</span>}
        </span>
      )}
    </span>
  );
}

export function HostPort({ ip, port }: { ip: string; port: number | null | undefined }) {
  return <span className="mono">{fmtHostPort(ip, port)}</span>;
}

/** ✓ / ✗ with a text label for screen readers. */
export function Check({ ok, label }: { ok: boolean; label?: string }) {
  return (
    <span className={`check ${ok ? "check-ok" : "check-no"}`} title={label ?? (ok ? "yes" : "no")}>
      <span aria-hidden>{ok ? "✓" : "✗"}</span>
      <span className="sr-only">{ok ? "yes" : "no"}</span>
    </span>
  );
}

export function RetransCell({ retrans, rstSent, rstRecv }: { retrans: number; rstSent: number; rstRecv: number }) {
  if (!retrans && !rstSent && !rstRecv) return null;
  return (
    <span className="chips">
      {retrans > 0 && (
        <Badge tone="warning" title="TCP retransmissions">
          {fmtInt(retrans)} retr
        </Badge>
      )}
      {rstSent + rstRecv > 0 && (
        <Badge tone="muted" title={`RST sent ${fmtInt(rstSent)}, received ${fmtInt(rstRecv)}`}>
          {fmtInt(rstSent + rstRecv)} rst
        </Badge>
      )}
    </span>
  );
}

const IF_KIND_TONE: Record<string, Tone> = { ethernet: "neutral", tunnel: "accent", bridge: "neutral", loopback: "muted", other: "muted" };

export function IfKindBadge({ kind }: { kind: string }) {
  return <Badge tone={IF_KIND_TONE[kind] ?? "neutral"}>{kind}</Badge>;
}
