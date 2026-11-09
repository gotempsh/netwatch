import { useEffect, useRef, useState, type ReactNode } from "react";
import type { Finding, Level } from "../api/types";
import { ApiError } from "../api/client";
import { useNow } from "../lib/clock";
import { ccFromLocation, flagEmoji, fmtAbsolute, fmtRelative } from "../lib/format";
import { sourceHref } from "../lib/router";

// ---------------------------------------------------------------------------
// Copy to clipboard

async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fall through */
  }
  // Fallback for non-secure contexts (e.g. plain http on a LAN address).
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  document.body.removeChild(ta);
  return ok;
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [state, setState] = useState<"idle" | "ok" | "fail">("idle");
  return (
    <button
      type="button"
      className={`copy-btn ${state}`}
      title="Copy to clipboard"
      onClick={async (e) => {
        e.stopPropagation();
        const ok = await copyText(text);
        setState(ok ? "ok" : "fail");
        setTimeout(() => setState("idle"), 1500);
      }}
    >
      {state === "ok" ? "Copied" : state === "fail" ? "Failed" : label}
    </button>
  );
}

/** A shell command the operator runs on the server. Read-only UI: copy, never execute. */
export function Command({ cmd, hint }: { cmd: string; hint?: string }) {
  return (
    <div className="cmd" title={hint}>
      <code>
        <span className="cmd-prompt" aria-hidden>
          ${" "}
        </span>
        {cmd}
      </code>
      <CopyButton text={cmd} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Time

export function RelTime({ ts, never = "never" }: { ts: number | null | undefined; never?: string }) {
  const now = useNow();
  if (ts == null || ts <= 0) return <span className="muted">{never}</span>;
  return (
    <time className="reltime" dateTime={new Date(ts * 1000).toISOString()} title={fmtAbsolute(ts)}>
      {fmtRelative(ts, now)}
    </time>
  );
}

// ---------------------------------------------------------------------------
// Geo

/** Country flag; renders nothing unless `cc` is exactly two ASCII letters. */
export function Flag({ cc, title }: { cc: string | null | undefined; title?: string | null }) {
  const f = flagEmoji(cc);
  if (!f) return null;
  return (
    <span className="flag" role="img" aria-label={title ?? cc ?? ""} title={title ?? cc ?? ""}>
      {f}
    </span>
  );
}

/** Renders "CN AS4134 Chinanet" with a flag derived from the leading country code. */
export function Location({ text }: { text: string }) {
  const cc = ccFromLocation(text);
  return (
    <span className="location">
      <Flag cc={cc} /> <span className="location-text">{text || "–"}</span>
    </span>
  );
}

export function IpLink({ ip }: { ip: string }) {
  return (
    <a className="ip mono" href={sourceHref(ip)} onClick={(e) => e.stopPropagation()}>
      {ip}
    </a>
  );
}

// ---------------------------------------------------------------------------
// Badges

export type Tone = "neutral" | "accent" | "good" | "warning" | "serious" | "critical" | "muted";

export function Badge({ tone = "neutral", children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span className={`badge tone-${tone}`} title={title}>
      {children}
    </span>
  );
}

const LEVEL_META: Record<Level, { tone: Tone; icon: string; label: string }> = {
  info: { tone: "accent", icon: "i", label: "Info" },
  warn: { tone: "warning", icon: "!", label: "Warning" },
  critical: { tone: "critical", icon: "!!", label: "Critical" },
};

/** Status always ships as icon + label, never color alone. */
export function LevelTag({ level, label }: { level: Level; label?: string }) {
  const m = LEVEL_META[level] ?? LEVEL_META.info;
  return (
    <span className={`level-tag tone-${m.tone}`}>
      <span className="level-icon" aria-hidden>
        {m.icon}
      </span>
      {label ?? m.label}
    </span>
  );
}

export function scoreTone(score: number): Tone {
  if (score >= 80) return "critical";
  if (score >= 60) return "serious";
  if (score >= 30) return "warning";
  if (score > 0) return "accent";
  return "muted";
}

/** 0-100 meter; fill carries severity, track is a lighter step; value printed in text ink. */
export function ScoreMeter({ score, wide }: { score: number; wide?: boolean }) {
  const s = Math.max(0, Math.min(100, Math.round(score)));
  const tone = scoreTone(s);
  return (
    <span className={`meter tone-${tone} ${wide ? "meter-wide" : ""}`} title={`Score ${s}/100`}>
      <span className="meter-value">{s}</span>
      <span className="meter-track" aria-hidden>
        <span className="meter-fill" style={{ width: `${s}%` }} />
      </span>
    </span>
  );
}

const KIND_LABEL: Record<string, string> = {
  port_scan: "port scan",
  ssh_bruteforce: "SSH brute force",
  threat_feed: "threat feed",
  syn_flood: "SYN flood",
  udp_probe: "UDP probe",
  rdp_probe: "RDP probe",
  http_flood: "HTTP flood",
};
export const kindLabel = (k: string) => KIND_LABEL[k] ?? k.replace(/_/g, " ");

export function KindChip({ kind, score, title }: { kind: string; score?: number; title?: string }) {
  return (
    <span className={`chip ${score != null ? `tone-${scoreTone(score)}` : ""}`} title={title}>
      {score != null && <span className="chip-dot" aria-hidden />}
      {kindLabel(kind)}
    </span>
  );
}

export function FindingChips({ findings }: { findings: Finding[] }) {
  if (!findings.length) return <span className="muted">–</span>;
  return (
    <span className="chips">
      {findings.map((f) => (
        <KindChip key={f.kind} kind={f.kind} score={f.score} title={`${f.score} · ${f.summary}`} />
      ))}
    </span>
  );
}

export function SourceFlags({ banned, allowlisted, feeds }: { banned: boolean; allowlisted: boolean; feeds: string[] }) {
  return (
    <span className="chips">
      {banned && <Badge tone="critical">banned</Badge>}
      {allowlisted && <Badge tone="good">allowlisted</Badge>}
      {feeds.length > 0 && (
        <Badge tone="serious" title={feeds.join(", ")}>
          feed{feeds.length > 1 ? ` ×${feeds.length}` : ""}
        </Badge>
      )}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Layout

export function Card({
  title,
  sub,
  actions,
  children,
  className = "",
  flush,
}: {
  title?: ReactNode;
  sub?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  flush?: boolean;
}) {
  return (
    <section className={`card ${flush ? "card-flush" : ""} ${className}`}>
      {(title || actions) && (
        <header className="card-head">
          <div>
            {title && <h2 className="card-title">{title}</h2>}
            {sub && <div className="card-sub">{sub}</div>}
          </div>
          {actions && <div className="card-actions">{actions}</div>}
        </header>
      )}
      <div className="card-body">{children}</div>
    </section>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

/** Inline state for a panel: loading / error / nothing. Returns null when data is present. */
export function PanelState({ loading, error, empty, emptyText = "Nothing to show." }: { loading: boolean; error: ApiError | null; empty?: boolean; emptyText?: string }) {
  if (error && error.status !== 0 && error.status < 500) return <div className="empty error-text">Error: {error.message}</div>;
  if (loading) return <div className="empty">Loading…</div>;
  if (empty) return <Empty>{emptyText}</Empty>;
  return null;
}

export function SortTh<K extends string>({ k, label, sort, onSort, title, align = "left" }: { k: K; label: string; sort: K; onSort: (k: K) => void; title?: string; align?: "left" | "right" }) {
  const active = sort === k;
  return (
    <th className={`sortable ${active ? "active" : ""} ${align === "right" ? "num" : ""}`} aria-sort={active ? "descending" : "none"} title={title ?? `Sort by ${label} (descending)`}>
      <button type="button" onClick={() => onSort(k)}>
        {label}
        <span className="sort-ind" aria-hidden>
          {active ? "▼" : "▽"}
        </span>
      </button>
    </th>
  );
}

export function Segmented<T extends string>({ value, options, onChange, label }: { value: T; options: { value: T; label: string }[]; onChange: (v: T) => void; label: string }) {
  return (
    <div className="segmented" role="radiogroup" aria-label={label}>
      {options.map((o) => (
        <button type="button" key={o.value} role="radio" aria-checked={value === o.value} className={value === o.value ? "on" : ""} onClick={() => onChange(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

/** Horizontal magnitude bar inside a table cell (single sequential hue). */
export function BarCell({ value, max, label }: { value: number; max: number; label: string }) {
  const w = max > 0 ? Math.max(value > 0 ? 1.5 : 0, (value / max) * 100) : 0;
  return (
    <span className="barcell" title={label}>
      <span className="barcell-track" aria-hidden>
        <span className="barcell-fill" style={{ width: `${w}%` }} />
      </span>
      <span className="barcell-label num">{label}</span>
    </span>
  );
}

// ---------------------------------------------------------------------------
// Filters

/**
 * Text filter bound to a route query param: local state while typing, pushed
 * upstream after a pause. Adopts external changes (back/forward, links).
 */
export function FilterInput({
  value,
  onCommit,
  placeholder,
  label,
  delay = 300,
  className = "",
  type = "search",
}: {
  value: string;
  onCommit: (v: string) => void;
  placeholder?: string;
  label: string;
  delay?: number;
  className?: string;
  type?: "search" | "text";
}) {
  const [text, setText] = useState(value);
  const pushed = useRef(value);
  const commit = useRef(onCommit);
  commit.current = onCommit;
  useEffect(() => {
    if (value !== pushed.current) {
      pushed.current = value;
      setText(value);
    }
  }, [value]);
  useEffect(() => {
    const next = text.trim();
    if (next === pushed.current) return;
    const id = setTimeout(() => {
      pushed.current = next;
      commit.current(next);
    }, delay);
    return () => clearTimeout(id);
  }, [text, delay]);
  return <input type={type} className={`input ${className}`} placeholder={placeholder} value={text} onChange={(e) => setText(e.target.value)} aria-label={label} />;
}

export function Select<T extends string>({ value, options, onChange, label, className = "" }: { value: T; options: { value: T; label: string }[]; onChange: (v: T) => void; label: string; className?: string }) {
  return (
    <select className={`input select ${className}`} value={value} onChange={(e) => onChange(e.target.value as T)} aria-label={label} title={label}>
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

/** Link tabs between sibling pages (hash routes). */
export function Tabs({ tabs, active }: { tabs: { href: string; label: string; key: string }[]; active: string }) {
  return (
    <nav className="tabs" aria-label="Sections">
      {tabs.map((t) => (
        <a key={t.key} href={t.href} className={t.key === active ? "on" : ""} aria-current={t.key === active ? "page" : undefined}>
          {t.label}
        </a>
      ))}
    </nav>
  );
}

/** Long value in a table cell: truncated, full text on hover. */
export function Trunc({ text, className = "", max }: { text: string | null | undefined; className?: string; max?: number }) {
  if (!text) return <span className="muted">–</span>;
  return (
    <span className={`trunc ${className}`} title={text} style={max ? { maxWidth: max } : undefined}>
      {text}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Ranked list (compact top-N with a magnitude bar)

export interface RankItem {
  key: string;
  label: ReactNode;
  sub?: ReactNode;
  value: number;
  valueLabel: string;
  title?: string;
  /** Click applies a filter; omitted = not clickable. */
  onClick?: () => void;
}

export function RankedList({ items, emptyText = "Nothing yet.", limit = 8 }: { items: RankItem[]; emptyText?: string; limit?: number }) {
  if (!items.length) return <Empty>{emptyText}</Empty>;
  const shown = items.slice(0, limit);
  const max = Math.max(0, ...shown.map((i) => i.value));
  return (
    <ol className="rank-list">
      {shown.map((it) => {
        const w = max > 0 ? Math.max(it.value > 0 ? 1.5 : 0, (it.value / max) * 100) : 0;
        const body = (
          <>
            <span className="rank-name">
              <span className="rank-label">{it.label}</span>
              {it.sub && <span className="rank-sub muted small">{it.sub}</span>}
            </span>
            <span className="rank-value num">{it.valueLabel}</span>
            <span className="rank-bar" aria-hidden>
              <span className="barcell-fill" style={{ width: `${w}%` }} />
            </span>
          </>
        );
        return (
          <li key={it.key}>
            {it.onClick ? (
              <button type="button" className="rank-item clickable" onClick={it.onClick} title={it.title ?? "Apply as filter"}>
                {body}
              </button>
            ) : (
              <div className="rank-item" title={it.title}>
                {body}
              </div>
            )}
          </li>
        );
      })}
    </ol>
  );
}
