// Status icon, the line-against-its-typical-range chart and the attack timeline lanes.
import { useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { fmtClock, fmtClockSec, fmtCompact, fmtDay } from "../lib/format";

/** 1, 2 or 5 times a power of ten, at least `raw`. */
function niceStep(raw: number): number {
  const p = 10 ** Math.floor(Math.log10(Math.max(raw, 1e-9)));
  return [1, 2, 5, 10].map((m) => m * p).find((v) => v >= raw) ?? 10 * p;
}
export type Sev = "critical" | "warn" | "ok";

export function useWidth<T extends HTMLElement>(): [React.RefObject<T | null>, number] {
  const ref = useRef<T>(null);
  const [w, setW] = useState(0);
  useLayoutEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(([e]) => setW(Math.floor(e.contentRect.width)));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, w];
}

/** Drawn status icon (one stroke family), always paired with a word by the caller. */
export function SevIcon({ sev, size = 16 }: { sev: Sev; size?: number }) {
  return (
    <svg className={`sev-icon sev-${sev}`} width={size} height={size} viewBox="0 0 16 16" aria-hidden>
      {sev === "ok" ? (
        <>
          <circle cx="8" cy="8" r="7" fill="currentColor" />
          <path d="M4.8 8.2l2.1 2.1 4.3-4.5" fill="none" stroke="var(--surface)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        </>
      ) : sev === "warn" ? (
        <>
          <path d="M8 1.2l7 12.6H1z" fill="currentColor" strokeLinejoin="round" />
          <path d="M8 6v3.6" stroke="var(--surface)" strokeWidth="1.8" strokeLinecap="round" />
          <circle cx="8" cy="11.8" r="1" fill="var(--surface)" />
        </>
      ) : (
        <>
          <path d="M5 1h6l4 4v6l-4 4H5l-4-4V5z" fill="currentColor" />
          <path d="M8 4.6v4.2" stroke="var(--surface)" strokeWidth="1.8" strokeLinecap="round" />
          <circle cx="8" cy="11.3" r="1" fill="var(--surface)" />
        </>
      )}
    </svg>
  );
}

export const SEV_WORD: Record<Sev, string> = { critical: "Act now", warn: "Check", ok: "Fine" };

// ---------------------------------------------------------------------------
// One series on one axis, with its typical range as a band when there is one,
// and events annotated in place instead of drawn as a second series.

export function BandChart({ x, y, lo, hi, marks, unit, label, height = 150 }: { x: number[]; y: number[]; lo?: number[]; hi?: number[]; marks: { ts: number; label: string }[]; unit: string; label: string; height?: number }) {
  const [ref, w] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const [table, setTable] = useState(false);
  const padL = 40, padR = 12, padT = 18, padB = 20;
  const max = Math.max(1, ...y, ...(hi ?? [])) * 1.1;
  const step = niceStep(max / 4);
  const ticks = Array.from({ length: Math.floor(max / step) + 1 }, (_, i) => i * step);
  const X = (i: number) => padL + (i / Math.max(1, x.length - 1)) * (w - padL - padR);
  const Y = (v: number) => padT + (1 - v / max) * (height - padT - padB);
  const line = y.map((v, i) => `${i ? "L" : "M"}${X(i).toFixed(1)},${Y(v).toFixed(1)}`).join("");
  const band = lo && hi && hi.map((v, i) => `${i ? "L" : "M"}${X(i).toFixed(1)},${Y(v).toFixed(1)}`).join("") + lo.map((_, i) => `L${X(lo.length - 1 - i).toFixed(1)},${Y(lo[lo.length - 1 - i]).toFixed(1)}`).join("") + "Z";
  const xi = (ts: number) => x.findIndex((t) => t >= ts);
  const xt = x.filter((_, i) => i % Math.ceil(x.length / 6) === 0);
  const h = hover ?? x.length - 1;
  const out = !lo || !hi ? null : y[h] > hi[h] ? "above typical" : y[h] < lo[h] ? "below typical" : "typical";
  return (
    <figure className="band-chart">
      <figcaption className="band-read">
        <span>
          <b className="tabular">{fmtCompact(y[h] ?? 0)}</b> {unit} at {x[h] ? fmtClockSec(x[h]) : "–"}
          {out && lo && hi && (
            <>
              {" "}
              · typical {fmtCompact(lo[h] ?? 0)}–{fmtCompact(hi[h] ?? 0)} · <span className={out === "typical" ? "muted" : "hot"}>{out}</span>
            </>
          )}
        </span>
        <button type="button" className="link-btn" onClick={() => setTable(!table)}>
          {table ? "Chart" : "Table"}
        </button>
      </figcaption>
      {table ? (
        <div className="scroll-y band-table">
          <table className="tbl tbl-compact">
            <thead>
              <tr>
                <th>Time</th>
                <th className="num">{unit}</th>
                {lo && hi && <th className="num">Typical</th>}
              </tr>
            </thead>
            <tbody>
              {x.map((t, i) => (
                <tr key={t}>
                  <td>{fmtClockSec(t)}</td>
                  <td className="num">{fmtCompact(y[i])}</td>
                  {lo && hi && (
                    <td className="num">
                      {fmtCompact(lo[i])}–{fmtCompact(hi[i])}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div ref={ref} className="band-plot">
          {w > 50 && (
            <svg width={w} height={height} role="img" aria-label={label} onPointerMove={(e) => {
              const r = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
              const i = Math.round(((e.clientX - r.left - padL) / (w - padL - padR)) * (x.length - 1));
              setHover(Math.max(0, Math.min(x.length - 1, i)));
            }} onPointerLeave={() => setHover(null)}>
              {ticks.map((t) => (
                <g key={t}>
                  <line x1={padL} x2={w - padR} y1={Y(t)} y2={Y(t)} className="band-grid" />
                  <text x={padL - 6} y={Y(t) + 4} className="band-axis" textAnchor="end">
                    {fmtCompact(t)}
                  </text>
                </g>
              ))}
              {xt.map((t) => (
                <text key={t} x={X(x.indexOf(t))} y={height - 4} className="band-axis" textAnchor="middle">
                  {fmtClock(t)}
                </text>
              ))}
              {band && <path d={band} className="band-fill" />}
              {marks.map((m) => {
                const i = xi(m.ts);
                if (i < 0) return null;
                return (
                  <g key={m.ts}>
                    <line x1={X(i)} x2={X(i)} y1={padT - 4} y2={height - padB} className="band-mark-line" />
                    <text x={X(i) + 4} y={padT - 6} className="band-mark-label">
                      {m.label}
                    </text>
                  </g>
                );
              })}
              <path d={line} className="band-line" />
              {hover !== null && <line x1={X(hover)} x2={X(hover)} y1={padT} y2={height - padB} className="band-cross" />}
              <circle cx={X(h)} cy={Y(y[h] ?? 0)} r="4" className="band-dot" />
            </svg>
          )}
        </div>
      )}
    </figure>
  );
}

// ---------------------------------------------------------------------------
// Attack timeline: one lane per source. Cell darkness = packets that hour
// (sequential, one hue). Under the strip, the ban: solid = dropped, hatched =
// counted but let through (a drop_banned = false dry run). Marks above: finding
// raised, ban proposed, login accepted.

export interface LaneEvent {
  ts: number;
  kind: "finding" | "proposal" | "login";
  label: string;
}
export interface Lane {
  key: string;
  label: ReactNode;
  side: ReactNode;
  cells: { ts: number; v: number }[];
  events: LaneEvent[];
  ban: { from: number; to: number | null; drops: boolean } | null;
}

const BINS = [0.16, 0.34, 0.55, 0.78, 1];

export function Lanes({ lanes, from, to, compact, labelW = 210, head = "Source" }: { lanes: Lane[]; from: number; to: number; compact?: boolean; labelW?: number; head?: string }) {
  const [ref, w] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<{ lane: string; ts: number } | null>(null);
  const span = to - from;
  const hourW = (w / span) * 3600;
  const X = (ts: number) => ((ts - from) / span) * w;
  const max = Math.max(1, ...lanes.flatMap((l) => l.cells.filter((c) => c.ts >= from).map((c) => c.v)));
  const bin = (v: number) => BINS[Math.min(4, Math.floor((Math.log1p(v) / Math.log1p(max)) * 4.999))];
  const rowH = compact ? 22 : 30;
  const dayTicks: number[] = [];
  if (span > 2 * 86400) {
    const d0 = new Date(from * 1000);
    d0.setHours(24, 0, 0, 0);
    const every = w ? Math.max(1, Math.ceil(56 / (w / (span / 86400)))) : 1;
    for (let t = d0.getTime() / 1000, i = 0; t < to; t += 86400, i++) if (i % every === 0) dayTicks.push(t);
  } else {
    const h0 = Math.ceil(from / (6 * 3600)) * 6 * 3600;
    for (let t = h0; t < to; t += 6 * 3600) dayTicks.push(t);
  }
  const hv = hover && lanes.find((l) => l.key === hover.lane);
  const hc = hv && hv.cells.find((c) => c.ts <= hover!.ts && hover!.ts < c.ts + 3600);
  return (
    <div className="lanes" style={{ ["--label-w" as string]: `${labelW}px` }}>
      <div className="lanes-head">
        <div className="lanes-label muted">{hv ? hv.key : compact ? "" : head}</div>
        <div ref={ref} className="lanes-axis">
          {w > 0 &&
            dayTicks.map((t) => (
              <span key={t} style={{ left: X(t) }}>
                {span > 2 * 86400 ? fmtDay(t) : fmtClock(t)}
              </span>
            ))}
        </div>
        {!compact && <div className="lanes-side muted">Now</div>}
      </div>
      {hv && (
        <div className="lanes-read" role="status">
          {fmtDay(hover!.ts)} {fmtClock(Math.floor(hover!.ts / 3600) * 3600)}: <b className="tabular">{hc ? hc.v.toLocaleString() : 0}</b> packets
          {hv.ban && hover!.ts >= hv.ban.from && (hv.ban.to === null || hover!.ts < hv.ban.to) ? (hv.ban.drops ? " · banned, dropped" : " · banned, counted only (dry run)") : ""}
          {hv.events.filter((e) => Math.abs(e.ts - hover!.ts) < 3600).map((e) => ` · ${e.label}`)}
        </div>
      )}
      {lanes.map((l) => (
        <div className="lane" key={l.key}>
          <div className="lanes-label">{l.label}</div>
          <svg className="lane-strip" width={w} height={rowH} onPointerMove={(e) => {
            const r = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
            setHover({ lane: l.key, ts: from + ((e.clientX - r.left) / w) * span });
          }} onPointerLeave={() => setHover(null)} role="img" aria-label={`${l.key}: activity, ban and events over the window`}>
            <defs>
              <pattern id={`hatch-${l.key}`} width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
                <line x1="0" y1="0" x2="0" y2="4" className="lane-hatch" />
              </pattern>
            </defs>
            <rect x="0" y={8} width={w} height={rowH - 16} className="lane-track" />
            {l.cells.filter((c) => c.ts >= from && c.ts < to).map((c) =>
              c.v > 0 ? <rect key={c.ts} x={X(c.ts)} y={8} width={Math.max(1, hourW - (hourW > 4 ? 1 : 0))} height={rowH - 16} className="lane-cell" style={{ opacity: bin(c.v) }} /> : null,
            )}
            {l.ban && <rect x={X(Math.max(from, l.ban.from))} y={rowH - 6} width={Math.max(2, X(Math.min(to, l.ban.to ?? to)) - X(Math.max(from, l.ban.from)))} height={4} rx={1} fill={l.ban.drops ? "var(--critical)" : `url(#hatch-${l.key})`} className="lane-ban" />}
            {l.events.map((e, i) => {
              const cx = X(e.ts);
              if (cx < 0 || cx > w) return null;
              return e.kind === "finding" ? (
                <path key={i} d={`M${cx},0 l4,4 l-4,4 l-4,-4z`} className="ev-finding" />
              ) : e.kind === "proposal" ? (
                <circle key={i} cx={cx} cy={4} r={3.2} className="ev-proposal" />
              ) : (
                <path key={i} d={`M${cx},0 l4.5,8 h-9z`} className="ev-login" />
              );
            })}
          </svg>
          {!compact && <div className="lanes-side">{l.side}</div>}
        </div>
      ))}
    </div>
  );
}

export function LaneLegend({ dryRun = false }: { dryRun?: boolean }) {
  return (
    <div className="lane-legend">
      <span>
        <svg width="40" height="10" aria-hidden>
          {BINS.map((o, i) => (
            <rect key={i} x={i * 8} y="1" width="7" height="8" className="lane-cell" style={{ opacity: o }} />
          ))}
        </svg>
        packets per hour
      </span>
      <span>
        <svg width="18" height="10" aria-hidden>
          <path d="M9,1 l4,4 l-4,4 l-4,-4z" className="ev-finding" />
        </svg>
        finding raised
      </span>
      <span>
        <svg width="12" height="10" aria-hidden>
          <circle cx="6" cy="5" r="3.2" className="ev-proposal" />
        </svg>
        ban proposed
      </span>
      {dryRun && <span>
        <svg width="22" height="10" aria-hidden>
          <defs>
            <pattern id="hatch-legend" width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
              <line x1="0" y1="0" x2="0" y2="4" className="lane-hatch" />
            </pattern>
          </defs>
          <rect x="1" y="3" width="20" height="4" fill="url(#hatch-legend)" className="lane-ban" />
        </svg>
        banned, counted only (dry run)
      </span>}
      <span>
        <svg width="22" height="10" aria-hidden>
          <rect x="1" y="3" width="20" height="4" rx="1" fill="var(--critical)" />
        </svg>
        banned, dropped
      </span>
      <span>
        <svg width="12" height="10" aria-hidden>
          <path d="M6,1 l4.5,8 h-9z" className="ev-login" />
        </svg>
        login accepted
      </span>
    </div>
  );
}
