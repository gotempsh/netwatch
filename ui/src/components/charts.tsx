// Hand-rolled SVG charts. Marks follow the dataviz spec: 2px lines with round
// joins, >=8px markers with a 2px surface ring, hairline solid grid, one y-axis,
// crosshair + single tooltip listing every series, legend for >=2 series,
// selective end labels, and a table-view twin for every chart.
import { useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent, type PointerEvent, type ReactNode } from "react";
import { fmtAbsolute, fmtClock, fmtDay } from "../lib/format";

/** Categorical slots, fixed order (validated palette, see styles/base.css). */
export type SeriesSlot = 1 | 2 | 3 | 4;
export interface ChartSeries {
  key: string;
  label: string;
  slot: SeriesSlot;
  values: number[];
}

const color = (slot: SeriesSlot) => `var(--series-${slot})`;

// ---------------------------------------------------------------------------
// scales

function niceStep(raw: number): number {
  if (raw <= 0 || !Number.isFinite(raw)) return 1;
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const norm = raw / mag;
  const nice = norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 2.5 ? 2.5 : norm <= 5 ? 5 : 10;
  return nice * mag;
}

function yScale(max: number, ticks = 4) {
  const step = niceStep((max || 1) / ticks);
  const top = Math.max(step, Math.ceil((max || 1) / step) * step);
  const out: number[] = [];
  for (let v = 0; v <= top + step / 2; v += step) out.push(v);
  return { top, ticks: out };
}

const TIME_STEPS = [10, 30, 60, 120, 300, 600, 900, 1800, 3600, 2 * 3600, 3 * 3600, 6 * 3600, 12 * 3600, 86400, 2 * 86400];

function timeTicks(min: number, max: number, maxTicks: number): { ticks: number[]; step: number } {
  const span = Math.max(1, max - min);
  const step = TIME_STEPS.find((s) => span / s <= maxTicks) ?? 7 * 86400;
  const tz = new Date(min * 1000).getTimezoneOffset() * 60; // align to local boundaries
  const first = Math.ceil((min - tz) / step) * step + tz;
  const ticks: number[] = [];
  for (let t = first; t <= max; t += step) ticks.push(t);
  return { ticks, step };
}

function tickLabel(ts: number, step: number): string {
  if (step >= 86400) return fmtDay(ts);
  if (step >= 3600) {
    const d = new Date(ts * 1000);
    return d.getHours() === 0 && d.getMinutes() === 0 ? fmtDay(ts) : fmtClock(ts);
  }
  return fmtClock(ts);
}

function nearestIndex(xs: number[], x: number): number {
  let lo = 0;
  let hi = xs.length - 1;
  while (hi - lo > 1) {
    const mid = (lo + hi) >> 1;
    if (xs[mid] < x) lo = mid;
    else hi = mid;
  }
  return Math.abs(xs[lo] - x) <= Math.abs(xs[hi] - x) ? lo : hi;
}

function useWidth<T extends HTMLElement>(): [React.RefObject<T | null>, number] {
  const ref = useRef<T>(null);
  const [w, setW] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    // Measure synchronously so the first paint has geometry, then track resizes.
    setW(Math.floor(el.getBoundingClientRect().width));
    const ro = new ResizeObserver((entries) => {
      const cw = Math.floor(entries[0].contentRect.width);
      setW((prev) => (prev === cw ? prev : cw));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, w];
}

// ---------------------------------------------------------------------------
// Legend

export function Legend({ series, latest, fmt }: { series: ChartSeries[]; latest?: (number | undefined)[]; fmt?: (n: number) => string }) {
  return (
    <ul className="legend">
      {series.map((s, i) => (
        <li key={s.key}>
          <span className="key-line" style={{ background: color(s.slot) }} aria-hidden />
          <span className="legend-label">{s.label}</span>
          {latest && fmt && latest[i] != null && <span className="legend-value">{fmt(latest[i] as number)}</span>}
        </li>
      ))}
    </ul>
  );
}

// ---------------------------------------------------------------------------
// TimeChart

export interface TimeChartProps {
  /** unix seconds, ascending */
  x: number[];
  series: ChartSeries[];
  yFormat: (n: number) => string;
  /** Format for the tooltip/table time column. */
  xFormat?: (ts: number) => string;
  height?: number;
  /** Label for the table view's value unit, e.g. "pkt/s". */
  ariaLabel: string;
  /** Extra controls rendered in the chart's header row (right side). */
  extra?: ReactNode;
  /** Dim while a refetch is pending (keeps the previous frame). */
  dim?: boolean;
  emptyText?: string;
}

const PAD = { l: 48, t: 10, b: 22 };

export function TimeChart({ x, series, yFormat, xFormat = fmtAbsolute, height = 180, ariaLabel, extra, dim, emptyText = "No data yet." }: TimeChartProps) {
  const [wrapRef, width] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const [tableView, setTableView] = useState(false);
  const single = series.length === 1;
  const padR = single ? 16 : 64;

  const geom = useMemo(() => {
    if (!x.length || width < 50) return null;
    const plotW = Math.max(10, width - PAD.l - padR);
    const plotH = height;
    const xMin = x[0];
    const xMax = x[x.length - 1] === xMin ? xMin + 1 : x[x.length - 1];
    const max = Math.max(0, ...series.flatMap((s) => s.values.filter(Number.isFinite)));
    const ys = yScale(max);
    const sx = (t: number) => PAD.l + ((t - xMin) / (xMax - xMin)) * plotW;
    const sy = (v: number) => PAD.t + plotH - (Math.max(0, v) / ys.top) * plotH;
    const px = x.map(sx);
    const paths = series.map((s) => {
      let d = "";
      s.values.forEach((v, i) => {
        if (!Number.isFinite(v)) return;
        d += `${d ? "L" : "M"}${px[i].toFixed(1)},${sy(v).toFixed(1)}`;
      });
      return d;
    });
    const area = single && paths[0] ? `${paths[0]}L${px[px.length - 1].toFixed(1)},${sy(0)}L${px[0].toFixed(1)},${sy(0)}Z` : null;
    const tt = timeTicks(xMin, xMax, Math.max(2, Math.floor(plotW / 90)));
    // End labels: one per series at the last point; drop any that would collide.
    const last = x.length - 1;
    const ends = series
      .map((s, i) => ({ i, y: sy(s.values[last] ?? 0), v: s.values[last] }))
      .filter((e) => e.v != null && Number.isFinite(e.v));
    const placed: typeof ends = [];
    for (const e of ends) if (placed.every((p) => Math.abs(p.y - e.y) >= 13)) placed.push(e);
    return { plotW, plotH, sx, sy, px, paths, area, ys, tt, placed, last };
  }, [x, series, width, height, single, padR]);

  const latest = series.map((s) => s.values[s.values.length - 1]);

  const onMove = (e: PointerEvent<SVGRectElement>) => {
    if (!geom) return;
    const rect = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect();
    setHover(nearestIndex(geom.px, e.clientX - rect.left));
  };
  const onKey = (e: KeyboardEvent<SVGSVGElement>) => {
    if (!x.length) return;
    if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
      e.preventDefault();
      const d = e.key === "ArrowLeft" ? -1 : 1;
      setHover((h) => Math.max(0, Math.min(x.length - 1, (h ?? x.length - 1) + (h == null ? 0 : d))));
    } else if (e.key === "Escape") setHover(null);
  };

  const tipLeft = hover != null && geom ? geom.px[hover] : 0;
  const tipFlip = tipLeft > width / 2;

  return (
    <figure className={`chart ${dim ? "dim" : ""}`}>
      <div className="chart-head">
        {series.length > 1 ? <Legend series={series} latest={latest} fmt={yFormat} /> : <span />}
        <div className="chart-tools">
          {extra}
          <button type="button" className="link-btn" aria-pressed={tableView} onClick={() => setTableView((v) => !v)}>
            {tableView ? "Chart" : "Table"}
          </button>
        </div>
      </div>
      {tableView ? (
        <div className="chart-table scroll-y">
          <table className="tbl tbl-compact">
            <thead>
              <tr>
                <th>Time</th>
                {series.map((s) => (
                  <th key={s.key} className="num">
                    {s.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {x
                .map((t, i) => ({ t, i }))
                .reverse()
                .map(({ t, i }) => (
                  <tr key={t}>
                    <td className="mono">{xFormat(t)}</td>
                    {series.map((s) => (
                      <td key={s.key} className="num">
                        {yFormat(s.values[i])}
                      </td>
                    ))}
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="chart-plot" ref={wrapRef} style={{ height: height + PAD.t + PAD.b }}>
          {!x.length && <div className="empty chart-empty">{emptyText}</div>}
          {geom && (
            <svg
              width={width}
              height={height + PAD.t + PAD.b}
              role="img"
              aria-label={ariaLabel}
              tabIndex={0}
              onKeyDown={onKey}
              onBlur={() => setHover(null)}
            >
              {/* grid + y ticks */}
              {geom.ys.ticks.map((v) => (
                <g key={v}>
                  <line className={v === 0 ? "axis-base" : "grid"} x1={PAD.l} x2={PAD.l + geom.plotW} y1={geom.sy(v)} y2={geom.sy(v)} />
                  <text className="tick" x={PAD.l - 6} y={geom.sy(v)} dy="0.32em" textAnchor="end">
                    {yFormat(v)}
                  </text>
                </g>
              ))}
              {/* x ticks */}
              {geom.tt.ticks.map((t) => (
                <text key={t} className="tick" x={geom.sx(t)} y={PAD.t + geom.plotH + 15} textAnchor="middle">
                  {tickLabel(t, geom.tt.step)}
                </text>
              ))}
              {geom.area && <path d={geom.area} fill={color(series[0].slot)} className="area-wash" />}
              {series.map((s, i) => (
                <path key={s.key} d={geom.paths[i]} fill="none" stroke={color(s.slot)} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
              ))}
              {/* end dots + selective end labels */}
              {geom.placed.map((e) => (
                <g key={series[e.i].key}>
                  <circle cx={geom.px[geom.last]} cy={e.y} r={4} fill={color(series[e.i].slot)} className="ring" />
                  {!single && (
                    <text className="end-label" x={geom.px[geom.last] + 8} y={e.y} dy="0.32em">
                      {yFormat(e.v)}
                    </text>
                  )}
                </g>
              ))}
              {/* crosshair */}
              {hover != null && (
                <g pointerEvents="none">
                  <line className="crosshair" x1={geom.px[hover]} x2={geom.px[hover]} y1={PAD.t} y2={PAD.t + geom.plotH} />
                  {series.map((s) =>
                    Number.isFinite(s.values[hover]) ? (
                      <circle key={s.key} cx={geom.px[hover]} cy={geom.sy(s.values[hover])} r={4} fill={color(s.slot)} className="ring" />
                    ) : null,
                  )}
                </g>
              )}
              <rect
                x={PAD.l}
                y={0}
                width={geom.plotW}
                height={height + PAD.t + PAD.b}
                fill="transparent"
                onPointerMove={onMove}
                onPointerDown={onMove}
                onPointerLeave={() => setHover(null)}
              />
            </svg>
          )}
          {geom && hover != null && (
            <div className="tooltip" style={{ left: tipFlip ? undefined : tipLeft + 12, right: tipFlip ? width - tipLeft + 12 : undefined, top: PAD.t }}>
              <div className="tooltip-time">{xFormat(x[hover])}</div>
              {series.map((s) => (
                <div className="tooltip-row" key={s.key}>
                  <span className="key-line" style={{ background: color(s.slot) }} aria-hidden />
                  <strong>{yFormat(s.values[hover])}</strong>
                  <span className="tooltip-label">{s.label}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </figure>
  );
}

// ---------------------------------------------------------------------------
// Sparkline + stat tile

export function Sparkline({ values, label }: { values: number[]; label: string }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const h = 28;
  const pts = values.filter(Number.isFinite);
  let d = "";
  let lastXY: [number, number] | null = null;
  if (width > 10 && pts.length > 1) {
    const max = Math.max(...pts) || 1;
    const min = Math.min(0, ...pts);
    const w = width - 6;
    pts.forEach((v, i) => {
      const x = 1 + (i / (pts.length - 1)) * w;
      const y = 3 + (h - 6) * (1 - (v - min) / (max - min || 1));
      d += `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`;
      lastXY = [x, y];
    });
  }
  const end = lastXY as [number, number] | null;
  return (
    <div className="sparkline" ref={ref} aria-label={label} role="img">
      {d && (
        <svg width={width} height={h}>
          <path d={d} fill="none" className="spark-line" strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
          {end && <circle cx={end[0]} cy={end[1]} r={3} className="spark-end ring" />}
        </svg>
      )}
    </div>
  );
}

export function StatTile({
  label,
  value,
  context,
  trend,
  status,
  href,
}: {
  label: string;
  value: string;
  context?: ReactNode;
  trend?: number[];
  status?: ReactNode;
  href?: string;
}) {
  const body = (
    <>
      <div className="tile-label">{label}</div>
      <div className="tile-value">{value}</div>
      <div className="tile-foot">
        {context && <span className="tile-context">{context}</span>}
        {status}
      </div>
      {trend && trend.length > 1 && <Sparkline values={trend} label={`${label}, last ${trend.length} samples`} />}
    </>
  );
  return href ? (
    <a className="tile tile-link" href={href}>
      {body}
    </a>
  ) : (
    <div className="tile">{body}</div>
  );
}
