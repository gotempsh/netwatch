// Human-readable formatting helpers. All timestamps from the API are unix seconds.

const nf0 = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 });
const nf1 = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });

/** 1234 -> "1,234"; used in table columns. */
export function fmtInt(n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n)) return "–";
  return nf0.format(n);
}

/** Auto-compact: 1,284 / 12.9K / 4.2M / 1.1B. */
export function fmtCompact(n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n)) return "–";
  const a = Math.abs(n);
  if (a < 10) return nf1.format(n);
  if (a < 10_000) return nf0.format(n);
  if (a < 1e6) return `${nf1.format(n / 1e3)}K`;
  if (a < 1e9) return `${nf1.format(n / 1e6)}M`;
  return `${nf1.format(n / 1e9)}B`;
}

const BYTE_UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];

export function fmtBytes(n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n)) return "–";
  let v = Math.abs(n);
  let i = 0;
  while (v >= 1024 && i < BYTE_UNITS.length - 1) {
    v /= 1024;
    i++;
  }
  const s = i === 0 ? nf0.format(v) : v < 10 ? v.toFixed(2) : v < 100 ? v.toFixed(1) : v.toFixed(0);
  return `${n < 0 ? "-" : ""}${s} ${BYTE_UNITS[i]}`;
}

/** Bits per second -> "12.4 Mbit/s". */
export function fmtBits(bitsPerSec: number | null | undefined): string {
  if (bitsPerSec == null || !Number.isFinite(bitsPerSec)) return "–";
  const units = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"];
  let v = bitsPerSec;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v < 10 && i > 0 ? v.toFixed(2) : v < 100 && i > 0 ? v.toFixed(1) : v.toFixed(0)} ${units[i]}`;
}

/** Bytes per second -> bit rate ("12.4 Mbit/s"). */
export function fmtBitrate(bytesPerSec: number | null | undefined): string {
  if (bytesPerSec == null || !Number.isFinite(bytesPerSec)) return "–";
  return fmtBits(bytesPerSec * 8);
}

export function fmtRate(perSec: number | null | undefined, unit = "/s"): string {
  if (perSec == null || !Number.isFinite(perSec)) return "–";
  if (perSec > 0 && perSec < 0.1) return `<0.1${unit}`;
  return `${fmtCompact(perSec)}${unit}`;
}

/** Seconds -> "3d 4h", "12m 3s". */
export function fmtDuration(secs: number | null | undefined): string {
  if (secs == null || !Number.isFinite(secs)) return "–";
  let s = Math.max(0, Math.round(secs));
  const d = Math.floor(s / 86400);
  s -= d * 86400;
  const h = Math.floor(s / 3600);
  s -= h * 3600;
  const m = Math.floor(s / 60);
  s -= m * 60;
  if (d > 0) return h ? `${d}d ${h}h` : `${d}d`;
  if (h > 0) return m ? `${h}h ${m}m` : `${h}h`;
  if (m > 0) return s && m < 10 ? `${m}m ${s}s` : `${m}m`;
  return `${s}s`;
}

/** Milliseconds -> "850 ms", "3.2 s". */
export function fmtMs(ms: number | null | undefined): string {
  if (ms == null || !Number.isFinite(ms)) return "–";
  if (ms < 1) return "<1 ms";
  if (ms < 1000) return `${ms < 10 ? ms.toFixed(1) : nf0.format(ms)} ms`;
  return ms < 60_000 ? `${(ms / 1000).toFixed(ms < 10_000 ? 2 : 1)} s` : fmtDuration(ms / 1000);
}

/** "192.0.2.1:443" / "[2001:db8::1]:443". */
export function fmtHostPort(ip: string, port: number | null | undefined): string {
  if (port == null || port === 0) return ip;
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
}

/** TTL in seconds -> "7d"; null -> "permanent". */
export function fmtTtl(secs: number | null | undefined): string {
  return secs == null ? "permanent" : fmtDuration(secs);
}

/** "3m ago" / "in 2h" relative to `nowSec`. */
export function fmtRelative(ts: number | null | undefined, nowSec: number): string {
  if (ts == null || !Number.isFinite(ts) || ts <= 0) return "never";
  const diff = nowSec - ts;
  const a = Math.abs(diff);
  if (a < 5) return "just now";
  let txt: string;
  if (a < 60) txt = `${Math.floor(a)}s`;
  else if (a < 3600) txt = `${Math.floor(a / 60)}m`;
  else if (a < 86400) txt = `${Math.floor(a / 3600)}h`;
  else if (a < 86400 * 60) txt = `${Math.floor(a / 86400)}d`;
  else txt = `${Math.floor(a / (86400 * 30))}mo`;
  return diff >= 0 ? `${txt} ago` : `in ${txt}`;
}

const dtf = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});
export function fmtAbsolute(ts: number | null | undefined): string {
  if (ts == null || !Number.isFinite(ts) || ts <= 0) return "–";
  return dtf.format(new Date(ts * 1000));
}

const tf = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" });
const tfs = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const df = new Intl.DateTimeFormat(undefined, { weekday: "short", day: "2-digit" });
const dhf = new Intl.DateTimeFormat(undefined, { weekday: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
export const fmtClock = (ts: number) => tf.format(new Date(ts * 1000));
export const fmtClockSec = (ts: number) => tfs.format(new Date(ts * 1000));
export const fmtDay = (ts: number) => df.format(new Date(ts * 1000));
export const fmtDayHour = (ts: number) => dhf.format(new Date(ts * 1000));

/** ISO 3166 alpha-2 -> regional-indicator flag emoji. Empty for unknown/invalid codes. */
export function flagEmoji(cc: string | null | undefined): string {
  if (!cc || !/^[A-Za-z]{2}$/.test(cc)) return "";
  const up = cc.toUpperCase();
  return String.fromCodePoint(...[...up].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

/** Location strings look like "CN AS4134 Chinanet"; pull the leading country code if present. */
export function ccFromLocation(location: string | null | undefined): string | null {
  if (!location) return null;
  const m = /^([A-Z]{2})\b/.exec(location.trim());
  return m ? m[1] : null;
}

/** TCP flag bitmask -> "SYN", "SYN|ACK", ... */
export function fmtTcpFlags(flags: number): string {
  if (!flags) return "–";
  const names: [number, string][] = [
    [0x02, "SYN"],
    [0x10, "ACK"],
    [0x01, "FIN"],
    [0x04, "RST"],
    [0x08, "PSH"],
    [0x20, "URG"],
    [0x40, "ECE"],
    [0x80, "CWR"],
  ];
  return names
    .filter(([b]) => flags & b)
    .map(([, n]) => n)
    .join("|");
}

export function isCidr(target: string): boolean {
  return target.includes("/");
}

/** Normalise HourPoint.hour / HistoryRow.last_hour: accept unix seconds or hours-since-epoch. */
export function hourToTs(hour: number): number {
  return hour < 1e7 ? hour * 3600 : hour;
}

export function pct(n: number, d: number): number {
  return d > 0 ? Math.min(100, Math.max(0, (n / d) * 100)) : 0;
}
