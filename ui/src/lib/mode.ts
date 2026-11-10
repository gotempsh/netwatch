// What the daemon does with bans, in words that match it. Two settings, never mixed:
// `mode` decides who bans (observe: you approve every ban; enforce: rules and the
// model ban too), `drop_banned` decides whether a ban drops packets or only counts them.
import type { Ban, Overview } from "../api/types";

type Sensor = Pick<Overview, "drop_banned" | "attach_mode">;

/** Banned packets are dropped: `drop_banned`, and on macOS only once pf took the anchor and pf.conf evaluates it. */
export function bansDrop(o: Sensor): boolean {
  return o.drop_banned && o.attach_mode !== "capture" && o.attach_mode !== "capture+pf-unreferenced";
}

/** Why bans only count, and what makes them drop; null when they drop. */
export function dryRun(o: Sensor): { why: string; fix: string; cmd: string } | null {
  if (bansDrop(o)) return null;
  if (!o.drop_banned) return { why: "drop_banned is off (a dry run)", fix: "Set drop_banned = true and restart netwatch", cmd: "sudoedit /etc/netwatch/netwatch.toml" };
  if (o.attach_mode === "capture+pf-unreferenced")
    return { why: "pf.conf never evaluates netwatch's anchor", fix: 'Add anchor "com.apple/netwatch" to /etc/pf.conf, then reload pf', cmd: "sudoedit /etc/pf.conf && sudo pfctl -f /etc/pf.conf" };
  return { why: "pf didn't start", fix: "The log says why pf couldn't start", cmd: "grep -i pf /var/log/netwatch.log" };
}

/** Packets a ban caught, whether or not they were dropped (older daemons only report `dropped`). */
export const banMatched = (b: Ban): number => b.matched ?? b.dropped;

export function modeChip(o: Pick<Overview, "mode" | "drop_banned" | "attach_mode">): { label: string; title: string } {
  const who = o.mode === "enforce" ? "Rules and the model ban automatically." : "Observe mode: rules and the model only propose bans; you approve them.";
  const dry = dryRun(o);
  const drop = dry ? `${dry.why}, so bans are counted, not dropped.` : "Banned sources are dropped.";
  return {
    label: `${o.mode === "enforce" ? "enforce · auto-ban on" : "observe · auto-ban off"}${bansDrop(o) ? "" : " · dry run"}`,
    title: `${who} ${drop}`,
  };
}
