// A shared, low-frequency clock so relative times ("3m ago") stay fresh without
// every component running its own timer. Also tracks the daemon's clock offset
// (from /api/overview `now`) so relative times are correct when the browser runs
// on a different machine than the daemon (e.g. via an SSH tunnel).
import { useSyncExternalStore } from "react";

let offsetSec = 0;
let nowSec = Date.now() / 1000;
const subs = new Set<() => void>();
let timer: ReturnType<typeof setInterval> | undefined;

function tick() {
  nowSec = Date.now() / 1000 + offsetSec;
  subs.forEach((f) => f());
}

function subscribe(cb: () => void) {
  subs.add(cb);
  if (!timer) timer = setInterval(tick, 5000);
  return () => {
    subs.delete(cb);
    if (subs.size === 0 && timer) {
      clearInterval(timer);
      timer = undefined;
    }
  };
}

/** Current daemon-aligned time in unix seconds, refreshed every 5s. */
export function useNow(): number {
  return useSyncExternalStore(subscribe, () => nowSec);
}

/** Record the daemon's notion of "now" (unix seconds). */
export function setServerNow(serverNow: number) {
  const next = serverNow - Date.now() / 1000;
  // Ignore sub-2s jitter (request latency) to avoid churn.
  if (Math.abs(next - offsetSec) > 2) {
    offsetSec = next;
    tick();
  }
}
