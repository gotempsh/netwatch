// Typed, read-only client for the netwatch daemon API (GET only).
import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from "react";
import type { ConnEvent, DestinationSort, DnsInfo, FlowRow, FlowSort, FlowsSummary, FlowView, InterfacesInfo, Listener } from "./types";

const MOCK = import.meta.env.VITE_MOCK === "1";

export class ApiError extends Error {
  status: number; // 0 = network error / daemon unreachable
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

// ---------------------------------------------------------------------------
// Connectivity state (drives the "daemon unreachable" banner)

interface Connectivity {
  reachable: boolean;
  lastError: string | null;
  lastOk: number | null; // ms epoch
}
let conn: Connectivity = { reachable: true, lastError: null, lastOk: null };
const connSubs = new Set<() => void>();

function setConn(next: Partial<Connectivity>) {
  const merged = { ...conn, ...next };
  if (merged.reachable === conn.reachable && merged.lastError === conn.lastError && !next.lastOk) return;
  conn = merged;
  connSubs.forEach((f) => f());
}

export function useConnectivity(): Connectivity {
  return useSyncExternalStore(
    (cb) => {
      connSubs.add(cb);
      return () => connSubs.delete(cb);
    },
    () => conn,
  );
}

// ---------------------------------------------------------------------------
// get<T>

/** Fetch a GET endpoint. `path` is relative to the UI origin, e.g. "/api/overview". */
export async function get<T>(path: string, signal?: AbortSignal): Promise<T> {
  if (MOCK) {
    // Dynamic import keeps fixtures out of the production bundle (VITE_MOCK is
    // statically replaced, so this branch is dead code in a normal build).
    const { mockGet } = await import("./mock");
    return (await mockGet(path, signal)) as T;
  }
  // The UI is served by the daemon at "/", so a relative "api/..." would also
  // work; we keep absolute "/api" so the dev proxy matches.
  let res: Response;
  try {
    res = await fetch(path, { method: "GET", headers: { Accept: "application/json" }, signal, cache: "no-store" });
  } catch (e) {
    if ((e as Error).name === "AbortError") throw e;
    const err = new ApiError(0, "daemon unreachable");
    setConn({ reachable: false, lastError: err.message });
    throw err;
  }
  if (res.status >= 500) {
    // The Vite dev proxy answers 502/504 (or 500) when the daemon is down.
    const err = new ApiError(res.status, `HTTP ${res.status} ${res.statusText}`.trim());
    setConn({ reachable: false, lastError: err.message });
    throw err;
  }
  setConn({ reachable: true, lastError: null, lastOk: Date.now() });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const body = await res.text();
      if (body) msg += `: ${body.slice(0, 200)}`;
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, msg);
  }
  return (await res.json()) as T;
}

/** Build "/api/x?a=1&b=2", skipping empty values. */
export function apiPath(base: string, params?: Record<string, string | number | boolean | null | undefined>): string {
  if (!params) return base;
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === null || v === undefined || v === "" || v === false) continue;
    qs.set(k, v === true ? "1" : String(v));
  }
  const s = qs.toString();
  return s ? `${base}?${s}` : base;
}

// ---------------------------------------------------------------------------
// Typed endpoint paths (for usePoll) and one-shot fetchers.

/** Time windows understood by the flow/DNS endpoints (`window_secs()` in api.rs). */
export type FlowWindow = "5m" | "15m" | "1h" | "6h" | "24h" | "7d" | "30d";

export interface FlowsParams {
  view?: FlowView;
  window?: FlowWindow | null;
  ip?: string | null;
  port?: number | null;
  process?: string | null;
  dir?: "in" | "out" | "unknown" | null;
  iface?: string | null;
  proto?: string | null;
  q?: string | null;
  sort?: FlowSort | null;
  limit?: number | null;
}

export const flowsPath = (p: FlowsParams = {}) => apiPath("/api/flows", { ...p });
export const flowsSummaryPath = (window?: FlowWindow | null) => apiPath("/api/flows/summary", { window });
export const destinationsPath = (
  p: { window?: FlowWindow | null; scope?: "public" | "all" | null; unnamed?: boolean; q?: string | null; sort?: DestinationSort | null; limit?: number | null } = {},
) => apiPath("/api/destinations", { ...p, unnamed: p.unnamed ? "true" : null });
export const interfacesPath = () => "/api/interfaces";
export const listenersPath = () => "/api/listeners";
export const dnsPath = (p: { window?: FlowWindow | null; q?: string | null; rcode?: string | null; limit?: number | null } = {}) => apiPath("/api/dns", { ...p });
export const connEventsPath = (p: { window?: FlowWindow | null; kind?: string | null; limit?: number | null } = {}) => apiPath("/api/conn_events", { ...p });

export const getFlows = (p?: FlowsParams, signal?: AbortSignal) => get<FlowRow[]>(flowsPath(p), signal);
export const getFlowsSummary = (window?: FlowWindow | null, signal?: AbortSignal) => get<FlowsSummary>(flowsSummaryPath(window), signal);
export const getInterfaces = (signal?: AbortSignal) => get<InterfacesInfo>(interfacesPath(), signal);
export const getListeners = (signal?: AbortSignal) => get<Listener[]>(listenersPath(), signal);
export const getDns = (p?: Parameters<typeof dnsPath>[0], signal?: AbortSignal) => get<DnsInfo>(dnsPath(p), signal);
export const getConnEvents = (p?: Parameters<typeof connEventsPath>[0], signal?: AbortSignal) => get<ConnEvent[]>(connEventsPath(p), signal);

// ---------------------------------------------------------------------------
// usePoll

// Last successful payload per path: navigating back to a page renders the
// previous frame immediately instead of flashing an empty state.
const cache = new Map<string, unknown>();

function useDocumentVisible(): boolean {
  return useSyncExternalStore(
    (cb) => {
      document.addEventListener("visibilitychange", cb);
      return () => document.removeEventListener("visibilitychange", cb);
    },
    () => document.visibilityState !== "hidden",
  );
}

export interface PollState<T> {
  data: T | undefined;
  error: ApiError | null;
  /** True while the first request for this path is in flight and nothing is cached. */
  loading: boolean;
  /** True when `data` belongs to a previous path (params changed, new data pending). */
  stale: boolean;
  updatedAt: number | null;
  refresh: () => void;
}

/**
 * Poll a GET endpoint every `intervalMs`. Pauses while the tab is hidden and
 * refetches immediately when it becomes visible again. Pass `null` to disable.
 */
export function usePoll<T>(path: string | null, intervalMs = 5000): PollState<T> {
  const visible = useDocumentVisible();
  const [state, setState] = useState<{ path: string | null; data: T | undefined; error: ApiError | null; updatedAt: number | null }>(() => ({
    path,
    data: path ? (cache.get(path) as T | undefined) : undefined,
    error: null,
    updatedAt: null,
  }));
  const [nonce, setNonce] = useState(0);
  const refresh = useCallback(() => setNonce((n) => n + 1), []);
  const latestPath = useRef(path);
  latestPath.current = path;

  useEffect(() => {
    if (!path || !visible) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let ctrl: AbortController | undefined;

    const cached = cache.get(path) as T | undefined;
    if (cached !== undefined) {
      setState((s) => (s.path === path ? s : { path, data: cached, error: null, updatedAt: s.updatedAt }));
    }

    const run = async () => {
      ctrl = new AbortController();
      try {
        const data = await get<T>(path, ctrl.signal);
        if (cancelled) return;
        cache.set(path, data);
        setState({ path, data, error: null, updatedAt: Date.now() });
      } catch (e) {
        if (cancelled || (e as Error).name === "AbortError") return;
        const err = e instanceof ApiError ? e : new ApiError(0, String(e));
        // Keep the previous frame on transient errors; drop it on 4xx for this path.
        setState((s) => ({
          path,
          data: err.status >= 400 && err.status < 500 ? undefined : s.data,
          error: err,
          updatedAt: s.updatedAt,
        }));
      }
      if (!cancelled && intervalMs > 0) timer = setTimeout(run, intervalMs);
    };
    run();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
      ctrl?.abort();
    };
  }, [path, intervalMs, visible, nonce]);

  const stale = state.path !== path;
  return {
    data: state.data,
    error: stale ? null : state.error,
    loading: state.data === undefined && !state.error,
    stale,
    updatedAt: state.updatedAt,
    refresh,
  };
}
