// Tiny hash router: #/, #/sources, #/sources/<ip>, #/connections, #/dns, #/interfaces, #/listeners,
// #/alerts, #/ssh, #/bans, #/geo, #/policy
// Optional query string after the path: #/sources?sort=syn&q=cn
import { useCallback, useSyncExternalStore } from "react";

export interface Route {
  path: string; // e.g. "/sources"
  parts: string[]; // decoded path segments, e.g. ["sources", "1.2.3.4"]
  query: URLSearchParams;
}

function parse(hash: string): Route {
  const raw = hash.replace(/^#/, "") || "/";
  const [p, q = ""] = raw.split("?", 2);
  const path = p.startsWith("/") ? p : `/${p}`;
  const parts = path
    .split("/")
    .filter(Boolean)
    .map((s) => {
      try {
        return decodeURIComponent(s);
      } catch {
        return s;
      }
    });
  return { path, parts, query: new URLSearchParams(q) };
}

function subscribe(cb: () => void) {
  window.addEventListener("hashchange", cb);
  return () => window.removeEventListener("hashchange", cb);
}

export function useRoute(): Route {
  const hash = useSyncExternalStore(subscribe, () => window.location.hash);
  return parse(hash);
}

export function href(path: string, query?: Record<string, string | number | boolean | null | undefined>): string {
  let h = `#${path}`;
  if (query) {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) {
      if (v === null || v === undefined || v === "" || v === false) continue;
      qs.set(k, v === true ? "1" : String(v));
    }
    const s = qs.toString();
    if (s) h += `?${s}`;
  }
  return h;
}

export const sourceHref = (ip: string) => `#/sources/${encodeURIComponent(ip)}`;

export function navigate(h: string, replace = false) {
  if (replace) {
    const url = `${window.location.pathname}${window.location.search}${h}`;
    window.history.replaceState(null, "", url);
    window.dispatchEvent(new HashChangeEvent("hashchange"));
  } else {
    window.location.hash = h;
  }
}

/** Read/write query params of the current route (replace, no history spam). */
export function useQueryState(): [URLSearchParams, (patch: Record<string, string | number | boolean | null | undefined>) => void] {
  const route = useRoute();
  const set = useCallback(
    (patch: Record<string, string | number | boolean | null | undefined>) => {
      const cur = parse(window.location.hash);
      const merged: Record<string, string> = {};
      cur.query.forEach((v, k) => (merged[k] = v));
      for (const [k, v] of Object.entries(patch)) {
        if (v === null || v === undefined || v === "" || v === false) delete merged[k];
        else merged[k] = v === true ? "1" : String(v);
      }
      navigate(href(cur.path, merged), true);
    },
    [],
  );
  return [route.query, set];
}
