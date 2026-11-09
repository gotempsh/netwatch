import { useEffect } from "react";
import type { Overview as OverviewData } from "./api/types";
import { usePoll, useConnectivity } from "./api/client";
import { setServerNow } from "./lib/clock";
import { useRoute } from "./lib/router";
import { Badge, RelTime } from "./components/ui";
import Overview from "./pages/Overview";
import Sources from "./pages/Sources";
import SourceDetail from "./pages/SourceDetail";
import Alerts from "./pages/Alerts";
import Ssh from "./pages/Ssh";
import Bans from "./pages/Bans";
import Geo from "./pages/Geo";
import Policy from "./pages/Policy";
import Connections from "./pages/Connections";
import Destinations from "./pages/Destinations";
import Interfaces from "./pages/Interfaces";
import Listeners from "./pages/Listeners";
import Dns from "./pages/Dns";

const NAV: { path: string; label: string; match: (p: string) => boolean }[] = [
  { path: "/", label: "Overview", match: (p) => p === "/" },
  { path: "/sources", label: "Sources", match: (p) => p.startsWith("/sources") },
  { path: "/connections", label: "Connections", match: (p) => p === "/connections" || p === "/destinations" },
  { path: "/dns", label: "DNS", match: (p) => p === "/dns" },
  { path: "/interfaces", label: "Network", match: (p) => p === "/interfaces" || p === "/listeners" },
  { path: "/alerts", label: "Alerts", match: (p) => p === "/alerts" },
  { path: "/ssh", label: "SSH", match: (p) => p === "/ssh" },
  { path: "/bans", label: "Bans & proposals", match: (p) => p === "/bans" },
  { path: "/geo", label: "Geography", match: (p) => p === "/geo" },
  { path: "/policy", label: "Policy & AI", match: (p) => p === "/policy" },
];

function ConnectivityBanner() {
  const c = useConnectivity();
  if (c.reachable) return null;
  return (
    <div className="banner" role="status">
      <span className="banner-dot" aria-hidden />
      <strong>Daemon unreachable</strong>
      <span className="muted">
        {c.lastError ? ` (${c.lastError})` : ""}. Showing last known data and retrying.
        {c.lastOk ? <> Last successful update <RelTime ts={c.lastOk / 1000} />.</> : null}
      </span>
    </div>
  );
}

export default function App() {
  const route = useRoute();
  // Light poll for the shell: nav counters, mode badge and daemon clock offset.
  const ov = usePoll<OverviewData>("/api/overview", 10_000);
  useEffect(() => {
    if (ov.data) setServerNow(ov.data.now);
  }, [ov.data]);

  useEffect(() => {
    window.scrollTo(0, 0);
    // On narrow screens the nav scrolls sideways; keep the current page in view.
    document.querySelector(".nav a.active")?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [route.path]);

  const pending = ov.data?.counts.proposals_pending ?? 0;
  const p = route.path.replace(/\/+$/, "") || "/";

  let page;
  if (p === "/") page = <Overview />;
  else if (p === "/sources") page = <Sources />;
  else if (route.parts[0] === "sources" && route.parts[1]) page = <SourceDetail ip={route.parts.slice(1).join("/")} />;
  else if (p === "/connections") page = <Connections />;
  else if (p === "/destinations") page = <Destinations />;
  else if (p === "/dns") page = <Dns />;
  else if (p === "/interfaces") page = <Interfaces />;
  else if (p === "/listeners") page = <Listeners />;
  else if (p === "/alerts") page = <Alerts />;
  else if (p === "/ssh") page = <Ssh />;
  else if (p === "/bans") page = <Bans />;
  else if (p === "/geo") page = <Geo />;
  else if (p === "/policy") page = <Policy />;
  else
    page = (
      <div className="page">
        <h1>Not found</h1>
        <p>
          No page at <code>{route.path}</code>. <a href="#/">Back to overview</a>.
        </p>
      </div>
    );

  return (
    <div className="app">
      <header className="topbar">
        <a className="brand" href="#/">
          <svg width="18" height="18" viewBox="0 0 16 16" aria-hidden>
            <circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" strokeWidth="1.6" />
            <circle cx="8" cy="8" r="2" fill="currentColor" />
          </svg>
          netwatch
        </a>
        <nav className="nav" aria-label="Main">
          {NAV.map((n) => (
            <a key={n.path} href={`#${n.path}`} className={n.match(p) ? "active" : ""} aria-current={n.match(p) ? "page" : undefined}>
              {n.label}
              {n.path === "/bans" && pending > 0 && <span className="nav-count" title={`${pending} pending proposals`}>{pending}</span>}
            </a>
          ))}
        </nav>
        <div className="topbar-meta">
          {ov.data && (
            <>
              <span className="mono muted" title={`netwatch ${ov.data.version}`}>
                {ov.data.host}
              </span>
              <Badge tone={ov.data.mode === "enforce" ? "critical" : "accent"} title={ov.data.mode === "enforce" ? "Bans are enforced" : "Observe only: nothing is dropped by policy"}>
                {ov.data.mode}
              </Badge>
            </>
          )}
          <span className="readonly-tag" title="This UI is read-only. Actions are done with the netwatch CLI on the server.">
            read-only
          </span>
        </div>
      </header>
      <ConnectivityBanner />
      <main className="main">{page}</main>
    </div>
  );
}
