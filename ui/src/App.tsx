import { useEffect, type ReactNode } from "react";
import type { Overview as OverviewData } from "./api/types";
import { usePoll, useConnectivity } from "./api/client";
import { setServerNow } from "./lib/clock";
import { href, navigate, useRoute } from "./lib/router";
import { modeChip } from "./lib/mode";
import { REDIRECTS, SECTIONS, sectionOf } from "./lib/sections";
import { Badge, RelTime } from "./components/ui";
import Status from "./pages/Status";
import Threats from "./pages/Threats";
import Sources from "./pages/Sources";
import SourceDetail from "./pages/SourceDetail";
import Alerts from "./pages/Alerts";
import Ssh from "./pages/Ssh";
import Bans from "./pages/Bans";
import Geo from "./pages/Geo";
import Policy from "./pages/Policy";
import TrafficMap from "./pages/TrafficMap";
import Connections from "./pages/Connections";
import Destinations from "./pages/Destinations";
import Interfaces from "./pages/Interfaces";
import Listeners from "./pages/Listeners";
import Dns from "./pages/Dns";

const PAGES: Record<string, () => ReactNode> = {
  "/": () => <Status />,
  "/threats": () => <Threats />,
  "/threats/sources": () => <Sources />,
  "/threats/alerts": () => <Alerts />,
  "/threats/ssh": () => <Ssh />,
  "/threats/networks": () => <Geo />,
  "/traffic": () => <TrafficMap />,
  "/traffic/connections": () => <Connections />,
  "/traffic/destinations": () => <Destinations />,
  "/traffic/dns": () => <Dns />,
  "/exposure": () => <Listeners />,
  "/exposure/interfaces": () => <Interfaces />,
  "/bans": () => <Bans />,
  "/bans/policy": () => <Policy />,
};

// The hosted demo on the docs site (`npm run build:demo`) says on every page that
// it isn't a real server. Plain `dev:mock` stays unmarked for the screenshots.
const DEMO = import.meta.env.VITE_DEMO === "1";

function DemoBanner() {
  return (
    <div className="banner banner-demo" role="note">
      <strong>Demo data — not a real server.</strong>
      <span className="muted">Everything here is generated in your browser.</span>
      <a href={import.meta.env.VITE_INSTALL_URL || "https://gotempsh.github.io/netwatch/installation/"}>Install netwatch</a>
    </div>
  );
}

function ConnectivityBanner({ hidden }: { hidden: boolean }) {
  const c = useConnectivity();
  if (c.reachable || hidden) return null;
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
  // Light poll for the shell: nav counters, mode chip and daemon clock offset.
  const ov = usePoll<OverviewData>("/api/overview", 10_000);
  useEffect(() => {
    if (ov.data) setServerNow(ov.data.now);
  }, [ov.data]);

  const raw = route.path.replace(/\/+$/, "") || "/";
  const moved = REDIRECTS[raw];
  const p = moved ?? raw;
  // Keep the old address working, but show the new one so it gets bookmarked.
  useEffect(() => {
    if (!moved) return;
    const q: Record<string, string> = {};
    route.query.forEach((v, k) => (q[k] = v));
    navigate(href(moved, q), true);
  }, [moved, route.query]);

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [p]);

  const pending = ov.data?.counts.proposals_pending ?? 0;
  const section = sectionOf(p);

  let page: ReactNode;
  if (PAGES[p]) page = PAGES[p]();
  else if (route.parts[0] === "sources" && route.parts[1]) page = <SourceDetail ip={route.parts.slice(1).join("/")} />;
  else
    page = (
      <div className="page">
        <h1>Not found</h1>
        <p>
          No page at <code>{route.path}</code>. <a href="#/">Back to Status</a>.
        </p>
      </div>
    );

  const chip = ov.data ? modeChip(ov.data) : null;
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
          {SECTIONS.map((s) => {
            const on = s.key === section.key;
            return (
              <a key={s.key} href={`#${s.path}`} className={on ? "active" : ""} aria-current={on ? "page" : undefined}>
                {s.label}
                {s.key === "bans" && pending > 0 && (
                  <span className="nav-count" aria-label={`${pending} waiting for approval`} title={`${pending} pending proposals`}>
                    {pending}
                  </span>
                )}
              </a>
            );
          })}
        </nav>
        <div className="topbar-meta">
          {ov.data && chip && (
            <>
              <span className="mono muted" title={`netwatch ${ov.data.version}`}>
                {ov.data.host}
              </span>
              <Badge tone={ov.data.mode === "enforce" ? "critical" : "accent"} title={chip.title}>
                {chip.label}
              </Badge>
            </>
          )}
          <span className="readonly-tag" title="This UI is read-only. Actions are done with the netwatch CLI on the server.">
            read-only
          </span>
        </div>
      </header>
      {section.tabs.length > 1 && (
        <nav className="subnav" aria-label={`${section.label} pages`}>
          <div className="subnav-inner">
            {section.tabs.map((t) => {
              const on = t.path === p;
              return (
                <a key={t.path} href={`#${t.path}`} className={on ? "active" : ""} aria-current={on ? "page" : undefined}>
                  {t.label}
                </a>
              );
            })}
          </div>
        </nav>
      )}
      {DEMO && <DemoBanner />}
      {/* Status says it in its verdict when the daemon stops answering. */}
      <ConnectivityBanner hidden={p === "/"} />
      <main className="main">{page}</main>
    </div>
  );
}
