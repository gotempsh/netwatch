// The five sections of the UI and the pages (tabs) inside each. Hash routes stay
// stable: pages that moved keep working through REDIRECTS, query included, so
// bookmarks, the docs and links from older daemons still land on the right tab.

export interface Tab {
  path: string;
  label: string;
}

export interface Section {
  key: string;
  label: string;
  path: string;
  tabs: Tab[];
}

export const SECTIONS: Section[] = [
  { key: "status", label: "Status", path: "/", tabs: [] },
  {
    key: "threats",
    label: "Threats",
    path: "/threats",
    tabs: [
      { path: "/threats", label: "Timeline" },
      { path: "/threats/sources", label: "Sources" },
      { path: "/threats/alerts", label: "Alerts" },
      { path: "/threats/ssh", label: "SSH logins" },
      { path: "/threats/networks", label: "Countries & networks" },
    ],
  },
  {
    key: "traffic",
    label: "Traffic",
    path: "/traffic",
    tabs: [
      { path: "/traffic", label: "Map" },
      { path: "/traffic/connections", label: "Connections" },
      { path: "/traffic/destinations", label: "Destinations" },
      { path: "/traffic/dns", label: "DNS" },
    ],
  },
  {
    key: "exposure",
    label: "Exposure",
    path: "/exposure",
    tabs: [
      { path: "/exposure", label: "Listening ports" },
      { path: "/exposure/interfaces", label: "Interfaces & sensor" },
    ],
  },
  {
    key: "bans",
    label: "Bans",
    path: "/bans",
    tabs: [
      { path: "/bans", label: "Bans & proposals" },
      { path: "/bans/policy", label: "Policy & AI" },
    ],
  },
];

/** Old paths (and section paths without a page of their own) to where they live now. */
export const REDIRECTS: Record<string, string> = {
  "/overview": "/",
  "/sources": "/threats/sources",
  "/alerts": "/threats/alerts",
  "/ssh": "/threats/ssh",
  "/geo": "/threats/networks",
  "/connections": "/traffic/connections",
  "/destinations": "/traffic/destinations",
  "/dns": "/traffic/dns",
  "/listeners": "/exposure",
  "/interfaces": "/exposure/interfaces",
  "/policy": "/bans/policy",
};

/** The section a path belongs to. A source page (/sources/<ip>) is part of Threats. */
export function sectionOf(path: string): Section {
  const first = path.split("/")[1] ?? "";
  if (first === "sources") return SECTIONS[1];
  return SECTIONS.find((s) => s.path !== "/" && s.path === `/${first}`) ?? SECTIONS[0];
}
