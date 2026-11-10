// The five sections of the UI and the pages (tabs) inside each. Hash routes stay
// stable: pages that moved keep working through REDIRECTS, query included, so
// bookmarks, the docs and links from older daemons still land on the right tab.

import type { IconName } from "../components/icons";

export interface Tab {
  path: string;
  label: string;
  icon: IconName;
}

export interface Section {
  key: string;
  label: string;
  path: string;
  icon: IconName;
  tabs: Tab[];
}

export const SECTIONS: Section[] = [
  { key: "status", icon: "status", label: "Status", path: "/", tabs: [] },
  {
    key: "threats",
    icon: "threats",
    label: "Threats",
    path: "/threats",
    tabs: [
      { path: "/threats", label: "Timeline", icon: "timeline" },
      { path: "/threats/sources", label: "Sources", icon: "sources" },
      { path: "/threats/alerts", label: "Alerts", icon: "alerts" },
      { path: "/threats/ssh", label: "SSH logins", icon: "ssh" },
      { path: "/threats/networks", label: "Countries & networks", icon: "networks" },
    ],
  },
  {
    key: "traffic",
    icon: "traffic",
    label: "Traffic",
    path: "/traffic",
    tabs: [
      { path: "/traffic", label: "Map", icon: "map" },
      { path: "/traffic/connections", label: "Connections", icon: "connections" },
      { path: "/traffic/destinations", label: "Destinations", icon: "destinations" },
      { path: "/traffic/dns", label: "DNS", icon: "dns" },
    ],
  },
  {
    key: "exposure",
    icon: "exposure",
    label: "Exposure",
    path: "/exposure",
    tabs: [
      { path: "/exposure", label: "Listening ports", icon: "ports" },
      { path: "/exposure/interfaces", label: "Interfaces & sensor", icon: "interfaces" },
    ],
  },
  {
    key: "bans",
    icon: "bans",
    label: "Bans",
    path: "/bans",
    tabs: [
      { path: "/bans", label: "Bans & proposals", icon: "proposals" },
      { path: "/bans/policy", label: "Policy & AI", icon: "policy" },
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
