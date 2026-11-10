// Outline icons for the section and page tabs, drawn on a 16px grid with a
// 1.5px stroke in the text colour so they read as part of the label.

const PATHS = {
  // sections
  status: <path d="M1.5 8.5h3l2-5 3 9 2-4h3" />,
  threats: (
    <>
      <path d="M8 1.75 2.75 3.75v4c0 3.2 2.2 5.4 5.25 6.5 3.05-1.1 5.25-3.3 5.25-6.5v-4z" />
      <path d="M8 5.25v3.25" />
      <path d="M8 10.9v.1" />
    </>
  ),
  traffic: (
    <>
      <path d="M2 5.5h11M10.5 3 13 5.5 10.5 8" />
      <path d="M14 10.5H3M5.5 8 3 10.5 5.5 13" />
    </>
  ),
  exposure: (
    <>
      <circle cx="8" cy="8" r="1.5" />
      <path d="M5.2 5.2a4 4 0 0 0 0 5.6M10.8 5.2a4 4 0 0 1 0 5.6" />
      <path d="M3 3a7 7 0 0 0 0 10M13 3a7 7 0 0 1 0 10" />
    </>
  ),
  bans: (
    <>
      <circle cx="8" cy="8" r="6" />
      <path d="M3.75 12.25l8.5-8.5" />
    </>
  ),
  // Threats
  timeline: (
    <>
      <path d="M2 4h5M2 8h9M2 12h12" />
      <circle cx="9.5" cy="4" r="1" />
    </>
  ),
  sources: (
    <>
      <circle cx="8" cy="8" r="5.5" />
      <circle cx="8" cy="8" r="2" />
      <path d="M8 1v2.5M8 12.5V15M1 8h2.5M12.5 8H15" />
    </>
  ),
  alerts: (
    <>
      <path d="M4 11V7a4 4 0 0 1 8 0v4l1.25 1.5h-10.5z" />
      <path d="M6.5 14.25h3" />
    </>
  ),
  ssh: (
    <>
      <rect x="1.75" y="2.75" width="12.5" height="10.5" rx="1.5" />
      <path d="M4.5 6.5 6.5 8.25 4.5 10M8.5 10.25h3" />
    </>
  ),
  networks: (
    <>
      <circle cx="8" cy="8" r="6" />
      <path d="M2 8h12" />
      <path d="M8 2c1.7 1.7 2.5 3.7 2.5 6s-.8 4.3-2.5 6c-1.7-1.7-2.5-3.7-2.5-6S6.3 3.7 8 2z" />
    </>
  ),
  // Traffic
  map: (
    <>
      <circle cx="3.5" cy="4" r="1.75" />
      <circle cx="3.5" cy="12" r="1.75" />
      <circle cx="12.5" cy="8" r="1.75" />
      <path d="M5.25 4.5c3 .3 3.5 3.2 5.5 3.5M5.25 11.5c3-.3 3.5-3.2 5.5-3.5" />
    </>
  ),
  connections: (
    <>
      <path d="M6.75 9.25a2.75 2.75 0 0 0 3.9 0l2-2a2.75 2.75 0 0 0-3.9-3.9l-.6.6" />
      <path d="M9.25 6.75a2.75 2.75 0 0 0-3.9 0l-2 2a2.75 2.75 0 0 0 3.9 3.9l.6-.6" />
    </>
  ),
  destinations: (
    <>
      <path d="M12.5 9v3.25a1.25 1.25 0 0 1-1.25 1.25h-7.5a1.25 1.25 0 0 1-1.25-1.25v-7.5A1.25 1.25 0 0 1 3.75 3.5H7" />
      <path d="M9.5 2h4.5v4.5M14 2 7.5 8.5" />
    </>
  ),
  dns: (
    <>
      <path d="M2.25 3.75h7.5l3.5 4.25-3.5 4.25h-7.5z" />
      <path d="M5 8h2.5" />
    </>
  ),
  // Exposure
  ports: (
    <>
      <rect x="2" y="3.5" width="12" height="9" rx="1.25" />
      <path d="M5 12.5v-3h6v3M6.5 6v1M9.5 6v1" />
    </>
  ),
  interfaces: (
    <>
      <rect x="4" y="4" width="8" height="8" rx="1" />
      <path d="M6.5 1.5V4M9.5 1.5V4M6.5 12v2.5M9.5 12v2.5M1.5 6.5H4M1.5 9.5H4M12 6.5h2.5M12 9.5h2.5" />
    </>
  ),
  // Bans
  proposals: (
    <>
      <path d="M2 4.25 3.25 5.5 5.5 3M2 10.25l1.25 1.25L5.5 9" />
      <path d="M8 4.25h6M8 10.25h6" />
    </>
  ),
  policy: (
    <>
      <path d="M2 4.5h5.5M11.5 4.5H14M2 11.5h2.5M8.5 11.5H14" />
      <circle cx="9.5" cy="4.5" r="1.75" />
      <circle cx="6.5" cy="11.5" r="1.75" />
    </>
  ),
};

export type IconName = keyof typeof PATHS;

export function Icon({ name, size = 16 }: { name: IconName; size?: number }) {
  return (
    <svg
      className="icon"
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      {PATHS[name]}
    </svg>
  );
}
