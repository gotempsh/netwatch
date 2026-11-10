// Builds the docs site from content/*.md into dist/. Every page is also
// published as Markdown (/<page>.md) for agents, with llms.txt listing them
// and llms-full.txt holding all of them.
//
//   BASE      path the site is served under (default "/"; "/netwatch/" on GitHub Pages)
//   SITE_URL  absolute URL of the site, used in the Markdown copies and llms.txt
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Marked } from "marked";
import { createHighlighter } from "shiki";
import { agentPrompt } from "./agent-prompt.mjs";
import { harnesses } from "./harness-logos.mjs";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(ROOT, "dist");
const BASE = (process.env.BASE ?? "/").replace(/\/?$/, "/");
const SITE_URL = (process.env.SITE_URL ?? "https://gotempsh.github.io/netwatch").replace(/\/$/, "");
const REPO = "gotempsh/netwatch";
const VERSION = fs
  .readFileSync(path.join(ROOT, "../netwatch/Cargo.toml"), "utf8")
  .match(/^version\s*=\s*"([^"]+)"/m)[1];

const NAV = [
  { title: "Getting started", pages: ["index", "installation", "quick-start", "web-ui", "security", "comparison"] },
  { title: "Running it", pages: ["docker", "macos"] },
  { title: "Features", pages: ["detection", "connections", "bans-and-policy", "exploits", "ai-analysis", "agents", "slack", "opentelemetry", "temps"] },
  { title: "Reference", pages: ["cli", "configuration", "api", "development"] },
];

// ---- pages -----------------------------------------------------------------

function frontmatter(src) {
  const m = src.match(/^---\n([\s\S]*?)\n---\n/);
  if (!m) return [{}, src];
  const meta = Object.fromEntries(
    m[1].split("\n").map((l) => {
      const i = l.indexOf(":");
      return [l.slice(0, i).trim(), l.slice(i + 1).trim()];
    }),
  );
  return [meta, src.slice(m[0].length)];
}

const pages = NAV.flatMap((s) =>
  s.pages.map((slug) => {
    const file = `${slug}.md`;
    const [meta, body] = frontmatter(fs.readFileSync(path.join(ROOT, "content", file), "utf8"));
    if (!meta.title) throw new Error(`${file}: no title`);
    return { slug, file, section: s.title, title: meta.title, nav: meta.nav ?? meta.title, description: meta.description ?? "", body };
  }),
);

// Trailing slash: GitHub Pages redirects /page to /page/ otherwise.
const href = (slug) => (slug === "index" ? BASE : `${BASE}${slug}/`);
const mdHref = (slug) => `${BASE}${slug}.md`;

// ---- Markdown -> HTML --------------------------------------------------------

const highlighter = await createHighlighter({
  themes: ["github-light", "github-dark-default"],
  langs: ["shell", "toml", "json", "text", "http"],
});

const slugify = (s) =>
  s
    .toLowerCase()
    .replace(/<[^>]+>/g, "")
    .replace(/&[a-z]+;/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");

const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

// Screenshots exist as name-dark.png and name-light.png; pages refer to name.png.
const shot = (src) => {
  const m = src.match(/^\/screenshots\/(.+)\.png$/);
  return m && fs.existsSync(path.join(ROOT, "public/screenshots", `${m[1]}-dark.png`)) ? m[1] : null;
};

const internal = (url) => url.startsWith("/") && !url.startsWith("//");
const localUrl = (url) => {
  if (!internal(url)) return url;
  const [p, hash] = url.slice(1).split("#");
  const page = p && !p.includes(".") && !p.endsWith("/") ? `${p}/` : p;
  return BASE + page + (hash ? `#${hash}` : "");
};

const ICON_COPY = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
const ICON_CHECK = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>`;
const ICON_MD = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="5" width="20" height="14" rx="2"/><path d="M6 15V9l2.5 3L11 9v6M16 9v6m-2.5-2.5L16 15l2.5-2.5" stroke-linecap="round"/></svg>`;
const ICON_GH = `<svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>`;
const ICON_CHEVRON = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>`;
const ICON_SPARKLES = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9.94 15.5A2 2 0 0 0 8.5 14.06l-6.14-1.58a.5.5 0 0 1 0-.96L8.5 9.94A2 2 0 0 0 9.94 8.5l1.58-6.14a.5.5 0 0 1 .96 0l1.58 6.14a2 2 0 0 0 1.44 1.44l6.14 1.58a.5.5 0 0 1 0 .96L15.5 14.06a2 2 0 0 0-1.44 1.44l-1.58 6.14a.5.5 0 0 1-.96 0z"/><path d="M20 3v4M22 5h-4"/></svg>`;
const LOGO = `<svg width="18" height="18" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" stroke-width="1.6"/><circle cx="8" cy="8" r="2" fill="currentColor"/></svg>`;

// ---- the set-up prompt for coding agents -------------------------------------

const PROMPT_TITLE = "Copy a prompt that installs netwatch, for your coding agent";

// <!-- copy-prompt --> on a page: the agents it is for, one line, the button,
// and the prompt underneath so nobody pastes one they haven't read.
const promptCard = `<div class="prompt-card">
  <div class="prompt-row">
    <ul class="harnesses" aria-label="Works with ${harnesses.map((h) => h.name).join(", ")} and other coding agents">${harnesses
      .map((h) => `<li title="${esc(h.name)}">${h.svg}</li>`)
      .join("")}</ul>
    <p>Paste it into your coding agent to install netwatch.</p>
    <button class="prompt-copy" type="button" data-copy-prompt>${ICON_SPARKLES}${ICON_CHECK}<span>Copy prompt</span></button>
  </div>
  <details class="prompt-text"><summary>Read the prompt</summary><pre>${esc(agentPrompt)}</pre></details>
</div>`;

// The same prompt in the top bar of every page. Where the browser refuses the
// clipboard, the prompt opens under the button to be selected by hand.
const promptButton = `<div class="prompt-top">
  <button class="prompt-pill" type="button" data-copy-prompt title="${PROMPT_TITLE}">${ICON_SPARKLES}${ICON_CHECK}<span>Copy prompt</span></button>
  <div class="prompt-pop" hidden><p>Your browser refused the clipboard. Select the prompt and copy it:</p><pre>${esc(agentPrompt)}</pre></div>
</div>`;

function render(md) {
  const toc = [];
  const marked = new Marked({
    gfm: true,
    renderer: {
      heading({ tokens, depth }) {
        const html = this.parser.parseInline(tokens);
        const id = slugify(html);
        if (depth === 2 || depth === 3) toc.push({ depth, id, text: html.replace(/<[^>]+>/g, "") });
        return `<h${depth} id="${id}"><a class="anchor" href="#${id}">${html}</a></h${depth}>\n`;
      },
      code({ text, lang }) {
        // Drawn in the browser by assets/app.js; the source shows until then.
        if (lang === "mermaid") return `<figure class="diagram"><pre class="mermaid">${esc(text)}</pre></figure>\n`;
        const language = { sh: "shell", bash: "shell", "": "text" }[lang ?? ""] ?? lang;
        const html = highlighter.codeToHtml(text, {
          lang: highlighter.getLoadedLanguages().includes(language) ? language : "text",
          themes: { light: "github-light", dark: "github-dark-default" },
          defaultColor: false,
        });
        return `<div class="code">${html}<button class="copy-code" type="button" aria-label="Copy code">${ICON_COPY}${ICON_CHECK}</button></div>\n`;
      },
      link({ href: url, title, tokens }) {
        const text = this.parser.parseInline(tokens);
        const ext = /^https?:/.test(url);
        return `<a href="${esc(localUrl(url))}"${title ? ` title="${esc(title)}"` : ""}${ext ? ' rel="noopener"' : ""}>${text}</a>`;
      },
      image({ href: src, title, text }) {
        const name = shot(src);
        const cap = title ? `<figcaption>${esc(title)}</figcaption>` : "";
        if (!name) return `<figure><img src="${esc(localUrl(src))}" alt="${esc(text)}" loading="lazy">${cap}</figure>`;
        const img = (scheme) => {
          const file = `${BASE}screenshots/${name}-${scheme}.png`;
          return `<a class="shot shot-${scheme}" href="${file}"><img src="${file}" alt="${esc(text)}" width="1920" height="1200" loading="lazy"></a>`;
        };
        return `<figure class="screenshot">${img("light")}${img("dark")}${cap}</figure>`;
      },
      table(token) {
        const head = token.header.map((c) => `<th${c.align ? ` style="text-align:${c.align}"` : ""}>${this.parser.parseInline(c.tokens)}</th>`).join("");
        const rows = token.rows
          .map((r) => `<tr>${r.map((c) => `<td${c.align ? ` style="text-align:${c.align}"` : ""}>${this.parser.parseInline(c.tokens)}</td>`).join("")}</tr>`)
          .join("\n");
        return `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table></div>\n`;
      },
    },
  });
  // Paragraphs holding just an image would wrap a <figure> in <p>, a list of
  // links after <!-- cards --> renders as cards, and each ### between
  // <!-- steps --> and <!-- /steps --> becomes a numbered step.
  const html = marked
    .parse(md)
    .replace(/<p>(<figure[\s\S]*?<\/figure>)<\/p>/g, "$1")
    .replace(/<!-- cards -->\s*<ul>/g, '<ul class="cards">')
    .replace(/<!-- copy-prompt -->/g, promptCard)
    .replace(/<!-- steps -->([\s\S]*?)<!-- \/steps -->/g, (_, inner) => {
      const steps = inner.split(/(?=<h3 )/).filter((s) => s.trim());
      return `<ol class="steps">${steps.map((s) => `<li>${s}</li>`).join("")}</ol>`;
    });
  return { html, toc };
}

// ---- Markdown for agents -----------------------------------------------------

// Absolute links and images, so the copy works pasted anywhere.
function agentMarkdown(p) {
  const body = p.body
    .replace(/<!-- (cards|steps|\/steps) -->\n/g, "")
    .replace(/<!-- copy-prompt -->/g, () => `\`\`\`text\n${agentPrompt}\n\`\`\``)
    .replace(/\]\((\/screenshots\/[^)\s]+)\.png(\s+"[^"]*")?\)/g, (_, s) => `](${SITE_URL}${s}-dark.png)`)
    .replace(/\]\((\/[^)\s]*)/g, (_, u) => {
      const [pathPart, hash = ""] = u.split("#");
      const slug = pathPart.slice(1) || "index";
      // Screenshots and the demo (built into dist/demo/ by ui/) aren't pages.
      const target = /^\/(screenshots|demo)\//.test(pathPart) ? `${SITE_URL}${pathPart}` : `${SITE_URL}/${slug}.md`;
      return `](${target}${hash ? `#${hash}` : ""}`;
    });
  return `# ${p.title}\n\n> ${p.description}\n\n${body.trim()}\n`;
}

// ---- layout ------------------------------------------------------------------

function sidebar(current) {
  return NAV.map(
    (s) =>
      `<div class="nav-group"><div class="nav-title">${s.title}</div><ul>${s.pages
        .map((slug) => {
          const p = pages.find((x) => x.slug === slug);
          return `<li><a href="${href(slug)}"${slug === current ? ' class="active" aria-current="page"' : ""}>${p.nav}</a></li>`;
        })
        .join("")}</ul></div>`,
  ).join("");
}

function copyMenu(p) {
  return `<div class="copy-page">
  <button class="copy-main" type="button" data-copy-page>${ICON_COPY}${ICON_CHECK}<span>Copy page</span></button>
  <button class="copy-toggle" type="button" aria-label="More options" aria-haspopup="menu" aria-expanded="false">${ICON_CHEVRON}</button>
  <div class="copy-menu" role="menu" hidden>
    <button type="button" role="menuitem" data-copy-page>${ICON_COPY}<span><b>Copy page</b><small>Copy page as Markdown for LLMs</small></span></button>
    <a role="menuitem" href="${mdHref(p.slug)}" target="_blank">${ICON_MD}<span><b>View as Markdown</b><small>Open this page as plain text</small></span></a>
    <a role="menuitem" href="https://github.com/${REPO}/edit/main/site/content/${p.file}" target="_blank" rel="noopener">${ICON_GH}<span><b>Edit this page on GitHub</b><small>Suggest changes to this page</small></span></a>
  </div>
</div>`;
}

function layout(p, i, html, toc, bare = false) {
  const prev = pages[i - 1];
  const next = pages[i + 1];
  const pager = `<nav class="pager">${prev ? `<a class="prev" href="${href(prev.slug)}"><small>Previous</small>${prev.nav}</a>` : "<span></span>"}${
    next ? `<a class="next" href="${href(next.slug)}"><small>Next</small>${next.nav}</a>` : ""
  }</nav>`;
  const tocHtml = toc.length
    ? `<div class="toc-title">On this page</div><ul>${toc.map((t) => `<li class="d${t.depth}"><a href="#${t.id}">${t.text}</a></li>`).join("")}</ul>`
    : "";
  const title = p.slug === "index" ? "netwatch — see who your server talks to" : `${p.title} — netwatch`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(p.description)}">
<meta property="og:title" content="${esc(p.title)}">
<meta property="og:description" content="${esc(p.description)}">
<meta property="og:image" content="${SITE_URL}/screenshots/status-dark.png">
<link rel="alternate" type="text/markdown" href="${mdHref(p.slug)}">
<link rel="icon" href="${BASE}favicon.svg" type="image/svg+xml">
<link rel="preload" href="${BASE}fonts/Geist-Variable.woff2" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="${BASE}style.css">
<script>document.documentElement.classList.toggle("dark",(localStorage.theme||(matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light"))==="dark")</script>
<script src="${BASE}app.js" defer></script>
</head>
<body>
<header class="top">
  <button class="menu" type="button" aria-label="Menu" aria-expanded="false"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg></button>
  <a class="brand" href="${BASE}">${LOGO}netwatch</a>
  <a class="version" href="https://github.com/${REPO}/releases" rel="noopener">v${VERSION}</a>
  <div class="spacer"></div>
  ${promptButton}
  <a class="top-link" href="${BASE}llms.txt">llms.txt</a>
  <a class="icon-btn" href="https://github.com/${REPO}" aria-label="GitHub" rel="noopener">${ICON_GH}</a>
  <button class="icon-btn theme" type="button" aria-label="Toggle dark mode"><svg class="sun" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32 1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41m11.32-11.32 1.41-1.41"/></svg><svg class="moon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg></button>
</header>
<div class="layout">
  <aside class="sidebar"><nav>${sidebar(p.slug)}</nav></aside>
  <main class="content">
    <div class="page-head">
      <div>
        <div class="crumb">${p.section}</div>
        <h1>${esc(p.title)}</h1>
      </div>
      ${bare ? "" : copyMenu(p)}
    </div>
    <p class="lead">${esc(p.description)}</p>
    <article class="prose">
${html}
    </article>
    ${bare ? "" : pager}
  </main>
  <aside class="toc">${tocHtml}</aside>
</div>
${bare ? "" : `<script type="text/markdown" id="page-md">${agentMarkdown(p).replace(/<\/script/gi, "<\\/script")}</script>`}
</body>
</html>
`;
}

// ---- write -------------------------------------------------------------------

fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(path.join(OUT, "fonts"), { recursive: true });
fs.cpSync(path.join(ROOT, "public"), OUT, { recursive: true });
fs.copyFileSync(path.join(ROOT, "assets/style.css"), path.join(OUT, "style.css"));
fs.copyFileSync(path.join(ROOT, "assets/app.js"), path.join(OUT, "app.js"));
// Mermaid, self-hosted. The browser fetches only the chunks a diagram needs.
const mermaid = path.join(ROOT, "node_modules/mermaid/dist");
fs.cpSync(path.join(mermaid, "mermaid.esm.min.mjs"), path.join(OUT, "mermaid/mermaid.esm.min.mjs"));
fs.cpSync(path.join(mermaid, "chunks/mermaid.esm.min"), path.join(OUT, "mermaid/chunks/mermaid.esm.min"), {
  recursive: true,
  filter: (src) => !src.endsWith(".map"),
});
// The one-line installer: curl -fsSL <site>/install.sh | sh
fs.copyFileSync(path.join(ROOT, "../scripts/get.sh"), path.join(OUT, "install.sh"));
const fonts = path.join(ROOT, "node_modules/geist/dist/fonts");
fs.copyFileSync(path.join(fonts, "geist-sans/Geist-Variable.woff2"), path.join(OUT, "fonts/Geist-Variable.woff2"));
fs.copyFileSync(path.join(fonts, "geist-mono/GeistMono-Variable.woff2"), path.join(OUT, "fonts/GeistMono-Variable.woff2"));

const full = [];
pages.forEach((p, i) => {
  const { html, toc } = render(p.body);
  const dir = p.slug === "index" ? OUT : path.join(OUT, p.slug);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "index.html"), layout(p, i, html, toc));
  const md = agentMarkdown(p);
  fs.writeFileSync(path.join(OUT, `${p.slug}.md`), md);
  full.push(md);
});

const llms = [
  "# netwatch",
  "",
  "> A single-binary traffic monitor for Linux servers (eBPF/XDP) and macOS: it records every connection with the process behind it, flags scans and brute force, proposes or enforces bans, and serves a read-only web UI on 127.0.0.1.",
  "",
  `Every page below is Markdown. ${SITE_URL}/llms-full.txt has all of them in one file.`,
  "",
  ...NAV.flatMap((s) => [
    `## ${s.title}`,
    "",
    ...s.pages.map((slug) => {
      const p = pages.find((x) => x.slug === slug);
      return `- [${p.title}](${SITE_URL}/${slug}.md): ${p.description}`;
    }),
    "",
  ]),
].join("\n");
fs.writeFileSync(path.join(OUT, "llms.txt"), llms);
fs.writeFileSync(path.join(OUT, "llms-full.txt"), full.join("\n---\n\n"));
fs.writeFileSync(
  path.join(OUT, "404.html"),
  layout(
    { slug: "404", file: "index.md", section: "", title: "Page not found", nav: "", description: "There is no page at this address.", body: "" },
    -1,
    `<p><a href="${BASE}">Back to the introduction</a></p>`,
    [],
    true,
  ),
);
console.log(`built ${pages.length} pages into ${path.relative(process.cwd(), OUT) || "."} (base ${BASE})`);
