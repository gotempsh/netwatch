// Theme toggle, mobile menu, copy buttons, the "Copy page" menu and diagrams.

const root = document.documentElement;

document.querySelector(".theme")?.addEventListener("click", () => {
  const dark = !root.classList.contains("dark");
  root.classList.toggle("dark", dark);
  localStorage.theme = dark ? "dark" : "light";
});

const menu = document.querySelector(".menu");
menu?.addEventListener("click", () => {
  const open = document.body.classList.toggle("nav-open");
  menu.setAttribute("aria-expanded", String(open));
});

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const t = document.createElement("textarea");
    t.value = text;
    t.style.position = "fixed";
    t.style.opacity = "0";
    document.body.append(t);
    t.select();
    document.execCommand("copy");
    t.remove();
  }
}

function flash(el) {
  el.classList.add("copied");
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove("copied"), 1600);
}

for (const btn of document.querySelectorAll(".copy-code")) {
  btn.addEventListener("click", async () => {
    await copy(btn.parentElement.querySelector("pre").innerText.replace(/\n$/, ""));
    flash(btn);
  });
}

// ---- Copy page ----

const box = document.querySelector(".copy-page");
if (box) {
  const toggle = box.querySelector(".copy-toggle");
  const list = box.querySelector(".copy-menu");
  const label = box.querySelector(".copy-main span");
  const setOpen = (open) => {
    list.hidden = !open;
    toggle.setAttribute("aria-expanded", String(open));
    if (open) list.querySelector("[role=menuitem]")?.focus();
  };
  toggle.addEventListener("click", (e) => {
    e.stopPropagation();
    setOpen(list.hidden);
  });
  document.addEventListener("click", (e) => {
    if (!box.contains(e.target)) setOpen(false);
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !list.hidden) {
      setOpen(false);
      toggle.focus();
    }
  });
  for (const btn of box.querySelectorAll("[data-copy-page]")) {
    btn.addEventListener("click", async () => {
      await copy(document.getElementById("page-md").textContent);
      setOpen(false);
      flash(box);
      label.textContent = "Copied";
      setTimeout(() => (label.textContent = "Copy page"), 1600);
    });
  }
}

// ---- Copy prompt: the card on the home page and the button in the top bar ----

// Unlike copy(), says whether it worked: if the browser refuses, the prompt
// is shown to be selected by hand instead.
async function copyPrompt() {
  try {
    await navigator.clipboard.writeText(document.querySelector(".prompt-pop pre").textContent);
    return true;
  } catch {
    return false;
  }
}

function confirmCopy(btn, failed) {
  const label = btn.querySelector("span");
  label.dataset.text ??= label.textContent;
  if (!failed) btn.classList.add("copied");
  label.textContent = failed ? "Select it below" : "Copied";
  clearTimeout(btn._t);
  btn._t = setTimeout(() => {
    btn.classList.remove("copied");
    label.textContent = label.dataset.text;
  }, 2000);
}

for (const card of document.querySelectorAll(".prompt-card")) {
  const btn = card.querySelector("[data-copy-prompt]");
  btn.addEventListener("click", async () => {
    const ok = await copyPrompt();
    if (!ok) card.querySelector("details").open = true;
    confirmCopy(btn, !ok);
  });
}

const promptTop = document.querySelector(".prompt-top");
if (promptTop) {
  const btn = promptTop.querySelector("[data-copy-prompt]");
  const pop = promptTop.querySelector(".prompt-pop");
  btn.addEventListener("click", async () => {
    if (await copyPrompt()) {
      pop.hidden = true;
      confirmCopy(btn, false);
    } else {
      pop.hidden = false;
    }
  });
  document.addEventListener("click", (e) => {
    if (!promptTop.contains(e.target)) pop.hidden = true;
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") pop.hidden = true;
  });
}

// ---- On this page: highlight the section in view ----

const links = [...document.querySelectorAll(".toc a")];
if (links.length) {
  const byId = new Map(links.map((a) => [decodeURIComponent(a.hash.slice(1)), a]));
  const heads = [...document.querySelectorAll(".prose h2[id], .prose h3[id]")];
  const update = () => {
    let current = heads[0];
    for (const h of heads) if (h.getBoundingClientRect().top < 120) current = h;
    for (const a of links) a.classList.toggle("active", a === byId.get(current?.id));
  };
  addEventListener("scroll", update, { passive: true });
  update();
}

// ---- Diagrams: drawn with the site's colours, again when the theme changes ----

const diagrams = [...document.querySelectorAll("pre.mermaid")];
if (diagrams.length) {
  const src = new URL("mermaid/mermaid.esm.min.mjs", document.currentScript.src).href;
  for (const d of diagrams) d.dataset.source = d.textContent;
  let mermaid;
  const draw = async () => {
    mermaid ??= (await import(src)).default;
    const css = getComputedStyle(root);
    const v = (name) => css.getPropertyValue(name).trim();
    mermaid.initialize({
      startOnLoad: false,
      theme: "base",
      look: "classic",
      flowchart: { wrappingWidth: 320 },
      fontFamily: v("--font"),
      themeVariables: {
        darkMode: root.classList.contains("dark"),
        background: v("--bg"),
        primaryColor: v("--bg-muted"),
        primaryTextColor: v("--fg"),
        primaryBorderColor: v("--border-strong"),
        lineColor: v("--fg-subtle"),
        textColor: v("--fg-muted"),
        titleColor: v("--fg-muted"),
        clusterBkg: v("--bg-subtle"),
        clusterBorder: v("--border"),
        edgeLabelBackground: v("--bg"),
        fontSize: "14px",
      },
    });
    for (const d of diagrams) {
      d.removeAttribute("data-processed");
      d.textContent = d.dataset.source;
    }
    await mermaid.run({ nodes: diagrams });
  };
  let queue = draw();
  new MutationObserver(() => (queue = queue.then(draw, draw))).observe(root, {
    attributes: true,
    attributeFilter: ["class"],
  });
}
