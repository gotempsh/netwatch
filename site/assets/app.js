// Theme toggle, mobile menu, copy buttons and the "Copy page" menu.

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
