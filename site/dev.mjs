// Serves dist/ on http://127.0.0.1:4321 and rebuilds when a page or asset changes.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const DIST = path.join(ROOT, "dist");
const PORT = Number(process.env.PORT ?? 4321);
const TYPES = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml", ".png": "image/png", ".woff2": "font/woff2", ".md": "text/plain", ".txt": "text/plain", ".sh": "text/plain" };

const build = () => spawnSync(process.execPath, [path.join(ROOT, "build.mjs")], { stdio: "inherit", env: { ...process.env, BASE: "/" } });
build();

let timer;
for (const dir of ["content", "assets", "public"]) {
  fs.watch(path.join(ROOT, dir), { recursive: true }, () => {
    clearTimeout(timer);
    timer = setTimeout(build, 100);
  });
}
fs.watch(path.join(ROOT, "build.mjs"), () => {
  clearTimeout(timer);
  timer = setTimeout(build, 100);
});

http
  .createServer((req, res) => {
    let file = path.join(DIST, decodeURIComponent(new URL(req.url, "http://x").pathname));
    if (!file.startsWith(DIST)) return res.writeHead(403).end();
    if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, "index.html");
    const found = fs.existsSync(file);
    if (!found) file = path.join(DIST, "404.html");
    res.writeHead(found ? 200 : 404, { "content-type": `${TYPES[path.extname(file)] ?? "application/octet-stream"}; charset=utf-8` });
    fs.createReadStream(file).pipe(res);
  })
  .listen(PORT, "127.0.0.1", () => console.log(`docs on http://127.0.0.1:${PORT}`));
