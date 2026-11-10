import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

// The hosted demo is a page people land on from a link, so give it a title and
// description of its own.
const demoHtml: Plugin = {
  name: "netwatch-demo-html",
  transformIndexHtml: (html) =>
    html.replace(
      "<title>netwatch</title>",
      '<title>netwatch demo</title>\n    <meta name="description" content="The netwatch web UI running on built-in demo data, in your browser. No server, nothing to install." />',
    ),
};

// The daemon embeds dist/ into its binary and serves it at "/", so assets must
// be referenced relatively. In dev, /api is proxied to the local daemon.
// `--mode demo` (npm run build:demo) builds the same UI on mock data into the
// docs site, at site/dist/demo/; relative assets work there too.
export default defineConfig(({ mode }) => ({
  base: "./",
  plugins: [react(), ...(mode === "demo" ? [demoHtml] : [])],
  build: {
    outDir: mode === "demo" ? "../site/dist/demo" : "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    proxy: {
      "/api": { target: "http://127.0.0.1:9180", changeOrigin: false },
    },
  },
}));
