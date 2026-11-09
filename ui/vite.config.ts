import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The daemon embeds dist/ into its binary and serves it at "/", so assets must
// be referenced relatively. In dev, /api is proxied to the local daemon.
export default defineConfig({
  base: "./",
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    proxy: {
      "/api": { target: "http://127.0.0.1:9180", changeOrigin: false },
    },
  },
});
