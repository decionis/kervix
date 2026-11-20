import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// dev: `npm run -w host/dashboard dev` with the bridge on :8787 (npm run bridge)
// prod: `npm run -w host/dashboard build`; the bridge serves dist/ itself
const bridge = process.env.KX_BRIDGE ?? "http://127.0.0.1:8787";
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": bridge,
      "/ws": { target: bridge.replace(/^http/, "ws"), ws: true },
    },
  },
  build: { chunkSizeWarningLimit: 1500 },
});
