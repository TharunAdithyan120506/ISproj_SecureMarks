import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// `npm run dev` serves on :5173 and forwards /api to the portal API on :8501.
// `npm run build` writes web/dist, which the portal API serves itself.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { "/api": "http://127.0.0.1:8501" } },
  build: { outDir: "dist", emptyOutDir: true, chunkSizeWarningLimit: 900 },
  test: { environment: "jsdom", globals: true },
});
