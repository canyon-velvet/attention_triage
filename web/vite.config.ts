import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  // Built into the Python package and committed, so installs need no Node (`triage ui` serves it).
  build: { outDir: "../src/attention_triage/static", emptyOutDir: true },
  // `pnpm dev` serves the page with live reload and forwards API calls to a running `triage ui`.
  server: { proxy: { "/api": "http://127.0.0.1:8765" } },
  test: { environment: "jsdom", setupFiles: ["src/test-setup.ts"] },
});
