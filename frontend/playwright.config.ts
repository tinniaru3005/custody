import { defineConfig } from "@playwright/test";

// End-to-end: the real FastAPI backend (embedded FalkorDB) serving the built UI.
// Build first: `npm run build`. Set PW_CHROMIUM to use a preinstalled Chromium.
const port = Number(process.env.E2E_PORT ?? 8765);
const python = process.env.PYTHON ?? ".venv/bin/python";

export default defineConfig({
  testDir: "./e2e",
  timeout: 120_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    viewport: { width: 1440, height: 1000 },
    launchOptions: process.env.PW_CHROMIUM ? { executablePath: process.env.PW_CHROMIUM } : {},
    screenshot: "only-on-failure",
  },
  webServer: {
    command: `${python} -m uvicorn custody.api.app:app --port ${port}`,
    cwd: "..",
    url: `http://127.0.0.1:${port}/api/health`,
    reuseExistingServer: false,
    timeout: 60_000,
    env: {
      CUSTODY_FALKORDB_EMBEDDED_PATH: process.env.E2E_DB ?? "/tmp/custody-e2e.db",
      CUSTODY_GRAPH_PREFIX: "custody-e2e",
      CUSTODY_STATIC_DIR: "frontend/dist",
      ANTHROPIC_API_KEY: "",
      // the e2e tests check the scripted story; a recorded LLM run (if one was recorded) is
      // covered by tests/integration/test_llm_replay.py
      CUSTODY_DEMO_MODE: "scripted",
    },
  },
});
