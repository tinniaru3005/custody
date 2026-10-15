import { expect, test, type Locator, type Page } from "@playwright/test";
import { writeFileSync } from "node:fs";

// Regenerates the screenshots used by the documentation site (src/docs/images/*.webp)
// from the real running app (FastAPI + embedded FalkorDB + the built UI). Skipped unless
// DOCS_SCREENSHOTS=1:
//   npm run build && DOCS_SCREENSHOTS=1 npx playwright test e2e/docs-screenshots.spec.ts
// The public-demo screenshot needs a second server in public-demo mode; set
// DOCS_PUBLIC_URL (e.g. http://127.0.0.1:8001 from `make api-public`) to include it.
const T = "/api/tenants/acme";
const OUT = "src/docs/images";
test.skip(!process.env.DOCS_SCREENSHOTS, "set DOCS_SCREENSHOTS=1 to regenerate doc screenshots");
test.use({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });

/** PNG from Playwright → WebP (encoded by Chromium itself, so no image tooling is needed). */
async function save(page: Page, name: string, png: Buffer, quality = 0.86) {
  const dataUrl = await page.evaluate(
    async ({ b64, q }) => {
      const img = new Image();
      img.src = `data:image/png;base64,${b64}`;
      await img.decode();
      const c = document.createElement("canvas");
      c.width = img.naturalWidth;
      c.height = img.naturalHeight;
      c.getContext("2d")!.drawImage(img, 0, 0);
      return c.toDataURL("image/webp", q);
    },
    { b64: png.toString("base64"), q: quality },
  );
  writeFileSync(`${OUT}/${name}.webp`, Buffer.from(dataUrl.split(",")[1], "base64"));
}

async function shotPage(page: Page, name: string) {
  await save(page, name, await page.screenshot());
}

async function shotEl(page: Page, el: Locator, name: string) {
  await el.scrollIntoViewIfNeeded();
  await page.waitForTimeout(300);
  await save(page, name, await el.screenshot());
}

test("primary demo, Guard, graph, worlds, metrics", async ({ page, request }) => {
  expect((await request.post(`${T}/console/demo/reset`)).status()).toBe(204);
  // empty console before the demo
  await page.goto("/");
  await expect(page.getByTestId("run-attack")).toBeVisible();
  await page.waitForTimeout(600);
  await shotPage(page, "console-empty");

  expect((await request.post(`${T}/console/demo/attack`)).status()).toBe(201);
  const demo = await (await request.get(`${T}/console/demo`)).json();

  await page.goto("/");
  await expect(page.getByTestId("recent-actions")).toBeVisible();
  await page.waitForTimeout(800);
  await shotPage(page, "dashboard");

  // the story at step 7, then individual steps
  await page.goto("/demo");
  await expect(page.getByText("Step 7: The historical provenance path explains why")).toBeVisible();
  await page.waitForTimeout(2500);
  await shotPage(page, "demo-overview");
  const timeline = page.getByTestId("timeline");
  // the whole step panel (title + detail), not just the detail body
  const detail = page.locator("section.panel").filter({ has: page.getByTestId("step-detail") });
  for (const [n, name] of [
    [1, "demo-step1-poisoned-page"],
    [3, "demo-step3-recall"],
    [5, "demo-step5-allow"],
    [6, "demo-step6-block"],
    [7, "demo-step7-path"],
  ] as const) {
    await timeline
      .locator("li")
      .nth(n - 1)
      .locator("button")
      .click();
    await page.waitForTimeout(1200);
    await shotEl(page, detail, name);
  }
  await shotEl(page, timeline, "demo-timeline");

  // Guard decision views
  await page.goto(`/guard/${demo.ids.blocked_action}`);
  const decision = page.getByTestId("decision-detail");
  await expect(decision).toBeVisible();
  await page.waitForTimeout(1000);
  await shotPage(page, "guard-block");
  await shotEl(page, page.getByTestId("contamination"), "guard-contamination");
  await shotEl(
    page,
    decision.locator(".grid-2").filter({ has: page.getByTestId("trifecta") }),
    "guard-checks",
  );
  const choke = page.getByTestId("chokepoints");
  await choke.locator("summary").click();
  await expect(page.getByTestId("chokepoint").first()).toBeVisible();
  await shotEl(page, choke, "guard-chokepoints");

  await page.goto(`/guard/${demo.ids.slack_action}`);
  await expect(page.getByTestId("certificate")).toBeVisible();
  await page.waitForTimeout(800);
  await shotEl(page, page.getByTestId("certificate"), "guard-certificate");

  // provenance graph: nodes, inspector on the vendor page, agents view
  await page.goto("/graph");
  await page.waitForTimeout(3500);
  await shotPage(page, "graph-nodes");
  await page.goto(`/graph?focus=${encodeURIComponent(demo.ids.vendor_source)}`);
  await expect(page.getByTestId("node-inspector")).toContainText("untrusted");
  await page.waitForTimeout(3000);
  await shotEl(page, page.getByTestId("node-inspector"), "graph-inspector");
  await page.goto("/graph?view=agents");
  await expect(page.getByTestId("influence-flows")).toBeVisible();
  await page.waitForTimeout(1500);
  await shotEl(
    page,
    page.locator("section.panel").filter({ has: page.getByTestId("influence-flows") }),
    "graph-agents",
  );

  // metrics
  await page.goto("/metrics");
  await expect(page.getByTestId("determinism")).toBeVisible();
  await page.waitForTimeout(800);
  await shotPage(page, "metrics");

  // retroactive re-adjudication (API), shown on the Warden page
  const graph = await (await request.get(`${T}/console/graph`)).json();
  const sam = graph.nodes.find(
    (n: { id: string; label: string }) => n.label === "Source" && n.id.startsWith("user:sam"),
  );
  expect(sam).toBeTruthy();
  const rv = await request.post(`${T}/guard/sources/${sam.id}/revoke`, {
    data: { approver: "priya@acme-robotics.example", reason: "account compromise drill" },
  });
  expect(rv.status()).toBe(201);
  await page.goto("/warden");
  await expect(page.getByTestId("readjudication").first()).toBeVisible();
  await page.waitForTimeout(600);
  await shotEl(page, page.getByTestId("readjudication").first(), "readjudication");

  // three worlds (built into acme-worlds; report stored on acme)
  expect((await request.post(`${T}/console/worlds`)).status()).toBe(201);
  await page.goto("/worlds");
  await expect(page.getByTestId("world-C")).toContainText("BLOCK");
  await page.waitForTimeout(800);
  await shotPage(page, "worlds");
});

test("extended scenario: Warden and approvals", async ({ page, request }) => {
  expect((await request.post(`${T}/console/demo/attack?scenario=extended`)).status()).toBe(201);
  await page.goto("/warden");
  await page.getByTestId("run-warden").click();
  await expect(page.locator("[data-tool]")).toHaveCount(7, { timeout: 30_000 });
  await page.waitForTimeout(800);
  await shotPage(page, "warden");
  await shotEl(page, page.getByTestId("tool-steps"), "warden-tools");
  await shotEl(page, page.getByTestId("warden-report"), "warden-report");

  await page.goto("/approvals");
  await expect(page.getByTestId("pending-card").first()).toBeVisible();
  await page.waitForTimeout(800);
  await shotPage(page, "approvals");
  await shotEl(page, page.getByTestId("blocked-card").first(), "approvals-blocked");
  const disc = page.getByTestId("pending-card").filter({ hasText: "send_disclosure" });
  await shotEl(page, disc, "approvals-disclosure");
  await disc.getByTestId("approve").click();
  const flip = page.getByTestId("endorsement-flip").first();
  await expect(flip).toBeVisible();
  await page.waitForTimeout(1500);
  await shotEl(page, flip, "approvals-flip");
});

test("public-demo mode banner", async ({ page }) => {
  const base = process.env.DOCS_PUBLIC_URL;
  test.skip(!base, "set DOCS_PUBLIC_URL to a server running with CUSTODY_PUBLIC_DEMO=true");
  await page.goto(`${base}/`);
  await expect(page.getByTestId("public-demo-tag")).toBeVisible();
  await page.waitForTimeout(800);
  await shotEl(page, page.getByTestId("simulation-banner"), "public-demo-banner");
  await shotPage(page, "public-demo-dashboard");
});
