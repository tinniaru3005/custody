import { expect, test } from "@playwright/test";

// Regenerates docs/screenshots/*.png. Skipped unless SCREENSHOTS=1:
//   npm run build && SCREENSHOTS=1 npx playwright test e2e/screenshots.spec.ts
const T = "/api/tenants/acme";
const OUT = "../docs/screenshots";
test.skip(!process.env.SCREENSHOTS, "set SCREENSHOTS=1 to regenerate docs/screenshots");

test("primary demo screenshots", async ({ page, request }) => {
  expect((await request.post(`${T}/console/demo/attack`)).status()).toBe(201);
  const demo = await (await request.get(`${T}/console/demo`)).json();
  await page.goto("/demo");
  await expect(page.getByText("Step 7: The historical provenance path explains why")).toBeVisible();
  await page.waitForTimeout(2500);
  await page.screenshot({ path: `${OUT}/demo.png`, fullPage: false });
  await page.goto("/");
  await page.waitForTimeout(800);
  await page.screenshot({ path: `${OUT}/dashboard.png` });
  await page.goto(`/guard/${demo.ids.blocked_action}`);
  await expect(page.getByTestId("decision-detail")).toBeVisible();
  await page.waitForTimeout(800);
  await page.screenshot({ path: `${OUT}/guard.png` });
  await page.goto("/graph");
  await page.waitForTimeout(3000);
  await page.screenshot({ path: `${OUT}/graph.png` });
  expect((await request.post(`${T}/console/worlds`)).status()).toBe(201);
  await page.goto("/worlds");
  await expect(page.getByTestId("world-C")).toContainText("BLOCK");
  await page.waitForTimeout(800);
  await page.screenshot({ path: `${OUT}/worlds.png`, fullPage: true });
  await page.goto("/metrics");
  await expect(page.getByTestId("determinism")).toBeVisible();
  await page.waitForTimeout(800);
  await page.screenshot({ path: `${OUT}/metrics.png` });
});

test("extended scenario screenshots (Warden, approvals)", async ({ page, request }) => {
  expect((await request.post(`${T}/console/demo/attack?scenario=extended`)).status()).toBe(201);
  await page.goto("/warden");
  await page.getByTestId("run-warden").click();
  await expect(page.locator("[data-tool]")).toHaveCount(7, { timeout: 30_000 });
  await page.waitForTimeout(800);
  await page.screenshot({ path: `${OUT}/warden.png` });
  await page.goto("/approvals");
  await expect(page.getByTestId("pending-card").first()).toBeVisible();
  await page.waitForTimeout(800);
  await page.screenshot({ path: `${OUT}/approvals.png` });
});
