import { expect, test } from "@playwright/test";

// The documentation site as production serves it: FastAPI's SPA fallback + the built UI.

test("docs deep links, screenshots, search and the console link work when served by the API", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));

  // a deep link with an anchor, loaded directly (not via client-side navigation)
  await page.goto("/docs/guard#checks");
  await expect(page.getByRole("heading", { level: 1, name: "Guard" })).toBeVisible();
  await expect(page.locator("#checks")).toBeInViewport();

  // every screenshot on the page loads
  const imgs = page.locator(".docs-prose img");
  expect(await imgs.count()).toBeGreaterThan(3);
  for (const img of await imgs.all()) {
    await img.scrollIntoViewIfNeeded();
    await expect
      .poll(() => img.evaluate((el) => (el as HTMLImageElement).naturalWidth))
      .toBeGreaterThan(0);
  }

  // search → a section on another page
  await page.keyboard.press("Control+k");
  await page.getByRole("textbox", { name: "Search query" }).fill("public demo read-only");
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/docs\/[a-z-]+#/);

  // the console's sidebar links to the docs, and the docs link back
  await page.goto("/");
  await page.getByTestId("docs-link").click();
  await expect(page).toHaveURL(/\/docs$/);
  await page.getByRole("link", { name: "Console", exact: true }).click();
  await expect(page.getByTestId("simulation-banner")).toBeVisible();

  expect(errors).toEqual([]);
});

test("docs pages have no horizontal scroll at phone width", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  for (const path of ["/docs", "/docs/api-reference", "/docs/configuration", "/docs/guard"]) {
    await page.goto(path);
    await page.waitForTimeout(400);
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - window.innerWidth,
    );
    expect(overflow, path).toBeLessThanOrEqual(1);
  }
});
