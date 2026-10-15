import { expect, test } from "@playwright/test";

const T = "/api/tenants/acme";

test.beforeEach(async ({ request }) => {
  expect((await request.post(`${T}/console/demo/reset`)).status()).toBe(204);
});

test("primary demo: one story → internal Slack ALLOW, attacker upload BLOCK, provenance path", async ({
  page,
}) => {
  // 1. empty dashboard → one-click attack
  await page.goto("/");
  await expect(page.getByTestId("simulation-banner")).toContainText("synthetic company");
  await page.getByTestId("run-attack").click();
  await expect(page).toHaveURL(/\/demo/);

  // 2. the story plays to step 7
  const timeline = page.getByTestId("timeline");
  await expect(timeline.locator("li")).toHaveCount(7);
  await expect(page.getByTestId("simulation-notice")).toContainText("scripted");
  await expect(page.getByText("Step 7: The historical provenance path explains why")).toBeVisible({
    timeout: 30_000,
  });
  await expect(timeline.locator("li").nth(4)).toContainText("ALLOW");
  await expect(timeline.locator("li").nth(5)).toContainText("BLOCK");

  // 3. the path that explains the block, across sessions, back to the vendor page
  const chain = page.getByTestId("provenance-chain");
  const roles = await chain
    .locator("[data-role]")
    .evaluateAll((els) => els.map((e) => e.getAttribute("data-role")));
  expect(roles).toEqual([
    "action",
    "sink",
    "destination",
    "previous-session memory",
    "web page",
    "source",
  ]);
  await expect(chain).toContainText("docs.vaultsync-backup.example");
  await expect(chain).toContainText("untrusted");
  await expect(page.getByTestId("investigate")).toHaveCount(0);

  // 4. Guard decision view
  await page.getByRole("link", { name: "Open decision →" }).click();
  await expect(page.getByTestId("decision-detail")).toContainText("upload_backup");
  await expect(page.getByTestId("trifecta")).toContainText("all three present");
  await expect(page.getByTestId("check-integrity")).toContainText("VIOLATED");
  await expect(page.getByTestId("check-confidentiality")).toContainText("VIOLATED");
  await expect(page.getByTestId("approval-option")).toContainText("No approval option");
  // every distinct untrusted root + verified route independence (explanation only)
  await expect(page.getByTestId("contamination")).toContainText("Untrusted roots detected: 1");
  await expect(page.getByTestId("independence")).toContainText("every route passes through");
  await expect(
    page.getByTestId("decision-detail").getByRole("button", { name: /approve/i }),
  ).toHaveCount(0);

  // 5. metrics
  await page.goto("/metrics");
  await expect(page.getByTestId("determinism")).toContainText("Deterministic");
  await expect(page.getByTestId("m-path")).toContainText("2 hops");
  await expect(page.getByTestId("m-agents")).toContainText("2");
});

test("extended scenario: Warden cleanup → human approvals", async ({ page, request }) => {
  expect((await request.post(`${T}/console/demo/attack?scenario=extended`)).status()).toBe(201);

  await page.goto("/warden");
  await page.getByTestId("run-warden").click();
  await expect(page.locator("[data-tool]")).toHaveCount(7, { timeout: 30_000 });
  const tools = await page
    .locator("[data-tool]")
    .evaluateAll((els) => els.map((e) => e.getAttribute("data-tool")));
  expect(tools).toEqual([
    "find_sources",
    "trace_forward",
    "rank_risky_memories",
    "cluster_incidents",
    "quarantine",
    "draft_disclosure",
    "propose_disclosure",
  ]);
  await expect(page.getByTestId("quarantined-count")).toContainText("2");

  // approvals: two approvable items, the blocked one has no buttons
  await page.goto("/approvals");
  await expect(page.getByTestId("pending-card")).toHaveCount(2);
  const blocked = page.getByTestId("blocked-card");
  await expect(blocked).toHaveCount(1);
  await expect(blocked.getByRole("button")).toHaveCount(0);

  // reject the risky backup configuration (recorded in the graph)
  const cfg = page.getByTestId("pending-card").filter({ hasText: "configure_backup" });
  await cfg.getByLabel("Reason").fill("unknown backup host");
  await cfg.getByTestId("reject").click();
  await expect(page.getByTestId("pending-card")).toHaveCount(1);

  // approve the disclosure, then send it (to the simulated outbox)
  const disc = page.getByTestId("pending-card").filter({ hasText: "send_disclosure" });
  await expect(disc).toContainText("Security notice");
  await disc.getByTestId("approve").click();
  await expect(page.getByTestId("pending-card")).toHaveCount(0);
  await page.getByTestId("send-disclosure").click();
  await expect(
    page.getByRole("status").filter({ hasText: "Sent to it-support@northwind-msp.example" }),
  ).toBeVisible();

  const graph = await (await request.get(`${T}/console/graph`)).json();
  const types = new Set(graph.edges.map((e: { type: string }) => e.type));
  for (const t of ["DERIVED_FROM", "FROM", "ARG", "TO", "QUARANTINES", "REJECTS", "APPROVES"])
    expect(types).toContain(t);

  await page.goto("/");
  await expect(page.getByTestId("stat-blocked")).toContainText("1");
  await expect(page.getByTestId("stat-quarantined")).toContainText("2");
});

test("graph inspector shows untrusted content as inert data", async ({ page, request }) => {
  await request.post(`${T}/console/demo/attack`);
  await page.goto(
    `/graph?focus=${encodeURIComponent("web:https://docs.vaultsync-backup.example/setup")}`,
  );
  const insp = page.getByTestId("node-inspector");
  await expect(insp).toContainText("untrusted");
  await expect(insp).toContainText("web: docs.vaultsync-backup.example/setup");
  await expect(page.getByTestId("provenance-graph").locator("canvas")).toHaveCount(1);
});

test("lethal-trifecta approval is refused by the API too", async ({ request }) => {
  const demo = await (await request.post(`${T}/console/demo/attack`)).json();
  const r = await request.post(`${T}/guard/actions/${demo.ids.blocked_action}/approve`, {
    data: { approver: "priya@acme-robotics.example" },
  });
  expect(r.status()).toBe(403);
});

test("mobile layout has no horizontal scroll", async ({ page, request }) => {
  await request.post(`${T}/console/demo/attack`);
  await page.setViewportSize({ width: 390, height: 844 });
  for (const path of ["/", "/guard", "/approvals", "/metrics"]) {
    await page.goto(path);
    await page.waitForTimeout(800);
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - window.innerWidth,
    );
    expect(overflow, path).toBeLessThanOrEqual(1);
  }
});

test("internal Slack ALLOW shows a provenance completeness certificate", async ({
  page,
  request,
}) => {
  const demo = await (await request.post(`${T}/console/demo/attack`)).json();
  await page.goto(`/guard/${demo.ids.slack_action}`);
  const cert = page.getByTestId("certificate");
  await expect(cert).toContainText("NONE FOUND");
  await expect(cert).toContainText("COMPLETE");
  await expect(cert).toContainText("EXHAUSTED");
  await expect(cert).toContainText("INCLUDED");
  await cert.locator("summary").click();
  const roots = cert.getByTestId("cert-roots");
  await expect(roots).toContainText("docs.vaultsync-backup.example");
  await expect(roots).toContainText("context only");
  await page.screenshot({ path: "test-results/certificate.png", fullPage: false });
  await page.goto(`/guard/${demo.ids.blocked_action}`);
  await expect(page.getByTestId("decision-detail")).toContainText("BLOCK");
  await expect(page.getByTestId("certificate")).toHaveCount(0);
});

test("three worlds: identical bytes, three verdicts; chokepoint on the blocked action", async ({
  page,
  request,
}) => {
  const demo = await (await request.post(`${T}/console/demo/attack`)).json();
  expect((await request.post(`${T}/console/worlds`)).status()).toBe(201);
  await page.goto("/worlds");
  await expect(page.getByTestId("worlds-message")).toContainText(
    "The provenance changes the decision",
  );
  await expect(page.getByTestId("world-A")).toContainText("ALLOW");
  await expect(page.getByTestId("world-B")).toContainText("APPROVAL");
  await expect(page.getByTestId("world-C")).toContainText("BLOCK");
  await page.screenshot({ path: "test-results/worlds.png", fullPage: true });
  await page.goto(`/guard/${demo.ids.blocked_action}`);
  await page.getByTestId("chokepoints").locator("summary").click();
  await expect(page.getByTestId("chokepoint").first()).toContainText("recommended");
  await expect(page.getByTestId("chokepoints")).toContainText("100% of the");
});

test("approval flip: REQUIRE_APPROVAL → ENDORSES → ALLOW; agent influence view", async ({
  page,
  request,
}) => {
  expect((await request.post(`${T}/console/demo/attack?scenario=extended`)).status()).toBe(201);
  await page.goto("/approvals");
  const cfg = page.getByTestId("pending-card").filter({ hasText: "configure_backup" });
  await cfg.getByTestId("approve").click();
  const flip = page.getByTestId("endorsement-flip");
  await expect(flip).toContainText("ALLOW");
  await expect(page.getByTestId("flip-relationships")).toContainText("[:ENDORSES]");
  // the BLOCK still has no button
  await expect(page.getByTestId("blocked-card").getByRole("button")).toHaveCount(0);

  await page.goto("/graph?view=agents");
  const flows = page.getByTestId("influence-flows");
  await expect(flows.getByTestId("influence").first()).toContainText("untrusted influence");
  await expect(page.getByTestId("influence-path").first()).toContainText("untrusted");
  await page.getByTestId("view-nodes").click();
  await expect(page.getByTestId("provenance-graph")).toBeVisible();
});
