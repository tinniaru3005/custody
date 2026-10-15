import { render, screen, within } from "@testing-library/react";
import demo from "../test/fixtures/demo.json";
import blocked from "../test/fixtures/explain_blocked.json";
import graph from "../test/fixtures/graph.json";
import { mockFetch, renderPage } from "../test/utils";
import type { DemoRun } from "../api/types";
import { DemoPage, RunModeBanner } from "./DemoPage";

describe("DemoPage", () => {
  it("shows the seven-step story, the simulation notice and the final provenance path", async () => {
    mockFetch([
      ["/console/demo", demo],
      ["/console/graph", graph],
      ["/explain", blocked],
    ]);
    renderPage(<DemoPage />);
    const tl = await screen.findByTestId("timeline");
    expect(within(tl).getAllByRole("listitem")).toHaveLength(7);
    expect(await screen.findByText(/Step 7/)).toBeInTheDocument();
    expect(await screen.findByTestId("provenance-chain")).toBeInTheDocument();
    const notice = screen.getByTestId("simulation-notice");
    expect(notice).toHaveTextContent(/synthetic/);
    expect(notice).toHaveTextContent(/scripted/);
    // the primary demo has no Warden / disclosure step; it ends on the path
    expect(screen.queryByTestId("investigate")).toBeNull();
    expect(screen.getByTestId("after-demo")).toBeInTheDocument();
    // not a public demo: the run button is offered
    expect(screen.getByTestId("run-attack")).toBeInTheDocument();
    expect(
      within(screen.getByTestId("force-graph-mock")).getAllByRole("listitem").length,
    ).toBeGreaterThan(15);
  });

  it("in the public demo offers only Reset Demo", async () => {
    mockFetch([
      ["/health", { status: "ok", falkordb: true, version: "x", public_demo: true }],
      ["/console/demo", demo],
      ["/console/graph", graph],
      ["/explain", blocked],
    ]);
    renderPage(<DemoPage />);
    expect(await screen.findByTestId("demo-reset")).toHaveTextContent(/Reset Demo/);
    expect(screen.queryByTestId("run-attack")).toBeNull();
  });

  it("labels the run: scripted simulation, or recorded LLM replay", () => {
    const run = demo as unknown as DemoRun;
    const { unmount } = render(<RunModeBanner run={run} />);
    expect(screen.getByTestId("run-mode")).toHaveTextContent("Scripted simulation");
    unmount();
    const rec = {
      label: "Recorded real LLM execution — deterministic replay",
      real_llm: true,
      model: "claude-x",
      recorded_at: "2026-10-06T08:00:00Z",
      llm_calls: 9,
      llm_calls_made: 0,
    };
    const { unmount: u2 } = render(
      <RunModeBanner run={{ ...run, mode: "recorded", recording: rec }} />,
    );
    expect(screen.getByTestId("run-mode")).toHaveTextContent(
      "Recorded real LLM execution — deterministic replay",
    );
    expect(screen.getByTestId("run-mode")).toHaveTextContent("0 made now");
    u2();
    render(
      <RunModeBanner
        run={{
          ...run,
          mode: "recorded",
          recording: { ...rec, real_llm: false, label: "Recorded test-double execution" },
        }}
      />,
    );
    expect(screen.getByTestId("run-mode")).not.toHaveTextContent("real LLM");
  });
});
