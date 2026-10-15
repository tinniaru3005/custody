import { screen, within } from "@testing-library/react";
import worlds from "../test/fixtures/worlds.json";
import { mockFetch, renderPage } from "../test/utils";
import { WorldsPage } from "./WorldsPage";
import { ReadjudicationCard } from "../components/Readjudications";
import type { ReadjudicationReport } from "../api/types";

describe("WorldsPage", () => {
  it("shows the same request and bytes side by side with three different verdicts", async () => {
    mockFetch([["/console/worlds", worlds]]);
    renderPage(<WorldsPage />);
    expect(await screen.findByTestId("worlds-message")).toHaveTextContent(
      "The content can be identical. The provenance changes the decision.",
    );
    expect(screen.getByTestId("same-destination")).toHaveTextContent("same");
    const verdicts = ["A", "B", "C"].map(
      (k) => within(screen.getByTestId(`world-${k}`)).getByTestId("verdict-badge").textContent,
    );
    expect(verdicts.join(" ")).toMatch(/ALLOW.*APPROVAL.*BLOCK/);
    const dests = ["A", "B", "C"].map(
      (k) => within(screen.getByTestId(`world-${k}`)).getByText(worlds.destination).textContent,
    );
    expect(new Set(dests).size).toBe(1);
    expect(within(screen.getByTestId("world-C")).getByTestId("world-chain")).toHaveTextContent(
      "untrusted",
    );
  });
});

describe("ReadjudicationCard", () => {
  it("separates what was known then from what is known now", () => {
    const r: ReadjudicationReport = {
      id: "rev_1",
      source_id: "github:acme/partners/contacts.md",
      trust_before: "trusted",
      trust_after: "untrusted",
      revoked_by: "sam@acme-robotics.example",
      reason: "compromised",
      revoked_at: "2026-10-06T10:00:00Z",
      graph_version_before: "g@v10",
      graph_version_after: "g@v12",
      downstream_datums: 9,
      memories: ["d_m"],
      messages: [],
      summary: { "ALLOW → BLOCK": 1, UNCHANGED: 1 },
      known_then: "then",
      known_now: "now",
      actions: [
        {
          action_id: "act_1",
          action_type: "send_email",
          agent: "ops",
          status: "executed",
          executed: true,
          original_verdict: "ALLOW",
          current_verdict: "BLOCK",
          current_triggered: ["integrity"],
          current_explanation: "",
          transition: "ALLOW → BLOCK",
          changed: true,
        },
        {
          action_id: "act_2",
          action_type: "send_email",
          agent: "ops",
          status: "executed",
          executed: true,
          original_verdict: "ALLOW",
          current_verdict: "ALLOW",
          current_triggered: [],
          current_explanation: "",
          transition: "UNCHANGED",
          changed: false,
        },
      ],
    };
    renderPage(<ReadjudicationCard r={r} />);
    expect(screen.getByTestId("readj-count")).toHaveTextContent("2 historical action(s) affected");
    expect(screen.getByTestId("readj-summary")).toHaveTextContent("ALLOW → BLOCK: 1");
    expect(screen.getByText("Known at execution time")).toBeInTheDocument();
    expect(screen.getByText("Known now")).toBeInTheDocument();
  });
});
