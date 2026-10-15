import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import influence from "../test/fixtures/influence.json";
import blocked from "../test/fixtures/explain_blocked.json";
import type { ActionExplain, GuardDecision } from "../api/types";
import { mockFetch, renderPage } from "../test/utils";
import { AgentInfluence } from "./AgentInfluence";
import { EndorsementFlip } from "./EndorsementFlip";

describe("AgentInfluence", () => {
  it("collapses provenance to Scout → Memory → Ops and reveals the path", async () => {
    mockFetch([["/console/influence", influence]]);
    renderPage(<AgentInfluence />);
    const flows = await screen.findByTestId("influence-flows");
    const row = within(flows).getAllByTestId("influence")[0];
    expect(row).toHaveTextContent(/scout.*Memory.*ops/);
    expect(row).toHaveTextContent("untrusted influence");
    // the first tainted flow is opened by default, showing the real path to the source
    const path = within(row).getByTestId("influence-path");
    expect(path).toHaveTextContent("web:https://docs.vaultsync-backup.example/setup");
    expect(path).toHaveTextContent("untrusted");
    await userEvent.click(within(row).getByRole("button"));
    expect(within(row).queryByTestId("influence-path")).toBeNull();
  });
});

describe("EndorsementFlip", () => {
  it("shows before → the new ENDORSES relationship → the re-run verdict", () => {
    const ex = blocked as unknown as ActionExplain;
    const after = { ...ex.decision, decision: "ALLOW", triggered_checks: [] } as GuardDecision;
    renderPage(
      <EndorsementFlip
        f={{
          actionId: "act_1",
          actionType: "configure_backup",
          before: "REQUIRE_HUMAN_APPROVAL",
          beforeTriggered: ["integrity"],
          after,
          knownBefore: [],
          explain: {
            ...ex,
            approvals: [
              {
                id: "apv_9",
                approver: "priya@acme-robotics.example",
                created_at: "2026-10-06T10:00:00Z",
                relation: "ENDORSES",
                datum_id: "d_dest",
              },
            ],
          },
        }}
      />,
    );
    const rel = screen.getByTestId("flip-relationships");
    expect(rel).toHaveTextContent(
      "(:Approval apv_9 by priya@acme-robotics.example)-[:ENDORSES]→(:Datum d_dest)",
    );
    const badges = screen.getAllByTestId("verdict-badge").map((b) => b.textContent);
    expect(badges[0]).toMatch(/APPROVAL/);
    expect(badges[1]).toMatch(/ALLOW/);
  });
});
