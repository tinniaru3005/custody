import { screen, within } from "@testing-library/react";
import blocked from "../test/fixtures/explain_blocked.json";
import slack from "../test/fixtures/explain_slack.json";
import type { ActionExplain } from "../api/types";
import { renderPage } from "../test/utils";
import { DecisionDetail } from "./DecisionDetail";

describe("DecisionDetail", () => {
  it("renders a lethal-trifecta BLOCK with every check and no approval option", () => {
    renderPage(<DecisionDetail ex={blocked as unknown as ActionExplain} />);
    expect(screen.getAllByText(/BLOCK/).length).toBeGreaterThan(0);
    for (const c of ["integrity", "confidentiality", "lethal_trifecta"]) {
      expect(within(screen.getByTestId(`check-${c}`)).getByText(/VIOLATED/)).toBeInTheDocument();
    }
    expect(screen.getByTestId("trifecta")).toHaveClass("hit");
    expect(screen.getByTestId("approval-option")).toHaveTextContent(/No approval option/);
    expect(screen.getByText(/deterministic · no LLM/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /approve/i })).toBeNull();
  });

  it("renders an ALLOW with passing checks", () => {
    renderPage(<DecisionDetail ex={slack as unknown as ActionExplain} />);
    expect(within(screen.getByTestId("check-integrity")).getByText(/passed/)).toBeInTheDocument();
    expect(screen.getByTestId("trifecta")).not.toHaveClass("hit");
  });
});
