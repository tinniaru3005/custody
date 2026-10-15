import { render, screen, within } from "@testing-library/react";
import type { ActionExplain, ContaminationReport } from "../api/types";
import blocked from "../test/fixtures/explain_blocked.json";
import { ContaminationSection } from "./Contamination";

const ex = blocked as unknown as ActionExplain;

describe("ContaminationSection", () => {
  it("shows the primary demo's single root and the verified shared memory", () => {
    const c = ex.decision.contamination!;
    render(<ContaminationSection c={c} actionId={ex.decision.action_id} />);
    const box = screen.getByTestId("contamination");
    expect(box).toHaveTextContent("Untrusted roots detected: 1");
    expect(within(box).getAllByTestId("root")).toHaveLength(1);
    expect(screen.getByTestId("independence")).toHaveTextContent(/not independent|no —/i);
    expect(box).toHaveTextContent(/verdict comes from the complete integrity search/);
  });

  it("distinguishes two roots from independent routes", () => {
    const base = ex.decision.contamination!;
    const second = { ...base.roots[0], source_id: "email:msg-1@partner.example" };
    const two: ContaminationReport = {
      ...base,
      root_count: 2,
      roots: [base.roots[0], second],
      independence: "independent",
      independent_routes: 2,
      shared_datum_id: null,
    };
    render(<ContaminationSection c={two} actionId="act_42" />);
    expect(screen.getByTestId("contamination")).toHaveTextContent("Untrusted roots detected: 2");
    expect(screen.getByTestId("contamination")).toHaveTextContent("Both influenced action act_42");
    expect(screen.getByTestId("independence")).toHaveTextContent(/yes/);
  });

  it("renders nothing without a report, and says 'at least' when incomplete", () => {
    const { container } = render(<ContaminationSection c={null} actionId="a" />);
    expect(container).toBeEmptyDOMElement();
    const c = { ...ex.decision.contamination!, roots_complete: false };
    render(<ContaminationSection c={c} actionId="a" />);
    expect(screen.getByTestId("contamination")).toHaveTextContent("at least 1");
  });
});
