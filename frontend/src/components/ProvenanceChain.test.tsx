import { screen } from "@testing-library/react";
import blocked from "../test/fixtures/explain_blocked.json";
import slack from "../test/fixtures/explain_slack.json";
import type { ActionExplain } from "../api/types";
import { renderPage } from "../test/utils";
import { ProvenanceChain } from "./ProvenanceChain";

const ex = blocked as unknown as ActionExplain;

describe("ProvenanceChain", () => {
  it("shows the full cross-session path behind the block, in order", () => {
    renderPage(<ProvenanceChain cards={ex.chain} />);
    const roles = [...document.querySelectorAll("[data-role]")].map((e) =>
      e.getAttribute("data-role"),
    );
    expect(roles).toEqual([
      "action",
      "sink",
      "destination",
      "previous-session memory",
      "web page",
      "source",
    ]);
    expect(screen.getByText("untrusted")).toBeInTheDocument();
    expect(screen.getByText("external")).toBeInTheDocument();
    expect(screen.getByText(/crosses into scout-day1/)).toBeInTheDocument();
    expect(screen.getByText("2 DERIVED_FROM hops")).toBeInTheDocument();
  });

  it("explains when an allowed action has no untrusted path", () => {
    const s = slack as unknown as ActionExplain;
    renderPage(<ProvenanceChain cards={s.chain} />);
    expect(screen.getByText("internal")).toBeInTheDocument();
  });
});
