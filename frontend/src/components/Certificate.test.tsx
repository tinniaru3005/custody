import { screen, within } from "@testing-library/react";
import slack from "../test/fixtures/explain_slack.json";
import blocked from "../test/fixtures/explain_blocked.json";
import type { ActionExplain } from "../api/types";
import { renderPage } from "../test/utils";
import { CertificateCard, CertificateSection } from "./Certificate";

const allow = (slack as unknown as ActionExplain).decision;
const block = (blocked as unknown as ActionExplain).decision;

describe("Provenance completeness certificate", () => {
  it("summarises the ALLOW concisely and expands to every root source", () => {
    renderPage(<CertificateCard c={allow.certificate!} />);
    expect(screen.getByTestId("cert-Untrusted influence")).toHaveTextContent("NONE FOUND");
    expect(screen.getByTestId("cert-Traversal")).toHaveTextContent("COMPLETE");
    expect(screen.getByTestId("cert-Frontier")).toHaveTextContent("EXHAUSTED");
    expect(screen.getByTestId("cert-Context provenance")).toHaveTextContent("INCLUDED");
    expect(screen.getByTestId("cert-Graph version")).toHaveTextContent(
      allow.certificate!.graph_version_label,
    );
    expect(screen.getByTestId("cert-Root sources checked")).toHaveTextContent(
      String(allow.certificate!.root_sources.length),
    );
    const rows = within(screen.getByTestId("cert-roots")).getAllByRole("row");
    expect(rows).toHaveLength(allow.certificate!.root_sources.length + 1);
    expect(screen.getByTestId("cert-roots")).toHaveTextContent("context only");
    expect(screen.getByTestId("cert-claim")).toHaveTextContent(/does not say the action is safe/);
    expect(screen.queryByText(/proven safe/i)).toBeNull();
    // precise statement, trust labels as policy inputs, coverage, deterministic id
    expect(screen.getByTestId("cert-statement")).toHaveTextContent(
      "No untrusted influence was found relative to the recorded provenance graph and current Source trust labels.",
    );
    expect(screen.getByTestId("cert-trust-note")).toHaveTextContent(/policy inputs/);
    expect(screen.getByTestId("cert-roots")).toHaveTextContent("Trust label (policy input)");
    expect(screen.getByTestId("cert-Provenance coverage")).toHaveTextContent("FULL CONTEXT");
    expect(screen.getByTestId("cert-Certificate ID")).toHaveTextContent(/^pcc_[0-9a-f]{16}$/);
    expect(screen.queryByTestId("cert-downgraded")).toBeNull();
  });

  it("downgrades visibly when reduced provenance is in the ancestry", () => {
    const c = {
      ...allow.certificate!,
      strength: "DOWNGRADED" as const,
      provenance_coverage: "REDUCED" as const,
      reduced_provenance_count: 1,
      reduced_provenance: [{ datum_id: "d_x", kind: "llm_output", coverage: "REDUCED" }],
    };
    renderPage(<CertificateCard c={c} />);
    expect(screen.getByTestId("cert-downgraded")).toBeInTheDocument();
    expect(screen.getByTestId("cert-Provenance coverage")).toHaveTextContent(
      /REDUCED.*not exhaustive/,
    );
    expect(screen.getByTestId("cert-statement")).toHaveTextContent(/not an exhaustive account/);
    expect(screen.getByTestId("cert-reduced")).toHaveTextContent("d_x");
  });

  it("is never shown for a BLOCK", () => {
    const { container } = renderPage(<CertificateSection d={block} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("says why when an ALLOW has no certificate", () => {
    renderPage(
      <CertificateSection
        d={{ ...allow, certificate: null, certificate_unavailable: "graph changed" }}
      />,
    );
    expect(screen.getByTestId("no-certificate")).toHaveTextContent("graph changed");
  });
});
