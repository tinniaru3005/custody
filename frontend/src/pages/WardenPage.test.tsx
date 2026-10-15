import { screen } from "@testing-library/react";
import warden from "../test/fixtures/warden.json";
import { mockFetch, renderPage } from "../test/utils";
import { WardenPage } from "./WardenPage";

describe("WardenPage", () => {
  it("renders every MCP tool call of the last investigation", async () => {
    mockFetch([["/console/warden", warden]]);
    renderPage(<WardenPage />);
    expect(await screen.findByTestId("quarantined-count")).toHaveTextContent("2");
    const tools = [...document.querySelectorAll("[data-tool]")].map((e) =>
      e.getAttribute("data-tool"),
    );
    expect(tools).toEqual(warden.tools_used);
    expect(screen.getByText("Risky-memory ranking")).toBeInTheDocument();
    expect(screen.getByText("Incident grouping")).toBeInTheDocument();
    expect(screen.getByText(/Draft to/)).toBeInTheDocument();
    expect(screen.getByTestId("warden-report")).toHaveTextContent(/APPROVAL NEEDED/);
  });
});
