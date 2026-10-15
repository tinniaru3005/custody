import { screen } from "@testing-library/react";
import { mockFetch, renderPage } from "../test/utils";
import { SimulationBanner } from "./Layout";

describe("SimulationBanner", () => {
  it("always discloses what is simulated", () => {
    mockFetch([]);
    renderPage(<SimulationBanner publicDemo={false} />);
    const b = screen.getByTestId("simulation-banner");
    expect(b).toHaveTextContent(/synthetic company/);
    expect(b).toHaveTextContent(/Slack, vault, GitHub/);
    expect(b).toHaveTextContent(/simulated sessions/);
    expect(b).toHaveTextContent(/scripted flows/);
    expect(screen.queryByTestId("reset-demo")).toBeNull();
  });

  it("shows the public-demo tag and Reset Demo in public mode", () => {
    mockFetch([]);
    renderPage(<SimulationBanner publicDemo />);
    expect(screen.getByTestId("public-demo-tag")).toHaveTextContent(/read-only/);
    expect(screen.getByTestId("reset-demo")).toBeEnabled();
  });
});
