import { screen } from "@testing-library/react";
import overview from "../test/fixtures/overview_after.json";
import { mockFetch, renderPage } from "../test/utils";
import { DashboardPage } from "./DashboardPage";

describe("DashboardPage", () => {
  it("shows agents, verdict counts, incidents and quarantined memories", async () => {
    mockFetch([["/console/overview", overview]]);
    renderPage(<DashboardPage />);
    expect(await screen.findByTestId("stat-blocked")).toHaveTextContent("1");
    expect(screen.getByTestId("stat-quarantined")).toHaveTextContent("2");
    expect(screen.getByTestId("stat-incidents")).toHaveTextContent("2");
    const names = [...document.querySelectorAll(".agent-name")].map((e) => e.textContent);
    expect(names).toEqual(["scout", "ops", "warden", "courier"]);
    expect(screen.getByText("upload_backup")).toBeInTheDocument();
    expect(screen.getAllByText("quarantined").length).toBe(2);
  });

  it("shows the run button on an empty tenant", async () => {
    mockFetch([
      ["/console/overview", { ...overview, empty: true, actions: [], agents: [], memories: [] }],
    ]);
    renderPage(<DashboardPage />);
    expect(await screen.findByTestId("run-attack")).toHaveTextContent(/Run attack scenario/);
  });

  it("shows an error state when the backend is down", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Promise.reject(new TypeError("Failed to fetch"))),
    );
    renderPage(<DashboardPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/Backend unreachable/);
  });
});
