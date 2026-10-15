import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import approvals from "../test/fixtures/approvals.json";
import { mockFetch, renderPage } from "../test/utils";
import { ApprovalsPage } from "./ApprovalsPage";

describe("ApprovalsPage", () => {
  it("offers approve/reject for approvable actions but never for lethal-trifecta blocks", async () => {
    mockFetch([["/console/approvals", approvals]]);
    renderPage(<ApprovalsPage />);
    const pending = await screen.findAllByTestId("pending-card");
    expect(pending).toHaveLength(1);
    expect(within(pending[0]).getByTestId("approve")).toBeEnabled();
    expect(within(pending[0]).getByText(/Why approval is needed/)).toBeInTheDocument();
    expect(within(pending[0]).getByTestId("provenance-chain")).toBeInTheDocument();
    const blocked = screen.getByTestId("blocked-card");
    expect(within(blocked).queryByRole("button")).toBeNull();
    expect(within(blocked).getByText(/cannot be approved/)).toBeInTheDocument();
  });

  it("records an approval through the Guard API", async () => {
    const id = approvals.pending[0].explain.action.id;
    const spy = mockFetch([
      [`/guard/actions/${id}/approve`, { decision: "ALLOW" }],
      ["/console/approvals", approvals],
    ]);
    renderPage(<ApprovalsPage />);
    const card = (await screen.findAllByTestId("pending-card"))[0];
    await userEvent.type(within(card).getByLabelText("Reason"), "verified");
    await userEvent.click(within(card).getByTestId("approve"));
    await waitFor(() =>
      expect(spy).toHaveBeenCalledWith(
        expect.stringContaining(`/api/tenants/acme/guard/actions/${id}/approve`),
        expect.objectContaining({ method: "POST" }),
      ),
    );
    const call = spy.mock.calls.find(([u]) => String(u).includes("/approve"))!;
    expect(JSON.parse(String(call[1]!.body))).toEqual({
      approver: "priya@acme-robotics.example",
      reason: "verified",
    });
  });
});
