import { api, ApiError } from "./client";

describe("api client", () => {
  it("prefixes /api and the tenant", async () => {
    const spy = vi.fn(async () => new Response("[]", { status: 200 }));
    vi.stubGlobal("fetch", spy);
    await api.actions();
    expect(spy).toHaveBeenCalledWith("/api/tenants/acme/console/actions", expect.anything());
  });

  it("surfaces the backend's detail message", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () => new Response(JSON.stringify({ detail: "lethal trifecta" }), { status: 403 }),
      ),
    );
    await expect(api.approve("act_1", "priya")).rejects.toMatchObject({
      status: 403,
      message: "lethal trifecta",
    });
  });

  it("maps network failures to status 0", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Promise.reject(new TypeError("down"))),
    );
    await expect(api.health()).rejects.toBeInstanceOf(ApiError);
  });
});
