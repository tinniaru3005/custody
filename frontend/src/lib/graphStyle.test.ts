import type { GraphNode } from "../api/types";
import { COLORS } from "./format";
import { nodeColor } from "./graphStyle";

const n = (p: Partial<GraphNode>): GraphNode => ({
  id: "x",
  label: "Datum",
  labels: [],
  title: "",
  flags: [],
  metadata: {},
  ...p,
});

describe("nodeColor", () => {
  it("distinguishes trusted, untrusted, secret, quarantined and blocked", () => {
    expect(nodeColor(n({ label: "Source", trust: "untrusted" }))).toBe(COLORS.untrusted);
    expect(nodeColor(n({ label: "Source", trust: "trusted" }))).toBe(COLORS.trusted);
    expect(nodeColor(n({ flags: ["secret"] }))).toBe(COLORS.secret);
    expect(nodeColor(n({ flags: ["tainted", "quarantined"], label: "Memory" }))).toBe(
      COLORS.quarantined,
    );
    expect(nodeColor(n({ label: "Action", verdict: "BLOCK", status: "blocked" }))).toBe(
      COLORS.untrusted,
    );
    expect(nodeColor(n({ label: "Sink", external: false }))).toBe(COLORS.trusted);
  });
});
