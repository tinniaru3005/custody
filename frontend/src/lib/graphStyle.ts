import type { GraphNode } from "../api/types";
import { COLORS } from "./format";

/** Fill colour of a graph node: its trust / sensitivity / containment / verdict state. */
export function nodeColor(n: GraphNode): string {
  const f = new Set(n.flags);
  if (f.has("quarantined")) return COLORS.quarantined;
  if (n.label === "Action") {
    if (n.verdict === "BLOCK" || n.status === "blocked") return COLORS.untrusted;
    if (n.status === "pending_approval") return COLORS.approval;
    if (n.status === "rejected") return COLORS.neutral;
    return COLORS.trusted;
  }
  if (n.label === "Sink") return n.external ? COLORS.untrusted : COLORS.trusted;
  if (n.label === "Approval") return n.verdict === "rejected" ? COLORS.untrusted : COLORS.approval;
  if (n.label === "Source")
    return n.trust === "untrusted"
      ? COLORS.untrusted
      : f.has("secret")
        ? COLORS.secret
        : COLORS.trusted;
  if (f.has("secret")) return COLORS.secret;
  if (f.has("tainted")) return COLORS.untrusted;
  if (f.has("endorsed")) return COLORS.trusted;
  return COLORS.neutral;
}
