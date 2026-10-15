import type { ActionStatus, Verdict } from "../api/types";

// Semantic colours (validated as a set for the dark surface: dataviz validate_palette.js).
// Every use is paired with a text label or a shape, never colour alone.
export const COLORS = {
  trusted: "#199e70",
  untrusted: "#e5484d",
  secret: "#c98500",
  quarantined: "#9085e9",
  neutral: "#64748b",
  approval: "#e2e8f0",
  edge: "#475569",
} as const;

export const VERDICT_LABEL: Record<Verdict, string> = {
  ALLOW: "ALLOW",
  REQUIRE_HUMAN_APPROVAL: "REQUIRE APPROVAL",
  BLOCK: "BLOCK",
};

export const verdictClass = (v?: string | null) =>
  v === "ALLOW"
    ? "allow"
    : v === "BLOCK"
      ? "block"
      : v === "REQUIRE_HUMAN_APPROVAL"
        ? "approval"
        : "none";

export const STATUS_LABEL: Record<ActionStatus, string> = {
  proposed: "proposed",
  pending_approval: "awaiting approval",
  approved: "approved",
  blocked: "blocked",
  rejected: "rejected",
  executed: "executed",
  failed: "failed",
};

export const CHECK_LABEL: Record<string, string> = {
  integrity: "Integrity",
  confidentiality: "Confidentiality",
  lethal_trifecta: "Lethal trifecta",
  human_review: "Human review",
  precedent: "Precedent",
};

export function shortId(id: string, n = 8): string {
  if (id.includes(":")) return id;
  const [p, rest] = id.split("_", 2);
  return rest ? `${p}_${rest.slice(0, n)}` : id.slice(0, n + 4);
}

export function fmtTime(iso?: string | null): string {
  if (!iso) return "–";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function fmtMs(ms?: number | null): string {
  if (ms === undefined || ms === null) return "–";
  return ms < 10 ? `${ms.toFixed(2)} ms` : `${ms.toFixed(1)} ms`;
}

export function truncate(s: string | null | undefined, n = 120): string {
  if (!s) return "";
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

export function hostOf(url?: string | null): string {
  if (!url) return "";
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
