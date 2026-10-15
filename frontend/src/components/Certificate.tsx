import type { GuardDecision, ProvenanceCertificate, RootSource } from "../api/types";
import { fmtMs, fmtTime } from "../lib/format";
import { VerdictBadge } from "./ui";

const STATUS_TEXT: Record<RootSource["status"], string> = {
  followed: "followed",
  context_only: "context only",
  cleared: "cleared",
};

function short(digest: string) {
  return digest.replace("sha256:", "").slice(0, 12);
}

/**
 * Provenance Completeness Certificate for an ALLOW. Concise summary first; root sources
 * and the raw evidence behind a disclosure. Never rendered for other verdicts.
 */
export function CertificateCard({
  c,
  compact = false,
}: {
  c: ProvenanceCertificate;
  compact?: boolean;
}) {
  const downgraded = c.strength === "DOWNGRADED";
  const rows: [string, string, string?][] = [
    ["Untrusted influence", "NONE FOUND (recorded graph · current trust labels)", "ok"],
    [
      "Provenance coverage",
      downgraded
        ? `REDUCED (${c.reduced_provenance_count ?? 0} model output(s)) · not exhaustive`
        : "FULL CONTEXT",
      downgraded ? "warn" : "ok",
    ],
    ["Traversal", c.traversal_complete ? "COMPLETE" : "INCOMPLETE", "ok"],
    ["Frontier", c.frontier_exhausted ? "EXHAUSTED" : "NOT EXHAUSTED", "ok"],
    ["Root sources checked", String(c.root_sources_checked)],
    [
      "Context provenance",
      c.context_provenance_included ? `INCLUDED (${c.context_edges_examined} context edges)` : "—",
      "ok",
    ],
    ["Graph version", c.graph_version_label],
  ];
  if (c.certificate_id) rows.push(["Certificate ID", c.certificate_id]);
  if (!compact) {
    rows.push(
      ["Max depth reached", String(c.max_depth_reached)],
      ["Examined", `${c.nodes_examined} nodes · ${c.relationships_examined} relationships`],
      ["Guard latency", fmtMs(c.guard_latency_ms)],
    );
  }
  return (
    <div className="certificate" data-testid="certificate">
      <div className="cert-head">
        <VerdictBadge verdict="ALLOW" />
        <span className="cert-title">
          Provenance completeness certificate
          {downgraded && (
            <span className="flag flag-secret" data-testid="cert-downgraded">
              {" "}
              downgraded
            </span>
          )}
        </span>
      </div>
      <p className="small cert-statement" data-testid="cert-statement">
        No untrusted influence was found relative to the recorded provenance graph and current
        Source trust labels.
        {downgraded &&
          " Some model outputs in this ancestry were recorded with reduced provenance, so this is not an exhaustive account of recorded influence."}
      </p>
      <dl className="cert-grid">
        {rows.map(([k, v, tone]) => (
          <div key={k} className="cert-row">
            <dt>{k}</dt>
            <dd
              className={
                tone === "ok" ? "cert-ok mono" : tone === "warn" ? "cert-warn mono" : "mono"
              }
              data-testid={`cert-${k}`}
            >
              {v}
            </dd>
          </div>
        ))}
      </dl>
      <details className="cert-details">
        <summary>
          Root sources ({c.root_sources.length}) and evidence
          {c.untrusted_roots_not_followed > 0 &&
            ` · ${c.untrusted_roots_not_followed} untrusted, not on a followed path`}
        </summary>
        <p className="small cert-claim" data-testid="cert-claim">
          {c.claim}
        </p>
        <p className="small muted" data-testid="cert-trust-note">
          {c.trust_labels_note ??
            "Source trust labels are policy inputs, not facts inferred by Custody."}
        </p>
        <table className="table small" data-testid="cert-roots">
          <thead>
            <tr>
              <th>Source</th>
              <th>Trust label (policy input)</th>
              <th>Guard</th>
              <th>Depth</th>
            </tr>
          </thead>
          <tbody>
            {c.root_sources.map((r) => (
              <tr key={r.id} title={r.note}>
                <td className="mono">{r.id}</td>
                <td>
                  <span
                    className={`flag flag-${r.trust === "untrusted" ? "untrusted" : "trusted"}`}
                  >
                    {r.trust ?? "?"}
                  </span>
                </td>
                <td>
                  {STATUS_TEXT[r.status]}
                  {r.status !== "followed" && <div className="muted small">{r.note}</div>}
                </td>
                <td className="mono">{r.min_depth}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {downgraded && (c.reduced_provenance?.length ?? 0) > 0 && (
          <p className="small" data-testid="cert-reduced">
            Reduced provenance:{" "}
            {c.reduced_provenance!.map((r) => (
              <span key={r.datum_id} className="mono">
                {r.datum_id} ({r.kind}, {r.coverage}){" "}
              </span>
            ))}
          </p>
        )}
        <ul className="small cert-evidence">
          <li>
            Scope: <span className="mono">{c.scope}</span>
          </li>
          <li>
            Termination: <span className="mono">{c.termination_reason}</span> · max depth{" "}
            {c.max_depth_reached} · {c.nodes_examined} nodes · {c.derived_from_edges_examined}{" "}
            DERIVED_FROM ({c.context_edges_examined} context) +{" "}
            {c.relationships_examined - c.derived_from_edges_examined} FROM edges
          </li>
          <li>
            Guard-followed nodes: {c.guard_followed_nodes} · payload: {c.payload}
          </li>
          <li>
            Graph <span className="mono">{c.graph}</span> version{" "}
            <span className="mono">v{c.graph_version}</span> · ancestry digest{" "}
            <span className="mono" title={c.ancestry_digest}>
              {short(c.ancestry_digest)}…
            </span>
          </li>
          <li>
            Guard {fmtMs(c.guard_latency_ms)} (certificate {fmtMs(c.certificate_latency_ms)}) ·
            issued {fmtTime(c.issued_at)} · <span className="mono">{c.id}</span>
          </li>
          {c.certificate_id && (
            <li>
              Certificate ID <span className="mono">{c.certificate_id}</span>: a deterministic
              fingerprint of {c.certificate_id_inputs?.join(", ")}. The same action against the same
              graph state gives the same ID; it is a comparison handle, not a proof.
            </li>
          )}
        </ul>
      </details>
    </div>
  );
}

/** For ALLOW decisions: the certificate, or why there is none. */
export function CertificateSection({ d }: { d: GuardDecision }) {
  if (d.decision !== "ALLOW") return null;
  if (d.certificate) return <CertificateCard c={d.certificate} />;
  return (
    <p className="small approval-note" data-testid="no-certificate">
      No completeness certificate: {d.certificate_unavailable ?? "not available"}
    </p>
  );
}
