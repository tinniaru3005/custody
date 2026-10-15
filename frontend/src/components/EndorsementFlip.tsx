import { Link } from "react-router-dom";
import { relKey, type Flip } from "../lib/flip";
import { VerdictBadge } from "./ui";

export function EndorsementFlip({ f }: { f: Flip }) {
  const rels = (f.explain?.approvals ?? []).filter(
    (a) => a.relation !== "REJECTS" && !f.knownBefore.includes(relKey(a)),
  );
  const cert = f.after.certificate;
  const cleared = cert?.root_sources.filter((r) => r.status === "cleared") ?? [];
  return (
    <div className="flip" data-testid="endorsement-flip">
      <div className="flip-row">
        <div className="flip-step">
          <div className="muted small">before</div>
          <VerdictBadge verdict={f.before} />
        </div>
        <div className="flip-arrow">→</div>
        <div className="flip-step flip-rel" data-testid="flip-relationships">
          <div className="muted small">human decision, written to the graph</div>
          {rels.length === 0 && <span className="muted small">reading back…</span>}
          {rels.map((a) => (
            <code key={a.id + a.relation + (a.datum_id ?? "")}>
              (:Approval {a.id} by {a.approver})-[:{a.relation}]→
              {a.relation === "ENDORSES" ? `(:Datum ${a.datum_id})` : `(:Action ${f.actionId})`}
            </code>
          ))}
        </div>
        <div className="flip-arrow">→</div>
        <div className="flip-step">
          <div className="muted small">Guard re-ran</div>
          <VerdictBadge verdict={f.after.decision} />
        </div>
      </div>
      <p className="small">
        <span className="mono">{f.actionType}</span> {f.actionId}: was{" "}
        {f.beforeTriggered.join(", ") || "—"}; now{" "}
        {f.after.triggered_checks?.length ? f.after.triggered_checks.join(", ") : "no check fires"}.{" "}
        {cleared.length > 0 &&
          `The certificate lists ${cleared.map((r) => r.id).join(", ")} as "cleared": every path to it now passes through endorsed data. `}
        {f.after.decision === "ALLOW" &&
          "Endorsement clears integrity only; confidentiality rules are unchanged."}
      </p>
      <Link className="small" to={`/graph?focus=${encodeURIComponent(rels[0]?.id ?? f.actionId)}`}>
        See the new relationship in the provenance graph →
      </Link>
    </div>
  );
}
