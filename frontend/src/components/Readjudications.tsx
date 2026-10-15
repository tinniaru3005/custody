import { useReadjudications } from "../api/hooks";
import type { ReadjudicationReport } from "../api/types";
import { fmtTime } from "../lib/format";
import { Panel, VerdictBadge } from "./ui";

export function ReadjudicationCard({ r }: { r: ReadjudicationReport }) {
  return (
    <div className="readjudication" data-testid="readjudication">
      <p className="small">
        <span className="mono">{r.source_id}</span> marked{" "}
        <strong>
          {r.trust_before} → {r.trust_after}
        </strong>{" "}
        by {r.revoked_by} {r.reason ? `(“${r.reason}”)` : ""} · {fmtTime(r.revoked_at)} · graph{" "}
        <span className="mono">
          {r.graph_version_before} → {r.graph_version_after}
        </span>
      </p>
      <p>
        <strong data-testid="readj-count">{r.actions.length} historical action(s) affected</strong>{" "}
        ({r.downstream_datums} downstream data, {r.memories.length} memories, {r.messages.length}{" "}
        messages)
      </p>
      <ul className="small mono" data-testid="readj-summary">
        {Object.entries(r.summary).map(([k, v]) => (
          <li key={k}>
            {k}: {v}
          </li>
        ))}
      </ul>
      <table className="table small">
        <thead>
          <tr>
            <th>Action</th>
            <th>Known at execution time</th>
            <th>Known now</th>
            <th>Status (unchanged)</th>
          </tr>
        </thead>
        <tbody>
          {r.actions.map((a) => (
            <tr key={a.action_id} title={a.current_explanation}>
              <td className="mono">
                {a.action_type} {a.action_id}
              </td>
              <td>{a.original_verdict ? <VerdictBadge verdict={a.original_verdict} /> : "—"}</td>
              <td>
                <VerdictBadge verdict={a.current_verdict} />
              </td>
              <td>{a.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted small">
        {r.known_then} {r.known_now}
      </p>
    </div>
  );
}

/** Latest trust revocations and their re-adjudications (if any). */
export function ReadjudicationsPanel() {
  const q = useReadjudications();
  if (!q.data?.length) return null;
  return (
    <Panel
      title="Re-adjudication after trust revocation"
      subtitle="History is kept: original verdicts stay; current verdicts are added next to them"
    >
      {q.data.slice(0, 3).map((r) => (
        <ReadjudicationCard key={r.id} r={r} />
      ))}
    </Panel>
  );
}
