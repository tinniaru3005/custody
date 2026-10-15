import { useState } from "react";
import { useInfluence } from "../api/hooks";
import type { InfluenceEdge } from "../api/types";
import { Empty, ErrorState, Loading, Panel } from "./ui";

function end(id: string) {
  const [type, ...rest] = id.split(":");
  const name = rest.join(":");
  return { type, name };
}

function Chip({ id }: { id: string }) {
  const e = end(id);
  return (
    <span className={`inf-chip inf-${e.type}`} title={id}>
      {e.type === "agent" ? e.name : e.name.replace(/^web:https?:\/\//, "web: ")}
    </span>
  );
}

function Row({ i, open, onClick }: { i: InfluenceEdge; open: boolean; onClick: () => void }) {
  return (
    <li className={`inf-row ${i.tainted ? "tainted" : "clean"}`} data-testid="influence">
      <button className="inf-btn" onClick={onClick} aria-expanded={open}>
        <Chip id={i.source} />
        <span className="inf-arrow">→</span>
        {i.via && (
          <>
            <span className="inf-chip inf-carrier" title={i.via_preview ?? ""}>
              {i.via_label} <span className="mono small">{i.via}</span>
            </span>
            <span className="inf-arrow">→</span>
          </>
        )}
        <Chip id={i.target} />
        <span className="inf-meta small muted">
          {i.tainted ? "untrusted influence" : "clean"} · {i.edges} edge(s)
          {i.sessions.length > 1 ? ` · ${i.sessions.join(" → ")}` : ""}
          {!i.followed && " · context only"}
        </span>
      </button>
      {open && (
        <ol className="world-chain inf-path" data-testid="influence-path">
          {i.path.map((s) => (
            <li key={s.id} className={s.trust ? `src src-${s.trust}` : ""}>
              {s.op && <span className="world-op mono">{s.op} ↓</span>}
              <span className="mono small">
                {s.label === "Source" ? s.id : `${s.label} ${s.id}`}
              </span>
              {s.agent && (
                <span className="muted small">
                  {" "}
                  · {s.agent}
                  {s.session_id ? `@${s.session_id}` : ""}
                </span>
              )}
              {s.trust && (
                <span className={`flag flag-${s.trust === "untrusted" ? "untrusted" : "trusted"}`}>
                  {s.trust}
                </span>
              )}
            </li>
          ))}
        </ol>
      )}
    </li>
  );
}

/** The provenance graph collapsed to who influenced whom (derived server-side). */
export function AgentInfluence() {
  const q = useInfluence();
  const [open, setOpen] = useState<string | null>(null);
  if (q.isLoading) return <Loading label="Collapsing provenance to agents…" />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  const v = q.data!;
  const flows = v.influences.filter((i) => i.kind !== "entry");
  const entries = v.influences.filter((i) => i.kind === "entry");
  const firstTainted = flows.find((i) => i.tainted)?.id ?? null;
  const shown = open ?? firstTainted;
  return (
    <Panel
      title="Agent-level influence"
      subtitle={`${v.summary} · derived from the FalkorDB provenance graph · click a row for the underlying path`}
    >
      {v.influences.length === 0 ? (
        <Empty title="No cross-agent influence recorded yet" />
      ) : (
        <>
          {entries.length > 0 && (
            <>
              <h4 className="section-title">Where untrusted content entered</h4>
              <ul className="inf-list">
                {entries.map((i) => (
                  <Row
                    key={i.id}
                    i={i}
                    open={shown === i.id}
                    onClick={() => setOpen(shown === i.id ? "" : i.id)}
                  />
                ))}
              </ul>
            </>
          )}
          <h4 className="section-title">Between agents</h4>
          <ul className="inf-list" data-testid="influence-flows">
            {flows.map((i) => (
              <Row
                key={i.id}
                i={i}
                open={shown === i.id}
                onClick={() => setOpen(shown === i.id ? "" : i.id)}
              />
            ))}
          </ul>
        </>
      )}
    </Panel>
  );
}
