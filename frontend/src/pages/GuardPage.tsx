import { Link, useNavigate, useParams } from "react-router-dom";
import { useActions, useExplain, useOverview } from "../api/hooks";
import { DecisionDetail } from "../components/DecisionDetail";
import { Empty, ErrorState, Loading, StatusBadge, VerdictBadge } from "../components/ui";
import { fmtMs, fmtTime, truncate } from "../lib/format";

export function GuardPage() {
  const { actionId } = useParams();
  const nav = useNavigate();
  const actions = useActions();
  const overview = useOverview();
  const fallback =
    overview.data?.demo?.blocked_action ??
    actions.data?.find((a) => a.verdict === "BLOCK")?.id ??
    actions.data?.[actions.data.length - 1]?.id;
  const id = actionId ?? fallback;
  const ex = useExplain(id);

  if (actions.isLoading) return <Loading label="Loading Guard decisions…" />;
  if (actions.error) return <ErrorState error={actions.error} onRetry={() => actions.refetch()} />;
  const list = actions.data ?? [];

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Guard decisions</h1>
          <p className="muted">
            Each decision is a pure function of Cypher provenance queries and a static policy.
            Re-running a check gives the same answer, with the exact path that caused it.
          </p>
        </div>
      </header>
      {list.length === 0 ? (
        <Empty title="No actions have been checked yet">
          <Link to="/demo">Run the attack scenario</Link> to generate agent activity.
        </Empty>
      ) : (
        <div className="guard-grid">
          <nav className="action-list" aria-label="Checked actions" data-testid="action-list">
            {list.map((a) => (
              <button
                key={a.id}
                className={`action-row ${a.id === id ? "active" : ""}`}
                onClick={() => nav(`/guard/${a.id}`)}
              >
                <span className="row between">
                  <span className="mono">{a.action_type}</span>
                  <VerdictBadge verdict={a.verdict} />
                </span>
                <span className="small muted">
                  {a.agent} · {fmtTime(a.sim_time ?? a.created_at)} · {fmtMs(a.latency_ms)}
                </span>
                <span className="small mono">{truncate(a.destination ?? "no sink", 42)}</span>
                <StatusBadge status={a.status} />
              </button>
            ))}
          </nav>
          <div>
            {ex.isLoading ? (
              <Loading label="Re-running the Guard…" />
            ) : ex.error ? (
              <ErrorState error={ex.error} onRetry={() => ex.refetch()} />
            ) : ex.data ? (
              <DecisionDetail ex={ex.data} />
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}
