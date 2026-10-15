import { Link } from "react-router-dom";
import { useMetrics } from "../api/hooks";
import { LatencyBars } from "../components/DecisionDetail";
import { Empty, ErrorState, Loading, Panel, Stat } from "../components/ui";
import { fmtMs } from "../lib/format";

export function MetricsPage() {
  const q = useMetrics();
  if (q.isLoading) return <Loading label="Re-running the Guard to measure it…" />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  const m = q.data!;
  if (!m.focus_action) {
    return (
      <div className="page">
        <h1>Metrics</h1>
        <Empty title="No blocked action to measure yet">
          <Link to="/demo">Run the attack scenario</Link> first.
        </Empty>
      </div>
    );
  }
  const samples = m.guard_latency_samples;
  const max = Math.max(...samples, 0.001);
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Metrics</h1>
          <p className="muted">
            Measured live: the blocked action was re-checked {m.deterministic_runs} times just now.
          </p>
        </div>
        <button className="btn" onClick={() => q.refetch()} disabled={q.isFetching}>
          {q.isFetching ? "Measuring…" : "Re-measure"}
        </button>
      </header>

      <div
        className={`determinism ${m.deterministic_identical ? "ok" : "bad"}`}
        data-testid="determinism"
      >
        <strong>{m.deterministic_identical ? "Deterministic" : "Non-deterministic!"}</strong>{" "}
        {m.deterministic_runs}/{m.deterministic_runs} re-runs returned the identical verdict, checks
        and paths. The decision comes from graph queries and a static policy. No model is consulted.
      </div>

      <div className="stats">
        <Stat
          label="Guard check latency (median)"
          value={fmtMs(m.guard_latency_ms)}
          hint="all Cypher queries + policy"
          testId="m-latency"
        />
        <Stat
          label="Provenance path length"
          value={`${m.path_length ?? "–"} hops`}
          hint={`${m.sessions_crossed.length} sessions · ${m.agents_crossed.length} agents crossed`}
          testId="m-path"
        />
        <Stat
          label="Affected memories"
          value={m.affected_memories}
          tone="quarantine"
          testId="m-memories"
        />
        <Stat
          label="Affected agents"
          value={m.affected_agents.length}
          hint={m.affected_agents.join(", ")}
          testId="m-agents"
        />
        <Stat
          label="Affected actions"
          value={m.affected_actions}
          hint={`${m.affected_messages} messages`}
          testId="m-actions"
        />
        <Stat label="Blocked actions" value={m.blocked_actions} tone="block" testId="m-blocked" />
      </div>

      <div className="grid-2">
        <Panel title="Latency breakdown" subtitle={`Blocked action ${m.focus_action}, last re-run`}>
          <LatencyBars
            latency={{ ...m.guard_latency_breakdown, total: m.guard_latency_ms ?? 0 }}
            totalLabel="total (median)"
          />
        </Panel>
        <Panel
          title="Recorded Guard decisions"
          subtitle={`${m.decisions_recorded} decisions in the audit trail · median ${fmtMs(m.guard_latency_p50)} · max ${fmtMs(m.guard_latency_max)}`}
        >
          <div
            className="spark"
            role="img"
            aria-label="Latency of each recorded Guard decision, in order"
          >
            {samples.map((s, i) => (
              <span
                key={i}
                style={{ height: `${Math.max(4, (s / max) * 100)}%` }}
                title={`decision ${i + 1}: ${fmtMs(s)}`}
              />
            ))}
          </div>
          <div className="row between small muted">
            <span>first</span>
            <span>ms per decision (hover a bar)</span>
            <span>latest</span>
          </div>
        </Panel>
      </div>

      <Panel title="Graph-backed: the queries behind every decision">
        <div style={{ overflowX: "auto", maxWidth: "100%" }}>
          <table className="table">
            <thead>
              <tr>
                <th>Query</th>
                <th>Answers</th>
                <th>Pattern</th>
              </tr>
            </thead>
            <tbody>
              {m.queries.map((qq) => (
                <tr key={qq.name}>
                  <td className="mono">{qq.name}</td>
                  <td>{qq.purpose}</td>
                  <td>
                    <code className="small">{qq.pattern}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="small muted">
          Graph size: {m.graph_nodes} nodes, {m.graph_edges} relationships. Sessions crossed by the
          blocked path: <span className="mono">{m.sessions_crossed.join(" → ")}</span>.
        </p>
      </Panel>
    </div>
  );
}
