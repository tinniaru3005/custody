import { Link, useNavigate } from "react-router-dom";
import { useOverview, usePublicDemo, useRunAttack } from "../api/hooks";
import {
  Empty,
  ErrorState,
  Flag,
  Loading,
  Panel,
  Stat,
  StatusBadge,
  VerdictBadge,
} from "../components/ui";
import { fmtMs, fmtTime, shortId, truncate } from "../lib/format";

export function DashboardPage() {
  const q = useOverview();
  const run = useRunAttack();
  const publicDemo = usePublicDemo();
  const nav = useNavigate();

  if (q.isLoading) return <Loading label="Loading tenant overview…" />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  const o = q.data!;

  const start = () => run.mutate(undefined, { onSuccess: () => nav("/demo?play=1") });

  if (o.empty) {
    return (
      <div className="page">
        <section className="hero">
          <h1>A poisoned memory, three days later.</h1>
          <p>
            Scout reads a (simulated) vendor page with a hidden instruction and saves it to shared
            memory. Three simulated days later, in a different session, Ops follows that memory and
            tries to copy a freshly rotated (fake) API key to the attacker. Custody reconstructs the
            full chain from the provenance graph and blocks it.
          </p>
          {!publicDemo && (
            <button
              className="btn primary xl"
              onClick={start}
              disabled={run.isPending}
              data-testid="run-attack"
            >
              {run.isPending ? "Running scenario…" : "▶ Run attack scenario"}
            </button>
          )}
          {run.error && <ErrorState error={run.error} />}
        </section>
      </div>
    );
  }

  const c = o.counts;
  const recent = [...o.actions].reverse();
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Dashboard</h1>
          <p className="muted">
            Every agent action is checked by the Guard against the provenance graph before it runs.
          </p>
        </div>
        <div className="row">
          <Link className="btn" to="/demo">
            Replay attack
          </Link>
          {o.demo?.blocked_action && (
            <Link className="btn primary" to={`/guard/${o.demo.blocked_action}`}>
              Why was it blocked?
            </Link>
          )}
        </div>
      </header>

      <div className="stats">
        <Stat label="Actions checked" value={c.actions} testId="stat-actions" />
        <Stat label="Allowed" value={c.allowed} tone="allow" testId="stat-allowed" />
        <Stat
          label="Require approval"
          value={c.approval}
          tone="approval"
          hint={c.pending_approval ? `${c.pending_approval} waiting` : "none waiting"}
          testId="stat-approval"
        />
        <Stat label="Blocked" value={c.blocked} tone="block" testId="stat-blocked" />
        <Stat
          label="Active incidents"
          value={o.incidents.length}
          tone="secret"
          testId="stat-incidents"
        />
        <Stat
          label="Quarantined memories"
          value={c.quarantined_memories}
          tone="quarantine"
          hint={
            c.tainted_memories
              ? `${c.tainted_memories} tainted, not yet contained`
              : "no tainted memory in use"
          }
          testId="stat-quarantined"
        />
      </div>

      <Panel title="Agents" subtitle="Who did what, and whether untrusted data reached them">
        <div className="agents">
          {o.agents.map((a) => (
            <div key={a.name} className={`agent ${a.contaminated ? "contaminated" : ""}`}>
              <div className="agent-head">
                <span className="agent-name">{a.name}</span>
                {a.contaminated && <Flag flag="tainted" />}
              </div>
              <p className="small muted">{a.role}</p>
              <div className="agent-nums small">
                <span>{a.sessions.length} sessions</span>
                <span>{a.data} data</span>
                <span>{a.memories} memories</span>
                <span>{a.actions} actions</span>
              </div>
              <div className="agent-verdicts small">
                <span className="v-allow">✓ {a.allowed}</span>
                <span className="v-approval">✋ {a.approval}</span>
                <span className="v-block">⛔ {a.blocked}</span>
              </div>
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="Recent actions" subtitle="Latest first · click to see the Guard decision">
        <div className="table-wrap">
          <table className="table" data-testid="recent-actions">
            <thead>
              <tr>
                <th>When</th>
                <th>Agent</th>
                <th>Action</th>
                <th>Destination</th>
                <th>Guard</th>
                <th>Status</th>
                <th className="num">Latency</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((a) => (
                <tr key={a.id} onClick={() => nav(`/guard/${a.id}`)} className="clickable">
                  <td className="small">{fmtTime(a.sim_time ?? a.created_at)}</td>
                  <td>{a.agent}</td>
                  <td className="mono">{a.action_type}</td>
                  <td className="mono small">{truncate(a.destination ?? "—", 38)}</td>
                  <td>
                    <VerdictBadge verdict={a.verdict} />
                  </td>
                  <td>
                    <StatusBadge status={a.status} />
                  </td>
                  <td className="num mono small">{fmtMs(a.latency_ms)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <div className="grid-even">
        <Panel title="Active incidents" subtitle="Connected components of contamination (graph)">
          {o.incidents.length === 0 ? (
            <Empty title="No incidents" />
          ) : (
            <ul className="incidents">
              {o.incidents.map((i) => (
                <li key={i.id} className={`incident sev-${i.severity}`}>
                  <div className="row between">
                    <span className={`sev sev-${i.severity}`}>{i.severity}</span>
                    <span className="mono small muted">{i.id}</span>
                  </div>
                  <div className="mono small">{i.sources.join(", ")}</div>
                  <div className="small muted">
                    {i.memories} memories · {i.messages} messages · {i.actions} actions
                    {i.blocked.length ? ` · ${i.blocked.length} blocked` : ""}
                    {i.executed_external.length
                      ? ` · ${i.executed_external.length} left the company`
                      : ""}
                  </div>
                </li>
              ))}
            </ul>
          )}
          <Link className="btn block" to="/warden">
            Investigate with Warden
          </Link>
        </Panel>

        <Panel title="Shared memory" subtitle="Quarantined memories are hidden from every agent">
          <ul className="memories" data-testid="memories">
            {o.memories.map((m) => (
              <li key={m.id} className={m.in_quarantine ? "q" : m.tainted ? "t" : ""}>
                <div className="row between">
                  <span className="mono">{m.key ?? shortId(m.id)}</span>
                  <span>
                    {m.in_quarantine ? (
                      <Flag flag="quarantined" />
                    ) : m.tainted ? (
                      <Flag flag="tainted" />
                    ) : (
                      <Flag flag="trusted" />
                    )}
                  </span>
                </div>
                <div className="small muted">
                  by {m.agent} · {m.session_id}
                </div>
                <div className="small">{truncate(m.preview, 110)}</div>
              </li>
            ))}
          </ul>
        </Panel>
      </div>
    </div>
  );
}
