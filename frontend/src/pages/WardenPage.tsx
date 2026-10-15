import { useState } from "react";
import { Link } from "react-router-dom";
import { useInvestigate, usePublicDemo, useWardenRun } from "../api/hooks";
import { ReadjudicationsPanel } from "../components/Readjudications";
import type { ActionView, NodeRef, PlannerName, WardenStep } from "../api/types";
import { Empty, ErrorState, Flag, Loading, Panel, VerdictBadge } from "../components/ui";
import { fmtTime, shortId, truncate } from "../lib/format";

const PRESETS = [
  "That vendor page was malicious. Clean it up.",
  "Mark vendor page malicious and investigate.",
  "The VaultSync docs page (https://docs.vaultsync-backup.example/setup) was malicious. Contain everything it touched.",
];

const TOOL_TITLE: Record<string, string> = {
  find_sources: "Find sources",
  trace_forward: "Trace forward",
  trace_back: "Trace back",
  rank_risky_memories: "Risky-memory ranking",
  cluster_incidents: "Incident grouping",
  simulate_policy: "Policy simulation",
  quarantine: "Quarantine",
  draft_disclosure: "Disclosure draft",
  propose_disclosure: "Request human approval",
  send_approved_disclosure: "Send approved disclosure",
};

type R = Record<string, unknown>;
const arr = <T,>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);

export function WardenPage() {
  const last = useWardenRun();
  const inv = useInvestigate();
  const readOnly = usePublicDemo();
  const [request, setRequest] = useState(PRESETS[0]);
  const [planner, setPlanner] = useState<PlannerName>("auto");
  const run = inv.data ?? last.data ?? null;

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Warden: incident response</h1>
          <p className="muted">
            The Warden is an agent that can only act through MCP tools over the provenance graph.
            Its quarantine and disclosure actions go through the same deterministic Guard as every
            other agent, and it cannot approve anything.
          </p>
        </div>
      </header>

      <Panel title="Command">
        <form
          className="command"
          onSubmit={(e) => {
            e.preventDefault();
            inv.mutate({ request, planner });
          }}
        >
          <textarea
            className="input"
            rows={2}
            value={request}
            onChange={(e) => setRequest(e.target.value)}
            aria-label="Instruction for the Warden"
          />
          <div className="row wrap">
            {PRESETS.map((p) => (
              <button type="button" key={p} className="chip" onClick={() => setRequest(p)}>
                {truncate(p, 52)}
              </button>
            ))}
          </div>
          <div className="row wrap">
            <label className="field inline">
              <span className="small muted">Planner</span>
              <select
                className="input"
                value={planner}
                onChange={(e) => setPlanner(e.target.value as PlannerName)}
              >
                <option value="auto">
                  auto (Claude if ANTHROPIC_API_KEY is set, else playbook)
                </option>
                <option value="playbook">deterministic playbook</option>
                <option value="anthropic">Claude (tool use)</option>
              </select>
            </label>
            <button
              className="btn primary"
              type="submit"
              disabled={inv.isPending || readOnly || request.trim().length < 3}
              title={
                readOnly ? "Disabled in the public demo (it can call a paid LLM API)" : undefined
              }
              data-testid="run-warden"
            >
              {inv.isPending ? "Investigating…" : "⚕ Run Warden"}
            </button>
          </div>
        </form>
        {inv.error && <ErrorState error={inv.error} />}
      </Panel>

      {last.isLoading ? (
        <Loading />
      ) : last.error ? (
        <ErrorState error={last.error} onRetry={() => last.refetch()} />
      ) : !run ? (
        <Empty title="No investigation yet">
          Run the attack scenario first, then give the Warden a command.
        </Empty>
      ) : (
        <>
          <Panel
            title="Report"
            subtitle={`“${run.request}” · ${run.planner} planner · operator ${run.operator} · ${fmtTime(run.created_at)}`}
          >
            <div className="stats small-stats">
              <div className="stat">
                <div className="stat-label">MCP tool calls</div>
                <div className="stat-value">{run.steps.length}</div>
              </div>
              <div className="stat stat-quarantine">
                <div className="stat-label">Memories quarantined</div>
                <div className="stat-value" data-testid="quarantined-count">
                  {run.quarantined_memory_ids.length}
                </div>
              </div>
              <div className="stat stat-block">
                <div className="stat-label">Already left the company</div>
                <div className="stat-value">{run.external_executed_actions.length}</div>
              </div>
              <div className="stat stat-approval">
                <div className="stat-label">Awaiting human approval</div>
                <div className="stat-value">{run.pending_approvals.length}</div>
              </div>
            </div>
            <pre className="report" data-testid="warden-report">
              {run.final_text}
            </pre>
            {run.pending_approvals.length > 0 && (
              <Link className="btn primary" to="/approvals">
                Review {run.pending_approvals.length} disclosure approval(s)
              </Link>
            )}
          </Panel>

          <Panel
            title="Tool activity"
            subtitle="Each step is one MCP tool call chosen by the planner"
          >
            <ol className="tool-steps" data-testid="tool-steps">
              {run.steps.map((s) => (
                <ToolStep key={s.n} step={s} />
              ))}
            </ol>
          </Panel>
        </>
      )}

      <ReadjudicationsPanel />
    </div>
  );
}

function ToolStep({ step }: { step: WardenStep }) {
  const r = (step.result ?? {}) as R;
  return (
    <li className={`tool-step ${step.is_error ? "err" : ""}`} data-tool={step.tool}>
      <div className="tool-head">
        <span className="tool-n">{step.n}</span>
        <span className="tool-name">{TOOL_TITLE[step.tool] ?? step.tool}</span>
        <code className="small">
          {step.tool}(
          {Object.entries(step.arguments)
            .filter(([, v]) => v !== null && v !== undefined)
            .map(([k, v]) => `${k}=${truncate(JSON.stringify(v), 60)}`)
            .join(", ")}
          )
        </code>
      </div>
      <div className="tool-body">
        {step.is_error ? (
          <p className="bad-text">{String((r as R).text ?? JSON.stringify(r))}</p>
        ) : (
          <ToolResult tool={step.tool} r={r} />
        )}
        <details>
          <summary className="small muted">raw result</summary>
          <pre className="raw">{JSON.stringify(step.result, null, 2)}</pre>
        </details>
      </div>
    </li>
  );
}

function NodeList({ items, empty = "none" }: { items: NodeRef[]; empty?: string }) {
  if (!items.length) return <span className="muted small">{empty}</span>;
  return (
    <ul className="mini-list">
      {items.map((n) => (
        <li key={n.id}>
          <span className="mono small">{n.key ?? shortId(n.id)}</span>{" "}
          <span className="muted small">{n.agent}</span>{" "}
          {n.influence && <Flag flag={n.influence === "direct" ? "tainted" : "context"} />}
          {n.in_quarantine && <Flag flag="quarantined" />}
        </li>
      ))}
    </ul>
  );
}

function ToolResult({ tool, r }: { tool: string; r: R }) {
  switch (tool) {
    case "find_sources":
      return (
        <ul className="mini-list">
          {arr<R>(r.sources).map((s) => (
            <li key={String(s.id)}>
              <span className="mono small">{String(s.id)}</span> <Flag flag={String(s.trust)} />{" "}
              <span className="muted small">{String(s.downstream_count)} downstream</span>
            </li>
          ))}
        </ul>
      );
    case "trace_forward": {
      const c = (r.counts ?? {}) as Record<string, number>;
      return (
        <div className="grid-3">
          <div>
            <h5>Affected memories ({c.memories ?? 0})</h5>
            <NodeList items={arr<NodeRef>(r.memories)} />
          </div>
          <div>
            <h5>Affected messages ({c.messages ?? 0})</h5>
            <NodeList items={arr<NodeRef>(r.messages)} />
            <h5>Recalls ({c.recalls ?? 0})</h5>
            <span className="small muted">
              {arr<NodeRef>(r.recalls)
                .map((x) => x.agent)
                .join(", ") || "none"}
            </span>
          </div>
          <div>
            <h5>Affected actions ({c.actions ?? 0})</h5>
            <ul className="mini-list">
              {arr<ActionView>(r.actions).map((a) => (
                <li key={a.id}>
                  <span className="mono small">{a.action_type}</span>{" "}
                  <span className="muted small">{a.agent}</span>{" "}
                  <VerdictBadge verdict={a.latest_decision} />{" "}
                  {a.influence === "context_only" && <Flag flag="context" />}
                  {a.executed && a.external && <Flag flag="external" />}
                </li>
              ))}
            </ul>
          </div>
          <p className="small span-3">{String(r.explanation ?? "")}</p>
        </div>
      );
    }
    case "rank_risky_memories":
      return (
        <table className="table compact">
          <thead>
            <tr>
              <th>Memory</th>
              <th className="num">Risk</th>
              <th className="num">Betweenness</th>
              <th>Tainted</th>
              <th>Why</th>
            </tr>
          </thead>
          <tbody>
            {arr<R>(r.memories).map((m) => {
              const mem = m.memory as NodeRef;
              return (
                <tr key={mem.id}>
                  <td className="mono small">{mem.key ?? shortId(mem.id)}</td>
                  <td className="num mono">{Number(m.risk_score).toFixed(1)}</td>
                  <td className="num mono">
                    {m.betweenness_normalized == null
                      ? "–"
                      : Number(m.betweenness_normalized).toFixed(2)}
                  </td>
                  <td>{m.tainted ? <Flag flag="tainted" /> : <Flag flag="trusted" />}</td>
                  <td className="small">{arr<string>(m.reasons).slice(0, 2).join("; ")}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      );
    case "cluster_incidents":
      return (
        <div>
          <p className="small muted">{String(r.method ?? "")}</p>
          <ul className="incidents">
            {arr<R>(r.incidents).map((i) => (
              <li key={String(i.id)} className={`incident sev-${i.severity}`}>
                <span className={`sev sev-${i.severity}`}>{String(i.severity)}</span>{" "}
                <span className="mono small">{String(i.id)}</span>
                <div className="small">{String(i.summary)}</div>
              </li>
            ))}
          </ul>
        </div>
      );
    case "quarantine":
      return (
        <p className="small">
          <strong>{String(r.status)}</strong> · Guard{" "}
          <VerdictBadge verdict={String(r.guard_verdict ?? "")} /> ·{" "}
          {arr<string>(r.quarantined).length} memories quarantined via action{" "}
          <Link className="mono" to={`/guard/${String(r.action_id)}`}>
            {shortId(String(r.action_id ?? ""))}
          </Link>
          {arr<string>(r.already_quarantined).length
            ? ` · already: ${arr<string>(r.already_quarantined).length}`
            : ""}
        </p>
      );
    case "draft_disclosure":
      return (
        <div>
          {arr<R>(r.drafts).map((d) => (
            <details key={String(d.draft_id)} className="draft">
              <summary>
                Draft to <span className="mono">{String(d.recipient)}</span>: {String(d.subject)}
              </summary>
              <pre>{String(d.body)}</pre>
            </details>
          ))}
          <p className="small muted">{String(r.internal_summary ?? "")}</p>
        </div>
      );
    case "propose_disclosure":
      return (
        <p className="small">
          Disclosure to <span className="mono">{String(r.recipient)}</span>: Guard{" "}
          <VerdictBadge verdict={String(r.verdict)} /> · nothing sent ·{" "}
          <Link to="/approvals">approve in the Approvals page</Link>
        </p>
      );
    default:
      return <p className="small muted">{truncate(JSON.stringify(r), 300)}</p>;
  }
}
