import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useDemo, useExplain, useGraph, usePublicDemo, useReset, useRunAttack } from "../api/hooks";
import type { DemoRun, DemoStep, GraphNode } from "../api/types";
import { CertificateCard } from "../components/Certificate";
import { Trifecta } from "../components/DecisionDetail";
import { GraphLegend, NodeInspector } from "../components/GraphParts";
import { ProvenanceChain } from "../components/ProvenanceChain";
import ProvenanceGraph from "../components/ProvenanceGraph";
import { Empty, ErrorState, Loading, Panel, VerdictBadge } from "../components/ui";
import { fmtMs, fmtTime } from "../lib/format";

const STEP_MS = 1800;

export function DemoPage() {
  const demo = useDemo();
  const graph = useGraph();
  const run = useRunAttack();
  const reset = useReset();
  const publicDemo = usePublicDemo();
  const [params, setParams] = useSearchParams();
  const [cur, setCur] = useState(0); // number of steps revealed (0..steps.length)
  const [playing, setPlaying] = useState(false);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const wantsPlay = useRef(params.get("play") === "1");

  const d = demo.data;
  const steps = useMemo(() => d?.steps ?? [], [d]);
  const blocked = useExplain(d?.ids.blocked_action);

  // On load: autoplay after "Run attack scenario" (?play=1), otherwise show the whole story.
  useEffect(() => {
    if (!steps.length) return;
    if (wantsPlay.current) {
      wantsPlay.current = false;
      setCur(1);
      setPlaying(true);
      params.delete("play");
      setParams(params, { replace: true });
    } else {
      setCur((c) => (c === 0 ? steps.length : c));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [steps.length]);

  const isPlaying = playing && cur < steps.length;
  useEffect(() => {
    if (!isPlaying) return;
    const t = setTimeout(() => setCur((c) => c + 1), STEP_MS);
    return () => clearTimeout(t);
  }, [isPlaying, cur]);

  const visible = useMemo(() => {
    const s = new Set<string>();
    steps.slice(0, cur).forEach((st) => st.node_ids.forEach((id) => s.add(id)));
    // quarantine / approval nodes created later (Warden) appear once the story is complete
    if (cur >= steps.length && graph.data) {
      graph.data.nodes.forEach((n) => {
        if (n.label === "Quarantine" || n.agent === "warden" || n.label === "Approval") s.add(n.id);
      });
      graph.data.edges.forEach((e) => {
        if (s.has(e.source)) s.add(e.target);
      });
    }
    return s;
  }, [steps, cur, graph.data]);

  const chain = blocked.data?.chain ?? [];
  const current: DemoStep | undefined = steps[cur - 1];
  const showPath = !!current && (current.key === "exfil_blocked" || current.key === "explain");
  const pathIds = showPath ? chain.map((c) => c.id) : undefined;

  const start = () =>
    run.mutate(undefined, {
      onSuccess: () => {
        setSelected(null);
        setCur(1);
        setPlaying(true);
      },
    });

  if (demo.isLoading) return <Loading label="Loading demo…" />;
  if (demo.error) return <ErrorState error={demo.error} onRetry={() => demo.refetch()} />;

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Attack demo</h1>
          <p className="muted">
            One story: a poisoned vendor page enters shared memory on Day 1; on Day 4 Ops gets a
            legitimate request, posts a secret to internal Slack (ALLOW) and is stopped from sending
            it to the attacker (BLOCK). The provenance path explains why.
          </p>
        </div>
        <div className="row">
          {!publicDemo && (
            <button
              className="btn primary"
              onClick={start}
              disabled={run.isPending}
              data-testid="run-attack"
            >
              {run.isPending
                ? "Running…"
                : d
                  ? "↻ Run attack scenario again"
                  : "▶ Run attack scenario"}
            </button>
          )}
          <button
            className="btn"
            data-testid="demo-reset"
            onClick={() => reset.mutate(undefined, { onSuccess: () => setCur(publicDemo ? 1 : 0) })}
            disabled={reset.isPending}
            title={publicDemo ? "Restore the initial demo state" : "Empty the tenant graph"}
          >
            {publicDemo ? "↺ Reset Demo" : "Reset"}
          </button>
        </div>
      </header>
      {run.error && <ErrorState error={run.error} />}

      {d && <RunModeBanner run={d} />}

      {d && (
        <Panel title="What is simulated" className="sim-panel">
          <ul className="sim-list" data-testid="simulation-notice">
            {(d.simulation ?? []).map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </Panel>
      )}

      {!d ? (
        <Empty title="No scenario has been run yet">
          Click <strong>Run attack scenario</strong> to record the simulated Day 1 and Day 4
          sessions into FalkorDB.
        </Empty>
      ) : (
        <div className="demo-grid">
          <Panel
            title="Timeline"
            actions={
              <div className="row tight">
                <button
                  className="btn ghost"
                  onClick={() => setCur(Math.max(1, cur - 1))}
                  aria-label="Previous step"
                >
                  ◀
                </button>
                <button
                  className="btn ghost"
                  onClick={() => {
                    if (isPlaying) return setPlaying(false);
                    if (cur >= steps.length) setCur(1);
                    setPlaying(true);
                  }}
                  data-testid="play-toggle"
                >
                  {isPlaying ? "❚❚ Pause" : cur >= steps.length ? "↺ Replay" : "▶ Play"}
                </button>
                <button
                  className="btn ghost"
                  onClick={() => setCur(Math.min(steps.length, cur + 1))}
                  aria-label="Next step"
                >
                  ▶
                </button>
              </div>
            }
          >
            <ol className="timeline" data-testid="timeline">
              {steps.map((s, i) => (
                <li
                  key={s.n}
                  className={`tl tone-${s.tone} ${i < cur ? "done" : "todo"} ${i === cur - 1 ? "current" : ""}`}
                >
                  <button
                    className="tl-btn"
                    onClick={() => {
                      setPlaying(false);
                      setCur(i + 1);
                    }}
                  >
                    <span className="tl-n">{s.n}</span>
                    <span className="tl-body">
                      <span className="tl-meta small muted">
                        {s.day} · {s.actor}
                      </span>
                      <span className="tl-title">{s.title}</span>
                    </span>
                    {s.verdict && i < cur && <VerdictBadge verdict={s.verdict} />}
                  </button>
                </li>
              ))}
            </ol>
          </Panel>

          <div className="stack">
            <Panel
              title={current ? `Step ${current.n}: ${current.title}` : "Ready"}
              subtitle={
                current
                  ? `${current.day} · ${fmtTime(current.sim_time)} · ${current.actor}`
                  : undefined
              }
              className={current ? `step-panel tone-${current.tone}` : ""}
            >
              {current ? (
                <StepDetail
                  step={current}
                  chain={chain}
                  blockedDecision={d.blocked_decision}
                  slackDecision={d.slack_decision}
                />
              ) : (
                <p className="muted">Press play to walk through the attack.</p>
              )}
            </Panel>

            <Panel
              title="Provenance graph"
              subtitle={`${visible.size} nodes recorded so far · click a node to inspect`}
              actions={<Link to="/graph">Open full graph →</Link>}
            >
              {graph.isLoading ? (
                <Loading />
              ) : graph.error ? (
                <ErrorState error={graph.error} />
              ) : (
                <div className="graph-with-inspector">
                  <ProvenanceGraph
                    graph={graph.data!}
                    visibleIds={visible}
                    pathIds={pathIds}
                    selectedId={selected?.id}
                    onSelect={setSelected}
                    height={430}
                  />
                  {selected && (
                    <NodeInspector
                      node={selected}
                      graph={graph.data!}
                      onSelect={setSelected}
                      onClose={() => setSelected(null)}
                    />
                  )}
                </div>
              )}
              <GraphLegend />
            </Panel>

            {cur >= steps.length && (
              <p className="small muted" data-testid="after-demo">
                That is the whole demo. Optional, outside the 3-minute story: incident response with
                the <Link to="/warden">Warden</Link> (best shown on the extended scenario).
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function StepDetail({
  step,
  chain,
  blockedDecision,
  slackDecision,
}: {
  step: DemoStep;
  chain: import("../api/types").ChainCard[];
  blockedDecision: import("../api/types").GuardDecision;
  slackDecision?: import("../api/types").GuardDecision;
}) {
  const integrity = blockedDecision.checks.integrity;
  return (
    <div className="step-detail" data-testid="step-detail">
      <p>{step.narrative}</p>
      {!!step.simulated?.length && (
        <div className="sim-chips" data-testid="step-simulated">
          {step.simulated.map((x) => (
            <span key={x} className="sim-chip">
              simulated: {x}
            </span>
          ))}
        </div>
      )}
      {step.verdict && step.key !== "explain" && (
        <p className="row">
          <VerdictBadge verdict={step.verdict} large={step.key === "exfil_blocked"} />
          {step.action_id && (
            <Link to={`/guard/${step.action_id}`} className="small">
              Open decision →
            </Link>
          )}
        </p>
      )}
      {step.key === "slack_allowed" && slackDecision?.certificate && (
        <CertificateCard c={slackDecision.certificate} compact />
      )}
      {step.key === "exfil_blocked" && (
        <>
          <Trifecta d={blockedDecision} />
          <p className="approval-note none" data-testid="no-approval">
            No approval button: {blockedDecision.approval.reason}
          </p>
        </>
      )}
      {step.key === "explain" && (
        <>
          <p className="mono small">
            {
              blockedDecision.paths.find((p) => p.check === "integrity" && p.status === "violating")
                ?.text
            }
            <br />
            search {integrity.search?.outcome ?? "?"} · integrity {fmtMs(integrity.latency_ms)} ·
            total {fmtMs(blockedDecision.latency_ms.total)}
          </p>
          <ProvenanceChain cards={chain} compact />
          {step.action_id && (
            <Link to={`/guard/${step.action_id}`} className="small">
              Open decision →
            </Link>
          )}
        </>
      )}
    </div>
  );
}

/** Which kind of run this is: a replay of a recorded LLM execution, or the scripted story. */
export function RunModeBanner({ run }: { run: DemoRun }) {
  const rec = run.mode === "recorded" ? run.recording : null;
  if (!rec)
    return (
      <div className="run-mode scripted" data-testid="run-mode">
        <strong>Scripted simulation</strong>
        <span className="muted"> — no LLM is called; agent outputs are scripted.</span>
      </div>
    );
  return (
    <div className={`run-mode ${rec.real_llm ? "real" : "double"}`} data-testid="run-mode">
      <strong>{rec.label}</strong>
      <span className="muted">
        {" "}
        — model <code>{rec.model}</code>, recorded {rec.recorded_at.slice(0, 10)}; {rec.llm_calls}{" "}
        model calls replayed from a fixture, {rec.llm_calls_made} made now. Guard verdicts are
        recomputed from the replayed graph.
      </span>
    </div>
  );
}
