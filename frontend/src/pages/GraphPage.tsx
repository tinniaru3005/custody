import { useMemo, useState, type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import { useExplain, useGraph, useOverview } from "../api/hooks";
import type { GraphNode } from "../api/types";
import { AgentInfluence } from "../components/AgentInfluence";
import { GraphLegend, NodeInspector } from "../components/GraphParts";
import ProvenanceGraph from "../components/ProvenanceGraph";
import { Empty, ErrorState, Loading, Panel } from "../components/ui";

const LABEL_FILTERS = [
  "Source",
  "Datum",
  "Memory",
  "Recall",
  "Message",
  "Action",
  "Sink",
  "Approval",
  "Quarantine",
  "Decision",
];

/** Detailed node-level provenance or the collapsed agent-level influence (?view=agents). */
export function GraphPage() {
  const [params, setParams] = useSearchParams();
  const view = params.get("view") === "agents" ? "agents" : "nodes";
  const set = (v: string) => {
    const p = new URLSearchParams(params);
    if (v === "agents") p.set("view", "agents");
    else p.delete("view");
    setParams(p);
  };
  const toggle = (
    <div className="view-toggle" role="group" aria-label="Graph view">
      <button
        className={`btn ${view === "nodes" ? "on" : ""}`}
        onClick={() => set("nodes")}
        data-testid="view-nodes"
      >
        Nodes
      </button>
      <button
        className={`btn ${view === "agents" ? "on" : ""}`}
        onClick={() => set("agents")}
        data-testid="view-agents"
      >
        Agent influence
      </button>
    </div>
  );
  if (view === "agents")
    return (
      <div className="page">
        <header className="page-head">
          <div>
            <h1>Agent influence</h1>
            <p className="muted">
              The same provenance, collapsed: which agent influenced which, through which memory or
              message, and whether it carries untrusted content.
            </p>
          </div>
          {toggle}
        </header>
        <AgentInfluence />
      </div>
    );
  return <NodeGraph toggle={toggle} />;
}

function NodeGraph({ toggle }: { toggle: ReactNode }) {
  const [params] = useSearchParams();
  const focus = params.get("focus");
  const [showDecisions, setShowDecisions] = useState(false);
  const graph = useGraph(showDecisions);
  const overview = useOverview();
  const blocked = useExplain(overview.data?.demo?.blocked_action ?? undefined);
  // the node picked by the user; a new ?focus= link resets it
  const [pick, setPick] = useState<{ focus: string | null; id: string | null } | null>(null);
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const [onlyTainted, setOnlyTainted] = useState(false);
  const [showPath, setShowPath] = useState(true);
  const [layout, setLayout] = useState<"dag" | "force">("dag");
  const [showSystem, setShowSystem] = useState(false);
  const [query, setQuery] = useState("");

  const selectedId = pick && pick.focus === focus ? pick.id : focus;
  const selected = graph.data?.nodes.find((n) => n.id === selectedId) ?? null;
  const setSelected = (n: GraphNode | null) => setPick({ focus, id: n?.id ?? null });

  const visible = useMemo(() => {
    if (!graph.data) return undefined;
    const q = query.trim().toLowerCase();
    const s = new Set<string>();
    for (const n of graph.data.nodes) {
      if (hidden.has(n.label)) continue;
      if (
        onlyTainted &&
        !n.flags.some((f) => ["tainted", "untrusted", "blocked", "quarantined"].includes(f)) &&
        n.label !== "Sink"
      )
        continue;
      if (q && !`${n.id} ${n.title} ${n.preview ?? ""} ${n.agent ?? ""}`.toLowerCase().includes(q))
        continue;
      s.add(n.id);
    }
    return s;
  }, [graph.data, hidden, onlyTainted, query]);

  const pathIds = showPath ? blocked.data?.chain.map((c) => c.id) : undefined;

  if (graph.isLoading) return <Loading label="Loading provenance graph…" />;
  if (graph.error) return <ErrorState error={graph.error} onRetry={() => graph.refetch()} />;
  const g = graph.data!;

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>Live provenance graph</h1>
          <p className="muted">
            Every input, output, memory, recall, message and action is a node in FalkorDB. Edges are{" "}
            <code>DERIVED_FROM</code>, <code>FROM</code>, <code>ARG</code>, <code>TO</code> and{" "}
            <code>ENDORSES</code>.
          </p>
        </div>
        {toggle}
        <div className="counts small mono">
          {Object.entries(g.counts)
            .sort()
            .map(([k, v]) => (
              <span key={k}>
                {k} {v}
              </span>
            ))}
        </div>
      </header>

      {g.nodes.length === 0 ? (
        <Empty title="The graph is empty">Run the attack scenario from the Attack demo page.</Empty>
      ) : (
        <Panel>
          <div className="toolbar">
            <input
              className="input"
              placeholder="Search nodes (id, text, agent)…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              aria-label="Search nodes"
            />
            <div className="chips" role="group" aria-label="Node types">
              {LABEL_FILTERS.map((l) => {
                const off = hidden.has(l) || (l === "Decision" && !showDecisions);
                return (
                  <button
                    key={l}
                    className={`chip ${off ? "off" : ""}`}
                    aria-pressed={!off}
                    onClick={() => {
                      if (l === "Decision") return setShowDecisions(!showDecisions);
                      const h = new Set(hidden);
                      if (h.has(l)) h.delete(l);
                      else h.add(l);
                      setHidden(h);
                    }}
                  >
                    {l}
                  </button>
                );
              })}
            </div>
            <label className="check-label">
              <input
                type="checkbox"
                checked={onlyTainted}
                onChange={(e) => setOnlyTainted(e.target.checked)}
              />{" "}
              Only contamination
            </label>
            <label className="check-label">
              <input
                type="checkbox"
                checked={showPath}
                onChange={(e) => setShowPath(e.target.checked)}
              />{" "}
              Highlight blocked path
            </label>
            <label className="check-label">
              <input
                type="checkbox"
                checked={showSystem}
                onChange={(e) => setShowSystem(e.target.checked)}
              />{" "}
              System sources
            </label>
            <select
              className="input"
              value={layout}
              onChange={(e) => setLayout(e.target.value as "dag" | "force")}
              aria-label="Layout"
            >
              <option value="dag">Layered (action → source)</option>
              <option value="force">Force-directed</option>
            </select>
          </div>
          <div className="graph-with-inspector">
            <ProvenanceGraph
              graph={g}
              visibleIds={visible}
              pathIds={pathIds}
              selectedId={selected?.id}
              focusId={focus}
              onSelect={setSelected}
              height={640}
              layout={layout}
              hideSystemSources={!showSystem}
            />
            {selected && (
              <NodeInspector
                node={selected}
                graph={g}
                onSelect={setSelected}
                onClose={() => setSelected(null)}
              />
            )}
          </div>
          <GraphLegend />
        </Panel>
      )}
    </div>
  );
}
