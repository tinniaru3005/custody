import { Link } from "react-router-dom";
import type { GraphNode, GraphView } from "../api/types";
import { COLORS, fmtTime } from "../lib/format";
import { Flag, UntrustedText } from "./ui";

const SHAPES: { label: string; shape: string; text: string }[] = [
  { label: "Source", shape: "hex", text: "Source" },
  { label: "Datum", shape: "circle", text: "Datum" },
  { label: "Memory", shape: "round", text: "Memory" },
  { label: "Recall", shape: "circle", text: "Recall" },
  { label: "Message", shape: "rect", text: "Message" },
  { label: "Action", shape: "square", text: "Action" },
  { label: "Sink", shape: "diamond", text: "Sink" },
  { label: "Approval", shape: "tri", text: "Approval" },
];

const STATES: { color: string; text: string; extra?: string }[] = [
  { color: COLORS.trusted, text: "trusted / allowed / internal" },
  { color: COLORS.untrusted, text: "untrusted, tainted, blocked or external" },
  { color: COLORS.secret, text: "secret" },
  { color: COLORS.quarantined, text: "quarantined", extra: "dashed ring" },
  { color: COLORS.approval, text: "awaiting approval" },
  { color: COLORS.neutral, text: "neutral" },
];

export function GraphLegend() {
  return (
    <div className="legend" aria-label="Graph legend">
      <div className="legend-group">
        {SHAPES.map((s) => (
          <span key={s.label} className="legend-item">
            <i className={`shape shape-${s.shape}`} aria-hidden /> {s.text}
          </span>
        ))}
      </div>
      <div className="legend-group">
        {STATES.map((s) => (
          <span key={s.text} className="legend-item">
            <i className="swatch" style={{ background: s.color }} aria-hidden /> {s.text}
            {s.extra ? ` (${s.extra})` : ""}
          </span>
        ))}
      </div>
      <div className="legend-group mono small">
        <span className="legend-item">→ edges point from derived data to its origin</span>
        <span className="legend-item">- - FROM / context-only influence</span>
        <span className="legend-item">red animated edges: path behind the decision</span>
      </div>
    </div>
  );
}

const SKIP = new Set(["guard"]);

export function NodeInspector({
  node,
  graph,
  onSelect,
  onClose,
}: {
  node: GraphNode;
  graph: GraphView;
  onSelect: (n: GraphNode) => void;
  onClose: () => void;
}) {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const out = graph.edges.filter((e) => e.source === node.id);
  const inc = graph.edges.filter((e) => e.target === node.id);
  const untrustedText =
    node.preview && (node.flags.includes("tainted") || node.flags.includes("untrusted"));
  const guard = node.metadata?.guard as
    { decision?: string; triggered?: string[]; latency_ms?: number } | undefined;
  return (
    <aside className="inspector" data-testid="node-inspector" aria-label="Node details">
      <header>
        <div>
          <div className="muted small">{node.label}</div>
          <h3>{node.title}</h3>
        </div>
        <button className="btn ghost" onClick={onClose} aria-label="Close details">
          ✕
        </button>
      </header>
      <div className="flags">
        {node.flags.map((f) => (
          <Flag key={f} flag={f} />
        ))}
      </div>
      <dl className="kv">
        <dt>id</dt>
        <dd className="mono">{node.id}</dd>
        {node.kind && (
          <>
            <dt>kind</dt>
            <dd>{node.kind}</dd>
          </>
        )}
        {node.agent && (
          <>
            <dt>agent</dt>
            <dd>{node.agent}</dd>
          </>
        )}
        {node.session_id && (
          <>
            <dt>session</dt>
            <dd className="mono">{node.session_id}</dd>
          </>
        )}
        {(node.sim_time || node.created_at) && (
          <>
            <dt>time</dt>
            <dd>
              {node.sim_day ? `${node.sim_day} · ` : ""}
              {fmtTime(node.sim_time ?? node.created_at)}
            </dd>
          </>
        )}
        {node.trust && (
          <>
            <dt>trust</dt>
            <dd>{node.trust}</dd>
          </>
        )}
        {node.sensitivity && (
          <>
            <dt>sensitivity</dt>
            <dd>{node.sensitivity}</dd>
          </>
        )}
        {node.status && (
          <>
            <dt>status</dt>
            <dd>{node.status}</dd>
          </>
        )}
        {guard?.decision && (
          <>
            <dt>Guard</dt>
            <dd>
              {guard.decision}
              {guard.triggered?.length ? ` (${guard.triggered.join(", ")})` : ""}
            </dd>
          </>
        )}
        {Object.entries(node.metadata ?? {})
          .filter(([k, v]) => !SKIP.has(k) && v !== null && v !== "" && typeof v !== "object")
          .map(([k, v]) => (
            <FragmentKV key={k} k={k} v={String(v)} />
          ))}
      </dl>
      {node.label === "Action" && (
        <Link className="btn primary block" to={`/guard/${encodeURIComponent(node.id)}`}>
          Open Guard decision
        </Link>
      )}
      {node.preview &&
        (untrustedText ? (
          <UntrustedText
            text={node.preview}
            label={
              node.flags.includes("untrusted")
                ? "untrusted content, shown as data"
                : "derived from untrusted content"
            }
          />
        ) : (
          <pre className="preview">{node.preview}</pre>
        ))}
      <EdgeList
        title="Outgoing (towards origin)"
        edges={out.map((e) => ({ e, other: byId.get(e.target) }))}
        onSelect={onSelect}
      />
      <EdgeList
        title="Incoming (derived / acting on it)"
        edges={inc.map((e) => ({ e, other: byId.get(e.source) }))}
        onSelect={onSelect}
      />
    </aside>
  );
}

function FragmentKV({ k, v }: { k: string; v: string }) {
  return (
    <>
      <dt>{k}</dt>
      <dd>{v}</dd>
    </>
  );
}

function EdgeList({
  title,
  edges,
  onSelect,
}: {
  title: string;
  edges: { e: GraphView["edges"][number]; other?: GraphNode }[];
  onSelect: (n: GraphNode) => void;
}) {
  if (!edges.length) return null;
  return (
    <div className="edge-list">
      <h4>{title}</h4>
      <ul>
        {edges.map(({ e, other }) => (
          <li key={e.id}>
            <span className="mono edge-type">
              {e.type}
              {e.op ? ` · ${e.op}` : ""}
              {e.role ? ` · ${e.role}` : ""}
              {e.attribution === "context" ? " · context" : ""}
            </span>
            {other ? (
              <button className="link" onClick={() => onSelect(other)}>
                {other.label}: {other.title}
              </button>
            ) : (
              <span className="muted">hidden node</span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
