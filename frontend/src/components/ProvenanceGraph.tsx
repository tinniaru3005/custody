import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D, {
  type ForceGraphMethods,
  type LinkObject,
  type NodeObject,
} from "react-force-graph-2d";
import type { GraphEdge, GraphNode, GraphView } from "../api/types";
import { COLORS } from "../lib/format";
import { nodeColor } from "../lib/graphStyle";

type NodeData = { data: GraphNode };
type LinkData = { data: GraphEdge };
type GNode = NodeObject<NodeData>;
type GLink = LinkObject<NodeData, LinkData>;

export interface ProvenanceGraphProps {
  graph: GraphView;
  /** Only these node ids are shown (demo playback). Undefined = all. */
  visibleIds?: Set<string>;
  /** Ordered ids of the responsible path: nodes and hops between them are emphasised. */
  pathIds?: string[];
  selectedId?: string | null;
  focusId?: string | null;
  onSelect?: (node: GraphNode | null) => void;
  height?: number;
  layout?: "dag" | "force";
  /** Hide trusted system Sources (agent outputs, memory store): hubs that add no signal. */
  hideSystemSources?: boolean;
}

const SIZE: Record<string, number> = {
  Source: 7.5,
  Action: 7,
  Sink: 6,
  Memory: 6.5,
  Approval: 5.5,
  Quarantine: 6,
  Decision: 3.5,
};

const EDGE_COLOR: Record<string, string> = {
  DERIVED_FROM: "#64748b",
  FROM: "#475569",
  ARG: "#94a3b8",
  TO: "#cbd5e1",
  ENDORSES: COLORS.trusted,
  APPROVES: COLORS.trusted,
  REJECTS: COLORS.untrusted,
  QUARANTINES: COLORS.quarantined,
  VIA: COLORS.quarantined,
  EVALUATES: "#334155",
};

function shapePath(ctx: CanvasRenderingContext2D, label: string, x: number, y: number, r: number) {
  ctx.beginPath();
  const poly = (k: number, rot = 0) => {
    for (let i = 0; i < k; i++) {
      const a = rot + (i * 2 * Math.PI) / k;
      const px = x + r * Math.cos(a);
      const py = y + r * Math.sin(a);
      if (i === 0) ctx.moveTo(px, py);
      else ctx.lineTo(px, py);
    }
    ctx.closePath();
  };
  switch (label) {
    case "Source":
      poly(6, Math.PI / 6);
      break;
    case "Action":
      ctx.rect(x - r * 0.85, y - r * 0.85, r * 1.7, r * 1.7);
      break;
    case "Sink":
      poly(4);
      break;
    case "Approval":
      poly(3, -Math.PI / 2);
      break;
    case "Quarantine":
      poly(8, Math.PI / 8);
      break;
    case "Memory":
      ctx.roundRect(x - r * 0.85, y - r * 0.85, r * 1.7, r * 1.7, r * 0.45);
      break;
    case "Message":
      ctx.rect(x - r, y - r * 0.65, r * 2, r * 1.3);
      break;
    default:
      ctx.arc(x, y, r, 0, 2 * Math.PI);
  }
}

export function ProvenanceGraph({
  graph,
  visibleIds,
  pathIds,
  selectedId,
  focusId,
  onSelect,
  height = 560,
  layout = "dag",
  hideSystemSources = true,
}: ProvenanceGraphProps) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const fgRef = useRef<ForceGraphMethods<NodeData, LinkData> | undefined>(undefined);
  const [cache] = useState(() => new Map<string, GNode>());
  const [width, setWidth] = useState(800);
  const [hover, setHover] = useState<string | null>(null);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) =>
      setWidth(Math.max(280, entries[0].contentRect.width)),
    );
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const pathSet = useMemo(() => new Set(pathIds ?? []), [pathIds]);
  const pathHops = useMemo(() => {
    const s = new Set<string>();
    (pathIds ?? []).forEach((id, i, arr) => {
      if (i > 0) {
        s.add(`${arr[i - 1]}|${id}`);
        s.add(`${id}|${arr[i - 1]}`);
      }
    });
    return s;
  }, [pathIds]);

  const data = useMemo(() => {
    const nodes: GNode[] = [];
    for (const n of graph.nodes) {
      if (visibleIds && !visibleIds.has(n.id)) continue;
      if (hideSystemSources && n.label === "Source" && n.kind === "system") continue;
      const cached = cache.get(n.id);
      const node: GNode = cached ? Object.assign(cached, { data: n }) : { id: n.id, data: n };
      cache.set(n.id, node);
      nodes.push(node);
    }
    const ids = new Set(nodes.map((n) => n.id as string));
    const links: GLink[] = graph.edges
      .filter((e) => ids.has(e.source) && ids.has(e.target))
      .map((e) => ({ source: e.source, target: e.target, data: e }));
    return { nodes, links };
  }, [graph, visibleIds, cache, hideSystemSources]);

  const neighbours = useMemo(() => {
    if (!hover) return null;
    const s = new Set<string>([hover]);
    for (const e of graph.edges) {
      if (e.source === hover) s.add(e.target);
      if (e.target === hover) s.add(e.source);
    }
    return s;
  }, [hover, graph.edges]);

  useEffect(() => {
    if (!focusId || !fgRef.current) return;
    const t = setTimeout(() => {
      const n = cache.get(focusId);
      if (n && n.x !== undefined && n.y !== undefined && fgRef.current) {
        fgRef.current.centerAt(n.x, n.y, 600);
        fgRef.current.zoom(2.6, 600);
      }
    }, 900);
    return () => clearTimeout(t);
  }, [focusId, data, cache]);

  // keep disconnected components (other incidents) close: short-range repulsion only
  useEffect(() => {
    const fg = fgRef.current;
    if (!fg) return;
    const charge = fg.d3Force("charge") as unknown as
      { strength: (v: number) => { distanceMax: (v: number) => void } } | undefined;
    charge?.strength(-55).distanceMax(90);
    const link = fg.d3Force("link") as unknown as { distance: (v: number) => void } | undefined;
    link?.distance(28);
    fg.d3ReheatSimulation();
  }, [data, layout]);

  useEffect(() => {
    const t = setTimeout(() => fgRef.current?.zoomToFit(400, 30), 1400);
    return () => clearTimeout(t);
  }, [data.nodes.length, layout]);

  const drawNode = useCallback(
    (node: GNode, ctx: CanvasRenderingContext2D, scale: number) => {
      const n = node.data;
      const x = node.x ?? 0;
      const y = node.y ?? 0;
      const onPath = pathSet.has(n.id);
      const dim =
        (neighbours && !neighbours.has(n.id)) || (pathSet.size > 0 && !onPath && !neighbours);
      const r = (SIZE[n.label] ?? 4.5) * (onPath ? 1.25 : 1);
      ctx.globalAlpha = dim ? 0.25 : 1;
      if (onPath) {
        ctx.beginPath();
        ctx.arc(x, y, r + 4, 0, 2 * Math.PI);
        ctx.fillStyle = "rgba(229,72,77,0.22)";
        ctx.fill();
      }
      shapePath(ctx, n.label, x, y, r);
      ctx.fillStyle = nodeColor(n);
      ctx.fill();
      const flags = new Set(n.flags);
      ctx.lineWidth = 1.2 / Math.max(scale, 0.6);
      ctx.strokeStyle = "#0b1020";
      ctx.stroke();
      if (flags.has("quarantined")) {
        ctx.setLineDash([2, 1.5]);
        ctx.lineWidth = 1.4;
        ctx.strokeStyle = COLORS.quarantined;
        ctx.beginPath();
        ctx.arc(x, y, r + 2.6, 0, 2 * Math.PI);
        ctx.stroke();
        ctx.setLineDash([]);
      }
      if (n.label === "Action" && (n.verdict === "BLOCK" || n.status === "blocked")) {
        ctx.strokeStyle = "#fff";
        ctx.lineWidth = 1.4;
        ctx.beginPath();
        ctx.moveTo(x - r * 0.5, y - r * 0.5);
        ctx.lineTo(x + r * 0.5, y + r * 0.5);
        ctx.moveTo(x + r * 0.5, y - r * 0.5);
        ctx.lineTo(x - r * 0.5, y + r * 0.5);
        ctx.stroke();
      }
      if (n.label === "Source" && n.trust === "untrusted") {
        ctx.fillStyle = "#fff";
        ctx.font = `bold ${r}px Inter, system-ui, sans-serif`;
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText("!", x, y + 0.5);
      }
      if (selectedId === n.id) {
        ctx.strokeStyle = "#f8fafc";
        ctx.lineWidth = 1.6;
        ctx.beginPath();
        ctx.arc(x, y, r + 4.5, 0, 2 * Math.PI);
        ctx.stroke();
      }
      const important = ["Source", "Action", "Memory"].includes(n.label);
      if (
        onPath ||
        selectedId === n.id ||
        hover === n.id ||
        scale > 2.4 ||
        (important && scale > 1.1)
      ) {
        const fs = Math.max(10 / scale, 2.4);
        ctx.font = `${fs}px Inter, system-ui, sans-serif`;
        ctx.textAlign = "center";
        ctx.textBaseline = "top";
        const label = n.title.length > 34 ? n.title.slice(0, 33) + "…" : n.title;
        ctx.fillStyle = dim ? "rgba(203,213,225,0.35)" : "#cbd5e1";
        ctx.fillText(label, x, y + r + 2);
      }
      ctx.globalAlpha = 1;
    },
    [pathSet, neighbours, selectedId, hover],
  );

  const linkKey = (l: GLink) => {
    const s = typeof l.source === "object" ? (l.source as GNode).id : l.source;
    const t = typeof l.target === "object" ? (l.target as GNode).id : l.target;
    return `${s}|${t}`;
  };

  return (
    <div ref={wrapRef} className="graph-wrap" style={{ height }} data-testid="provenance-graph">
      <ForceGraph2D<NodeData, LinkData>
        ref={fgRef}
        graphData={data}
        width={width}
        height={height}
        backgroundColor="rgba(0,0,0,0)"
        dagMode={layout === "dag" ? "lr" : undefined}
        dagLevelDistance={layout === "dag" ? 46 : undefined}
        onDagError={() => undefined}
        cooldownTicks={120}
        nodeRelSize={5}
        nodeCanvasObject={drawNode}
        nodePointerAreaPaint={(node, color, ctx) => {
          ctx.fillStyle = color;
          ctx.beginPath();
          ctx.arc(node.x ?? 0, node.y ?? 0, (SIZE[node.data.label] ?? 4.5) + 3, 0, 2 * Math.PI);
          ctx.fill();
        }}
        nodeLabel={(node) => `${node.data.label}: ${node.data.title}`}
        linkColor={(l) =>
          pathHops.has(linkKey(l)) ? COLORS.untrusted : (EDGE_COLOR[l.data.type] ?? COLORS.edge)
        }
        linkWidth={(l) => (pathHops.has(linkKey(l)) ? 2.6 : l.data.type === "TO" ? 1.4 : 0.8)}
        linkLineDash={(l) =>
          l.data.attribution === "context" ? [2, 2] : l.data.type === "FROM" ? [4, 2] : null
        }
        linkDirectionalArrowLength={3.2}
        linkDirectionalArrowRelPos={0.92}
        linkDirectionalParticles={(l) => (pathHops.has(linkKey(l)) ? 3 : 0)}
        linkDirectionalParticleWidth={2.2}
        linkDirectionalParticleColor={() => "#fecaca"}
        linkLabel={(l) =>
          `${l.data.type}${l.data.op ? ` {op: ${l.data.op}}` : ""}${l.data.role ? ` {role: ${l.data.role}}` : ""}${
            l.data.attribution && l.data.attribution !== "inherit"
              ? ` {attribution: ${l.data.attribution}}`
              : ""
          }`
        }
        linkCanvasObjectMode={() => "after"}
        linkCanvasObject={(l, ctx, scale) => {
          if (!pathHops.has(linkKey(l)) && scale < 3) return;
          const s = l.source as GNode;
          const t = l.target as GNode;
          if (s.x === undefined || t.x === undefined) return;
          const fs = Math.max(8 / scale, 2);
          ctx.font = `${fs}px ui-monospace, monospace`;
          ctx.fillStyle = pathHops.has(linkKey(l)) ? "#fecaca" : "#94a3b8";
          ctx.textAlign = "center";
          ctx.textBaseline = "bottom";
          const txt = l.data.op ?? l.data.role ?? l.data.type;
          ctx.fillText(
            l.data.type === "DERIVED_FROM" ? txt : l.data.type,
            (s.x + t.x) / 2,
            ((s.y ?? 0) + (t.y ?? 0)) / 2 - 1,
          );
        }}
        onNodeHover={(n) => setHover(n ? (n.id as string) : null)}
        onNodeClick={(n) => onSelect?.(n.data)}
        onBackgroundClick={() => onSelect?.(null)}
      />
    </div>
  );
}

export default ProvenanceGraph;
