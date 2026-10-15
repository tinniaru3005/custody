"""Read models for the Custody operator console (the React UI).

Everything here is a read over the tenant graph. Policy decisions still come only from the
deterministic Guard; these views just shape graph facts for display.
"""
from __future__ import annotations

import json
import statistics
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field

from custody.demo.attack import AGENT_ROLES, VENDOR_SOURCE_ID, DemoRun, latest_demo
from custody.graph import schema as S
from custody.graph.model import load_metadata
from custody.guard.models import GuardDecision
from custody.guard.policy import GuardPolicy
from custody.guard.service import Guard
from custody.recorder.service import Recorder
from custody.warden import queries as WQ
from custody.warden.analysis import WardenAnalysis
from custody.graph.repository import READ_TIMEOUT_MS

HIDDEN_LABELS = {S.RUN, S.GRAPH_META, S.REVOCATION, S.READJUDICATION}


# ============================================================================ models
class GraphNode(BaseModel):
    id: str
    label: str                          # primary label: Source, Datum, Memory, Recall, ...
    labels: List[str]
    title: str                          # short human label
    kind: Optional[str] = None
    agent: Optional[str] = None
    session_id: Optional[str] = None
    preview: Optional[str] = None       # masked for secrets; may be attacker text (display only)
    created_at: Optional[str] = None
    sim_time: Optional[str] = None
    sim_day: Optional[str] = None
    step: Optional[int] = None
    trust: Optional[str] = None         # Source
    sensitivity: Optional[str] = None   # Datum
    status: Optional[str] = None        # Action
    verdict: Optional[str] = None       # Action (latest Guard decision) / Decision / Approval
    external: Optional[bool] = None     # Sink (policy classification)
    flags: List[str] = Field(default_factory=list)  # trusted untrusted secret tainted quarantined blocked ...
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    type: str
    op: Optional[str] = None
    attribution: Optional[str] = None
    role: Optional[str] = None


class GraphView(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    counts: Dict[str, int]


class AgentSummary(BaseModel):
    name: str
    role: str
    sessions: List[str]
    data: int
    memories: int
    actions: int
    allowed: int
    approval: int
    blocked: int
    contaminated: bool
    last_seen: Optional[str] = None


class ActionSummary(BaseModel):
    id: str
    action_type: str
    agent: str
    session_id: Optional[str] = None
    status: str
    created_at: str
    sim_time: Optional[str] = None
    destination: Optional[str] = None
    sink_kind: Optional[str] = None
    external: bool = False
    verdict: Optional[str] = None
    triggered: List[str] = Field(default_factory=list)
    latency_ms: Optional[float] = None
    explanation: Optional[str] = None
    decisions: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)


class MemorySummary(BaseModel):
    id: str
    key: Optional[str] = None
    agent: Optional[str] = None
    session_id: Optional[str] = None
    preview: str
    created_at: str
    sim_time: Optional[str] = None
    in_quarantine: bool = False
    quarantine_id: Optional[str] = None
    tainted: bool = False


class QuarantineSummary(BaseModel):
    id: str
    memory_ids: List[str]
    reason: Optional[str] = None
    action_id: Optional[str] = None
    incident_id: Optional[str] = None
    created_at: Optional[str] = None


class IncidentSummary(BaseModel):
    id: str
    severity: str
    sources: List[str]
    summary: str
    memories: int
    messages: int
    actions: int
    blocked: List[str]
    executed_external: List[str]


class Overview(BaseModel):
    tenant: str
    empty: bool
    demo: Optional[Dict[str, Any]] = None     # {id, created_at, blocked_action, ...}
    agents: List[AgentSummary]
    actions: List[ActionSummary]
    counts: Dict[str, int]
    incidents: List[IncidentSummary]
    memories: List[MemorySummary]
    quarantines: List[QuarantineSummary]
    graph_counts: Dict[str, int]


class ActionExplain(BaseModel):
    action: ActionSummary
    decision: GuardDecision               # fresh, deterministic re-check (not recorded)
    history: List[Dict[str, Any]]         # recorded Decision nodes (enforcement-time)
    approvals: List[Dict[str, Any]]
    chain: List[Dict[str, Any]]           # Action → Sink → ... → Source, for the hero view


class Metrics(BaseModel):
    focus_action: Optional[str] = None
    guard_latency_ms: Optional[float] = None
    guard_latency_breakdown: Dict[str, float] = Field(default_factory=dict)
    guard_latency_samples: List[float] = Field(default_factory=list)
    guard_latency_p50: Optional[float] = None
    guard_latency_max: Optional[float] = None
    path_length: Optional[int] = None
    sessions_crossed: List[str] = Field(default_factory=list)
    agents_crossed: List[str] = Field(default_factory=list)
    affected_memories: int = 0
    affected_agents: List[str] = Field(default_factory=list)
    affected_actions: int = 0
    affected_messages: int = 0
    blocked_actions: int = 0
    decisions_recorded: int = 0
    deterministic_runs: int = 0
    deterministic_identical: bool = True
    graph_nodes: int = 0
    graph_edges: int = 0
    queries: List[Dict[str, str]] = Field(default_factory=list)


# ============================================================================ helpers
def _primary(labels: List[str]) -> str:
    for l in (S.MEMORY, S.RECALL, S.MESSAGE, S.TYPED):
        if l in labels:
            return l
    return labels[0] if labels else "?"


def _host(url: str) -> str:
    from urllib.parse import urlsplit

    p = urlsplit(url)
    return (p.hostname or url) + (p.path if p.path not in ("", "/") else "")


def _title(label: str, p: Dict[str, Any], meta: Dict[str, Any]) -> str:
    if label == S.SOURCE:
        ref = meta.get("url") or meta.get("path") or meta.get("user") or meta.get("ref") \
            or meta.get("agent") or meta.get("component") or p.get("id")
        if p.get("kind") == "web":
            ref = _host(ref)
        return f"{p.get('kind')}: {ref}"
    if label == S.MEMORY:
        return f"memory: {meta.get('key') or p.get('id')}"
    if label == S.RECALL:
        return f"recall by {p.get('agent')}"
    if label == S.MESSAGE:
        return f"message {meta.get('sender', '?')} → {meta.get('recipient', '?')}"
    if label == S.ACTION:
        return str(p.get("action_type"))
    if label == S.SINK:
        return str(p.get("destination"))
    if label == S.APPROVAL:
        verdict = p.get("verdict") or "approved"
        return f"{verdict} by {p.get('approver')}"
    if label == S.DECISION:
        return f"decision: {p.get('decision')}"
    if label == S.QUARANTINE:
        return "quarantine"
    kind = p.get("kind")
    if kind == "user_input":
        return "user request"
    if kind == "web_content":
        return "web page content"
    if kind == "secret":
        return f"secret: {meta.get('path', '')}"
    if kind == "tool_output":
        return "inbound content"
    if meta.get("tool_arg"):
        return f"{meta['tool']}.{meta['tool_arg']}"
    if meta.get("warden_draft"):
        return "disclosure draft"
    return f"{p.get('agent') or ''} output".strip()


class ConsoleViews:
    def __init__(self, recorder: Recorder, policy: GuardPolicy, tenant: str, db: Any = None):
        self.recorder = recorder
        self.repo = recorder.repo
        self.policy = policy
        self.tenant = tenant
        self.db = db
        self.analysis = WardenAnalysis(self.repo, policy, db, recorder.max_trace_depth)

    def _ro(self, q: str, params: Optional[Dict[str, Any]] = None):
        return self.repo.graph.ro_query(q, params or {}, timeout=READ_TIMEOUT_MS).result_set

    # ------------------------------------------------------------------ facts
    def tainted_ids(self) -> Set[str]:
        """Datums directly downstream of an untrusted Source (Guard-followed edges only)."""
        return {did for _sid, did in self._ro(WQ.contaminated(self.recorder.max_trace_depth),
                                              {"warden": "warden"})}

    def latest_decisions(self) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        counts: Dict[str, int] = defaultdict(int)
        for aid, dc in self._ro(f"MATCH (dc:{S.DECISION})-[:{S.EVALUATES}]->(a:{S.ACTION}) "
                                "RETURN a.id, dc ORDER BY dc.created_at, dc.seq"):
            out[aid] = dict(dc.properties)
            counts[aid] += 1
        for aid in out:
            out[aid]["_count"] = counts[aid]
        return out

    # ------------------------------------------------------------------ graph
    def graph(self, include_decisions: bool = False) -> GraphView:
        tainted = self.tainted_ids()
        decisions = self.latest_decisions()
        nodes: List[GraphNode] = []
        keep: Set[str] = set()
        for (n,) in self._ro("MATCH (n) RETURN n"):
            labels = list(n.labels)
            if HIDDEN_LABELS & set(labels):
                continue
            if S.DECISION in labels and not include_decisions:
                continue
            p = dict(n.properties)
            if "id" not in p:
                continue
            meta = load_metadata(p.get("metadata")) if isinstance(p.get("metadata"), str) else {}
            label = _primary(sorted(labels, key=lambda l: (l != S.DATUM, l))
                             if S.DATUM in labels else labels)
            flags: List[str] = []
            node = GraphNode(id=p["id"], label=label, labels=labels, title=_title(label, p, meta),
                             kind=p.get("kind"), agent=p.get("agent"),
                             session_id=p.get("session_id"), preview=p.get("preview"),
                             created_at=p.get("created_at"), sim_time=meta.get("sim_time"),
                             sim_day=meta.get("sim_day"), step=meta.get("demo_step"))
            if label == S.SOURCE:
                node.trust = p.get("trust")
                flags.append(p.get("trust", "trusted"))
                node.metadata = meta
                if p.get("kind") == "vault":
                    flags.append("secret")
            elif S.DATUM in labels:
                node.sensitivity = p.get("sensitivity")
                if p.get("sensitivity") == "secret":
                    flags.append("secret")
                if p["id"] in tainted:
                    flags.append("tainted")
                if p.get("in_quarantine"):
                    flags.append("quarantined")
                if p.get("endorsed"):
                    flags.append("endorsed")
                if p.get("agent") == "warden":
                    flags.append("warden")
                node.metadata = {k: v for k, v in meta.items()
                                 if k not in ("sim_time", "sim_day", "demo_step")}
            elif label == S.ACTION:
                node.status = p.get("status")
                dec = decisions.get(p["id"])
                node.verdict = dec.get("decision") if dec else None
                flags.append(p.get("status", ""))
                if node.verdict == "BLOCK":
                    flags.append("blocked")
                if p.get("agent") == "warden":
                    flags.append("warden")
                node.metadata = {k: v for k, v in meta.items()
                                 if k not in ("sim_time", "sim_day", "demo_step")}
                if dec:
                    node.metadata["guard"] = {"decision": dec.get("decision"),
                                              "triggered": dec.get("triggered"),
                                              "latency_ms": dec.get("latency_ms")}
            elif label == S.SINK:
                from custody.graph.model import SinkRecord

                cls = self.policy.classify_sink(SinkRecord(
                    id=p["id"], destination=p.get("destination", ""), kind=p.get("kind", ""),
                    external=bool(p.get("external")), workspace=p.get("workspace")))
                node.external = cls.external
                flags.append("external" if cls.external else "internal")
                node.metadata = {"zone": cls.zone, "reason": cls.reason,
                                 "workspace": p.get("workspace"), "kind": p.get("kind")}
            elif label == S.APPROVAL:
                node.verdict = p.get("verdict") or "approved"
                node.metadata = {"approver": p.get("approver"), "reason": p.get("reason"),
                                 "approver_kind": p.get("approver_kind")}
                flags.append(node.verdict)
            elif label == S.DECISION:
                node.verdict = p.get("decision")
                node.metadata = {"explanation": p.get("explanation"),
                                 "latency_ms": p.get("latency_ms"), "policy": p.get("policy")}
            elif label == S.QUARANTINE:
                node.metadata = {"reason": p.get("reason"), "actor": p.get("actor"),
                                 "incident_id": p.get("incident_id"),
                                 "action_id": p.get("action_id")}
                flags.append("quarantined")
            node.flags = [f for f in flags if f]
            nodes.append(node)
            keep.add(node.id)

        edges: List[GraphEdge] = []
        for a, r, b in self._ro("MATCH (a)-[r]->(b) RETURN a.id, r, b.id"):
            if a not in keep or b not in keep:
                continue
            props = r.properties
            edges.append(GraphEdge(id=f"{a}|{r.relation}|{b}|{len(edges)}", source=a, target=b,
                                   type=r.relation, op=props.get("op"),
                                   attribution=props.get("attribution"), role=props.get("role")))
        counts: Dict[str, int] = defaultdict(int)
        for n in nodes:
            counts[n.label] += 1
        for e in edges:
            counts[e.type] += 1
        return GraphView(nodes=nodes, edges=edges, counts=dict(counts))

    # ---------------------------------------------------------------- actions
    def actions(self) -> List[ActionSummary]:
        decisions = self.latest_decisions()
        out = []
        for a, k in self._ro(WQ.ALL_ACTIONS):
            p = a.properties
            meta = load_metadata(p.get("metadata"))
            sink = self.analysis._sink_view(k)
            dec = decisions.get(p["id"], {})
            out.append(ActionSummary(
                id=p["id"], action_type=p["action_type"], agent=p["agent"],
                session_id=p.get("session_id"), status=p["status"], created_at=p["created_at"],
                sim_time=meta.get("sim_time"),
                destination=sink.destination if sink else None,
                sink_kind=sink.kind if sink else None, external=bool(sink and sink.external),
                verdict=dec.get("decision"), triggered=list(dec.get("triggered") or []),
                latency_ms=dec.get("latency_ms"), explanation=dec.get("explanation"),
                decisions=dec.get("_count", 0),
                metadata={k: v for k, v in meta.items()
                          if k not in ("sim_time", "sim_day", "demo_step")}))
        return out

    def _action_summary(self, action_id: str) -> ActionSummary:
        for a in self.actions():
            if a.id == action_id:
                return a
        from custody.graph.repository import NotFound

        raise NotFound(f"action {action_id!r} not found")

    def explain(self, action_id: str) -> ActionExplain:
        summary = self._action_summary(action_id)
        guard = Guard(self.recorder, self.policy, record_decisions=False)
        decision = guard.check(action_id)
        history = []
        for d in self.repo.decisions_for(action_id):
            d = dict(d)
            d.pop("seq", None)
            history.append(d)
        approvals = [dict(r[0].properties, relation=r[1]) for r in self._ro(
            f"MATCH (ap:{S.APPROVAL})-[r:{S.APPROVES}|{S.REJECTS}]->(:{S.ACTION} {{id: $id}}) "
            "RETURN ap, type(r) ORDER BY ap.created_at", {"id": action_id})]
        approvals += [dict(r[0].properties, relation="ENDORSES", datum_id=r[1]) for r in self._ro(
            f"MATCH (:{S.ACTION} {{id: $id}})-[:{S.ARG}]->(d:{S.DATUM})<-[:{S.ENDORSES}]-"
            f"(ap:{S.APPROVAL}) RETURN ap, d.id", {"id": action_id})]
        return ActionExplain(action=summary, decision=decision, history=history,
                             approvals=approvals, chain=self.chain(decision))

    @staticmethod
    def chain(decision: GuardDecision) -> List[Dict[str, Any]]:
        """The responsible path as display cards: Action → Sink → arg → … → Source.

        Uses the worst integrity path (violating first, then limited/cleared); falls back to
        the confidentiality path when there is no integrity path."""
        order = {"violating": 0, "limited": 1, "cleared": 2, "info": 3}
        paths = sorted(decision.paths, key=lambda p: (p.check.value != "integrity",
                                                      order.get(p.status, 9), p.length))
        cards: List[Dict[str, Any]] = [{
            "role": "action", "id": decision.action_id, "label": "Action",
            "title": decision.action_type, "agent": decision.agent,
            "detail": f"proposed by {decision.agent}", "verdict": decision.decision.value}]
        if decision.sink.destination:
            cards.append({"role": "sink", "id": decision.sink.id, "label": "Sink",
                          "title": decision.sink.destination,
                          "detail": f"{decision.sink.zone}: {decision.sink.reason}",
                          "external": decision.sink.external, "op": "TO"})
        if not paths:
            return cards
        p = paths[0]
        cards[-1]["path_check"] = p.check.value
        names = {"llm_output": "agent output", "recall": "recalled memory",
                 "memory": "shared memory", "message": "inter-agent message",
                 "web_content": "web page", "user_input": "user request",
                 "secret": "vault secret", "tool_output": "inbound content",
                 "typed_value": "typed value"}
        sessions_seen: List[str] = []
        for i, n in enumerate(p.nodes):
            op = "ARG:" + p.arg_role if i == 0 else p.ops[i - 1]
            if "Source" in n.labels:
                cards.append({"role": "source", "id": n.id, "label": "Source",
                              "title": n.preview or n.id, "kind": n.kind, "trust": n.trust,
                              "detail": f"{n.kind} source · {n.trust}", "op": op})
                continue
            label = next((l for l in ("Memory", "Recall", "Message", "Typed") if l in n.labels),
                         "Datum")
            role = names.get(n.kind or "", n.kind or "datum")
            if i == 0:
                role = p.arg_role
            elif n.kind == "memory" and n.session_id and sessions_seen \
                    and n.session_id != sessions_seen[0]:
                role = "previous-session memory"
            elif n.kind == "llm_output" and n.agent:
                role = f"{n.agent.capitalize()} output"
            if n.session_id and n.session_id not in sessions_seen:
                sessions_seen.append(n.session_id)
            cards.append({"role": role, "id": n.id, "label": label, "title": n.preview or n.id,
                          "agent": n.agent, "session_id": n.session_id, "kind": n.kind,
                          "sensitivity": n.sensitivity, "endorsed": n.endorsed, "op": op,
                          "detail": " · ".join(x for x in (n.agent, n.session_id) if x)})
        cards[0]["path_status"] = p.status
        cards[0]["path_length"] = p.length
        return cards

    def human_decided_action_ids(self) -> Set[str]:
        """Actions a human approved, rejected or whose destination a human endorsed."""
        rows = self._ro(
            f"MATCH (ap:{S.APPROVAL})-[:{S.APPROVES}|{S.REJECTS}]->(a:{S.ACTION}) RETURN a.id "
            f"UNION MATCH (ap:{S.APPROVAL})-[:{S.ENDORSES}]->(:{S.DATUM})<-[:{S.ARG}]-(a:{S.ACTION}) "
            "RETURN a.id")
        return {r[0] for r in rows}

    # --------------------------------------------------------------- memories
    def memories(self) -> List[MemorySummary]:
        tainted = self.tainted_ids()
        out = []
        for (m,) in self._ro(f"MATCH (m:{S.DATUM}:{S.MEMORY}) RETURN m ORDER BY m.created_at"):
            p = m.properties
            meta = load_metadata(p.get("metadata"))
            out.append(MemorySummary(id=p["id"], key=meta.get("key"), agent=p.get("agent"),
                                     session_id=p.get("session_id"), preview=p.get("preview", ""),
                                     created_at=p.get("created_at", ""),
                                     sim_time=meta.get("sim_time"),
                                     in_quarantine=bool(p.get("in_quarantine")),
                                     quarantine_id=p.get("quarantine_id"),
                                     tainted=p["id"] in tainted))
        return out

    # --------------------------------------------------------------- overview
    def overview(self) -> Overview:
        actions = self.actions()
        memories = self.memories()
        tainted = self.tainted_ids()
        rows = self._ro(f"MATCH (d:{S.DATUM}) WHERE d.agent IS NOT NULL "
                        "RETURN d.agent, d.session_id, d.id, 'Memory' IN labels(d), d.created_at")
        per: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"sessions": set(), "data": 0,
                                                              "memories": 0, "tainted": False,
                                                              "last": ""})
        for agent, sess, did, is_mem, at in rows:
            x = per[agent]
            if sess:
                x["sessions"].add(sess)
            x["data"] += 1
            x["memories"] += int(bool(is_mem))
            x["tainted"] |= did in tainted
            x["last"] = max(x["last"], at or "")
        for a in actions:
            per[a.agent]["last"] = max(per[a.agent]["last"], a.created_at)
        agents = []
        for name in sorted(per, key=lambda n: (list(AGENT_ROLES).index(n)
                                               if n in AGENT_ROLES else 99, n)):
            x = per[name]
            mine = [a for a in actions if a.agent == name]
            agents.append(AgentSummary(
                name=name, role=AGENT_ROLES.get(name, "agent"), sessions=sorted(x["sessions"]),
                data=x["data"], memories=x["memories"], actions=len(mine),
                allowed=sum(a.verdict == "ALLOW" for a in mine),
                approval=sum(a.verdict == "REQUIRE_HUMAN_APPROVAL" for a in mine),
                blocked=sum(a.verdict == "BLOCK" for a in mine), contaminated=x["tainted"],
                last_seen=x["last"] or None))
        counts = {
            "actions": len(actions),
            "allowed": sum(a.verdict == "ALLOW" for a in actions),
            "approval": sum(a.verdict == "REQUIRE_HUMAN_APPROVAL" for a in actions),
            "pending_approval": sum(a.status == "pending_approval" for a in actions),
            "blocked": sum(a.verdict == "BLOCK" for a in actions),
            "executed": sum(a.status == "executed" for a in actions),
            "memories": len(memories),
            "quarantined_memories": sum(m.in_quarantine for m in memories),
            "tainted_memories": sum(m.tainted and not m.in_quarantine for m in memories),
        }
        incidents = []
        try:
            res = self.analysis.cluster_incidents(use_falkordb_wcc=False)
            for i in res.incidents:
                incidents.append(IncidentSummary(
                    id=i.id, severity=i.severity, sources=[s.id for s in i.sources],
                    summary=i.summary, memories=len(i.memories), messages=len(i.messages),
                    actions=len(i.actions), blocked=i.blocked_actions,
                    executed_external=i.executed_external_actions))
        except Exception:  # pragma: no cover - empty/odd graphs: dashboard still renders
            incidents = []
        quarantines = [QuarantineSummary(id=q["id"], memory_ids=q["memory_ids"],
                                         reason=q.get("reason"), action_id=q.get("action_id"),
                                         incident_id=q.get("incident_id"),
                                         created_at=q.get("created_at"))
                       for q in self.repo.quarantines()]
        demo = latest_demo(self.recorder)
        demo_info = None
        if demo:
            demo_info = {"id": demo.id, "created_at": demo.created_at,
                         "blocked_action": demo.ids.get("blocked_action"),
                         "slack_action": demo.ids.get("slack_action"),
                         "cleanup_request": demo.cleanup_request}
        gc = self.repo.counts()
        return Overview(tenant=self.tenant, empty=not actions and not memories, demo=demo_info,
                        agents=agents, actions=actions, counts=counts, incidents=incidents,
                        memories=memories, quarantines=quarantines,
                        graph_counts={k: v for k, v in gc.items() if "Run" not in k})

    # ---------------------------------------------------------------- metrics
    def metrics(self, runs: int = 5) -> Metrics:
        m = Metrics()
        demo: Optional[DemoRun] = latest_demo(self.recorder)
        actions = self.actions()
        focus = demo.ids.get("blocked_action") if demo else None
        if focus is None:
            focus = next((a.id for a in actions if a.verdict == "BLOCK"), None)
        decisions = [d for d in (self.latest_decisions().values())]
        m.blocked_actions = sum(a.verdict == "BLOCK" for a in actions)
        m.decisions_recorded = int(self._ro(f"MATCH (d:{S.DECISION}) RETURN count(d)")[0][0])
        samples = [float(r[0]) for r in self._ro(
            f"MATCH (d:{S.DECISION}) WHERE d.latency_ms IS NOT NULL "
            "RETURN d.latency_ms ORDER BY d.created_at")]
        m.guard_latency_samples = [round(x, 3) for x in samples]
        if samples:
            m.guard_latency_p50 = round(statistics.median(samples), 3)
            m.guard_latency_max = round(max(samples), 3)
        gc = self.repo.counts()
        m.graph_nodes = sum(v for k, v in gc.items() if k.startswith("node:") and "Run" not in k)
        m.graph_edges = sum(v for k, v in gc.items() if k.startswith("rel:"))
        m.queries = [
            {"name": "untrusted_origin_search", "purpose": "verdict: complete BFS (no depth "
             "bound) → PATH_FOUND / NO_PATH / INDETERMINATE (fails closed)",
             "pattern": "UNWIND $frontier … (n)-[r:DERIVED_FROM]->(m) per level, visited set"},
            {"name": "integrity_paths", "purpose": "evidence: destination → … → untrusted Source",
             "pattern": "(a:Action)-[:ARG]->(d)-[:DERIVED_FROM*0..25]->(x)-[:FROM]->"
                        "(s:Source {trust:'untrusted'})"},
            {"name": "confidentiality_paths", "purpose": "evidence: payload → … → secret Datum",
             "pattern": "(a:Action)-[:ARG]->(d)-[:DERIVED_FROM*0..25]->(x {sensitivity:'secret'})"},
            {"name": "destination_binding", "purpose": "sink literal = destination datum",
             "pattern": "(a)-[:TO]->(k:Sink), (a)-[:ARG {role:'destination'}]->(d)"},
        ]
        if focus:
            m.focus_action = focus
            guard = Guard(self.recorder, self.policy, record_decisions=False)
            fingerprints = set()
            totals = []
            last: Optional[GuardDecision] = None
            for _ in range(max(1, runs)):
                last = guard.check(focus)
                totals.append(last.latency_ms.get("total", 0.0))
                fingerprints.add(json.dumps({
                    "decision": last.decision.value,
                    "triggered": [c.value for c in last.triggered_checks],
                    "paths": [p.text for p in last.paths]}, sort_keys=True))
            assert last is not None
            m.deterministic_runs = len(totals)
            m.deterministic_identical = len(fingerprints) == 1
            m.guard_latency_ms = round(statistics.median(totals), 3)
            m.guard_latency_breakdown = {k: v for k, v in last.latency_ms.items() if k != "total"}
            worst = next((p for p in last.paths if p.check.value == "integrity"
                          and p.status == "violating"), None) or (last.paths[0] if last.paths else None)
            if worst:
                m.path_length = worst.length
                m.sessions_crossed = worst.sessions
                m.agents_crossed = worst.agents
        source = VENDOR_SOURCE_ID if demo else None
        if source is None:
            srcs = self._ro("MATCH (s:Source {trust:'untrusted'}) RETURN s.id ORDER BY s.created_at")
            source = srcs[0][0] if srcs else None
        if source:
            try:
                tf = self.analysis.trace_forward(source)
                m.affected_memories = len(tf.memories)
                m.affected_messages = len(tf.messages)
                m.affected_actions = len(tf.actions)
                agents = {n.agent for n in (tf.origin_data + tf.derived_data + tf.memories
                                            + tf.recalls + tf.messages) if n.agent}
                agents |= {a.agent for a in tf.actions}
                m.affected_agents = sorted(a for a in agents if a != "warden")
            except Exception:  # pragma: no cover
                pass
        _ = decisions
        return m
