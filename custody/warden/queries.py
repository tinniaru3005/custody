"""Cypher used by the Warden. All of it is read-only except the sandbox labelling query,
which only ever runs against a GRAPH.COPY clone.

Traversal conventions match the Guard (``custody.guard.queries``):
- ``(d)-[:DERIVED_FROM*]->(ancestor)`` walks backwards (towards sources);
- ``(o)<-[:DERIVED_FROM*]-(descendant)`` walks forwards (towards everything it influenced);
- an edge with ``attribution = 'context'`` means "was in the model's context, but the
  value was attributed elsewhere". The Guard never follows such edges; the Warden reports
  nodes reached only through them as ``influence = context_only``.
"""
from __future__ import annotations

from custody.guard.queries import FOLLOW

WARDEN_AGENT = "warden"

DIRECT = f"CASE WHEN {FOLLOW} THEN 1 ELSE 0 END"


def _d(depth: int) -> int:
    return max(1, min(int(depth), 100))


GET_SOURCE = "MATCH (s:Source {id: $id}) RETURN s"
GET_DATUM_NODE = "MATCH (d:Datum {id: $id}) RETURN d"

FIND_SOURCES = (
    "MATCH (s:Source) "
    "WHERE ($kind IS NULL OR s.kind = $kind) AND ($trust IS NULL OR s.trust = $trust) "
    "OPTIONAL MATCH (s)<-[:FROM]-(o:Datum) "
    "WITH s, collect(o) AS os "
    "RETURN s, size(os), [o IN os | o.preview], [o IN os | o.value], [o IN os | o.id] "
    "ORDER BY s.created_at"
)


def downstream_count(depth: int) -> str:
    return (
        "MATCH (o:Datum) WHERE o.id IN $ids "
        f"MATCH p = (o)<-[:DERIVED_FROM*1..{_d(depth)}]-(d:Datum) "
        f"WHERE {FOLLOW} AND coalesce(d.agent, '') <> $warden "
        "RETURN count(DISTINCT d)"
    )


ORIGINS_OF_SOURCE = "MATCH (s:Source {id: $id})<-[:FROM]-(o:Datum) RETURN o.id ORDER BY o.created_at"


def forward(depth: int) -> str:
    """Everything downstream of the origin datums, with min depth and whether any path
    to it avoids 'context' edges (direct influence)."""
    return (
        "MATCH (o:Datum) WHERE o.id IN $ids "
        f"MATCH p = (o)<-[:DERIVED_FROM*0..{_d(depth)}]-(d:Datum) "
        f"WITH d, min(length(p)) AS depth, max({DIRECT}) AS direct "
        "RETURN d, depth, direct ORDER BY depth, d.created_at"
    )


ACTIONS_ON = (
    "MATCH (a:Action)-[r:ARG]->(d:Datum) WHERE d.id IN $ids "
    "OPTIONAL MATCH (a)-[:TO]->(k:Sink) "
    "RETURN a, k, collect(DISTINCT [r.role, d.id]) "
    "ORDER BY a.created_at"
)

ALL_ACTIONS = (
    "MATCH (a:Action) OPTIONAL MATCH (a)-[:TO]->(k:Sink) "
    "RETURN a, k ORDER BY a.created_at"
)

LATEST_DECISIONS = (
    "MATCH (dc:Decision)-[:EVALUATES]->(a:Action) WHERE a.id IN $ids "
    "RETURN a.id, dc.decision, dc.explanation, dc.created_at, dc.seq "
    "ORDER BY dc.created_at, dc.seq"
)


def ancestors_of_action(depth: int) -> str:
    """Every ancestor of every argument of an action, with the Source it came FROM."""
    return (
        "MATCH (a:Action {id: $aid})-[arg:ARG]->(d:Datum) "
        f"MATCH p = (d)-[:DERIVED_FROM*0..{_d(depth)}]->(x:Datum) "
        f"WITH x, min(length(p)) AS depth, max({DIRECT}) AS direct, "
        "collect(DISTINCT d.id) AS via "
        "OPTIONAL MATCH (x)-[:FROM]->(s:Source) "
        "RETURN x, depth, direct, via, s ORDER BY depth, x.created_at"
    )


def action_paths(depth: int) -> str:
    """Concrete provenance paths from each argument of an action to a Source."""
    return (
        "MATCH (a:Action {id: $aid})-[arg:ARG]->(d:Datum) "
        f"MATCH p = (d)-[:DERIVED_FROM*0..{_d(depth)}]->(x:Datum) "
        "MATCH (x)-[:FROM]->(s:Source) "
        "RETURN arg.role, d.id, [n IN nodes(p) | n.id], "
        "[r IN relationships(p) | coalesce(r.op, 'derive')], "
        "[r IN relationships(p) | coalesce(r.attribution, 'inherit')], "
        "[n IN nodes(p) WHERE n.endorsed = true | n.id], s, length(p) AS len "
        "ORDER BY len LIMIT $limit"
    )


def memory_downstream(depth: int) -> str:
    """For each memory: the datums it directly influenced (excluding Warden artefacts)."""
    return (
        "MATCH (m:Datum:Memory) "
        "WHERE $incq OR coalesce(m.in_quarantine, false) = false "
        f"OPTIONAL MATCH p = (m)<-[:DERIVED_FROM*1..{_d(depth)}]-(d:Datum) "
        f"WHERE {FOLLOW} AND coalesce(d.agent, '') <> $warden "
        "WITH m, collect(DISTINCT d) AS ds "
        "RETURN m, [x IN ds | x.id], [x IN ds | labels(x)] ORDER BY m.created_at"
    )


BETWEENNESS = (
    "CALL algo.betweenness({nodeLabels: ['Datum', 'Action', 'Source'], "
    "relationshipTypes: ['DERIVED_FROM', 'ARG', 'FROM']}) "
    "YIELD node, score "
    "WHERE 'Memory' IN labels(node) "
    "RETURN node.id, score"
)


def contaminated(depth: int) -> str:
    """(untrusted source, datum) pairs: datums directly downstream of untrusted sources."""
    return (
        "MATCH (s:Source {trust: 'untrusted'})<-[:FROM]-(o:Datum) "
        f"MATCH p = (o)<-[:DERIVED_FROM*0..{_d(depth)}]-(d:Datum) "
        f"WHERE {FOLLOW} AND coalesce(d.agent, '') <> $warden "
        "RETURN DISTINCT s.id, d.id"
    )


CONTAMINATED_EDGES = (
    "MATCH (a:Datum)-[:DERIVED_FROM]->(b:Datum) WHERE a.id IN $ids AND b.id IN $ids "
    "RETURN a.id, b.id"
)

# --- sandbox-only (runs on a GRAPH.COPY clone, never on the live tenant graph)
SANDBOX_LABEL_CONTAMINATED = (
    "MATCH (n) WHERE (n:Datum OR n:Source OR n:Action) AND n.id IN $ids "
    "SET n:Contaminated RETURN count(n)"
)
SANDBOX_WCC = (
    "CALL algo.WCC({nodeLabels: ['Contaminated'], "
    "relationshipTypes: ['DERIVED_FROM', 'FROM', 'ARG']}) "
    "YIELD node, componentId RETURN node.id, componentId"
)


def actions_depending_on_recalls(depth: int) -> str:
    """Actions whose arguments directly derive from a Recall of one of $mids."""
    return (
        "MATCH (a:Action)-[:ARG]->(d:Datum) "
        f"MATCH p = (d)-[:DERIVED_FROM*0..{_d(depth)}]->(r:Recall) "
        f"WHERE {FOLLOW} "
        "MATCH (r)-[:DERIVED_FROM]->(m:Memory) WHERE m.id IN $mids "
        "RETURN DISTINCT a.id, m.id"
    )
