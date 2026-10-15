"""Complete, fail-closed provenance reachability.

Variable-length Cypher patterns (``-[:DERIVED_FROM*0..N]->``) enumerate *paths* and need a
hard upper bound ``N``. When nothing is found within ``N`` hops that only means "no path
within N hops" — it is not a proof that no path exists. Security decisions must not
confuse the two.

This module answers reachability questions with a level-by-level breadth-first search over
nodes, driven from Python against FalkorDB:

- each level is one read-only query that expands the current frontier by one
  ``DERIVED_FROM`` hop, applying the edge filter (e.g. skip ``attribution = 'context'``)
  and the node filter (e.g. stop at endorsed Datums);
- a visited set makes it cycle-safe and visits every node at most once, so there is no
  depth bound by default — the search runs until the frontier is empty;
- it stops early with a witness path as soon as a target node is reached.

Every search returns a :class:`ProvenanceSearch` with one of three outcomes:

``PATH_FOUND``     a relevant path exists (a witness path is attached)
``NO_PATH``        the traversal exhausted the reachable graph: no relevant path exists
``INDETERMINATE``  the traversal did not finish (depth/node limit, timeout, query error)

Only ``path_found is False and search_complete is True`` proves absence. Callers that gate
risky actions must treat ``INDETERMINATE`` like ``PATH_FOUND`` (fail closed).
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from collections.abc import Sequence

from pydantic import BaseModel, Field

from custody.graph import schema as S

# Resource limits. Depth is unbounded by default; these bound work, and hitting any of
# them yields INDETERMINATE (never NO_PATH).
DEFAULT_MAX_NODES = 100_000
DEFAULT_TIMEOUT_MS = 2_000
_BATCH = 500  # frontier ids per expansion query

# Edges the Guard follows: 'context' edges record presence in the model's context only.
FOLLOW_EDGE = "coalesce(r.attribution, 'inherit') <> 'context'"
NOT_ENDORSED = "coalesce(m.endorsed, false) = false"
# Datum m comes FROM an untrusted Source; tail = that source id (for the witness path)
UNTRUSTED_HIT = f"size([(m)-[:{S.FROM}]->(s:{S.SOURCE} {{trust: 'untrusted'}}) | s.id]) > 0"
UNTRUSTED_TAIL = f"[(m)-[:{S.FROM}]->(s:{S.SOURCE} {{trust: 'untrusted'}}) | s.id][0..1]"
SECRET_HIT = "m.sensitivity = 'secret'"


class SearchOutcome(str, Enum):
    PATH_FOUND = "PATH_FOUND"
    NO_PATH = "NO_PATH"
    INDETERMINATE = "INDETERMINATE"


class TerminationReason(str, Enum):
    PATH_FOUND = "path_found"        # a target was reached (witness attached)
    EXHAUSTED = "exhausted"          # frontier empty: every reachable node was examined
    DEPTH_LIMIT = "depth_limit"      # an explicit max_depth was hit with nodes left to visit
    NODE_LIMIT = "node_limit"        # visited-node budget exhausted
    TIMEOUT = "timeout"              # wall-clock budget (or the server query timeout) hit
    QUERY_ERROR = "query_error"      # a traversal query failed


class ProvenanceSearch(BaseModel):
    """Result + metadata of one provenance reachability search."""

    outcome: SearchOutcome
    path_found: bool
    search_complete: bool            # the answer is conclusive (witness found, or graph exhausted)
    termination_reason: TerminationReason
    max_depth_reached: bool = False  # True iff stopped because an explicit depth bound was hit
    depth_explored: int = 0          # deepest BFS level fully expanded
    depth_limit: Optional[int] = None  # None = unbounded
    nodes_visited: int = 0
    queries: int = 0
    latency_ms: float = 0.0
    error: Optional[str] = None
    method: str = "bfs"              # bfs | bounded_paths (witness from the evidence query)
    witness_node_ids: List[str] = Field(default_factory=list)  # start ... target [, Source]
    witness_ops: List[str] = Field(default_factory=list)

    @property
    def proves_no_path(self) -> bool:
        """The only state in which a caller may treat the provenance as clean."""
        return (not self.path_found) and self.search_complete

    @property
    def indeterminate(self) -> bool:
        return self.outcome == SearchOutcome.INDETERMINATE

    def summary(self) -> str:
        bits = [f"{self.outcome.value} ({self.termination_reason.value})",
                f"{self.nodes_visited} node(s)", f"depth {self.depth_explored}"]
        if self.depth_limit is not None:
            bits.append(f"limit {self.depth_limit}")
        if self.error:
            bits.append(f"error: {self.error}")
        return ", ".join(bits)


@dataclass(frozen=True)
class SearchSpec:
    """What to traverse and what counts as a hit.

    Expressions are Cypher over ``r`` (the DERIVED_FROM edge being crossed) and ``m`` (the
    Datum it reaches). ``node_ok`` is also applied to the start nodes. ``tail`` is a list
    expression of extra ids to append to the witness (e.g. the untrusted Source).
    """

    hit: str
    tail: str = "[]"
    node_ok: str = "true"
    edge_ok: str = "true"
    params: Optional[Dict[str, Any]] = None


def witness_from_bounded(path_ids: Sequence[str], ops: Sequence[str], latency_ms: float,
                         depth_limit: Optional[int]) -> ProvenanceSearch:
    """A PATH_FOUND result whose witness came from a bounded path-enumeration query."""
    return ProvenanceSearch(
        outcome=SearchOutcome.PATH_FOUND, path_found=True, search_complete=True,
        termination_reason=TerminationReason.PATH_FOUND, depth_explored=max(0, len(ops) - 1),
        depth_limit=depth_limit, queries=1, latency_ms=latency_ms, method="bounded_paths",
        witness_node_ids=list(path_ids), witness_ops=list(ops))


def _is_timeout(exc: BaseException) -> bool:
    return "timed out" in str(exc).lower() or isinstance(exc, TimeoutError)


def search(graph: Any, start_ids: Sequence[str], spec: SearchSpec, *,
           max_depth: Optional[int] = None, max_nodes: int = DEFAULT_MAX_NODES,
           timeout_ms: Optional[int] = DEFAULT_TIMEOUT_MS,
           collect: Optional[Dict[str, int]] = None,
           edges_out: Optional[List[Tuple[str, str, str, str]]] = None,
           reverse: bool = False,
           parents_out: Optional[Dict[str, Tuple[Optional[str], Optional[str]]]] = None,
           ) -> ProvenanceSearch:
    """Breadth-first reachability from ``start_ids`` along DERIVED_FROM edges.

    Never returns NO_PATH unless every node reachable under ``spec`` was expanded.
    ``collect``, if given, receives every visited node id with its BFS depth (= length of
    the shortest path from a start node). ``edges_out``, if given, receives every
    DERIVED_FROM edge examined as ``(from, to, op, attribution)``. ``reverse=True`` walks
    forward in time (from a Datum to everything derived from it). Cost is linear in
    visited nodes and edges, unlike
    variable-length path patterns, which enumerate paths (exponential in dense DAGs such as
    a multi-turn session where every output derives from every earlier one).
    ``parents_out``, if given, receives the BFS tree: visited id -> (parent id, op), so a
    shortest path to any visited node can be rebuilt without enumerating paths.
    """
    level: Dict[str, int] = collect if collect is not None else {}
    t0 = time.perf_counter()
    deadline = None if timeout_ms is None else t0 + timeout_ms / 1000.0
    params = dict(spec.params or {})
    if "ids" in params:  # reserved: the frontier batch parameter of every expansion query
        raise ValueError("SearchSpec.params must not use the reserved name 'ids'")
    st: Dict[str, Any] = {"queries": 0, "depth": 0}
    parent: Dict[str, Tuple[Optional[str], Optional[str]]] = \
        parents_out if parents_out is not None else {}  # id -> (parent id, op)

    def done(outcome: SearchOutcome, reason: TerminationReason, *, error: Optional[str] = None,
             hit: Optional[str] = None, tail: Sequence[str] = ()) -> ProvenanceSearch:
        ids: List[str] = []
        ops: List[str] = []
        if hit is not None:
            cur: Optional[str] = hit
            while cur is not None:
                ids.append(cur)
                p, op = parent[cur]
                if op is not None:
                    ops.append(op)
                cur = p
            ids.reverse()
            ops.reverse()
            for t in tail:
                ids.append(t)
                ops.append(S.FROM)
        return ProvenanceSearch(
            outcome=outcome, path_found=outcome == SearchOutcome.PATH_FOUND,
            search_complete=outcome != SearchOutcome.INDETERMINATE, termination_reason=reason,
            max_depth_reached=reason == TerminationReason.DEPTH_LIMIT,
            depth_explored=st["depth"], depth_limit=max_depth, nodes_visited=len(parent),
            queries=st["queries"], latency_ms=round((time.perf_counter() - t0) * 1000, 3),
            error=error, witness_node_ids=ids, witness_ops=ops)

    def run(query: str, extra: Dict[str, Any]) -> List[list]:
        remaining = None
        if deadline is not None:
            remaining = int((deadline - time.perf_counter()) * 1000)
            if remaining <= 0:
                raise TimeoutError("traversal time budget exhausted")
        st["queries"] += 1
        return graph.ro_query(query, {**params, **extra},
                              timeout=max(1, remaining) if remaining is not None else None
                              ).result_set

    start_q = (f"UNWIND $ids AS i MATCH (m:{S.DATUM} {{id: i}}) WHERE {spec.node_ok} "
               f"RETURN m.id, {spec.hit}, {spec.tail}")
    # "WITH n" pins the plan to: index lookup of the frontier, then expand. Without it the
    # planner may scan every Datum per frontier id (O(frontier x graph); 500 ms for a
    # 500-node frontier in a 500-node graph instead of 3 ms).
    expand_q = (f"UNWIND $ids AS i MATCH (n:{S.DATUM} {{id: i}}) WITH n "
                + (f"MATCH (n)<-[r:{S.DERIVED_FROM}]-(m:{S.DATUM}) " if reverse else
                   f"MATCH (n)-[r:{S.DERIVED_FROM}]->(m:{S.DATUM}) ")
                + f"WHERE {spec.edge_ok} AND {spec.node_ok} "
                f"RETURN DISTINCT n.id, m.id, coalesce(r.op, type(r)), "
                f"coalesce(r.attribution, 'inherit'), {spec.hit}, {spec.tail}")
    try:
        frontier: List[str] = []
        for mid, hit, tail in run(start_q, {"ids": list(dict.fromkeys(start_ids))}):
            if mid in parent:
                continue
            parent[mid] = (None, None)
            level[mid] = 0
            if hit:
                return done(SearchOutcome.PATH_FOUND, TerminationReason.PATH_FOUND,
                            hit=mid, tail=tail or [])
            frontier.append(mid)
        while frontier:
            if max_depth is not None and st["depth"] >= max_depth:
                # Probe one more hop: if anything new is reachable, the search is incomplete.
                for i in range(0, len(frontier), _BATCH):
                    if any(row[1] not in parent
                           for row in run(expand_q, {"ids": frontier[i:i + _BATCH]})):
                        return done(SearchOutcome.INDETERMINATE, TerminationReason.DEPTH_LIMIT)
                break
            nxt: List[str] = []
            for i in range(0, len(frontier), _BATCH):
                for nid, mid, op, attr, hit, tail in run(expand_q,
                                                         {"ids": frontier[i:i + _BATCH]}):
                    if edges_out is not None:
                        edges_out.append((nid, mid, op, attr))
                    if mid in parent:
                        continue  # already visited (also makes cycles terminate)
                    parent[mid] = (nid, op)
                    level[mid] = level[nid] + 1
                    if hit:
                        st["depth"] += 1
                        return done(SearchOutcome.PATH_FOUND, TerminationReason.PATH_FOUND,
                                    hit=mid, tail=tail or [])
                    nxt.append(mid)
                    if len(parent) > max_nodes:
                        return done(SearchOutcome.INDETERMINATE, TerminationReason.NODE_LIMIT)
            frontier = nxt
            if frontier:
                st["depth"] += 1
    except Exception as exc:  # noqa: BLE001 - any failure makes the search inconclusive
        reason = TerminationReason.TIMEOUT if _is_timeout(exc) else TerminationReason.QUERY_ERROR
        return done(SearchOutcome.INDETERMINATE, reason, error=f"{type(exc).__name__}: {exc}")
    return done(SearchOutcome.NO_PATH, TerminationReason.EXHAUSTED)


# ------------------------------------------------------------------ canned searches
def untrusted_origin(graph: Any, start_ids: Sequence[str], *, risk_rank: Optional[int] = None,
                     exclude: Sequence[str] = (), hit: str = UNTRUSTED_HIT,
                     **limits: Any) -> ProvenanceSearch:
    """Is there a path from ``start_ids`` to an untrusted Source with no endorsed Datum on
    it (and, when ``risk_rank`` is given, no typed Datum whose ``max_risk`` covers it)?
    Follows the same edges as the Guard (``attribution <> 'context'``)."""
    node_ok, params = untrusted_node_filter(risk_rank, exclude)
    return search(graph, start_ids, SearchSpec(hit=hit, tail=UNTRUSTED_TAIL,
                                               node_ok=node_ok, edge_ok=FOLLOW_EDGE,
                                               params=params), **limits)


def untrusted_node_filter(risk_rank: Optional[int] = None, exclude: Sequence[str] = ()
                          ) -> Tuple[str, Dict[str, Any]]:
    """The node filter of the integrity search: endorsed Datums clear a path, typed
    (quarantined) Datums whose ``max_risk`` covers ``risk_rank`` clear it, ``exclude``
    removes Datums (what-ifs)."""
    node_ok = NOT_ENDORSED
    params: Dict[str, Any] = {}
    if risk_rank is not None:
        node_ok += (" AND NOT (coalesce(m.quarantined, false) = true AND "
                    "(CASE coalesce(m.max_risk, 'low') WHEN 'high' THEN 1 ELSE 0 END) >= $risk_rank)")
        params["risk_rank"] = int(risk_rank)
    if exclude:  # what-if: treat these Datums as removed (chokepoint analysis)
        node_ok += " AND NOT m.id IN $exclude"
        params["exclude"] = list(exclude)
    return node_ok, params


def secret_origin(graph: Any, start_ids: Sequence[str], **limits: Any) -> ProvenanceSearch:
    """Is there a Guard-followed path from ``start_ids`` to a Datum with sensitivity 'secret'?"""
    return search(graph, start_ids, SearchSpec(hit=SECRET_HIT, edge_ok=FOLLOW_EDGE), **limits)


def path_to(graph: Any, from_id: str, to_id: str, **limits: Any) -> ProvenanceSearch:
    """Any DERIVED_FROM path from a Datum to ``to_id`` (a Datum, or a Source via FROM)."""
    spec = SearchSpec(
        hit=f"(m.id = $to OR size([(m)-[:{S.FROM}]->(s {{id: $to}}) | s]) > 0)",
        tail="CASE WHEN m.id = $to THEN [] ELSE [$to] END", params={"to": to_id})
    return search(graph, [from_id], spec, **limits)


def ancestors(graph: Any, start_ids: Sequence[str], *, max_depth: Optional[int] = None,
              **limits: Any) -> Tuple[Dict[str, int], ProvenanceSearch]:
    """Every Datum reachable from ``start_ids`` over DERIVED_FROM (all edges, start nodes
    included), with its shortest distance. Replaces ``*0..N`` path enumeration for
    lineage-style questions."""
    depth: Dict[str, int] = {}
    res = search(graph, start_ids, SearchSpec(hit="false"), max_depth=max_depth,
                 collect=depth, **limits)
    return depth, res


class AncestorGraph(BaseModel):
    """The complete recorded ancestor graph of some Datums: every DERIVED_FROM edge,
    including ``attribution: 'context'`` edges, and the Source each Datum came FROM."""

    search: ProvenanceSearch
    depth: Dict[str, int] = Field(default_factory=dict)            # datum id -> min depth
    edges: List[Tuple[str, str, str, str]] = Field(default_factory=list)  # from, to, op, attr
    sources: Dict[str, Dict[str, Any]] = Field(default_factory=dict)  # datum id -> source info
    node_flags: Dict[str, Dict[str, Any]] = Field(default_factory=dict)  # datum id -> flags

    @property
    def complete(self) -> bool:
        return self.search.search_complete and \
            self.search.termination_reason == TerminationReason.EXHAUSTED


def ancestor_graph(graph: Any, start_ids: Sequence[str], **limits: Any) -> AncestorGraph:
    """Walk ALL DERIVED_FROM edges (no pruning, context edges included) from ``start_ids``
    to exhaustion, then read each visited Datum's Source and flags. Incomplete if any limit
    is hit or a query fails (``complete`` is then False)."""
    depth: Dict[str, int] = {}
    edges: List[Tuple[str, str, str, str]] = []
    res = search(graph, start_ids, SearchSpec(hit="false"), collect=depth, edges_out=edges,
                 **limits)
    out = AncestorGraph(search=res, depth=depth, edges=edges)
    if not res.search_complete or not depth:
        return out
    try:
        rows = graph.ro_query(
            f"MATCH (d:{S.DATUM}) WHERE d.id IN $ids "
            f"OPTIONAL MATCH (d)-[:{S.FROM}]->(s:{S.SOURCE}) "
            "RETURN d.id, coalesce(d.endorsed, false), coalesce(d.quarantined, false), "
            "coalesce(d.max_risk, 'low'), s.id, s.kind, s.trust, d.kind, d.coverage",
            {"ids": list(depth)}, timeout=limits.get("timeout_ms") or DEFAULT_TIMEOUT_MS
        ).result_set
    except Exception as exc:  # noqa: BLE001 - reading the roots failed: not complete
        out.search = res.model_copy(update={
            "outcome": SearchOutcome.INDETERMINATE, "search_complete": False,
            "termination_reason": (TerminationReason.TIMEOUT if _is_timeout(exc)
                                   else TerminationReason.QUERY_ERROR),
            "error": f"{type(exc).__name__}: {exc}"})
        return out
    for did, endorsed, quarantined, risk, sid, kind, trust, dkind, coverage in rows:
        out.node_flags[did] = {"endorsed": bool(endorsed), "quarantined": bool(quarantined),
                               "max_risk": risk, "kind": dkind, "coverage": coverage}
        if sid is not None:
            out.sources[did] = {"id": sid, "kind": kind, "trust": trust}
    return out
