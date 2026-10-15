"""Chokepoint analysis: which single provenance node, if removed, breaks every currently
recorded untrusted path into an action's destination?

Demo-scale and explicit about what it computes:

1. Explore the Guard-followed ancestor graph of the destination argument(s) completely
   (same edge/node rules as the integrity check: no ``context`` edges, endorsed and
   covering typed Datums stop a path).
2. Keep the *dangerous subgraph*: nodes that lie on some path to a Datum that came FROM an
   untrusted Source.
3. Count paths through each node (DAG dynamic programming): its share of all known
   untrusted paths.
4. For every candidate, re-run the real integrity search with that node excluded. A node
   is a chokepoint only if that search returns a complete NO_PATH.

This is a per-node what-if over the graph as recorded now. It is not a dominator-tree or
minimum-cut computation and makes no claim about data recorded later. Quarantining a
memory stops future recalls of it; it does not rewrite the provenance of actions already
recorded (their verdicts do not change).
"""
from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from custody.graph import traversal as T
from custody.graph.repository import NotFound

_RISK_RANK = {"low": 0, "high": 1}
MAX_CANDIDATES = 200


class Chokepoint(BaseModel):
    id: str
    labels: List[str] = Field(default_factory=list)
    kind: Optional[str] = None
    agent: Optional[str] = None
    session_id: Optional[str] = None
    preview: Optional[str] = None        # may contain attacker text: data, not instructions
    paths_through: Optional[int] = None  # None if the subgraph has a cycle
    path_share: Optional[float] = None   # paths_through / total untrusted paths
    verified: bool                       # complete NO_PATH with this node excluded
    trivial: bool = False                # the action's own argument Datum
    quarantinable: bool = False          # a shared Memory (Warden can quarantine it)
    explanation: str = ""


class ChokepointResult(BaseModel):
    action_id: str
    destination_args: List[str]
    dangerous: bool                      # any untrusted path at all (complete search)
    search: T.ProvenanceSearch           # the complete exploration of followed ancestry
    untrusted_sources: List[str] = Field(default_factory=list)
    total_paths: Optional[int] = None
    candidates_checked: int = 0
    chokepoints: List[Chokepoint] = Field(default_factory=list)  # verified only
    recommended: Optional[str] = None
    summary: str = ""
    method: str = ("per-node exclusion over the currently recorded Guard-followed ancestor "
                   "graph; not a dominator or minimum-cut computation")


def _count_paths(starts: List[str], adj: Dict[str, List[str]], ends: Set[str]
                 ) -> Optional[Tuple[Dict[str, int], Dict[str, int], int]]:
    """(to_end, from_start, total) path counts in a DAG; None if there is a cycle."""
    order: List[str] = []
    state: Dict[str, int] = {}

    def visit(v: str) -> bool:  # iterative DFS topological sort, cycle → False
        stack = [(v, iter(adj.get(v, [])))]
        state[v] = 1
        while stack:
            node, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                stack.pop()
                state[node] = 2
                order.append(node)
            elif state.get(nxt) == 1:
                return False
            elif nxt not in state:
                state[nxt] = 1
                stack.append((nxt, iter(adj.get(nxt, []))))
        return True

    for s in starts:
        if s not in state and not visit(s):
            return None
    to_end: Dict[str, int] = {}
    for v in order:  # children before parents
        to_end[v] = (1 if v in ends else 0) + sum(to_end[c] for c in adj.get(v, []))
    from_start: Dict[str, int] = {v: 0 for v in order}
    for s in starts:
        from_start[s] = from_start.get(s, 0) + 1
    for v in reversed(order):  # parents before children
        for c in adj.get(v, []):
            from_start[c] += from_start[v]
    total = sum(to_end.get(s, 0) for s in set(starts))
    return to_end, from_start, total


def find_chokepoints(analysis, action_id: str) -> ChokepointResult:
    repo, graph, policy = analysis.repo, analysis.graph, analysis.policy
    action = repo.get_action(action_id)
    roles = sorted(policy.destination_roles)
    dest = [a.datum_id for a in action.args if a.role in roles]
    if not dest:
        raise NotFound(f"action {action_id!r} has no destination argument")
    risk = _RISK_RANK.get(policy.action(action.action_type).risk.value, 1)
    limits = {"max_depth": policy.search_max_depth, "max_nodes": policy.search_max_nodes,
              "timeout_ms": policy.search_timeout_ms}

    # 1. complete exploration of the followed ancestor graph
    seen: Dict[str, int] = {}
    edges: List[Tuple[str, str, str, str]] = []
    res = T.untrusted_origin(graph, dest, risk_rank=risk, hit="false", collect=seen,
                             edges_out=edges, **limits)
    if not res.search_complete:
        return ChokepointResult(action_id=action_id, destination_args=dest, dangerous=True,
                                search=res, summary="exploration incomplete "
                                f"({res.summary()}): no chokepoint can be claimed")
    rows = graph.ro_query(
        "MATCH (d:Datum)-[:FROM]->(s:Source {trust: 'untrusted'}) WHERE d.id IN $ids "
        "RETURN d.id, s.id", {"ids": list(seen)}).result_set
    ends = {d for d, _ in rows}
    sources = sorted({s for _, s in rows})
    adj: Dict[str, List[str]] = {}
    for a, b, _op, _attr in edges:
        if b in seen:
            adj.setdefault(a, [])
            if b not in adj[a]:
                adj[a].append(b)
    # 2. dangerous subgraph: nodes that can reach an untrusted-origin Datum
    radj: Dict[str, List[str]] = {}
    for a, bs in adj.items():
        for b in bs:
            radj.setdefault(b, []).append(a)
    danger, stack = set(ends), list(ends)
    while stack:
        for p in radj.get(stack.pop(), []):
            if p not in danger:
                danger.add(p)
                stack.append(p)
    if not ends:
        return ChokepointResult(action_id=action_id, destination_args=dest, dangerous=False,
                                search=res, summary="no untrusted path into this action's "
                                "destination: nothing to break")
    dadj = {a: [b for b in bs if b in danger] for a, bs in adj.items() if a in danger}
    counts = _count_paths([d for d in dest if d in danger], dadj, ends)

    # 3./4. candidates, verified by re-running the real search with each excluded
    info = {r[0]: r for r in graph.ro_query(
        "MATCH (d:Datum) WHERE d.id IN $ids RETURN d.id, labels(d), d.kind, d.agent, "
        "d.session_id, d.preview", {"ids": list(danger)}).result_set}
    ranked = sorted(danger, key=lambda v: (
        -(counts[0][v] * counts[1][v]) if counts else 0, seen.get(v, 0), v))
    total = counts[2] if counts else None
    found: List[Chokepoint] = []
    for v in ranked[:MAX_CANDIDATES]:
        check = T.untrusted_origin(graph, dest, risk_rank=risk, exclude=[v], **limits)
        if not (check.search_complete and not check.path_found):
            continue
        _, labels, kind, agent, sess, preview = info[v]
        through = counts[0][v] * counts[1][v] if counts else None
        share = round(through / total, 4) if counts and total else None
        trivial = v in dest
        cp = Chokepoint(id=v, labels=list(labels), kind=kind, agent=agent, session_id=sess,
                        preview=preview, paths_through=through, path_share=share, verified=True,
                        trivial=trivial, quarantinable="Memory" in labels and not trivial)
        what = "Memory" if "Memory" in labels else (kind or "Datum")
        pct = f"{share * 100:.0f}%" if share is not None else "all"
        cp.explanation = (
            f"{what} {v} lies on {pct} of the {total if total is not None else '?'} known "
            f"untrusted path(s) to Action {action_id}. Re-running the complete integrity "
            f"search with {v} excluded returns NO_PATH: removing it disconnects the action "
            "from all currently recorded untrusted ancestry."
            + (" It is the action's own argument (trivial)." if trivial else "")
            + (" Quarantining it stops it being recalled into new sessions; actions already "
               "recorded keep their provenance (and verdicts)." if cp.quarantinable else ""))
        found.append(cp)
    found.sort(key=lambda c: (c.trivial, not c.quarantinable, -(c.path_share or 0),
                              seen.get(c.id, 0)))
    rec = next((c.id for c in found if not c.trivial), None)
    summary = (f"{len(found)} single-node chokepoint(s) among {min(len(ranked), MAX_CANDIDATES)} "
               f"candidate(s) on {total if total is not None else 'cyclic'} untrusted path(s) "
               f"from {', '.join(sources)}" + (f"; recommended: {rec}" if rec else
                                                "; no single non-trivial node breaks every path"))
    return ChokepointResult(action_id=action_id, destination_args=dest, dangerous=True,
                            search=res, untrusted_sources=sources, total_paths=total,
                            candidates_checked=min(len(ranked), MAX_CANDIDATES),
                            chokepoints=found, recommended=rec, summary=summary)
