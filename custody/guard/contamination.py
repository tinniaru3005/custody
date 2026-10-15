"""Which untrusted roots reach an action's destination, and are the routes independent?

Explanation only: the verdict never depends on anything here. The Guard decides from the
complete integrity search (does ANY uncleared route exist); this module describes a
violation that was already found:

1. **All distinct untrusted roots.** One BFS over the destination's Guard-followed
   ancestry (same edge and node filters as the verdict: context-only edges are not
   followed, endorsed Datums and covering typed values clear a route), collecting every
   visited Datum, then one query for the untrusted Sources they come FROM. Linear in the
   ancestry; no path enumeration.
2. **One representative route per root**: the shortest one, rebuilt from the BFS tree.
3. **Independence**, with node-disjointness after the action's own argument as the
   definition (two routes are independent if they share no Datum other than the argument):

   - remove every Datum of route 1 and search again for any untrusted root; a hit is a
     second route sharing nothing with the first (repeated greedily): *independent,
     verified by construction*;
   - otherwise, remove each Datum of route 1 alone; if a complete search then finds no
     untrusted root, every route passes through that Datum: *converging, verified*;
   - if no single Datum of route 1 does that and every search completed, no single Datum
     lies on all routes, so (Menger's theorem) at least two independent routes exist:
     *independent, verified by exhaustion*;
   - anything else (a search hit a limit, or the check budget ran out): *unverified*.

   Every claim is backed by complete searches; "multiple roots" and "independent routes"
   are reported separately (two roots can share one route segment, one root can be reached
   independently twice).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from custody.graph import schema as S
from custody.graph import traversal as T


@dataclass
class RawRoute:
    source_id: str
    entry_id: str
    ids: List[str]                    # arg datum ... entry datum, Source
    ops: List[str]


@dataclass
class RawReport:
    roots: List[RawRoute] = field(default_factory=list)   # closest first
    root_count: int = 0
    roots_complete: bool = False
    roots_search: Optional[T.ProvenanceSearch] = None
    independence: str = "unverified"  # independent | converging | direct | unverified
    independent_routes: int = 1       # node-disjoint routes in hand (lower bound)
    method: Optional[str] = None      # disjoint_routes | no_single_shared_datum | shared_datum
    shared_datum_id: Optional[str] = None
    extra_routes: List[RawRoute] = field(default_factory=list)  # routes 2.. (disjoint)
    checks_run: int = 0
    latency_ms: float = 0.0


def _route(parents: Dict[str, Tuple[Optional[str], Optional[str]]], entry: str,
           source: str) -> RawRoute:
    ids: List[str] = []
    ops: List[str] = []
    cur: Optional[str] = entry
    while cur is not None:
        ids.append(cur)
        p, op = parents[cur]
        if op is not None:
            ops.append(op)
        cur = p
    ids.reverse()
    ops.reverse()
    return RawRoute(source_id=source, entry_id=entry, ids=ids + [source], ops=ops + [S.FROM])


def _from_search(s: T.ProvenanceSearch) -> RawRoute:
    return RawRoute(source_id=s.witness_node_ids[-1], entry_id=s.witness_node_ids[-2],
                    ids=list(s.witness_node_ids), ops=list(s.witness_ops))


def analyse(graph, start_ids: Sequence[str], *, risk_rank: Optional[int] = None,
            max_nodes: int = T.DEFAULT_MAX_NODES, timeout_ms: int = 1_000,
            max_checks: int = 25, max_roots: int = 10, max_routes: int = 3) -> RawReport:
    """Roots, representative routes and independence for the destination ``start_ids``.
    ``timeout_ms`` is the budget for the whole analysis; ``max_checks`` bounds the number
    of extra complete searches for the independence test."""
    t0 = time.perf_counter()
    deadline = t0 + timeout_ms / 1000.0
    starts = list(dict.fromkeys(start_ids))
    out = RawReport()

    def left() -> int:
        return max(1, int((deadline - time.perf_counter()) * 1000))

    # 1. every Datum on an uncleared Guard-followed route, with its BFS tree
    node_ok, params = T.untrusted_node_filter(risk_rank)
    depth: Dict[str, int] = {}
    parents: Dict[str, Tuple[Optional[str], Optional[str]]] = {}
    out.roots_search = T.search(graph, starts, T.SearchSpec(
        hit="false", node_ok=node_ok, edge_ok=T.FOLLOW_EDGE, params=params),
        max_nodes=max_nodes, timeout_ms=left(), collect=depth, parents_out=parents)
    out.roots_complete = out.roots_search.search_complete
    entries: Dict[str, Tuple[int, str]] = {}  # source id -> (depth, entry datum)
    ids = sorted(depth)
    for i in range(0, len(ids), 5_000):
        for did, sid in graph.ro_query(
                f"UNWIND $ids AS i MATCH (m:{S.DATUM} {{id: i}})-[:{S.FROM}]->"
                f"(s:{S.SOURCE} {{trust: 'untrusted'}}) RETURN m.id, s.id",
                {"ids": ids[i:i + 5_000]}).result_set:
            best = entries.get(sid)
            if best is None or (depth[did], did) < best:
                entries[sid] = (depth[did], did)
    out.root_count = len(entries)
    ordered = sorted(entries.items(), key=lambda kv: (kv[1][0], kv[0]))
    out.roots = [_route(parents, entry, sid) for sid, (_, entry) in ordered[:max_roots]]
    if not out.roots:
        out.latency_ms = round((time.perf_counter() - t0) * 1000, 3)
        return out

    # 2. independence
    first = out.roots[0]
    interior = [i for i in first.ids[:-1] if i not in starts]
    if not interior:  # the argument itself is untrusted content
        out.independence, out.method = "direct", None
        out.latency_ms = round((time.perf_counter() - t0) * 1000, 3)
        return out

    complete = True
    excluded = list(interior)
    while out.independent_routes < max_routes and out.checks_run < max_checks:
        out.checks_run += 1
        s = T.untrusted_origin(graph, starts, risk_rank=risk_rank, exclude=excluded,
                               max_nodes=max_nodes, timeout_ms=left())
        if not s.search_complete:
            complete = False
            break
        if not s.path_found:
            break
        r = _from_search(s)
        out.extra_routes.append(r)
        out.independent_routes += 1
        excluded += [i for i in r.ids[:-1] if i not in starts]
    if out.independent_routes >= 2:
        out.independence, out.method = "independent", "disjoint_routes"
    elif complete:
        cut, all_checked = None, True
        for x in interior:
            if out.checks_run >= max_checks or time.perf_counter() >= deadline:
                all_checked = False
                break
            out.checks_run += 1
            s = T.untrusted_origin(graph, starts, risk_rank=risk_rank, exclude=[x],
                                   max_nodes=max_nodes, timeout_ms=left())
            if not s.search_complete:
                all_checked = False
                continue
            if not s.path_found:
                cut = x
                break
        if cut is not None:
            out.independence, out.method, out.shared_datum_id = \
                "converging", "shared_datum", cut
        elif all_checked:
            out.independence, out.method = "independent", "no_single_shared_datum"
            out.independent_routes = 2
    out.latency_ms = round((time.perf_counter() - t0) * 1000, 3)
    return out
