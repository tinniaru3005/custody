"""Agent-level influence projection: the provenance graph collapsed to who influenced whom.

Derived from the recorded graph on every call (nothing is hand-built):

- ``Source → agent``: an agent read a Datum that came FROM an untrusted Source.
- ``agent → Memory m → agent`` / ``agent → Message m → agent``: a Datum recorded by one
  agent derives from a Memory or Message recorded by another (the carrier).
- ``agent → agent``: any other cross-agent DERIVED_FROM edge.

Each influence aggregates the underlying edges and is marked ``tainted`` when its carrier is
downstream of an untrusted Source along Guard-followed edges (complete forward traversal).
``path`` is one underlying provenance path, child → carrier → … → untrusted Source when
tainted, for the UI to reveal on click.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from custody.graph import schema as S
from custody.graph import traversal as T


class PathStep(BaseModel):
    id: str
    label: str                       # Source, Memory, Recall, Message, Datum
    kind: Optional[str] = None
    agent: Optional[str] = None
    session_id: Optional[str] = None
    trust: Optional[str] = None      # Source only
    op: Optional[str] = None         # hop into this step


class Influence(BaseModel):
    id: str
    source: str                      # "agent:scout" | "source:web:…"
    target: str                      # "agent:ops"
    via: Optional[str] = None        # carrier Datum id (Memory / Message), if any
    via_label: Optional[str] = None
    via_preview: Optional[str] = None
    kind: str                        # entry | memory | message | direct
    edges: int                       # underlying DERIVED_FROM / FROM edges
    followed: bool                   # at least one edge the Guard follows (not context-only)
    tainted: bool
    sessions: List[str] = Field(default_factory=list)
    path: List[PathStep] = Field(default_factory=list)


class Participant(BaseModel):
    id: str                          # agent:<name> | source:<source id>
    label: str
    type: str                        # agent | source
    tainted: bool = False            # agent produced tainted data / untrusted source


class InfluenceView(BaseModel):
    participants: List[Participant]
    influences: List[Influence]
    summary: str
    search: T.ProvenanceSearch       # the taint traversal (complete or not)


def _primary(labels: List[str]) -> str:
    for lab in (S.MEMORY, S.MESSAGE, S.RECALL, S.TYPED):
        if lab in labels:
            return lab
    return S.DATUM


def build(repo) -> InfluenceView:
    g = repo.graph
    ro = lambda q, p=None: g.ro_query(q, p or {}).result_set  # noqa: E731

    # taint: everything downstream of an untrusted Source over Guard-followed edges
    entries = ro(f"MATCH (d:{S.DATUM})-[:{S.FROM}]->(s:{S.SOURCE} {{trust: 'untrusted'}}) "
                 "RETURN s.id, d.id, d.agent, d.session_id, d.kind, labels(d)")
    tainted: Dict[str, int] = {}
    search = T.search(g, [r[1] for r in entries],
                      T.SearchSpec(hit="false", edge_ok=T.FOLLOW_EDGE),
                      collect=tainted, reverse=True)
    taint: Set[str] = set(tainted)

    agg: Dict[Tuple[str, str, Optional[str]], Dict[str, Any]] = {}

    def add(src: str, dst: str, via: Optional[str], kind: str, followed: bool,
            sessions: Tuple[Optional[str], Optional[str]], example: Tuple[Any, ...]) -> None:
        key = (src, dst, via)
        a = agg.setdefault(key, {"kind": kind, "edges": 0, "followed": False, "sessions": set(),
                                 "example": example})
        a["edges"] += 1
        a["followed"] |= followed
        a["sessions"] |= {s for s in sessions if s}

    for sid, did, agent, sess, _kind, _labels in entries:
        if agent:
            add(f"source:{sid}", f"agent:{agent}", None, "entry", True, (None, sess),
                ("entry", did, sid))

    for (cid, cagent, csess, pid, pagent, psess, plabels, attr, op) in ro(
            f"MATCH (c:{S.DATUM})-[r:{S.DERIVED_FROM}]->(p:{S.DATUM}) "
            "WHERE c.agent IS NOT NULL AND p.agent IS NOT NULL AND c.agent <> p.agent "
            "RETURN c.id, c.agent, c.session_id, p.id, p.agent, p.session_id, labels(p), "
            "coalesce(r.attribution, 'inherit'), r.op"):
        label = _primary(plabels)
        kind = {S.MEMORY: "memory", S.MESSAGE: "message"}.get(label, "direct")
        add(f"agent:{pagent}", f"agent:{cagent}", pid if kind != "direct" else None, kind,
            attr != "context", (psess, csess), ("edge", cid, pid, op))

    # details for carriers and example nodes
    ids = {k[2] for k in agg if k[2]} | {a["example"][1] for a in agg.values()}
    info = {r[0]: r for r in ro(
        "MATCH (n:Datum) WHERE n.id IN $ids RETURN n.id, labels(n), n.kind, n.agent, "
        "n.session_id, n.preview", {"ids": list(ids)})}
    src_info = {r[0]: r for r in ro(f"MATCH (s:{S.SOURCE}) RETURN s.id, s.kind, s.trust")}

    def step(i: str, op: Optional[str] = None) -> PathStep:
        if i in info:
            _, labels, kind, agent, sess, _p = info[i]
            return PathStep(id=i, label=_primary(labels), kind=kind, agent=agent,
                            session_id=sess, op=op)
        s = src_info.get(i)
        return PathStep(id=i, label="Source", kind=s[1] if s else None,
                        trust=s[2] if s else None, op=op)

    influences: List[Influence] = []
    for n, ((src, dst, via), a) in enumerate(sorted(
            agg.items(), key=lambda kv: (kv[1]["kind"] != "entry", kv[0]))):
        ex = a["example"]
        if ex[0] == "entry":
            is_tainted = True
            path = [step(ex[1]), step(ex[2], "FROM")]
        else:
            _, cid, pid, op = ex
            is_tainted = pid in taint and a["followed"]
            path = [step(cid), step(pid, op)]
            if is_tainted:
                w = T.untrusted_origin(g, [pid])
                if w.path_found:
                    for i, o in zip(w.witness_node_ids[1:], w.witness_ops):
                        if i not in info:
                            row = ro("MATCH (n:Datum {id: $id}) RETURN n.id, labels(n), n.kind, "
                                     "n.agent, n.session_id, n.preview", {"id": i})
                            if row:
                                info[i] = row[0]
                        path.append(step(i, o))
        carrier = info.get(via) if via else None
        influences.append(Influence(
            id=f"inf{n}", source=src, target=dst, via=via,
            via_label=_primary(carrier[1]) if carrier else None,
            via_preview=carrier[5] if carrier else None, kind=a["kind"], edges=a["edges"],
            followed=a["followed"], tainted=is_tainted, sessions=sorted(a["sessions"]),
            path=path))

    tainted_agents = {i.target for i in influences if i.tainted}
    parts: Dict[str, Participant] = {}
    for i in influences:
        for end in (i.source, i.target):
            if end in parts:
                continue
            typ, _, name = end.partition(":")
            parts[end] = Participant(id=end, label=name, type=typ,
                                     tainted=(typ == "source") or end in tainted_agents)
    n_cross = sum(1 for i in influences if i.kind != "entry")
    n_bad = sum(1 for i in influences if i.kind != "entry" and i.tainted)
    summary = (f"{sum(p.type == 'agent' for p in parts.values())} agent(s), "
               f"{n_cross} cross-agent channel(s), {n_bad} carrying untrusted influence"
               + ("" if search.search_complete else
                  f" (taint traversal incomplete: {search.summary()})"))
    return InfluenceView(participants=list(parts.values()), influences=influences,
                         summary=summary, search=search)
