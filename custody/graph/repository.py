"""Low-level graph persistence for one tenant graph.

The repository knows Cypher; it does not know *why* something is being recorded.
Higher-level semantics (what a "recall" or "message" means) live in the Recorder.
The graph is append-only: nodes are created, never mutated, except for
``Datum.endorsed`` (set by approvals) and ``Action.status``.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel
from collections.abc import Iterable, Sequence

from falkordb import Graph

from custody.graph import schema as S
from custody.graph import traversal as T
from custody.graph.model import (
    ActionArg,
    ActionRecord,
    ActionStatus,
    ActionTrace,
    ApprovalRecord,
    ArgTrace,
    DatumKind,
    DatumRecord,
    Lineage,
    LineageEntry,
    ProvenancePath,
    QuarantineRecord,
    Sensitivity,
    SinkRecord,
    SourceKind,
    SourceRecord,
    Trust,
    dump_metadata,
    load_metadata,
    utcnow_iso,
)


class NotFound(LookupError):
    pass


def _props_clause(var: str, props: Dict[str, Any], param_prefix: str) -> Tuple[str, Dict[str, Any]]:
    """Build ``{k: $prefix_k, ...}`` for non-null props (FalkorDB rejects null props)."""
    parts, params = [], {}
    for k, v in props.items():
        if v is None:
            continue
        pname = f"{param_prefix}_{k}"
        parts.append(f"{k}: ${pname}")
        params[pname] = v
    return "{" + ", ".join(parts) + "}", params


# Every read query gets a server-side timeout so no single query can hang a request.
READ_TIMEOUT_MS = 10_000

_BUMP = (f"MERGE (m:{S.GRAPH_META} {{id: 'graph'}}) "
         "SET m.FIELD = coalesce(m.FIELD, 0) + 1")


class GraphVersion(BaseModel):
    """``finished`` counts completed provenance writes to the tenant graph. ``started`` ==
    ``finished`` means no write was in flight when it was read."""

    graph: str
    started: int
    finished: int

    @property
    def quiescent(self) -> bool:
        return self.started == self.finished

    @property
    def label(self) -> str:
        return f"{self.graph}@v{self.finished}"


def _clamp_depth(depth: int) -> int:
    # Variable-length bounds cannot be parameterised; clamp to a safe int.
    return max(1, min(int(depth), 100))


# ---------------------------------------------------------------- node converters
def _source_from_node(node: Any) -> SourceRecord:
    p = node.properties
    return SourceRecord(
        id=p["id"],
        kind=SourceKind(p["kind"]),
        trust=Trust(p["trust"]),
        metadata=load_metadata(p.get("metadata")),
        created_at=p.get("created_at", ""),
    )


def _datum_from_node(node: Any, source_id: Optional[str] = None,
                     parent_ids: Optional[List[str]] = None) -> DatumRecord:
    p = node.properties
    return DatumRecord(
        id=p["id"],
        kind=DatumKind(p["kind"]),
        labels=sorted(node.labels, key=lambda l: (l != S.DATUM, l)),
        value=p.get("value"),
        preview=p.get("preview", ""),
        fingerprint=p.get("fingerprint", ""),
        sensitivity=Sensitivity(p.get("sensitivity", "normal")),
        endorsed=bool(p.get("endorsed", False)),
        created_at=p.get("created_at", ""),
        agent=p.get("agent"),
        session_id=p.get("session_id"),
        source_id=source_id,
        parent_ids=parent_ids or [],
        metadata=load_metadata(p.get("metadata")),
        attribution=p.get("attribution", "inherit"),
        quarantined=bool(p.get("quarantined", False)),
        value_type=p.get("value_type"),
        max_risk=p.get("max_risk"),
        in_quarantine=bool(p.get("in_quarantine", False)),
        quarantine_id=p.get("quarantine_id"),
        coverage=p.get("coverage"),
    )


def _sink_from_node(node: Any) -> SinkRecord:
    p = node.properties
    return SinkRecord(id=p["id"], destination=p["destination"], kind=p["kind"],
                      external=bool(p["external"]), workspace=p.get("workspace"))


class GraphRepository:
    def __init__(self, graph: Graph) -> None:
        self.graph = graph

    # ------------------------------------------------------------------ util
    def _q(self, query: str, params: Optional[Dict[str, Any]] = None, *, bump: bool = True):
        """Every graph write goes through here. ``bump`` brackets it with the graph-version
        counters (``started`` before, ``finished`` after), so a reader can tell whether the
        graph changed, or was mid-write, while it was reading. Audit records (Decision,
        Run) don't bump: they are not provenance."""
        if not bump:
            return self.graph.query(query, params or {})
        self.graph.query(_BUMP.replace("FIELD", "started"))
        try:
            return self.graph.query(query, params or {})
        finally:
            self.graph.query(_BUMP.replace("FIELD", "finished"))

    def graph_version(self) -> GraphVersion:
        """The tenant graph's version: number of completed provenance writes."""
        rows = self.graph.ro_query(
            f"MATCH (m:{S.GRAPH_META} {{id: 'graph'}}) RETURN m.started, m.finished",
            timeout=READ_TIMEOUT_MS).result_set
        started, finished = (rows[0] if rows else (0, 0))
        return GraphVersion(graph=getattr(self.graph, "name", None) or "?",
                            started=int(started or 0), finished=int(finished or 0))

    def _ro(self, query: str, params: Optional[Dict[str, Any]] = None,
            timeout: Optional[int] = READ_TIMEOUT_MS):
        return self.graph.ro_query(query, params or {}, timeout=timeout)

    # --------------------------------------------------------------- sources
    def upsert_source(self, source_id: str, kind: SourceKind, trust: Trust,
                      metadata: Optional[Dict[str, Any]] = None) -> SourceRecord:
        """Create the Source if absent. Existing sources are immutable (first write wins)."""
        res = self._q(
            f"MERGE (s:{S.SOURCE} {{id: $id}}) "
            "ON CREATE SET s.kind = $kind, s.trust = $trust, s.metadata = $metadata, "
            "s.created_at = $now "
            "RETURN s",
            {"id": source_id, "kind": SourceKind(kind).value, "trust": Trust(trust).value,
             "metadata": dump_metadata(metadata), "now": utcnow_iso()},
        )
        return _source_from_node(res.result_set[0][0])

    def revoke_source_trust(self, source_id: str, *, revocation_id: str, revoked_by: str,
                            reason: Optional[str], at: str) -> str:
        """Mark a Source untrusted from now on. The one explicit mutation of a Source: the
        previous label is kept (``trust_original``) and a (:TrustRevocation) records who,
        when and why. Data, edges and recorded Decisions are untouched. Returns the trust
        label before the revocation."""
        res = self._q(
            f"MATCH (s:{S.SOURCE} {{id: $id}}) "
            "WITH s, s.trust AS before "
            "SET s.trust_original = coalesce(s.trust_original, s.trust), s.trust = 'untrusted', "
            "s.revoked_at = $at, s.revoked_by = $by "
            f"CREATE (r:{S.REVOCATION} {{id: $rid, source_id: $id, revoked_by: $by, "
            "reason: $reason, created_at: $at, trust_before: before})-[:REVOKES]->(s) "
            "RETURN before",
            {"id": source_id, "rid": revocation_id, "by": revoked_by, "reason": reason or "",
             "at": at})
        if not res.result_set:
            raise NotFound(f"source {source_id!r} not found")
        return res.result_set[0][0]

    def record_readjudication(self, revocation_id: str, action_id: str,
                              props: Dict[str, Any]) -> None:
        clause, params = _props_clause("rj", props, "rj")
        params.update({"aid": action_id, "rid": revocation_id})
        self._q(f"MATCH (a:{S.ACTION} {{id: $aid}}), (r:{S.REVOCATION} {{id: $rid}}) "
                f"CREATE (rj:{S.READJUDICATION} {clause})-[:{S.READJUDICATES}]->(a) "
                f"CREATE (r)-[:{S.PRODUCED}]->(rj)", params)

    def get_source(self, source_id: str) -> SourceRecord:
        res = self._ro(f"MATCH (s:{S.SOURCE} {{id: $id}}) RETURN s", {"id": source_id})
        if not res.result_set:
            raise NotFound(f"source {source_id!r} not found")
        return _source_from_node(res.result_set[0][0])

    # ----------------------------------------------------------------- data
    def get_data(self, ids: Iterable[str]) -> Dict[str, DatumRecord]:
        ids = list(dict.fromkeys(ids))
        if not ids:
            return {}
        res = self._ro(f"MATCH (d:{S.DATUM}) WHERE d.id IN $ids RETURN d", {"ids": ids})
        return {row[0].properties["id"]: _datum_from_node(row[0]) for row in res.result_set}

    def require_data(self, ids: Iterable[str]) -> Dict[str, DatumRecord]:
        ids = list(dict.fromkeys(ids))
        found = self.get_data(ids)
        missing = [i for i in ids if i not in found]
        if missing:
            raise NotFound(f"datum not found: {', '.join(missing)}")
        return found

    def get_datum(self, datum_id: str) -> DatumRecord:
        res = self._ro(
            f"MATCH (d:{S.DATUM} {{id: $id}}) "
            f"OPTIONAL MATCH (d)-[:{S.FROM}]->(s:{S.SOURCE}) "
            f"OPTIONAL MATCH (d)-[:{S.DERIVED_FROM}]->(p:{S.DATUM}) "
            "RETURN d, s.id, collect(p.id)",
            {"id": datum_id},
        )
        if not res.result_set:
            raise NotFound(f"datum {datum_id!r} not found")
        node, source_id, parents = res.result_set[0]
        return _datum_from_node(node, source_id=source_id, parent_ids=sorted(parents))

    def create_datum(self, datum: DatumRecord, source_id: str,
                     parents: Sequence[Tuple[str, ...]] = ()) -> DatumRecord:
        """Create a Datum, its FROM edge and DERIVED_FROM edges in one query.

        ``parents`` is a sequence of ``(parent_datum_id, op)`` or
        ``(parent_datum_id, op, attribution)``; attribution defaults to ``inherit``.
        Caller must have verified the source and parents exist (see ``require_data``).
        """
        extra = [l for l in datum.labels if l != S.DATUM]
        for l in extra:
            if l not in S.DATUM_LABELS:
                raise ValueError(f"illegal datum label {l!r}")
        labels = ":".join([S.DATUM, *extra])
        props = {
            "id": datum.id,
            "kind": datum.kind.value,
            "value": datum.value,
            "preview": datum.preview,
            "fingerprint": datum.fingerprint,
            "sensitivity": datum.sensitivity.value,
            "endorsed": datum.endorsed,
            "created_at": datum.created_at,
            "agent": datum.agent,
            "session_id": datum.session_id,
            "metadata": dump_metadata(datum.metadata),
            "attribution": datum.attribution,
            "quarantined": True if datum.quarantined else None,
            "value_type": datum.value_type,
            "max_risk": datum.max_risk.value if datum.max_risk else None,
            "coverage": datum.coverage,
        }
        clause, params = _props_clause("d", props, "d")
        norm = [(p[0], p[1], p[2] if len(p) > 2 else "inherit") for p in parents]
        params.update({
            "source_id": source_id,
            "now": datum.created_at,
            "parents": [{"id": pid, "op": op, "attr": attr} for pid, op, attr in norm],
        })
        res = self._q(
            f"MATCH (s:{S.SOURCE} {{id: $source_id}}) "
            f"CREATE (d:{labels} {clause}) "
            f"CREATE (d)-[:{S.FROM} {{created_at: $now}}]->(s) "
            "WITH d "
            "UNWIND $parents AS par "
            f"MATCH (p:{S.DATUM} {{id: par.id}}) "
            f"CREATE (d)-[:{S.DERIVED_FROM} {{op: par.op, attribution: par.attr, "
            "created_at: $now}]->(p) "
            "RETURN count(p)",
            params,
        )
        if res.nodes_created != 1:
            raise NotFound(f"source {source_id!r} not found; datum not created")
        return datum.model_copy(update={"source_id": source_id,
                                        "parent_ids": sorted({p[0] for p in norm})})

    def mark_endorsed(self, datum_ids: Sequence[str]) -> None:
        self._q(f"MATCH (d:{S.DATUM}) WHERE d.id IN $ids SET d.endorsed = true",
                {"ids": list(datum_ids)})

    # --------------------------------------------------------------- sinks
    def upsert_sink(self, sink: SinkRecord) -> SinkRecord:
        res = self._q(
            f"MERGE (k:{S.SINK} {{id: $id}}) "
            "ON CREATE SET k.destination = $destination, k.kind = $kind, k.external = $external, "
            "k.workspace = $workspace "
            "RETURN k",
            sink.model_dump(),
        )
        return _sink_from_node(res.result_set[0][0])

    # -------------------------------------------------------------- actions
    def create_action(self, action: ActionRecord) -> ActionRecord:
        props = {
            "id": action.id,
            "action_type": action.action_type,
            "agent": action.agent,
            "status": action.status.value,
            "created_at": action.created_at,
            "session_id": action.session_id,
            "metadata": dump_metadata(action.metadata),
        }
        clause, params = _props_clause("a", props, "a")
        params["args"] = [a.model_dump() for a in action.args]
        params["now"] = action.created_at
        self._q(
            f"CREATE (a:{S.ACTION} {clause}) "
            "WITH a "
            "UNWIND $args AS arg "
            f"MATCH (d:{S.DATUM} {{id: arg.datum_id}}) "
            f"CREATE (a)-[:{S.ARG} {{role: arg.role, created_at: $now}}]->(d)",
            params,
        )
        if action.sink is not None:
            self.upsert_sink(action.sink)
            self._q(
                f"MATCH (a:{S.ACTION} {{id: $aid}}), (k:{S.SINK} {{id: $kid}}) "
                f"CREATE (a)-[:{S.TO}]->(k)",
                {"aid": action.id, "kid": action.sink.id},
            )
        return action

    def get_action(self, action_id: str) -> ActionRecord:
        res = self._ro(
            f"MATCH (a:{S.ACTION} {{id: $id}}) "
            f"OPTIONAL MATCH (a)-[:{S.TO}]->(k:{S.SINK}) "
            f"OPTIONAL MATCH (a)-[r:{S.ARG}]->(d:{S.DATUM}) "
            "RETURN a, k, collect([r.role, d.id])",
            {"id": action_id},
        )
        if not res.result_set:
            raise NotFound(f"action {action_id!r} not found")
        node, sink, args = res.result_set[0]
        p = node.properties
        return ActionRecord(
            id=p["id"],
            action_type=p["action_type"],
            agent=p["agent"],
            status=ActionStatus(p["status"]),
            created_at=p["created_at"],
            session_id=p.get("session_id"),
            args=sorted((ActionArg(role=r, datum_id=d) for r, d in args if d is not None),
                        key=lambda a: (a.role, a.datum_id)),
            sink=_sink_from_node(sink) if sink is not None else None,
            metadata=load_metadata(p.get("metadata")),
        )

    def set_action_status(self, action_id: str, status: ActionStatus) -> None:
        res = self._q(f"MATCH (a:{S.ACTION} {{id: $id}}) SET a.status = $status RETURN a.id",
                      {"id": action_id, "status": ActionStatus(status).value})
        if not res.result_set:
            raise NotFound(f"action {action_id!r} not found")

    # ------------------------------------------------------------ approvals
    def create_approval(self, approval: ApprovalRecord) -> ApprovalRecord:
        props = {"id": approval.id, "approver": approval.approver,
                 "approver_kind": approval.approver_kind, "reason": approval.reason,
                 "created_at": approval.created_at, "verdict": approval.verdict,
                 "egress": True if approval.egress else None}
        clause, params = _props_clause("ap", props, "ap")
        params.update({"ids": approval.endorsed_ids, "now": approval.created_at})
        self._q(f"CREATE (ap:{S.APPROVAL} {clause})", params)
        if approval.endorsed_ids:
            self._q(
                f"MATCH (ap:{S.APPROVAL} {{id: $apid}}) "
                f"UNWIND $ids AS did MATCH (d:{S.DATUM} {{id: did}}) "
                f"CREATE (ap)-[:{S.ENDORSES} {{created_at: $now, egress: $egress}}]->(d) "
                "SET d.endorsed = true",
                {"apid": approval.id, "ids": approval.endorsed_ids, "now": approval.created_at,
                 "egress": bool(approval.egress)},
            )
        if approval.action_id and approval.verdict == "rejected":
            self._q(
                f"MATCH (ap:{S.APPROVAL} {{id: $apid}}), (a:{S.ACTION} {{id: $aid}}) "
                f"CREATE (ap)-[:{S.REJECTS} {{created_at: $now}}]->(a)",
                {"apid": approval.id, "aid": approval.action_id, "now": approval.created_at})
        elif approval.action_id:
            self._q(
                f"MATCH (ap:{S.APPROVAL} {{id: $apid}}), (a:{S.ACTION} {{id: $aid}}) "
                f"CREATE (ap)-[:{S.APPROVES} {{checks: $checks, created_at: $now}}]->(a)",
                {"apid": approval.id, "aid": approval.action_id, "now": approval.created_at,
                 "checks": list(approval.checks)},
            )
        return approval

    def action_approvals(self, action_id: str) -> List[Dict[str, Any]]:
        """Action-scoped approvals: [{id, approver, approver_kind, checks, created_at}]."""
        res = self._ro(
            f"MATCH (ap:{S.APPROVAL})-[r:{S.APPROVES}]->(a:{S.ACTION} {{id: $id}}) "
            "RETURN ap.id, ap.approver, ap.approver_kind, coalesce(r.checks, []), ap.created_at "
            "ORDER BY ap.created_at",
            {"id": action_id},
        )
        return [{"id": i, "approver": who, "approver_kind": kind or "human",
                 "checks": list(checks), "created_at": at}
                for i, who, kind, checks, at in res.result_set]

    def endorsements_of(self, datum_ids: Sequence[str]) -> Dict[str, List[Dict[str, Any]]]:
        """For each endorsed datum id, the approvals that ENDORSE it."""
        if not datum_ids:
            return {}
        res = self._ro(
            f"MATCH (ap:{S.APPROVAL})-[:{S.ENDORSES}]->(d:{S.DATUM}) WHERE d.id IN $ids "
            "RETURN d.id, ap.id, ap.approver, ap.created_at ORDER BY ap.created_at",
            {"ids": list(datum_ids)},
        )
        out: Dict[str, List[Dict[str, Any]]] = {}
        for did, apid, who, at in res.result_set:
            out.setdefault(did, []).append({"id": apid, "approver": who, "created_at": at})
        return out

    # ------------------------------------------------------------ decisions
    def create_decision(self, props: Dict[str, Any]) -> None:
        """Append a Guard Decision node linked to its Action (audit trail)."""
        clause, params = _props_clause("dc", props, "dc")
        params["aid"] = props["action_id"]
        self._q(
            f"MATCH (a:{S.ACTION} {{id: $aid}}) "
            f"CREATE (dc:{S.DECISION} {clause})-[:{S.EVALUATES}]->(a)",
            params, bump=False,
        )

    def decisions_for(self, action_id: str) -> List[Dict[str, Any]]:
        res = self._ro(
            f"MATCH (dc:{S.DECISION})-[:{S.EVALUATES}]->(:{S.ACTION} {{id: $id}}) "
            "RETURN dc ORDER BY dc.created_at, dc.seq",
            {"id": action_id},
        )
        return [dict(row[0].properties) for row in res.result_set]

    # ----------------------------------------------------------- quarantine
    def quarantine_memories(self, q: QuarantineRecord) -> List[str]:
        """Create a Quarantine node, link it to the memories (and the Action that did it)
        and flag the memories ``in_quarantine``. Returns the memory ids actually linked."""
        props = {"id": q.id, "actor": q.actor, "reason": q.reason, "action_id": q.action_id,
                 "incident_id": q.incident_id, "created_at": q.created_at}
        clause, params = _props_clause("q", props, "q")
        self._q(f"CREATE (q:{S.QUARANTINE} {clause})", params)
        res = self._q(
            f"MATCH (q:{S.QUARANTINE} {{id: $qid}}) "
            f"UNWIND $ids AS mid MATCH (m:{S.DATUM}:{S.MEMORY} {{id: mid}}) "
            f"CREATE (q)-[:{S.QUARANTINES} {{created_at: $now}}]->(m) "
            "SET m.in_quarantine = true, m.quarantine_id = $qid "
            "RETURN m.id",
            {"qid": q.id, "ids": list(q.memory_ids), "now": q.created_at},
        )
        if q.action_id:
            self._q(
                f"MATCH (q:{S.QUARANTINE} {{id: $qid}}), (a:{S.ACTION} {{id: $aid}}) "
                f"CREATE (q)-[:{S.VIA}]->(a)",
                {"qid": q.id, "aid": q.action_id},
            )
        return [row[0] for row in res.result_set]

    def lift_quarantine(self, memory_ids: Sequence[str], *, lift_id: str, lifted_by: str,
                        approved_by: str, action_id: str, at: str) -> List[str]:
        """End the quarantine of memories (append-only): a (:QuarantineLift) records who
        asked and which human approved; the original (:Quarantine) node, its edges and the
        memory's provenance are untouched. Returns the memory ids un-flagged."""
        res = self._q(
            f"CREATE (l:{S.QUARANTINE_LIFT} {{id: $lid, lifted_by: $by, approved_by: $ap, "
            "action_id: $aid, created_at: $at}) WITH l "
            f"UNWIND $ids AS mid MATCH (m:{S.DATUM}:{S.MEMORY} {{id: mid}}) "
            "WHERE coalesce(m.in_quarantine, false) = true "
            f"CREATE (l)-[:{S.LIFTS} {{quarantine_id: m.quarantine_id}}]->(m) "
            "SET m.in_quarantine = false, m.quarantine_id = null RETURN m.id",
            {"lid": lift_id, "by": lifted_by, "ap": approved_by, "aid": action_id, "at": at,
             "ids": list(memory_ids)})
        return [r[0] for r in res.result_set]

    def restore_source_trust(self, source_id: str, *, restoration_id: str, restored_by: str,
                             approved_by: str, action_id: str, at: str) -> str:
        """Undo a trust revocation (append-only record). Only a revoked Source can be
        restored, and only to its original label. Returns the label now in force."""
        res = self._q(
            f"MATCH (s:{S.SOURCE} {{id: $id}}) WHERE s.trust_original IS NOT NULL "
            "WITH s, s.trust AS before "
            "SET s.trust = s.trust_original, s.restored_at = $at "
            f"CREATE (r:{S.TRUST_RESTORATION} {{id: $rid, source_id: $id, restored_by: $by, "
            "approved_by: $ap, action_id: $aid, created_at: $at, trust_before: before})"
            f"-[:{S.RESTORES}]->(s) RETURN s.trust",
            {"id": source_id, "rid": restoration_id, "by": restored_by, "ap": approved_by,
             "aid": action_id, "at": at})
        if not res.result_set:
            raise NotFound(f"source {source_id!r} not found or was never revoked")
        return res.result_set[0][0]

    def quarantines(self) -> List[Dict[str, Any]]:
        res = self._ro(
            f"MATCH (q:{S.QUARANTINE}) "
            f"OPTIONAL MATCH (q)-[:{S.QUARANTINES}]->(m:{S.MEMORY}) "
            "RETURN q, collect(m.id) ORDER BY q.created_at"
        )
        return [{**dict(q.properties), "memory_ids": sorted(ids)} for q, ids in res.result_set]

    def search_memories(self, *, text: Optional[str] = None, key: Optional[str] = None,
                        agent: Optional[str] = None, include_quarantined: bool = False,
                        limit: int = 50) -> List[DatumRecord]:
        """Shared-memory retrieval. Quarantined memories are excluded unless asked for."""
        where = []
        if not include_quarantined:
            where.append("coalesce(m.in_quarantine, false) = false")
        if agent:
            where.append("m.agent = $agent")
        if text:
            where.append("(toLower(coalesce(m.value, '')) CONTAINS toLower($text) "
                         "OR toLower(m.metadata) CONTAINS toLower($text))")
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        res = self._ro(
            f"MATCH (m:{S.DATUM}:{S.MEMORY}) {clause} "
            "RETURN m ORDER BY m.created_at DESC LIMIT $limit",
            {"agent": agent, "text": text, "limit": max(1, int(limit))},
        )
        out = [_datum_from_node(row[0]) for row in res.result_set]
        if key:
            out = [m for m in out if m.metadata.get("key") == key]
        return out

    # ------------------------------------------------- label-creep helpers
    def find_value_candidates(self, context_ids: Sequence[str], value: str, value_fp: str,
                              max_depth: int = 25) -> List[Tuple[DatumRecord, int]]:
        """Ancestors (or members) of the context whose value contains ``value`` or whose
        fingerprint equals ``value_fp`` (exact match, works for secrets whose raw value is
        never stored). Returns (datum, min depth). Token-boundary filtering is done by
        the caller."""
        if not context_ids:
            return []
        # BFS, not *0..N path enumeration (exponential in multi-turn sessions). Bounded and
        # fail-safe: a candidate that is not found only means no exact attribution.
        depths, _ = T.ancestors(self.graph, list(context_ids), max_depth=_clamp_depth(max_depth))
        if not depths:
            return []
        res = self._ro(
            f"MATCH (s:{S.DATUM}) WHERE s.id IN $ids "
            "AND (s.fingerprint = $fp OR (s.value IS NOT NULL AND s.value CONTAINS $value)) "
            f"OPTIONAL MATCH (s)-[:{S.FROM}]->(src:{S.SOURCE}) "
            "RETURN s, src.id",
            {"ids": list(depths), "fp": value_fp, "value": value},
        )
        out = [(_datum_from_node(n, source_id=sid), depths[n.properties["id"]])
               for n, sid in res.result_set]
        return sorted(out, key=lambda x: (x[1], x[0].created_at))

    def uncleared_untrusted_paths(self, datum_id: str, max_depth: int = 25,
                                  limit: int = 1) -> List[ProvenancePath]:
        """Provenance paths from ``datum_id`` to an untrusted Source on which no Datum is
        endorsed, following only edges the Guard follows (attribution != 'context')."""
        depth = _clamp_depth(max_depth)
        res = self._ro(
            f"MATCH p = (d:{S.DATUM} {{id: $id}})-[:{S.DERIVED_FROM}*0..{depth}]->(x:{S.DATUM}) "
            "WHERE all(r IN relationships(p) WHERE coalesce(r.attribution, 'inherit') <> 'context') "
            "AND none(n IN nodes(p) WHERE n.endorsed = true) "
            f"MATCH (x)-[:{S.FROM}]->(s:{S.SOURCE} {{trust: 'untrusted'}}) "
            "RETURN [n IN nodes(p) | n.id] + [s.id], "
            "[r IN relationships(p) | r.op] + ['FROM'], length(p) + 1 AS len "
            "ORDER BY len LIMIT $limit",
            {"id": datum_id, "limit": max(1, int(limit))},
        )
        return [ProvenancePath(node_ids=ids, ops=ops, length=n) for ids, ops, n in res.result_set]

    # ----------------------------------------------------------- provenance
    def lineage(self, datum_id: str, max_depth: int = 25) -> Lineage:
        """All ancestors of a Datum (including itself) via DERIVED_FROM, with sources."""
        depths, _ = T.ancestors(self.graph, [datum_id], max_depth=_clamp_depth(max_depth))
        if not depths:
            raise NotFound(f"datum {datum_id!r} not found")
        res = self._ro(
            f"MATCH (a:{S.DATUM}) WHERE a.id IN $ids "
            f"OPTIONAL MATCH (a)-[:{S.FROM}]->(s:{S.SOURCE}) RETURN a, s",
            {"ids": list(depths)},
        )
        entries = sorted(
            (LineageEntry(
                datum=_datum_from_node(a, source_id=s.properties["id"] if s is not None else None),
                depth=depths[a.properties["id"]],
                source=_source_from_node(s) if s is not None else None)
             for a, s in res.result_set),
            key=lambda e: (e.depth, e.datum.created_at, e.datum.id))
        return Lineage(root_id=datum_id, entries=entries)

    def find_paths(self, from_id: str, to_id: str, max_depth: int = 25,
                   limit: int = 10) -> List[ProvenancePath]:
        """Provenance paths from a Datum back to an ancestor Datum or Source, shortest first."""
        depth = _clamp_depth(max_depth)
        res = self._ro(
            f"MATCH (a:{S.DATUM} {{id: $from}}), (b {{id: $to}}) "
            f"MATCH p = (a)-[:{S.DERIVED_FROM}|{S.FROM}*1..{depth}]->(b) "
            "RETURN [n IN nodes(p) | n.id], "
            "[r IN relationships(p) | coalesce(r.op, type(r))], length(p) AS len "
            "ORDER BY len LIMIT $limit",
            {"from": from_id, "to": to_id, "limit": max(1, int(limit))},
        )
        return [ProvenancePath(node_ids=ids, ops=ops, length=length)
                for ids, ops, length in res.result_set]

    def find_path(self, from_id: str, to_id: str, max_depth: int = 25) -> Optional[ProvenancePath]:
        """Shortest provenance path, or None."""
        paths = self.find_paths(from_id, to_id, max_depth, limit=1)
        return paths[0] if paths else None

    def trace_action(self, action_id: str, max_depth: int = 25) -> ActionTrace:
        action = self.get_action(action_id)
        args = [ArgTrace(role=a.role, datum_id=a.datum_id,
                         lineage=self.lineage(a.datum_id, max_depth))
                for a in action.args]
        return ActionTrace(action=action, args=args)

    # ------------------------------------------------------------------ runs
    def save_run(self, run_id: str, kind: str, payload: str) -> None:
        """Store a UI run report (demo scenario, Warden investigation). Not provenance."""
        self._q(f"CREATE (:{S.RUN} {{id: $id, kind: $kind, payload: $payload, created_at: $now}})",
                {"id": run_id, "kind": kind, "payload": payload, "now": utcnow_iso()}, bump=False)

    def latest_run(self, kind: str) -> Optional[str]:
        res = self._ro(f"MATCH (r:{S.RUN} {{kind: $kind}}) RETURN r.payload "
                       "ORDER BY r.created_at DESC LIMIT 1", {"kind": kind})
        return res.result_set[0][0] if res.result_set else None

    # ------------------------------------------------------------------ stats
    def counts(self) -> Dict[str, int]:
        nodes = self._ro("MATCH (n) UNWIND labels(n) AS l RETURN l, count(*)").result_set
        rels = self._ro("MATCH ()-[r]->() RETURN type(r), count(*)").result_set
        out = {f"node:{l}": c for l, c in nodes if l != S.GRAPH_META}
        out.update({f"rel:{t}": c for t, c in rels})
        return out
