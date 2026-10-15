"""Retroactive re-adjudication after a trust revocation.

A Source that was trusted when decisions were made (an internal repo, a partner feed, a
user account) can later turn out to be compromised. ``revoke_and_readjudicate``:

1. marks the Source untrusted from now on (``GraphRepository.revoke_source_trust``: the old
   label is kept and a ``(:TrustRevocation)`` records who/when/why);
2. walks FORWARD from every Datum that came FROM the Source, over every DERIVED_FROM edge
   (context edges included), with the same complete, fail-closed traversal as the Guard;
3. finds the historical memories, messages and actions downstream;
4. re-runs the CURRENT Guard on every affected action (read-only: no Decision is written
   and no action status changes), and
5. stores one ``(:Readjudication)-[:READJUDICATES]->(:Action)`` per action next to the
   original ``(:Decision)`` nodes.

History is not rewritten: the Decision recorded at execution time ("what was known then")
stays as it was; the Readjudication says "what is known now". Executed actions stay executed.
"""
from __future__ import annotations

import json
from collections import Counter
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from custody.graph import schema as S
from custody.graph import traversal as T
from custody.graph.model import ActionStatus, new_id, utcnow_iso
from custody.guard.models import ApprovalRefused, GuardDecision
from custody.guard.service import Guard


class ArgInfluence(BaseModel):
    role: str
    datum_id: str


class ReadjudicatedAction(BaseModel):
    action_id: str
    action_type: str
    agent: str
    status: str                          # unchanged by re-adjudication
    executed: bool
    influenced_args: List[ArgInfluence]
    # what was known at execution time: the last Decision recorded before the revocation
    original_verdict: Optional[str] = None
    original_decision_id: Optional[str] = None
    original_evaluated_at: Optional[str] = None
    # what is known now: the current Guard over the current graph
    current_verdict: str
    current_triggered: List[str] = Field(default_factory=list)
    current_explanation: str = ""
    current_path: Optional[str] = None   # a violating path that now reaches the source
    transition: str                      # "ALLOW → BLOCK" | "UNCHANGED" | "none → …"
    changed: bool


class ReadjudicationReport(BaseModel):
    id: str                              # the TrustRevocation id
    source_id: str
    trust_before: str
    trust_after: str = "untrusted"
    revoked_by: str
    reason: Optional[str] = None
    revoked_at: str
    graph_version_before: str
    graph_version_after: str
    traversal: T.ProvenanceSearch
    downstream_datums: int
    memories: List[str] = Field(default_factory=list)
    messages: List[str] = Field(default_factory=list)
    actions: List[ReadjudicatedAction]
    summary: Dict[str, int]
    known_then: str = ("Original verdict: the last Guard Decision recorded for the action "
                       "before the revocation, unchanged in the graph.")
    known_now: str = ("Current verdict: today's Guard over today's graph, in which the source "
                      "is untrusted. Recorded as a Readjudication; action status unchanged.")


def _original(guard: Guard, action_id: str, before: str) -> Optional[Dict[str, Any]]:
    decided = [d for d in guard.repo.decisions_for(action_id)
               if (d.get("created_at") or "") <= before]
    return decided[-1] if decided else None


def _transition(original: Optional[str], current: str) -> str:
    if original == current:
        return "UNCHANGED"
    return f"{original or 'none'} → {current}"


def revoke_and_readjudicate(guard: Guard, source_id: str, *, approver: str,
                            reason: Optional[str] = None,
                            approver_kind: str = "human",
                            warden_action_id: Optional[str] = None) -> ReadjudicationReport:
    """``approver`` must be a human, except when the revocation executes a Guard-ALLOWed
    Warden ``revoke_source_trust`` action (``warden_action_id``): revoking trust only
    tightens, so the asymmetric remediation policy lets it run without a human."""
    if warden_action_id is None:
        guard._require_human(approver, approver_kind)
    else:
        a = guard.repo.get_action(warden_action_id)
        if a.action_type != "revoke_source_trust" or a.agent != "warden" \
                or a.status not in (ActionStatus.APPROVED, ActionStatus.PROPOSED):
            raise ApprovalRefused(f"{warden_action_id} is not an open Warden "
                                  "revoke_source_trust action")
    repo = guard.repo
    repo.get_source(source_id)  # 404 if missing
    v_before = repo.graph_version()
    at = utcnow_iso()
    rid = new_id("rev")
    trust_before = repo.revoke_source_trust(source_id, revocation_id=rid, revoked_by=approver,
                                            reason=reason, at=at)

    # ---- forward from the source (complete traversal; incomplete → refuse)
    roots = [r[0] for r in repo.graph.ro_query(
        f"MATCH (d:{S.DATUM})-[:{S.FROM}]->(:{S.SOURCE} {{id: $id}}) RETURN d.id",
        {"id": source_id}).result_set]
    downstream: Dict[str, int] = {}
    trav = T.search(repo.graph, roots, T.SearchSpec(hit="false"), collect=downstream,
                    reverse=True, **guard._limits())
    if not trav.search_complete:
        raise ApprovalRefused(  # fail closed: the trust change stays, the report is refused
            f"forward traversal from {source_id} did not complete "
            f"({trav.summary()}); affected actions cannot be listed exhaustively")
    ids = list(downstream)
    kinds = repo.graph.ro_query(
        f"MATCH (d:{S.DATUM}) WHERE d.id IN $ids RETURN d.id, labels(d)", {"ids": ids}).result_set
    memories = sorted(i for i, labels in kinds if S.MEMORY in labels)
    messages = sorted(i for i, labels in kinds if S.MESSAGE in labels)
    hits: Dict[str, List[ArgInfluence]] = {}
    for aid, role, did in repo.graph.ro_query(
            f"MATCH (a:{S.ACTION})-[r:{S.ARG}]->(d:{S.DATUM}) WHERE d.id IN $ids "
            "RETURN a.id, r.role, d.id ORDER BY a.created_at, a.id", {"ids": ids}).result_set:
        hits.setdefault(aid, []).append(ArgInfluence(role=role, datum_id=did))

    # ---- re-run the current Guard on each affected action (no Decision written)
    current_guard = Guard(guard.recorder, guard.policy, record_decisions=False)
    results: List[ReadjudicatedAction] = []
    for aid, args in hits.items():
        action = repo.get_action(aid)
        orig = _original(guard, aid, at)
        d: GuardDecision = current_guard.check(aid)
        path = next((p.text for p in d.paths
                     if p.status == "violating" and p.nodes and p.nodes[-1].id == source_id),
                    None)
        transition = _transition(orig.get("decision") if orig else None, d.decision.value)
        item = ReadjudicatedAction(
            action_id=aid, action_type=action.action_type, agent=action.agent,
            status=action.status.value, executed=action.status == ActionStatus.EXECUTED,
            influenced_args=args,
            original_verdict=orig.get("decision") if orig else None,
            original_decision_id=orig.get("id") if orig else None,
            original_evaluated_at=orig.get("created_at") if orig else None,
            current_verdict=d.decision.value,
            current_triggered=[c.value for c in d.triggered_checks],
            current_explanation=d.explanation, current_path=path,
            transition=transition, changed=transition != "UNCHANGED")
        results.append(item)
        repo.record_readjudication(rid, aid, {
            "id": new_id("rjd"), "revocation_id": rid, "source_id": source_id,
            "original_verdict": item.original_verdict,
            "original_decision_id": item.original_decision_id,
            "current_verdict": item.current_verdict,
            "current_triggered": item.current_triggered, "transition": item.transition,
            "explanation": item.current_explanation, "created_at": utcnow_iso()})

    report = ReadjudicationReport(
        id=rid, source_id=source_id, trust_before=trust_before, revoked_by=approver,
        reason=reason, revoked_at=at, graph_version_before=v_before.label,
        graph_version_after=repo.graph_version().label, traversal=trav,
        downstream_datums=len(ids), memories=memories, messages=messages, actions=results,
        summary=dict(Counter(r.transition for r in results)))
    repo.save_run(rid, "readjudication", json.dumps(report.model_dump(mode="json")))
    return report


def latest_reports(guard: Guard, limit: int = 10) -> List[ReadjudicationReport]:
    rows = guard.repo.graph.ro_query(
        f"MATCH (r:{S.RUN} {{kind: 'readjudication'}}) RETURN r.payload "
        "ORDER BY r.created_at DESC LIMIT $n", {"n": limit}).result_set
    return [ReadjudicationReport.model_validate_json(p) for (p,) in rows]
