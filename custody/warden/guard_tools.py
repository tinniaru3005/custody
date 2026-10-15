"""The deterministic Guard, exposed to MCP clients (``check_action``, ``explain_decision``).

Thin adapters over ``custody.guard.Guard``: no policy logic lives here. They exist so an
agent framework that speaks MCP can ask Custody for a verdict and its evidence.

What the verdict is worth depends on two things outside this module:
- the action and its provenance must have been recorded completely (every Datum in the
  model's context linked; see "Recording soundness" in the README), and
- the caller must actually enforce it. Custody does not execute or stop anything here; an
  agent that ignores BLOCK is not protected.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from custody.graph.repository import NotFound
from custody.guard.models import GuardDecision, Verdict
from custody.guard.service import Guard

ENFORCEMENT_NOTE = ("Custody did not execute or block anything: the caller must enforce "
                    "this verdict (execute only on ALLOW). The verdict is only as good as "
                    "the recorded provenance.")
_VERDICT = {Verdict.ALLOW: "ALLOW", Verdict.REQUIRE_HUMAN_APPROVAL: "REQUIRE_APPROVAL",
            Verdict.BLOCK: "BLOCK"}


class CheckSummary(BaseModel):
    violated: bool
    detail: str
    search_outcome: Optional[str] = None      # PATH_FOUND | NO_PATH | INDETERMINATE
    termination_reason: Optional[str] = None


class EvidencePath(BaseModel):
    check: str
    status: str                               # violating | cleared | limited | info
    length: int
    node_ids: List[str]
    ops: List[str]
    sessions: List[str] = Field(default_factory=list)
    agents: List[str] = Field(default_factory=list)
    text: str


class GuardCheckResult(BaseModel):
    action_id: str
    action_type: str
    agent: str
    action_status: str
    verdict: str                              # ALLOW | REQUIRE_APPROVAL | BLOCK
    fail_closed: bool                         # an incomplete search made this non-ALLOW
    search_complete: bool
    indeterminate_checks: List[str] = Field(default_factory=list)
    triggered: List[str] = Field(default_factory=list)
    checks: Dict[str, CheckSummary] = Field(default_factory=dict)
    paths: List[EvidencePath] = Field(default_factory=list)
    untrusted_sources: List[str] = Field(default_factory=list)
    sink: Dict[str, Any] = Field(default_factory=dict)
    approval: Dict[str, Any] = Field(default_factory=dict)
    explanation: str
    certificate: Optional[Dict[str, Any]] = None   # summary, ALLOW only
    # distinct untrusted roots, one route each, route independence (explanation only)
    contamination: Optional[Dict[str, Any]] = None
    decision_id: str
    recorded: bool                            # a (:Decision) audit node was written
    policy: str
    latency_ms: float
    enforcement: str = ENFORCEMENT_NOTE


class RecordedDecision(BaseModel):
    id: str
    verdict: str
    triggered: List[str] = Field(default_factory=list)
    explanation: str = ""
    created_at: Optional[str] = None
    policy: Optional[str] = None


class DecisionExplanation(BaseModel):
    action_id: str
    recorded: RecordedDecision                # what was decided then (stored in the graph)
    current: GuardCheckResult                 # the same Guard over the current graph
    matches_recorded: bool                    # same verdict and triggered checks
    graph_version: str
    note: str = ("Recorded decisions store the verdict, triggered checks and explanation; "
                 "provenance paths are recomputed from the current graph (append-only: an "
                 "existing Datum's ancestry only changes through endorsements or trust "
                 "revocations, which matches_recorded makes visible).")


def summarise(d: GuardDecision, recorded: bool) -> GuardCheckResult:
    checks = {name: CheckSummary(
        violated=c.violated, detail=c.detail,
        search_outcome=c.search.outcome.value if c.search else None,
        termination_reason=c.search.termination_reason.value if c.search else None)
        for name, c in d.checks.items() if c.evaluated}
    cert = None
    if d.certificate is not None:
        c = d.certificate
        cert = {"claim": c.claim, "root_sources_checked": c.root_sources_checked,
                "untrusted_roots_not_followed": c.untrusted_roots_not_followed,
                "graph_version": c.graph_version_label, "ancestry_digest": c.ancestry_digest,
                "nodes_examined": c.nodes_examined, "certificate_id": c.certificate_id,
                "strength": c.strength, "provenance_coverage": c.provenance_coverage,
                "reduced_provenance_count": c.reduced_provenance_count,
                "trust_labels_note": c.trust_labels_note,
                "root_sources": [{"id": r.id, "trust": r.trust, "status": r.status}
                                 for r in c.root_sources]}
    cont = None
    if d.contamination is not None:
        c = d.contamination
        cont = {"root_count": c.root_count, "roots_complete": c.roots_complete,
                "roots": [{"source": r.source_id, "kind": r.source_kind, "hops": r.hops,
                           "route": r.path.text} for r in c.roots],
                "independence": c.independence, "independent_routes": c.independent_routes,
                "shared_datum_id": c.shared_datum_id, "detail": c.detail}
    return GuardCheckResult(
        action_id=d.action_id, action_type=d.action_type, agent=d.agent,
        action_status=d.action_status, verdict=_VERDICT[d.decision],
        fail_closed=not d.search_complete and d.decision != Verdict.ALLOW,
        search_complete=d.search_complete,
        indeterminate_checks=[c.value for c in d.indeterminate_checks],
        triggered=[c.value for c in d.triggered_checks], checks=checks,
        paths=[EvidencePath(check=p.check.value, status=p.status, length=p.length,
                            node_ids=[n.id for n in p.nodes], ops=p.ops, sessions=p.sessions,
                            agents=p.agents, text=p.text) for p in d.paths],
        untrusted_sources=sorted({s.id for s in d.sources if s.trust == "untrusted"}),
        sink=d.sink.model_dump(mode="json"), approval=d.approval.model_dump(mode="json"),
        explanation=d.explanation, certificate=cert, contamination=cont, decision_id=d.id, recorded=recorded,
        policy=d.policy, latency_ms=d.latency_ms.get("total", 0.0))


def check_action(guard: Guard, action_id: str) -> GuardCheckResult:
    """Run the Guard on a recorded action. Writes a Decision audit node; never changes the
    action's status and never executes anything."""
    d = guard.check(action_id)
    return summarise(d, recorded=guard.record_decisions)


def explain_decision(guard: Guard, action_id: str,
                     decision_id: Optional[str] = None) -> DecisionExplanation:
    history = guard.repo.decisions_for(action_id)
    if decision_id:
        history = [h for h in history if h.get("id") == decision_id]
    if not history:
        raise NotFound(f"no recorded Guard decision for action {action_id!r}"
                       + (f" with id {decision_id!r}" if decision_id else "")
                       + "; call check_action first")
    h = history[-1]
    rec = RecordedDecision(id=h["id"], verdict=_VERDICT.get(Verdict(h["decision"]), h["decision"]),
                           triggered=list(h.get("triggered") or []),
                           explanation=h.get("explanation", ""), created_at=h.get("created_at"),
                           policy=h.get("policy"))
    now = Guard(guard.recorder, guard.policy, record_decisions=False).check(action_id)
    cur = summarise(now, recorded=False)
    return DecisionExplanation(
        action_id=action_id, recorded=rec, current=cur,
        matches_recorded=(rec.verdict == cur.verdict
                          and sorted(rec.triggered) == sorted(cur.triggered)),
        graph_version=guard.repo.graph_version().label)
