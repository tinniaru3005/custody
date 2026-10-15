"""Warden: the investigation / remediation agent's capabilities.

Investigation (read-only): find_sources, trace_back, trace_forward, rank_risky_memories,
cluster_incidents, simulate_policy (GRAPH.COPY sandbox).

Remediation goes through the SAME deterministic Guard as every other agent:

Remediation is asymmetric (``custody.warden.remediation``): tightening actions
(quarantine / disable recall, revoke Source trust) execute on a Guard ALLOW; loosening
actions (unquarantine, endorse, restore trust, weaken a restriction) are proposals that a
human must approve through the Guard before a fresh Guard check lets them run.

- ``quarantine``  → records an Action ``quarantine_memory`` by agent ``warden`` (target =
  the memories), ``Guard.enforce`` decides, and only an ALLOW executes it. Executing
  creates ``(:Quarantine)-[:QUARANTINES]->(:Memory)`` + ``-[:VIA]->(:Action)`` and flags the
  memories ``in_quarantine``, so the shared-memory layer stops returning them. Quarantine
  NEVER deletes or alters provenance: the memory node, its DERIVED_FROM / FROM edges and
  every recorded Decision stay; historical actions re-checked later get the same verdict
  and the same path. Only future retrieval changes (checked on every execution).
- ``draft_disclosure`` → only writes a draft (a Datum by agent ``warden``); nothing is sent.
- ``propose_disclosure`` → records an Action ``send_disclosure`` (external email sink) and
  runs ``Guard.enforce``. Policy marks ``send_disclosure`` as ``human_review``, so the
  Guard returns REQUIRE_HUMAN_APPROVAL even when every provenance check passes. The
  action is never auto-executed.
- ``send_approved_disclosure`` → ``AgentRuntime.execute``: re-runs the Guard and executes
  only on ALLOW, which requires a recorded human approval.
- ``approve_disclosure`` → for humans only (Python/CLI/HTTP); NOT exposed as an MCP tool.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, replace
from typing import Any, Dict, List, Optional
from collections.abc import Callable, Sequence

from custody.graph.model import (ActionStatus, Attribution, DatumRecord, QuarantineRecord,
                                  fingerprint, new_id, utcnow_iso)
from custody.graph.repository import GraphRepository, NotFound
from custody.guard.models import ApprovalRefused, GuardDecision, Verdict
from custody.guard.policy import DEFAULT_POLICY, GuardPolicy, policy_for_tenant
from custody.guard.service import Guard
from custody.recorder.service import Recorder
from custody.runtime import AgentRuntime, ExecutionDenied
from custody.runtime.runtime import AgentSession
from custody.runtime.tools import Delivery, Outbox, ToolSpec, default_tools
from custody.warden.analysis import WardenAnalysis
from custody.warden.models import (
    ClusterIncidentsResult,
    DisclosureDraft,
    DraftDisclosureResult,
    FindSourcesResult,
    PolicySpec,
    ProposeDisclosureResult,
    QuarantineResult,
    RankRiskyMemoriesResult,
    SendDisclosureResult,
    SimulationResult,
    TraceBackResult,
    TraceForwardResult,
    WhyAllowedResult,
)
from custody.warden.queries import WARDEN_AGENT
from custody.warden.remediation import (LOOSENING, LOOSENING_ACTIONS, LOOSENING_POLICY,
                                        NOT_APPLIED_BY_WARDEN, REMEDIATION_POLICY,
                                        TIGHTENING_ACTIONS, TIGHTENING_POLICY,
                                        RemediationResult, direction)
from custody.warden.simulate import simulate_policy

QUARANTINE_TOOL = "quarantine_memory"
DISCLOSURE_TOOL = "send_disclosure"


@dataclass(frozen=True)
class CallbackTool(ToolSpec):
    """A runtime tool whose execution is an internal callback instead of an outbox delivery."""

    handler: Optional[Callable[[str, Dict[str, str]], Delivery]] = None

    def execute(self, outbox: Outbox, action_id: str, args: Dict[str, str]) -> Delivery:
        assert self.handler is not None
        return self.handler(action_id, args)


def harden_policy(policy: GuardPolicy) -> GuardPolicy:
    """Only ever strengthens the tenant policy for the Warden's own actions: disclosures
    and security-loosening remediations always need a human (``human_review``), and every
    remediation type is guarded (the Guard always evaluates it)."""
    actions = dict(policy.actions)
    ap = policy.action(DISCLOSURE_TOOL)
    if not (ap.human_review and ap.outbound):
        actions[DISCLOSURE_TOOL] = replace(ap, outbound=True, human_review=True)
    for t in LOOSENING_ACTIONS:
        cur = actions.get(t, LOOSENING_POLICY)
        actions[t] = replace(cur, human_review=True, irreversible=True)
    for t in TIGHTENING_ACTIONS:
        cur = actions.get(t, TIGHTENING_POLICY)
        if not cur.guarded:
            actions[t] = replace(cur, irreversible=True)
    if actions == dict(policy.actions):
        return policy                       # already as strict: keep the same object
    return replace(policy, actions=actions)


class Warden:
    def __init__(self, recorder: Recorder, policy: GuardPolicy = DEFAULT_POLICY, *,
                 db: Any = None, operator: str = "security-operator",
                 tenant: Optional[str] = None) -> None:
        self.recorder = recorder
        self.repo: GraphRepository = recorder.repo
        self.policy = harden_policy(policy)
        self.db = db
        self.tenant = tenant
        self.operator = operator
        self.guard = Guard(recorder, self.policy)
        tools = dict(default_tools())
        tools[QUARANTINE_TOOL] = CallbackTool(QUARANTINE_TOOL, ("target",), None,
                                              handler=self._execute_quarantine)
        tools[DISCLOSURE_TOOL] = ToolSpec(DISCLOSURE_TOOL, ("destination", "payload"),
                                          lambda d: ("email", d, None))
        for name, handler in (("revoke_source_trust", self._execute_revoke),
                              ("unquarantine_memory", self._execute_unquarantine),
                              ("endorse_data", self._execute_endorse),
                              ("restore_source_trust", self._execute_restore),
                              ("weaken_restriction", self._execute_not_applied)):
            tools[name] = CallbackTool(name, ("target",), None, handler=handler)
        # Warden's own runtime: its actions are proposed → Guard.enforce → executed on ALLOW,
        # exactly like any worker agent's.
        self.runtime = AgentRuntime(recorder, self.guard, tools=tools)
        self.analysis = WardenAnalysis(self.repo, self.policy, db, recorder.max_trace_depth)
        self.session: Optional[AgentSession] = None
        self.instruction_id: Optional[str] = None

    @classmethod
    def for_tenant(cls, provider: Any, tenant: str, *, operator: str = "security-operator",
                   policy: Optional[GuardPolicy] = None) -> "Warden":
        repo = GraphRepository(provider.graph(tenant))
        rec = Recorder(repo, max_trace_depth=provider.max_trace_depth)
        return cls(rec, policy or policy_for_tenant(tenant), db=provider.db, operator=operator,
                   tenant=tenant)

    # ================================================================ session
    def begin(self, request: str, *, operator: Optional[str] = None) -> str:
        """Start a Warden session: the operator's request is recorded as trusted user input
        and every Warden action derives from it."""
        if operator:
            self.operator = operator
        self.session = self.runtime.session(WARDEN_AGENT, new_id("warden"))
        self.instruction_id = self.session.user(request, user=self.operator).id
        return self.instruction_id

    def _ensure_session(self, what: str) -> AgentSession:
        if self.session is None or self.instruction_id is None:
            self.begin(f"(direct tool call) {what}")
        assert self.session is not None
        return self.session

    # ========================================================== investigation
    def find_sources(self, query: Optional[str] = None, kind: Optional[str] = None,
                     trust: Optional[str] = None, limit: int = 20) -> FindSourcesResult:
        return self.analysis.find_sources(query, kind, trust, limit)

    def trace_back(self, action_id: str) -> TraceBackResult:
        return self.analysis.trace_back(action_id)

    def trace_forward(self, source_id: str) -> TraceForwardResult:
        return self.analysis.trace_forward(source_id)

    def check_action(self, action_id: str):
        from custody.warden.guard_tools import check_action

        return check_action(self.guard, action_id)

    def explain_decision(self, action_id: str, decision_id: Optional[str] = None):
        from custody.warden.guard_tools import explain_decision

        return explain_decision(self.guard, action_id, decision_id)

    def find_chokepoints(self, action_id: str):
        from custody.warden.chokepoints import find_chokepoints

        return find_chokepoints(self.analysis, action_id)

    def rank_risky_memories(self, limit: int = 10,
                            include_quarantined: bool = False) -> RankRiskyMemoriesResult:
        return self.analysis.rank_risky_memories(limit, include_quarantined)

    def cluster_incidents(self) -> ClusterIncidentsResult:
        return self.analysis.cluster_incidents()

    def simulate_policy(self, policy: PolicySpec | Dict[str, Any]) -> SimulationResult:
        spec = policy if isinstance(policy, PolicySpec) else PolicySpec.model_validate(policy)
        return simulate_policy(self.db, self.repo, self.guard.policy, spec,
                               prefer_copy=self.db is not None)

    # ============================================================= quarantine
    def quarantine(self, memory_ids: Sequence[str], reason: Optional[str] = None,
                   incident_id: Optional[str] = None) -> QuarantineResult:
        ids = list(dict.fromkeys(memory_ids))
        found = self.repo.get_data(ids)
        todo, already, rejected = [], [], []
        for mid in ids:
            d = found.get(mid)
            if d is None:
                rejected.append({"id": mid, "reason": "not found"})
            elif not d.is_memory:
                rejected.append({"id": mid, "reason": f"is a {d.kind.value}, not a memory"})
            elif d.in_quarantine:
                already.append(mid)
            else:
                todo.append(mid)
        if not todo:
            return QuarantineResult(status="nothing_to_do", already_quarantined=already,
                                    rejected=rejected)
        s = self._ensure_session("quarantine")
        target = s.arg("target", json.dumps(sorted(todo)), tool=QUARANTINE_TOOL,
                       derived_from=[self.instruction_id, *todo],
                       attribution=Attribution.INHERIT.value)
        res = self.runtime.propose(
            agent=WARDEN_AGENT, session_id=s.session_id, tool=QUARANTINE_TOOL,
            arg_datums={"target": target.id},
            metadata={"reason": reason or "", "incident_id": incident_id or "",
                      "requested_by": self.operator})
        d = res.decision
        status = {Verdict.ALLOW: "quarantined", Verdict.BLOCK: "blocked",
                  Verdict.REQUIRE_HUMAN_APPROVAL: "pending_approval"}[d.decision]
        qid = None
        done: List[str] = []
        if res.executed and res.delivery is not None:
            qid = res.delivery.destination.split(":", 1)[1]
            done = json.loads(res.delivery.payload)
        return QuarantineResult(status=status, quarantine_id=qid, action_id=res.action_id,
                                guard_verdict=d.decision.value, guard_explanation=d.explanation,
                                quarantined=done, already_quarantined=already, rejected=rejected)

    def _provenance_footprint(self, ids: Sequence[str]) -> List[Any]:
        """The recorded provenance of these Datums: their own DERIVED_FROM / FROM edges
        (what they came from). New Datums later derived FROM them add edges pointing at
        them; that is new history, not a rewrite, so incoming edges are not compared."""
        return sorted(self.repo.graph.ro_query(
            "MATCH (m:Datum)-[r:DERIVED_FROM|FROM]->(x) WHERE m.id IN $ids "
            "RETURN m.id, type(r), x.id, coalesce(r.op, ''), coalesce(r.attribution, '')",
            {"ids": list(ids)}).result_set)

    def _execute_quarantine(self, action_id: str, args: Dict[str, str]) -> Delivery:
        ids = json.loads(args["target"])
        before = self._provenance_footprint(ids)
        meta = self.repo.get_action(action_id).metadata
        q = QuarantineRecord(id=new_id("qtn"), memory_ids=ids, action_id=action_id,
                             actor=WARDEN_AGENT, reason=meta.get("reason") or None,
                             incident_id=meta.get("incident_id") or None, created_at=utcnow_iso())
        linked = sorted(self.repo.quarantine_memories(q))
        if self._provenance_footprint(ids) != before:  # invariant: never rewrite history
            raise RuntimeError("quarantine changed the provenance of a memory")
        payload = json.dumps(linked)
        return Delivery(action_id=action_id, tool=QUARANTINE_TOOL, sink_kind="memory_store",
                        destination=f"quarantine:{q.id}", workspace=None, payload=payload,
                        payload_fingerprint=fingerprint(payload))

    def why_allowed(self, action_id: str) -> WhyAllowedResult:
        """Deterministic answer to "why was this action allowed?": the current Guard
        decision (read-only re-run), its Provenance Completeness Certificate, and a
        fixed-template rendering of the certificate's evidence and the policy result."""
        action = self.repo.get_action(action_id)
        d = Guard(self.recorder, self.guard.policy, record_decisions=False).check(action_id)
        hist = self.repo.decisions_for(action_id)
        rec = hist[-1]["decision"] if hist else None
        out = WhyAllowedResult(
            action_id=action_id, action_type=action.action_type,
            action_status=action.status.value, allowed=d.decision == Verdict.ALLOW,
            verdict=d.decision.value, recorded_verdict=rec,
            matches_recorded=(rec == d.decision.value) if rec else None,
            certificate=d.certificate.model_dump(mode="json") if d.certificate else None,
            certificate_unavailable=d.certificate_unavailable)
        ev = out.evidence
        if d.decision != Verdict.ALLOW:
            ev.append(f"Not allowed: the Guard's verdict is {d.decision.value} "
                      f"({', '.join(c.value for c in d.triggered_checks)}). {d.explanation}")
            return out
        ev.append(f"Policy result: ALLOW under {d.policy}; no check violated.")
        for name in ("integrity", "confidentiality", "lethal_trifecta", "human_review",
                     "precedent"):
            c = d.checks.get(name)
            if c is not None and c.evaluated:
                cleared = c.cleared_by_action_approval or c.cleared_by_endorsement
                ev.append(f"  {name}: {'violated' if c.violated else 'passed'} — {c.detail}"
                          + (f" (cleared by human approval {', '.join(cleared)})"
                             if cleared else ""))
        c = d.certificate
        if c is None:
            ev.append("No completeness certificate: " + (d.certificate_unavailable or "?"))
            return out
        ev += [
            f"Traversal: {'COMPLETE' if c.traversal_complete else 'INCOMPLETE'}, frontier "
            f"{'EXHAUSTED' if c.frontier_exhausted else 'NOT exhausted'} "
            f"({c.termination_reason}); {c.nodes_examined} node(s), "
            f"{c.relationships_examined} relationship(s), max depth {c.max_depth_reached}.",
            f"Context-edge coverage: {c.context_edges_examined} context edge(s) of "
            f"{c.derived_from_edges_examined} DERIVED_FROM edge(s) included; provenance "
            f"coverage {c.provenance_coverage} → certificate {c.strength}"
            + (f" ({c.reduced_provenance_count} model output(s) with reduced provenance: "
               "not an exhaustive account)" if c.strength != "STRONG" else "") + ".",
            f"Root Sources reached: {c.root_sources_checked} (trust labels are policy inputs):",
        ]
        ev += [f"  {r.id} [{r.trust}] — {r.status}" + (f": {r.note}" if r.note else "")
               for r in c.root_sources]
        ev += [f"Graph version: {c.graph_version_label}; certificate {c.certificate_id}; "
               f"ancestry {c.ancestry_digest[:19]}…",
               f"Payload: {c.payload}.",
               "Claim: " + c.claim]
        return out

    # ============================================================ remediation
    def remediation_policy(self) -> Dict[str, Dict[str, str]]:
        """The asymmetric remediation table (deterministic, not configurable at runtime)."""
        return {k: dict(v) for k, v in REMEDIATION_POLICY.items()}

    def disable_memory_recall(self, memory_ids: Sequence[str],
                              reason: Optional[str] = None) -> QuarantineResult:
        """Tightening: same operation as ``quarantine`` (future recall/search stop)."""
        return self.quarantine(memory_ids, reason=reason)

    def _propose_remediation(self, kind: str, targets: Sequence[str],
                             reason: Optional[str]) -> RemediationResult:
        dirn = direction(kind)
        action_type = REMEDIATION_POLICY[kind]["action"]
        s = self._ensure_session(kind)
        tgt = list(dict.fromkeys(targets))
        target = s.arg("target", json.dumps(tgt), tool=action_type,
                       derived_from=[self.instruction_id],
                       attribution=Attribution.INHERIT.value)
        # tightening: Guard decides and an ALLOW executes; loosening: never auto-executed
        res = self.runtime.propose(
            agent=WARDEN_AGENT, session_id=s.session_id, tool=action_type,
            arg_datums={"target": target.id},
            metadata={"reason": reason or "", "requested_by": self.operator,
                      "remediation": kind, "direction": dirn},
            auto_execute=dirn != LOOSENING)
        d = res.decision
        if res.executed:
            status = "executed"
        elif d.decision == Verdict.BLOCK:
            status = "blocked"
        elif d.decision == Verdict.REQUIRE_HUMAN_APPROVAL:
            status = "pending_approval"
        else:
            status = "not_executed"
        detail: Dict[str, object] = {}
        if res.delivery is not None:
            detail = json.loads(res.delivery.payload)
        return RemediationResult(
            kind=kind, direction=dirn, status=status, action_id=res.action_id, targets=tgt,
            guard_verdict=d.decision.value, guard_explanation=d.explanation, detail=detail,
            how_to_approve=(
                "A human approves with POST /tenants/<tenant>/guard/actions/"
                f"{res.action_id}/approve (or Warden.approve_remediation); then call "
                f"execute_approved_remediation('{res.action_id}'). The Warden cannot approve."
                if status == "pending_approval" else None))

    def revoke_source_trust(self, source_id: str,
                            reason: Optional[str] = None) -> RemediationResult:
        """Tightening: mark a Source untrusted (Guard-checked; executes on ALLOW) and
        re-adjudicate everything downstream (existing retroactive re-adjudication)."""
        self.repo.get_source(source_id)
        return self._propose_remediation("revoke_source_trust", [source_id], reason)

    def propose_loosening(self, kind: str, targets: Sequence[str],
                          reason: Optional[str] = None) -> RemediationResult:
        """Loosening (unquarantine_memory, endorse_data, restore_source_trust,
        weaken_restriction): recorded as a proposal only; a human must approve."""
        if direction(kind) != LOOSENING:
            raise ValueError(f"{kind} is not a loosening action; call it directly")
        return self._propose_remediation(kind, targets, reason)

    def approve_remediation(self, action_id: str, *, approver: str,
                            reason: Optional[str] = None) -> GuardDecision:
        """Human approval of a proposed loosening remediation (never callable by the
        Warden itself, never exposed as an MCP tool)."""
        if not approver or approver.strip().lower() in {WARDEN_AGENT, f"system:agent:{WARDEN_AGENT}"}:
            raise ApprovalRefused("the Warden cannot approve its own actions")
        action = self.repo.get_action(action_id)
        if action.action_type not in LOOSENING_ACTIONS:
            raise ValueError(f"{action_id} is not a loosening remediation")
        return self.guard.approve(action_id, approver=approver, reason=reason)

    def execute_approved_remediation(self, action_id: str) -> RemediationResult:
        """Run an approved loosening remediation: the runtime re-runs the Guard, which
        ALLOWs only with a recorded human approval."""
        action = self.repo.get_action(action_id)
        kind = action.metadata.get("remediation", action.action_type)
        if action.action_type not in LOOSENING_ACTIONS or action.agent != WARDEN_AGENT:
            raise ValueError(f"{action_id} is not a Warden loosening remediation")
        targets = []
        for arg in action.args:
            if arg.datum_id not in self.runtime.values:
                d = self.repo.get_datum(arg.datum_id)
                if d.value is not None:
                    self.runtime.values[d.id] = d.value
            if arg.role == "target":
                targets = json.loads(self.runtime.values.get(arg.datum_id, "[]"))
        if action.action_type in NOT_APPLIED_BY_WARDEN:
            d = Guard(self.recorder, self.policy, record_decisions=False).check(action_id)
            return RemediationResult(
                kind=kind, direction=LOOSENING, action_id=action_id, targets=targets,
                status="approved_not_applied" if d.decision == Verdict.ALLOW else "not_executed",
                guard_verdict=d.decision.value, guard_explanation=d.explanation,
                detail={"note": "the Warden never applies restriction changes; a human "
                                "applies them outside Custody's agents"})
        try:
            delivery = self.runtime.execute(action_id)
        except ExecutionDenied as exc:
            d = self.guard.check(action_id)
            return RemediationResult(kind=kind, direction=LOOSENING, action_id=action_id,
                                     targets=targets, status="not_executed",
                                     guard_verdict=d.decision.value,
                                     guard_explanation=str(exc))
        return RemediationResult(kind=kind, direction=LOOSENING, action_id=action_id,
                                 targets=targets, status="executed",
                                 guard_verdict=Verdict.ALLOW.value,
                                 detail=json.loads(delivery.payload))

    def _human_approver(self, action_id: str) -> str:
        humans = [a for a in self.repo.action_approvals(action_id)
                  if a["approver_kind"] == "human" and "human_review" in a["checks"]]
        if not humans:  # the Guard already refused execution in this case; belt and braces
            raise ApprovalRefused(f"{action_id} has no human approval")
        return humans[-1]["approver"]

    def _delivery(self, action_id: str, tool: str, dest: str, payload: Dict[str, Any]) -> Delivery:
        raw = json.dumps(payload, sort_keys=True)
        return Delivery(action_id=action_id, tool=tool, sink_kind="custody_state",
                        destination=dest, workspace=None, payload=raw,
                        payload_fingerprint=fingerprint(raw))

    def _execute_revoke(self, action_id: str, args: Dict[str, str]) -> Delivery:
        from custody.guard.readjudicate import revoke_and_readjudicate

        (sid,) = json.loads(args["target"])
        meta = self.repo.get_action(action_id).metadata
        rep = revoke_and_readjudicate(
            self.guard, sid, approver=f"{WARDEN_AGENT} (requested by {self.operator})",
            reason=meta.get("reason") or None, warden_action_id=action_id)
        return self._delivery(action_id, "revoke_source_trust", f"source:{sid}", {
            "revocation_id": rep.id, "source_id": sid, "trust_before": rep.trust_before,
            "summary": rep.summary, "actions_readjudicated": len(rep.actions)})

    def _execute_unquarantine(self, action_id: str, args: Dict[str, str]) -> Delivery:
        ids = json.loads(args["target"])
        before = self._provenance_footprint(ids)
        lifted = self.repo.lift_quarantine(
            ids, lift_id=new_id("qlift"), lifted_by=WARDEN_AGENT,
            approved_by=self._human_approver(action_id), action_id=action_id, at=utcnow_iso())
        if self._provenance_footprint(ids) != before:
            raise RuntimeError("unquarantine changed the provenance of a memory")
        return self._delivery(action_id, "unquarantine_memory", "memory_store",
                              {"unquarantined": sorted(lifted)})

    def _execute_endorse(self, action_id: str, args: Dict[str, str]) -> Delivery:
        ids = json.loads(args["target"])
        ap = self.guard.endorse(ids, approver=self._human_approver(action_id),
                                reason=f"approved Warden proposal {action_id}")
        return self._delivery(action_id, "endorse_data", "datums",
                              {"endorsement_id": ap.id, "endorsed": ids})

    def _execute_restore(self, action_id: str, args: Dict[str, str]) -> Delivery:
        (sid,) = json.loads(args["target"])
        trust = self.repo.restore_source_trust(
            sid, restoration_id=new_id("rst"), restored_by=WARDEN_AGENT,
            approved_by=self._human_approver(action_id), action_id=action_id, at=utcnow_iso())
        return self._delivery(action_id, "restore_source_trust", f"source:{sid}",
                              {"source_id": sid, "trust": trust})

    def _execute_not_applied(self, action_id: str, args: Dict[str, str]) -> Delivery:
        raise ExecutionDenied("restriction changes are applied by a human, not the Warden")

    # ============================================================= disclosure
    def draft_disclosure(self, action_ids: Sequence[str], notes: Optional[str] = None,
                         claims: Optional[Sequence[Dict[str, Any]]] = None
                         ) -> DraftDisclosureResult:
        """Draft (never send) one disclosure per external recipient.

        Every factual sentence is a cited claim (``custody.warden.citations``): the Warden's
        own claims cite the Action, Sink, provenance path and Sources; ``notes`` (one claim
        per sentence, ids in [brackets]) and ``claims`` ([{"text", "citations"}]) from a
        model are checked the same way. A claim whose ids do not exist or are outside the
        traced incident is removed and listed in ``rejected_claims``."""
        from custody.graph import traversal as T
        from custody.warden import citations as C

        skipped: List[Dict[str, str]] = []
        groups: Dict[tuple, List[Any]] = {}
        for aid in dict.fromkeys(action_ids):
            try:
                action = self.repo.get_action(aid)
            except NotFound:
                skipped.append({"action_id": aid, "reason": "not found"})
                continue
            if action.agent == WARDEN_AGENT:
                skipped.append({"action_id": aid, "reason": "Warden's own action"})
                continue
            if action.status != ActionStatus.EXECUTED:
                skipped.append({"action_id": aid, "reason": f"status {action.status.value}: "
                                "it was never executed, nothing left the organisation"})
                continue
            cls = self.policy.classify_sink(action.sink)
            if not cls.external:
                skipped.append({"action_id": aid, "reason": f"internal sink ({cls.reason})"})
                continue
            groups.setdefault((action.sink.kind, action.sink.destination), []).append(action)

        s = self._ensure_session("draft_disclosure") if groups else None
        drafts: List[DisclosureDraft] = []
        model_claims = C.claims_from_notes(notes) + [
            C.CitedClaim(text=str(c.get("text", "")), citations=list(c.get("citations") or []),
                         origin="model") for c in (claims or [])]
        for (kind, recipient), actions in groups.items():
            scope = C.incident_scope(self.repo, actions, self.guard._limits())
            exposed, secrets, parents, dest_ids = [], [], [], []
            facts: List[C.CitedClaim] = []
            for a in actions:
                facts.append(C.CitedClaim(
                    text=f"On {a.created_at[:10]} an automated assistant at our organisation "
                         f"sent you a {a.action_type} message",
                    citations=[a.id] + ([a.sink.id] if a.sink and a.sink.id else [])))
                w = T.untrusted_origin(self.repo.graph, [x.datum_id for x in a.args],
                                       **self.guard._limits())
                if w.path_found:
                    facts.append(C.CitedClaim(
                        text="Its content was influenced by an untrusted third-party source "
                             f"({w.witness_node_ids[-1]}) through this recorded path",
                        citations=list(w.witness_node_ids), chain=True))
                for arg in a.args:
                    d = self.repo.get_datum(arg.datum_id)
                    lin = self.repo.lineage(arg.datum_id)
                    if arg.role == "destination":
                        dest_ids.append(d.id)
                        parents.append(d.id)
                        continue
                    if lin.max_sensitivity.value == "secret":
                        for e in lin.entries:
                            if e.datum.sensitivity.value == "secret" and e.source:
                                path = e.datum.metadata.get("path") or e.source.id
                                secrets.append(f"{path} (fingerprint …{e.datum.fingerprint[-8:]})")
                                facts.append(C.CitedClaim(
                                    text=f"It included a credential from {path} (value "
                                         "withheld)", citations=[e.datum.id, e.source.id]))
                    else:
                        exposed.append(d.preview)
                        parents.append(d.id)
                        facts.append(C.CitedClaim(text=f"It contained: \u201c{d.preview}\u201d",
                                                  citations=[d.id]))
            ok, rejected = C.verify(self.repo, facts + model_claims, scope)
            secrets = sorted(set(secrets))
            subject = "Security notice: information we sent you may have been manipulated"
            steps = ["Do not act on the instructions, links or endpoints in the message(s) "
                     "listed below; delete them.",
                     "If you already acted on them (e.g. configured an endpoint), revert "
                     "that change and tell us."]
            if secrets:
                steps.append("Treat the credential(s) listed as compromised; we are rotating "
                             "them on our side.")
            own = [c for c in ok if c.origin == "warden"]
            extra = [c for c in ok if c.origin == "model"]
            body_lines = ["Hello,", "",
                          "We are writing about messages an automated assistant at our "
                          "organisation sent you. Each statement below cites the records in "
                          "our provenance graph it is based on.", "", "What happened:"]
            body_lines += [f"  - {c.rendered}." for c in own]
            body_lines += ["", "What we ask you to do:"] + [f"  - {x}" for x in steps]
            if extra:
                body_lines += ["", "Additional details:"] + [f"  - {c.rendered}." for c in extra]
            body_lines += ["", "We are sorry for the trouble. Reply to this message with any "
                           "questions.", "", "— Security team"]
            body = "\n".join(body_lines)
            assert s is not None
            draft = self.recorder.record_llm_output(
                body, agent=WARDEN_AGENT, session_id=s.session_id,
                derived_from=[self.instruction_id, *dict.fromkeys(parents)],
                metadata={"warden_draft": True, "recipient": recipient, "sink_kind": kind,
                          "subject": subject, "action_ids": [a.id for a in actions],
                          "destination_datum_ids": dest_ids,
                          "citations": sorted({c for cl in ok for c in cl.citations})})
            self.runtime.values[draft.id] = body
            drafts.append(DisclosureDraft(
                draft_id=draft.id, recipient=recipient, sink_kind=kind, subject=subject,
                body=body, action_ids=[a.id for a in actions], data_exposed=exposed,
                secrets_exposed=secrets, recommended_steps=steps,
                claims=[c.model_dump() for c in ok],
                rejected_claims=[c.model_dump() for c in rejected],
                citation_scope_complete=scope.complete))
        n_rej = sum(len(d.rejected_claims) for d in drafts)
        summary = (f"{len(drafts)} disclosure draft(s) for {sum(len(d.action_ids) for d in drafts)}"
                   f" executed external action(s); {len(skipped)} action(s) skipped; "
                   f"{n_rej} unsupported claim(s) removed.")
        next_step = ("Review the drafts. To send one, call propose_disclosure(draft_id): the "
                     "Guard checks it and a human must approve it before anything is sent."
                     if drafts else "Nothing to disclose externally.")
        return DraftDisclosureResult(drafts=drafts, skipped=skipped, internal_summary=summary,
                                     next_step=next_step)

    def _draft(self, draft_id: str) -> DatumRecord:
        d = self.repo.get_datum(draft_id)
        if d.agent != WARDEN_AGENT or not d.metadata.get("warden_draft"):
            raise ValueError(f"{draft_id} is not a Warden disclosure draft")
        return d

    def propose_disclosure(self, draft_id: str) -> ProposeDisclosureResult:
        draft = self._draft(draft_id)
        if draft.metadata.get("sink_kind") != "email":
            raise ValueError("only email disclosures can be proposed; send other channels "
                             "manually after review")
        recipient = draft.metadata["recipient"]
        s = self._ensure_session("propose_disclosure")
        body = self.runtime.values.get(draft.id, draft.value or "")
        dest = s.arg("destination", recipient, tool=DISCLOSURE_TOOL,
                     derived_from=[self.instruction_id, draft.id,
                                   *draft.metadata.get("destination_datum_ids", [])],
                     attribution=Attribution.EXACT.value)
        payload = s.arg("payload", body, tool=DISCLOSURE_TOOL, derived_from=[draft.id],
                        attribution=Attribution.INHERIT.value)
        res = self.runtime.propose(
            agent=WARDEN_AGENT, session_id=s.session_id, tool=DISCLOSURE_TOOL,
            arg_datums={"destination": dest.id, "payload": payload.id},
            metadata={"draft_id": draft.id, "subject": draft.metadata.get("subject", ""),
                      "requested_by": self.operator},
            auto_execute=False)
        d: GuardDecision = res.decision
        return ProposeDisclosureResult(
            draft_id=draft.id, action_id=res.action_id, recipient=recipient,
            verdict=d.decision.value, status=d.action_status,
            approval_required=d.decision != Verdict.ALLOW, approval=d.approval.model_dump(),
            explanation=d.explanation, sent=False,
            how_to_approve=(
                "Nothing has been sent. A human approves with "
                f"POST /tenants/<tenant>/guard/actions/{res.action_id}/approve "
                "{\"approver\": \"<you>\"} (or Warden.approve_disclosure / "
                f"`python -m custody.warden approve {res.action_id} --approver <you>`); then "
                f"call send_approved_disclosure('{res.action_id}')."
                if d.decision == Verdict.REQUIRE_HUMAN_APPROVAL else
                "The Guard blocked this disclosure; it cannot be approved."
                if d.decision == Verdict.BLOCK else
                f"Approved; call send_approved_disclosure('{res.action_id}')."))

    def approve_disclosure(self, action_id: str, *, approver: str,
                           reason: Optional[str] = None) -> GuardDecision:
        """Human approval of a proposed disclosure (never callable by the Warden itself)."""
        if not approver or approver.strip().lower() in {WARDEN_AGENT, f"system:agent:{WARDEN_AGENT}"}:
            raise ApprovalRefused("the Warden cannot approve its own actions")
        action = self.repo.get_action(action_id)
        if action.action_type != DISCLOSURE_TOOL:
            raise ValueError(f"{action_id} is not a disclosure")
        return self.guard.approve(action_id, approver=approver, reason=reason)

    def send_approved_disclosure(self, action_id: str) -> SendDisclosureResult:
        action = self.repo.get_action(action_id)
        if action.action_type != DISCLOSURE_TOOL or action.agent != WARDEN_AGENT:
            raise ValueError(f"{action_id} is not a Warden disclosure")
        for arg in action.args:  # e.g. after a server restart: reload non-secret values
            if arg.datum_id not in self.runtime.values:
                d = self.repo.get_datum(arg.datum_id)
                if d.value is not None:
                    self.runtime.values[d.id] = d.value
        try:
            delivery = self.runtime.execute(action_id)
        except ExecutionDenied as exc:
            decision = self.guard.check(action_id)
            return SendDisclosureResult(action_id=action_id, sent=False,
                                        verdict=decision.decision.value,
                                        status=self.repo.get_action(action_id).status.value,
                                        detail=f"not sent: {exc}")
        return SendDisclosureResult(action_id=action_id, sent=True, verdict=Verdict.ALLOW.value,
                                    status=ActionStatus.EXECUTED.value,
                                    destination=delivery.destination,
                                    payload_fingerprint=delivery.payload_fingerprint,
                                    detail="sent after human approval and a fresh Guard ALLOW")
