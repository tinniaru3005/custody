"""simulate_policy: "if this policy had been enabled earlier, what would have happened?"

The live tenant graph is never written:

1. ``GRAPH.COPY`` the tenant graph into a throwaway sandbox (``GraphSandbox``), or, if the
   server cannot copy, fall back to a ``GRAPH.RO_QUERY``-only view of the live graph.
2. Re-run the deterministic Guard on every recorded Action inside the sandbox twice —
   under the tenant's current policy (baseline) and under the hypothetical one — with
   ``record_decisions=False`` (no Decision nodes, not even on the clone).
3. Optionally apply a hypothetical quarantine: actions whose arguments derive (directly)
   from a recall of those memories are reported as prevented, because the recall would
   have been refused.
4. Delete the clone; compare node/relationship counts of the live graph before and after.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any, Dict, List

from custody.graph.model import ActionStatus, RiskTier
from custody.graph.repository import GraphRepository
from custody.guard.models import Verdict
from custody.guard.policy import ActionPolicy, GuardPolicy
from custody.guard.service import Guard
from custody.recorder.service import Recorder
from custody.warden import queries as Q
from custody.warden.models import PolicySpec, SimulatedAction, SimulationResult
from custody.warden.sandbox import GraphSandbox


def build_policy(base: GuardPolicy, spec: PolicySpec) -> GuardPolicy:
    changes: Dict[str, Any] = {"name": spec.name, "version": "sim"}
    for f in ("internal_email_domains", "internal_slack_workspaces", "shared_slack_channels",
              "internal_hosts", "internal_ticket_systems"):
        v = getattr(spec, f)
        if v is not None:
            changes[f] = frozenset(x.lower() if f != "shared_slack_channels" else x for x in v)
    actions = dict(base.actions)
    for name, a in spec.actions.items():
        actions[name] = ActionPolicy(a.outbound, a.irreversible, RiskTier(a.risk), a.human_review)
    for name in spec.human_review_action_types:
        cur = base.action(name)
        actions[name] = replace(actions.get(name, cur), human_review=True)
    changes["actions"] = actions
    if spec.max_depth:
        changes["max_depth"] = spec.max_depth
    return replace(base, **changes)


def simulate_policy(db: Any, live_repo: GraphRepository, current: GuardPolicy,
                    spec: PolicySpec, prefer_copy: bool = True) -> SimulationResult:
    hypothetical = build_policy(current, spec)
    before = live_repo.counts()
    rows: List[SimulatedAction] = []
    with GraphSandbox(db, live_repo.graph, prefer_copy=prefer_copy) as sb:
        repo = GraphRepository(sb.graph)
        rec = Recorder(repo, max_trace_depth=max(current.max_depth, hypothetical.max_depth))
        base_guard = Guard(rec, current, record_decisions=False)
        sim_guard = Guard(rec, hypothetical, record_decisions=False)
        prevented: Dict[str, List[str]] = {}
        if spec.quarantined_memory_ids:
            for aid, mid in sb.graph.ro_query(
                    Q.actions_depending_on_recalls(hypothetical.max_depth),
                    {"mids": list(spec.quarantined_memory_ids)}).result_set:
                prevented.setdefault(aid, []).append(mid)
        for a, k in sb.graph.ro_query(Q.ALL_ACTIONS).result_set:
            p = a.properties
            aid = p["id"]
            b = base_guard.check(aid)
            s = sim_guard.check(aid)
            prev = aid in prevented
            expl = s.explanation
            if prev:
                expl = (f"Would not have been proposed: depends on a recall of quarantined "
                        f"memor{'y' if len(prevented[aid]) == 1 else 'ies'} "
                        f"{', '.join(sorted(set(prevented[aid])))}. " + expl)
            rows.append(SimulatedAction(
                action_id=aid, action_type=p["action_type"], agent=p["agent"],
                status=p["status"], executed=p["status"] == ActionStatus.EXECUTED.value,
                sink_destination=k.properties.get("destination") if k is not None else None,
                baseline=b.decision.value, simulated=s.decision.value,
                changed=(b.decision != s.decision) or prev,
                simulated_triggered=[c.value for c in s.triggered_checks],
                prevented_by_quarantine=prev, explanation=expl))
    after = live_repo.counts()

    blocked = [r.action_id for r in rows if r.simulated == Verdict.BLOCK.value]
    approval = [r.action_id for r in rows if r.simulated == Verdict.REQUIRE_HUMAN_APPROVAL.value]
    new_block = [r.action_id for r in rows
                 if r.simulated == Verdict.BLOCK.value and r.baseline != Verdict.BLOCK.value]
    new_appr = [r.action_id for r in rows if r.simulated == Verdict.REQUIRE_HUMAN_APPROVAL.value
                and r.baseline == Verdict.ALLOW.value]
    prevented_ids = [r.action_id for r in rows if r.prevented_by_quarantine]
    stopped = [r.action_id for r in rows if r.executed and
               (r.simulated != Verdict.ALLOW.value or r.prevented_by_quarantine)]
    unchanged = before == after
    summary = (f"Under '{hypothetical.name}': {len(blocked)} action(s) would be blocked, "
               f"{len(approval)} would need human approval "
               f"({len(new_block)} newly blocked, {len(new_appr)} newly sent for approval vs. "
               f"'{current.name}')")
    if prevented_ids:
        summary += f"; {len(prevented_ids)} prevented by the hypothetical quarantine"
    if stopped:
        summary += (f". {len(stopped)} action(s) that actually EXECUTED would have been "
                    f"stopped: {', '.join(stopped)}")
    summary += f". Isolation: {sb.mode}; live graph unchanged: {unchanged}."
    return SimulationResult(
        policy_name=hypothetical.name, baseline_policy=f"{current.name}@{current.version}",
        isolation=sb.info(), actions=rows, would_block=blocked, would_require_approval=approval,
        newly_blocked=new_block, newly_require_approval=new_appr,
        prevented_by_quarantine=prevented_ids, executed_but_would_have_been_stopped=stopped,
        live_graph_unchanged=unchanged, summary=summary)
