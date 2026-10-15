"""Warden's remediation policy: asymmetric, explicit, deterministic.

Security-TIGHTENING actions may execute automatically when the Guard ALLOWs them:

    quarantine_memory        a memory stops being returned by search / recall
    disable_memory_recall    the same operation (quarantine), named for what it does
    revoke_source_trust      a Source is marked untrusted from now on; history is
                             re-adjudicated (custody.guard.readjudicate)

Security-LOOSENING actions are only ever *proposed* by the Warden. Policy marks them
``human_review``, so the Guard returns REQUIRE_HUMAN_APPROVAL however clean the
provenance is; they never auto-execute; a human approves through the Guard (agents and the
Warden are refused); execution re-runs the Guard and needs that approval:

    unquarantine_memory      end a memory's quarantine (append-only QuarantineLift)
    endorse_data             a human endorsement of previously untrusted data
    restore_source_trust     undo a trust revocation (append-only TrustRestoration)
    weaken_restriction       any other relaxation (e.g. a policy change): recordable and
                             approvable, but never applied by the Warden

Every remediation is an Action recorded through the Recorder and decided by the same
``Guard.enforce`` as any agent's action. Nothing here bypasses the Guard.
"""
from __future__ import annotations

from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from custody.guard.policy import ActionPolicy
from custody.graph.model import RiskTier

TIGHTENING = "tightening"
LOOSENING = "loosening"

# kind -> (direction, recorded action type, what it targets)
REMEDIATION_POLICY: Dict[str, Dict[str, str]] = {
    "quarantine_memory": {"direction": TIGHTENING, "action": "quarantine_memory",
                          "target": "memory"},
    "disable_memory_recall": {"direction": TIGHTENING, "action": "quarantine_memory",
                              "target": "memory"},
    "revoke_source_trust": {"direction": TIGHTENING, "action": "revoke_source_trust",
                            "target": "source"},
    "unquarantine_memory": {"direction": LOOSENING, "action": "unquarantine_memory",
                            "target": "memory"},
    "endorse_data": {"direction": LOOSENING, "action": "endorse_data", "target": "datum"},
    "restore_source_trust": {"direction": LOOSENING, "action": "restore_source_trust",
                             "target": "source"},
    "weaken_restriction": {"direction": LOOSENING, "action": "weaken_restriction",
                           "target": "restriction"},
}
TIGHTENING_ACTIONS = frozenset(v["action"] for v in REMEDIATION_POLICY.values()
                               if v["direction"] == TIGHTENING)
LOOSENING_ACTIONS = frozenset(v["action"] for v in REMEDIATION_POLICY.values()
                              if v["direction"] == LOOSENING)
NOT_APPLIED_BY_WARDEN = frozenset({"weaken_restriction"})

# Guard policy for remediation action types. Both are guarded (irreversible), so the Guard
# always evaluates them; loosening ones always need a human (human_review).
TIGHTENING_POLICY = ActionPolicy(outbound=False, irreversible=True, risk=RiskTier.LOW)
LOOSENING_POLICY = ActionPolicy(outbound=False, irreversible=True, risk=RiskTier.HIGH,
                                human_review=True)


def direction(kind: str) -> str:
    if kind not in REMEDIATION_POLICY:
        raise ValueError(f"unknown remediation {kind!r}; known: {sorted(REMEDIATION_POLICY)}")
    return REMEDIATION_POLICY[kind]["direction"]


class RemediationResult(BaseModel):
    kind: str
    direction: Literal["tightening", "loosening"]
    status: Literal["executed", "pending_approval", "blocked", "rejected", "approved_not_applied",
                    "nothing_to_do", "not_executed"]
    action_id: Optional[str] = None
    targets: List[str] = Field(default_factory=list)
    guard_verdict: Optional[str] = None
    guard_explanation: Optional[str] = None
    detail: Dict[str, object] = Field(default_factory=dict)
    how_to_approve: Optional[str] = None
    policy: str = ("tightening: may execute automatically on Guard ALLOW; loosening: "
                   "proposal only, a human must approve and the Guard re-checks")
