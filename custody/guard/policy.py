"""Static, deterministic Guard policy: which actions are checked and which sinks are internal.

Nothing here calls a model. A sink's ``external`` flag as declared by the agent/tool is
advisory only; the Guard re-classifies every sink from the tenant policy and fails
closed (unknown kinds and unparseable destinations are external).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from email.utils import parseaddr
from typing import Dict, FrozenSet, Optional
from collections.abc import Mapping
from urllib.parse import urlsplit

from custody.graph.model import RiskTier, SinkRecord


@dataclass(frozen=True)
class ActionPolicy:
    outbound: bool
    irreversible: bool
    risk: RiskTier = RiskTier.HIGH
    # Always require an explicit human approval (check "human_review"), even when every
    # provenance check passes. Used for Warden's external disclosures.
    human_review: bool = False

    @property
    def guarded(self) -> bool:
        return self.outbound or self.irreversible


# Unknown action types are treated as outbound, irreversible and high risk (fail closed).
UNKNOWN_ACTION = ActionPolicy(outbound=True, irreversible=True, risk=RiskTier.HIGH)

DEFAULT_ACTIONS: Mapping[str, ActionPolicy] = {
    # outbound, high risk
    "send_email": ActionPolicy(True, True, RiskTier.HIGH),
    "post_slack": ActionPolicy(True, True, RiskTier.HIGH),
    "upload_backup": ActionPolicy(True, True, RiskTier.HIGH),
    "http_post": ActionPolicy(True, True, RiskTier.HIGH),
    "configure_backup": ActionPolicy(True, True, RiskTier.HIGH),
    # Warden: external incident disclosures always need a human, on top of normal checks
    "send_disclosure": ActionPolicy(True, True, RiskTier.HIGH, human_review=True),
    # irreversible but low risk: internal bookkeeping
    "update_ticket": ActionPolicy(False, True, RiskTier.LOW),
    "add_ticket_comment": ActionPolicy(False, True, RiskTier.LOW),
    # Warden: containment of shared memories (internal state change, no sink)
    "quarantine_memory": ActionPolicy(False, True, RiskTier.LOW),
    # Warden remediation (custody/warden/remediation.py): tightening may run on ALLOW,
    # loosening always needs a human (human_review)
    "revoke_source_trust": ActionPolicy(False, True, RiskTier.LOW),
    "unquarantine_memory": ActionPolicy(False, True, RiskTier.HIGH, human_review=True),
    "endorse_data": ActionPolicy(False, True, RiskTier.HIGH, human_review=True),
    "restore_source_trust": ActionPolicy(False, True, RiskTier.HIGH, human_review=True),
    "weaken_restriction": ActionPolicy(False, True, RiskTier.HIGH, human_review=True),
    # neither outbound nor irreversible: not checked
    "read_file": ActionPolicy(False, False, RiskTier.LOW),
    "search_memory": ActionPolicy(False, False, RiskTier.LOW),
}

URL_SINK_KINDS = frozenset({"http", "https", "url", "webhook", "backup", "upload_backup",
                            "http_post", "configure_backup"})


@dataclass(frozen=True)
class SinkClassification:
    external: bool
    zone: str  # "internal" | "external"
    reason: str


def _host_matches(host: str, allowed: FrozenSet[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in allowed)


@dataclass(frozen=True)
class GuardPolicy:
    name: str = "default"
    version: str = "1"
    internal_email_domains: FrozenSet[str] = frozenset()
    internal_slack_workspaces: FrozenSet[str] = frozenset()
    # Slack Connect / shared channels inside an internal workspace that other orgs can read
    shared_slack_channels: FrozenSet[str] = frozenset()
    internal_hosts: FrozenSet[str] = frozenset()
    internal_ticket_systems: FrozenSet[str] = frozenset()
    actions: Mapping[str, ActionPolicy] = field(default_factory=lambda: dict(DEFAULT_ACTIONS))
    destination_roles: FrozenSet[str] = frozenset({"destination"})
    # Depth of the bounded path-enumeration queries that produce *evidence* (explanations,
    # UI). Verdicts do not depend on it: they come from complete reachability searches
    # (custody.graph.traversal) that run until the reachable graph is exhausted.
    max_depth: int = 25
    path_limit: int = 50
    # Resource bounds for the complete searches. Hitting any of them makes the search
    # INDETERMINATE, which the Guard treats as a violation (fail closed), never as clean.
    # search_max_depth=None means no depth bound.
    search_max_depth: Optional[int] = None
    search_max_nodes: int = 100_000
    search_timeout_ms: Optional[int] = 2_000
    # Server-side timeout for the bounded *evidence* queries. Path enumeration can be
    # exponential in dense DAGs (multi-turn sessions); if it times out the decision keeps
    # only the complete search's witness path as evidence. Verdicts are unaffected.
    evidence_timeout_ms: int = 250
    # Escalate REQUIRE_HUMAN_APPROVAL → BLOCK when a human already REJECTED a secret-bearing
    # action to the same Sink and this payload is secret (deterministic precedent).
    precedent_escalation: bool = True
    # Allow a human "secret egress" endorsement of a destination value to clear the
    # confidentiality check (integrity must be clean and the value must match exactly).
    egress_endorsements: bool = True
    # Explanation of an integrity violation: every distinct untrusted root, one route per
    # root and whether routes are independent (custody/guard/contamination.py). Runs after
    # the verdict and never changes it; bounded by its own time / search budget.
    contamination_analysis: bool = True
    contamination_timeout_ms: int = 1_000
    contamination_max_checks: int = 25

    def action(self, action_type: str) -> ActionPolicy:
        return self.actions.get(action_type, UNKNOWN_ACTION)

    def classify_sink(self, sink: Optional[SinkRecord]) -> SinkClassification:
        if sink is None:
            return SinkClassification(False, "none", "action has no sink")
        kind = (sink.kind or "").lower()
        dest = (sink.destination or "").strip()
        if kind == "email":
            _, addr = parseaddr(dest)
            if "@" not in addr:
                return SinkClassification(True, "external", f"unparseable email {dest!r}")
            domain = addr.rsplit("@", 1)[1]
            if _host_matches(domain, self.internal_email_domains):
                return SinkClassification(False, "internal", f"email domain {domain} is internal")
            return SinkClassification(True, "external", f"email domain {domain} is not internal")
        if kind == "slack":
            ws = (sink.workspace or "").lower()
            if ws not in self.internal_slack_workspaces:
                return SinkClassification(True, "external",
                                          f"Slack workspace {ws or '?'} is not internal")
            if dest.lower() in self.shared_slack_channels:
                return SinkClassification(True, "external",
                                          f"{dest} is a shared (Slack Connect) channel")
            return SinkClassification(False, "internal",
                                      f"Slack channel {dest} in internal workspace {ws}")
        if kind in URL_SINK_KINDS:
            parts = urlsplit(dest)
            host = parts.hostname or ""
            if parts.scheme not in ("https", "http") or not host:
                return SinkClassification(True, "external", f"unparseable URL {dest!r}")
            if _host_matches(host, self.internal_hosts):
                return SinkClassification(False, "internal", f"host {host} is internal")
            return SinkClassification(True, "external", f"host {host} is not internal")
        if kind == "ticket":
            ws = (sink.workspace or "").lower()
            if ws in self.internal_ticket_systems:
                return SinkClassification(False, "internal", f"ticket system {ws} is internal")
            return SinkClassification(True, "external", f"ticket system {ws or '?'} unknown")
        return SinkClassification(True, "external", f"unknown sink kind {kind!r} (fail closed)")


DEFAULT_POLICY = GuardPolicy()

ACME_POLICY = GuardPolicy(
    name="acme-robotics",
    internal_email_domains=frozenset({"acme-robotics.example"}),
    internal_slack_workspaces=frozenset({"acme-robotics"}),
    shared_slack_channels=frozenset({"#ext-rivalbots-partners"}),
    internal_hosts=frozenset({"acme-robotics.example"}),
    internal_ticket_systems=frozenset({"acme-jira"}),
)

_TENANT_POLICIES: Dict[str, GuardPolicy] = {"acme": ACME_POLICY}


def register_policy(tenant: str, policy: GuardPolicy) -> None:
    _TENANT_POLICIES[tenant] = policy


def policy_for_tenant(tenant: str) -> GuardPolicy:
    return _TENANT_POLICIES.get(tenant, DEFAULT_POLICY)
