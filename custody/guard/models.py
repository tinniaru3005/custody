"""Structured Guard decisions."""
from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from custody.graph.traversal import ProvenanceSearch, SearchOutcome


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"
    BLOCK = "BLOCK"


class CheckName(str, Enum):
    INTEGRITY = "integrity"
    CONFIDENTIALITY = "confidentiality"
    LETHAL_TRIFECTA = "lethal_trifecta"
    HUMAN_REVIEW = "human_review"   # action type always needs an explicit human approval
    PRECEDENT = "precedent"         # a human already rejected secret data to this same Sink


class PathNode(BaseModel):
    id: str
    labels: List[str]
    kind: Optional[str] = None          # datum kind, or source kind for the Source node
    agent: Optional[str] = None
    session_id: Optional[str] = None
    preview: Optional[str] = None       # masked for secrets
    sensitivity: Optional[str] = None
    endorsed: bool = False
    quarantined: bool = False
    trust: Optional[str] = None         # only on the Source node


class PathEvidence(BaseModel):
    """One concrete provenance path found by a Cypher query."""

    check: CheckName
    arg_role: str
    arg_datum_id: str
    nodes: List[PathNode]               # arg datum ... origin datum [, Source]
    ops: List[str]                      # op of each hop (derive/save/recall/send/attribute/extract/FROM)
    length: int                         # number of DERIVED_FROM hops
    status: str                         # violating | cleared | limited | info
    cleared_by: List[str] = Field(default_factory=list)  # approval ids (endorsements)
    endorsed_datum_ids: List[str] = Field(default_factory=list)
    typed_datum_ids: List[str] = Field(default_factory=list)
    sessions: List[str] = Field(default_factory=list)
    agents: List[str] = Field(default_factory=list)
    text: str = ""                      # one-line rendering


class SourceInfo(BaseModel):
    id: str
    kind: str
    trust: str
    reached_from: List[str] = Field(default_factory=list)  # arg datum ids


class RootRoute(BaseModel):
    """One distinct untrusted root of the destination and a representative route to it."""

    source_id: str
    source_kind: Optional[str] = None
    source_label: Optional[str] = None     # URL / ref, if recorded
    entry_datum_id: str                    # the Datum that came FROM the source
    hops: int                              # DERIVED_FROM hops of the representative route
    path: PathEvidence                     # the shortest route to this root (display only)


class ContaminationReport(BaseModel):
    """Distinct untrusted roots and whether the contamination routes are independent.

    Explanation only, computed after the verdict; see custody/guard/contamination.py."""

    root_count: int                        # distinct untrusted roots reached
    roots_complete: bool                   # False: the root search hit a limit ("at least")
    roots: List[RootRoute] = Field(default_factory=list)   # closest first (capped)
    independence: str                      # independent | converging | direct | unverified
    independent_routes: int = 1            # node-disjoint routes established (lower bound)
    method: Optional[str] = None           # disjoint_routes | no_single_shared_datum | shared_datum
    shared_datum_id: Optional[str] = None  # every route passes through it (converging)
    extra_routes: List[PathEvidence] = Field(default_factory=list)  # disjoint routes 2..
    detail: str = ""
    checks_run: int = 0
    latency_ms: float = 0.0
    note: str = ("Explanation only. The verdict comes from the complete integrity search "
                 "(does any uncleared route exist), not from these routes or their length.")


class SinkInfo(BaseModel):
    id: Optional[str] = None
    kind: Optional[str] = None
    destination: Optional[str] = None
    workspace: Optional[str] = None
    declared_external: Optional[bool] = None
    external: bool                      # Guard's classification (authoritative)
    zone: str
    reason: str
    bound: Optional[bool] = None        # destination literal matches a destination arg datum


class Precedent(BaseModel):
    """A prior human rejection that escalates the current decision (exact graph facts)."""

    rejected_action_id: str
    rejected_action_type: str
    approval_id: str                    # the (:Approval {verdict:'rejected'}) node
    approver: str
    reason: Optional[str] = None
    rejected_at: Optional[str] = None
    sink_id: str
    sink_destination: Optional[str] = None
    secret_payload_datum_ids: List[str] = Field(default_factory=list)
    relationship: str                   # the graph pattern, with ids, that matched


class CheckResult(BaseModel):
    name: CheckName
    evaluated: bool = True
    violated: bool = False
    raw_violation: bool = False         # before action-scoped approvals
    detail: str = ""
    paths: List[PathEvidence] = Field(default_factory=list)
    cleared_by_action_approval: List[str] = Field(default_factory=list)
    latency_ms: float = 0.0
    query: Optional[str] = None         # name of the Cypher query used
    # Complete provenance search behind the verdict (integrity / confidentiality only).
    # outcome PATH_FOUND | NO_PATH | INDETERMINATE; INDETERMINATE counts as violated.
    search: Optional[ProvenanceSearch] = None
    # confidentiality: human secret-egress endorsements that cleared it (Approval ids)
    cleared_by_endorsement: List[str] = Field(default_factory=list)
    precedents: List[Precedent] = Field(default_factory=list)   # precedent check only

    @property
    def outcome(self) -> Optional[SearchOutcome]:
        return self.search.outcome if self.search else None


class ApprovalOption(BaseModel):
    available: bool
    reason: str
    endorse_datum_ids: List[str] = Field(default_factory=list)  # data-level ENDORSES
    approve_checks: List[str] = Field(default_factory=list)     # action-scoped APPROVES


class RootSource(BaseModel):
    """A Source reached in the complete recorded ancestor graph of the destination."""

    id: str
    kind: Optional[str] = None
    trust: Optional[str] = None
    datum_ids: List[str] = Field(default_factory=list)  # ancestor Datums that came FROM it
    min_depth: int = 0                  # DERIVED_FROM hops from the destination argument
    # followed:     on a path the Guard follows (for an ALLOW, always a trusted Source)
    # context_only: reached only through attribution='context' edges (exact-value
    #               attribution: a trusted Datum supplied the value verbatim)
    # cleared:      every Guard-followed path to it passes through endorsed/typed data
    status: str
    note: str = ""


class ProvenanceCertificate(BaseModel):
    """Evidence for an ALLOW: the negative claim, made precise and tied to a graph state.

    Issued only when the Guard's integrity search was a complete NO_PATH, a second
    traversal of the complete recorded ancestor graph (all DERIVED_FROM edges, context
    edges included) also ran to exhaustion, and the graph version did not change while the
    check ran. It certifies the recorded graph, not that the action is safe.
    """

    id: str
    action_id: str
    decision_id: str
    issued_at: str
    claim: str
    scope: str
    untrusted_influence: str = "NONE_FOUND"
    traversal_complete: bool
    frontier_exhausted: bool
    termination_reason: str
    root_sources_checked: int
    root_sources: List[RootSource]
    untrusted_roots_not_followed: int    # present in the ancestry, excluded with a reason
    max_depth_reached: int
    nodes_examined: int
    relationships_examined: int          # DERIVED_FROM + FROM edges
    derived_from_edges_examined: int
    context_edges_examined: int
    context_provenance_included: bool
    guard_followed_nodes: int            # nodes on Guard-followed paths (integrity search)
    graph: str
    graph_version: int                   # completed provenance writes (see GraphVersion)
    graph_version_label: str
    ancestry_digest: str                 # sha256 of the examined nodes, edges and roots
    payload: str                         # confidentiality outcome, for completeness
    guard_latency_ms: float = 0.0
    certificate_latency_ms: float = 0.0
    integrity_search: Optional[ProvenanceSearch] = None
    ancestor_search: Optional[ProvenanceSearch] = None
    limits: Dict[str, Optional[int]] = Field(default_factory=dict)
    # Provenance coverage of every model-produced Datum in the ancestry examined:
    # FULL_CONTEXT only if all of them recorded edges to their whole context window.
    provenance_coverage: str = "FULL_CONTEXT"          # FULL_CONTEXT | REDUCED
    strength: str = "STRONG"                           # STRONG | DOWNGRADED
    reduced_provenance_count: int = 0
    reduced_provenance: List[Dict[str, Optional[str]]] = Field(default_factory=list)  # ≤20
    trust_labels_note: str = (
        "Source trust labels are policy inputs (set by whoever registered the Source or "
        "by tenant policy), not facts Custody infers. Every reached root Source is listed "
        "with its label so the assumption can be audited.")
    # Deterministic fingerprint of the decision state (action, destination, ancestry and
    # roots with trust labels, graph + version, coverage, policy). Same state -> same id;
    # any relevant change -> a different id. A comparison/re-check handle, not a proof.
    certificate_id: str = ""
    certificate_id_inputs: List[str] = Field(default_factory=list)


class GuardDecision(BaseModel):
    id: str
    action_id: str
    action_type: str
    agent: str
    action_status: str
    decision: Verdict
    triggered_checks: List[CheckName] = Field(default_factory=list)
    explanation: str
    checks: Dict[str, CheckResult]
    paths: List[PathEvidence] = Field(default_factory=list)
    sources: List[SourceInfo] = Field(default_factory=list)
    sink: SinkInfo
    approval: ApprovalOption
    latency_ms: Dict[str, float]
    policy: str
    evaluated_at: str
    deterministic: bool = True          # no model was consulted
    # False if any provenance search was INDETERMINATE (depth/node limit, timeout, query
    # error). Such a decision is never ALLOW: unknown provenance is treated as violating.
    search_complete: bool = True
    indeterminate_checks: List[CheckName] = Field(default_factory=list)
    # Provenance Completeness Certificate: only for ALLOW decisions whose negative claim is
    # backed by complete traversals at a stable graph version; otherwise the reason.
    certificate: Optional[ProvenanceCertificate] = None
    certificate_unavailable: Optional[str] = None
    # Distinct untrusted roots of the destination + route independence (explanation only;
    # computed when the integrity check found an uncleared route).
    contamination: Optional[ContaminationReport] = None

    @property
    def allowed(self) -> bool:
        return self.decision == Verdict.ALLOW


class ApprovalRefused(PermissionError):
    """The policy does not allow this approval (e.g. a lethal-trifecta action)."""
