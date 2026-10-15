"""Domain model for the provenance graph.

Node labels
-----------
- ``Source``                 where information entered the system (user, web, vault, ...)
- ``Datum``                  any piece of information. Every information-bearing node
                             carries this label so a single ``DERIVED_FROM`` traversal
                             covers inputs, LLM outputs, memories, recalls and messages.
- ``Datum:Memory``           a memory saved to shared, cross-session storage
- ``Datum:Recall``           one retrieval of a Memory into a session/agent context
- ``Datum:Message``          an inter-agent message
- ``Action``                 a (proposed) side effect an agent wants to perform
- ``Sink``                   where an Action sends data
- ``Approval``               a human/system endorsement of specific data
- ``Decision``               an audit record of one Guard evaluation of an Action
- ``Quarantine``             a Warden containment record: QUARANTINES memories, VIA an Action
"""
from __future__ import annotations

import hashlib
import json
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- enums
class SourceKind(str, Enum):
    USER = "user"
    WEB = "web"
    VAULT = "vault"
    EMAIL = "email"
    GITHUB = "github"
    SLACK = "slack"
    SYSTEM = "system"


class Trust(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class Sensitivity(str, Enum):
    NORMAL = "normal"
    SENSITIVE = "sensitive"
    SECRET = "secret"

    @property
    def rank(self) -> int:
        return _SENSITIVITY_RANK[self]

    @classmethod
    def max(cls, *values: "Sensitivity | str") -> "Sensitivity":
        levels = [cls(v) for v in values]
        return max(levels, key=lambda s: s.rank) if levels else cls.NORMAL


_SENSITIVITY_RANK = {Sensitivity.NORMAL: 0, Sensitivity.SENSITIVE: 1, Sensitivity.SECRET: 2}


class DatumKind(str, Enum):
    """What produced a Datum. Stored as ``Datum.kind``."""

    USER_INPUT = "user_input"
    WEB_CONTENT = "web_content"
    SECRET = "secret"
    TOOL_OUTPUT = "tool_output"
    LLM_OUTPUT = "llm_output"
    MEMORY = "memory"
    RECALL = "recall"
    MESSAGE = "message"
    TYPED_VALUE = "typed_value"  # value extracted by the quarantined reader


# Datums written by a model call (the ones that have a context window, hence coverage).
MODEL_OUTPUT_KINDS = frozenset({"llm_output", "memory", "message", "typed_value"})

# Extra labels applied on top of :Datum for subtype kinds.
DATUM_SUBTYPE_LABEL: Dict[DatumKind, str] = {
    DatumKind.MEMORY: "Memory",
    DatumKind.RECALL: "Recall",
    DatumKind.MESSAGE: "Message",
    DatumKind.TYPED_VALUE: "Typed",
}


class DerivationOp(str, Enum):
    """Stored on DERIVED_FROM edges as ``op`` to explain *how* data flowed."""

    DERIVE = "derive"    # LLM/tool consumed the parent as context
    SAVE = "save"        # content persisted as a memory
    RECALL = "recall"    # memory retrieved into a session
    SEND = "send"        # content sent as an inter-agent message
    ATTRIBUTE = "attribute"  # exact-value attribution to a trusted supplier
    EXTRACT = "extract"  # quarantined reader extracted a typed value


class ProvenanceCoverage(str, Enum):
    """Stored on model-produced Datums (``llm_output``, ``memory``, ``message``,
    ``typed_value``) as ``coverage``: what the recorded DERIVED_FROM edges cover.

    - ``FULL_CONTEXT``: edges were recorded to everything that was in the producing model
      call's context window (the soundness contract; exact-value attribution keeps those
      edges, marking the non-supplier ones ``context``, so it stays FULL_CONTEXT).
    - ``REDUCED``: a narrower attribution method was used (e.g. only cited/retrieved
      items were linked). Negative claims over such a Datum cannot be exhaustive.

    A model-produced Datum without the property (older data) is treated as REDUCED.
    """

    FULL_CONTEXT = "FULL_CONTEXT"
    REDUCED = "REDUCED"


class Attribution(str, Enum):
    """Stored on DERIVED_FROM edges as ``attribution``.

    - ``inherit``: the child inherits everything from this parent (default; legacy
      edges without the property are treated as ``inherit``).
    - ``exact``:   the child's value exactly matches a value this (trusted) parent
      supplied, so the child is attributed to it.
    - ``context``: the parent was in the model's context but the child's value was
      attributed elsewhere (exact match). Kept for audit; the Guard does NOT follow it.
    """

    INHERIT = "inherit"
    EXACT = "exact"
    CONTEXT = "context"


class RiskTier(str, Enum):
    LOW = "low"
    HIGH = "high"


class ActionStatus(str, Enum):
    PROPOSED = "proposed"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    BLOCKED = "blocked"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"


class ArgRole(str, Enum):
    DESTINATION = "destination"
    PAYLOAD = "payload"


# --------------------------------------------------------------------------- helpers
class _Deterministic:
    """Counter-based ids and a fixed, ticking clock (see ``deterministic_ids``)."""

    def __init__(self, seed: str, start: datetime) -> None:
        self.seed = hashlib.sha256(seed.encode()).hexdigest()[:6]
        self.n = 0
        self.t = start
        self.ticks = 0

    def next_id(self, prefix: str) -> str:
        self.n += 1
        return f"{prefix}_{self.seed}{self.n:010d}"

    def now(self) -> datetime:
        self.ticks += 1
        return self.t + timedelta(milliseconds=self.ticks)


_DETERMINISTIC: ContextVar[Optional[_Deterministic]] = ContextVar("custody_deterministic",
                                                                   default=None)


@contextmanager
def deterministic_ids(seed: str = "demo",
                      start: datetime = datetime(2026, 1, 1, tzinfo=timezone.utc)):
    """Within this block ``new_id`` and ``utcnow_iso`` are deterministic, so a scripted
    scenario produces an identical graph every time (used to restore the public demo)."""
    token = _DETERMINISTIC.set(_Deterministic(seed, start))
    try:
        yield
    finally:
        _DETERMINISTIC.reset(token)


def utcnow_iso() -> str:
    det = _DETERMINISTIC.get()
    now = det.now() if det is not None else datetime.now(timezone.utc)
    return now.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    det = _DETERMINISTIC.get()
    if det is not None:
        return det.next_id(prefix)
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def fingerprint(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def safe_preview(value: str, sensitivity: Sensitivity, max_len: int = 200) -> str:
    """Preview safe to show in UIs / logs. Secrets are masked."""
    if sensitivity == Sensitivity.SECRET:
        tail = value[-4:] if len(value) >= 12 else ""
        return f"[secret:{len(value)} chars]" + (f"…{tail}" if tail else "")
    return value if len(value) <= max_len else value[: max_len - 1] + "…"


def dump_metadata(metadata: Optional[Dict[str, Any]]) -> str:
    # FalkorDB properties cannot hold maps, so metadata is stored as JSON text.
    return json.dumps(metadata or {}, sort_keys=True, default=str)


def load_metadata(raw: Optional[str]) -> Dict[str, Any]:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return {}


# --------------------------------------------------------------------------- records
class SourceRecord(BaseModel):
    id: str
    kind: SourceKind
    trust: Trust
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: str


class DatumRecord(BaseModel):
    id: str
    kind: DatumKind
    labels: List[str] = Field(default_factory=lambda: ["Datum"])
    value: Optional[str] = None  # never populated for secrets
    preview: str
    fingerprint: str
    sensitivity: Sensitivity
    endorsed: bool = False
    created_at: str
    agent: Optional[str] = None
    session_id: Optional[str] = None
    source_id: Optional[str] = None
    parent_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    # label-creep mitigation: "inherit" (default) or "exact" (see Attribution)
    attribution: str = Attribution.INHERIT.value
    # quarantined/typed reader: a constrained value extracted from untrusted content
    quarantined: bool = False
    value_type: Optional[str] = None
    max_risk: Optional[RiskTier] = None
    # Warden containment of a Memory. Deliberately NOT ``quarantined``: that flag marks a
    # typed value from the quarantined reader, which the Guard treats as a *limited* path.
    in_quarantine: bool = False
    quarantine_id: Optional[str] = None
    # provenance coverage of a model-produced Datum (see ProvenanceCoverage); None for
    # inputs (user, web, vault, tool output, recall), which have no context window
    coverage: Optional[str] = None

    @property
    def is_memory(self) -> bool:
        return "Memory" in self.labels

    @property
    def is_message(self) -> bool:
        return "Message" in self.labels


class SinkRecord(BaseModel):
    id: str
    destination: str
    kind: str
    external: bool  # as declared by the caller; the Guard re-classifies deterministically
    workspace: Optional[str] = None  # e.g. Slack workspace for kind == "slack"


class ActionArg(BaseModel):
    role: str
    datum_id: str


class ActionRecord(BaseModel):
    id: str
    action_type: str
    agent: str
    status: ActionStatus
    created_at: str
    session_id: Optional[str] = None
    args: List[ActionArg] = Field(default_factory=list)
    sink: Optional[SinkRecord] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ApprovalRecord(BaseModel):
    id: str
    approver: str
    approver_kind: str = "human"
    reason: Optional[str] = None
    created_at: str
    endorsed_ids: List[str] = Field(default_factory=list)
    action_id: Optional[str] = None
    # Guard checks this approval clears for ``action_id`` only (action-scoped approval)
    checks: List[str] = Field(default_factory=list)
    # "approved" (ENDORSES / APPROVES) or "rejected" (REJECTS the action; clears nothing)
    verdict: str = "approved"
    # ENDORSES with egress=True: the human also pre-approves sending secret data to the
    # destination value this Datum holds (see Guard: secret-egress endorsement)
    egress: bool = False


# ---- read models for provenance traces (facts only, no policy decisions) ----
class LineageEntry(BaseModel):
    datum: DatumRecord
    depth: int
    source: Optional[SourceRecord] = None


class Lineage(BaseModel):
    root_id: str
    entries: List[LineageEntry]

    @property
    def sources(self) -> List[SourceRecord]:
        seen: Dict[str, SourceRecord] = {}
        for e in self.entries:
            if e.source and e.source.id not in seen:
                seen[e.source.id] = e.source
        return list(seen.values())

    @property
    def untrusted_sources(self) -> List[SourceRecord]:
        return [s for s in self.sources if s.trust == Trust.UNTRUSTED]

    @property
    def max_sensitivity(self) -> Sensitivity:
        return Sensitivity.max(*(e.datum.sensitivity for e in self.entries))


class ProvenancePath(BaseModel):
    node_ids: List[str]
    ops: List[str]
    length: int


class ArgTrace(BaseModel):
    role: str
    datum_id: str
    lineage: Lineage


class ActionTrace(BaseModel):
    action: ActionRecord
    args: List[ArgTrace]


class QuarantineRecord(BaseModel):
    """Warden containment: these memories are withheld from normal shared-memory retrieval."""

    id: str
    memory_ids: List[str]
    action_id: Optional[str] = None   # the Guard-checked Action that performed it
    actor: str = "warden"
    reason: Optional[str] = None
    incident_id: Optional[str] = None
    created_at: str
