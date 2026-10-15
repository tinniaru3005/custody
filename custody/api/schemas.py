"""Request bodies for the Recorder API (responses reuse custody.graph.model records)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from custody.graph.model import ActionStatus, ProvenanceCoverage, Sensitivity, SourceKind, Trust


class _Base(BaseModel):
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    id: Optional[str] = Field(default=None, description="Optional client-supplied id")


class SourceIn(BaseModel):
    id: str
    kind: SourceKind
    trust: Trust
    metadata: Dict[str, Any] = Field(default_factory=dict)


class UserInputIn(_Base):
    text: str
    user: str
    agent: Optional[str] = None
    sensitivity: Sensitivity = Sensitivity.NORMAL


class WebContentIn(_Base):
    content: str
    url: str
    agent: Optional[str] = None


class ExternalContentIn(_Base):
    content: str
    kind: SourceKind
    ref: str
    trust: Trust = Trust.UNTRUSTED
    sensitivity: Sensitivity = Sensitivity.NORMAL
    agent: Optional[str] = None


class VaultSecretIn(_Base):
    secret: str
    path: str
    agent: Optional[str] = None


class LLMOutputIn(_Base):
    text: str
    agent: str
    derived_from: List[str] = Field(
        ..., description="EVERY Datum id in the model's context window. Custody's "
                         "'no provenance path' results assume this list is complete.")
    model: Optional[str] = None
    sensitivity: Optional[Sensitivity] = None
    coverage: ProvenanceCoverage = Field(
        ProvenanceCoverage.FULL_CONTEXT,
        description="FULL_CONTEXT if derived_from is the whole context window (the "
                    "contract); REDUCED if a narrower attribution was used. REDUCED "
                    "downgrades any certificate whose ancestry contains this output.")


class MemoryIn(_Base):
    content: str
    agent: str
    derived_from: List[str] = Field(..., min_length=1)
    key: Optional[str] = None
    sensitivity: Optional[Sensitivity] = None
    coverage: ProvenanceCoverage = ProvenanceCoverage.FULL_CONTEXT


class RecallIn(_Base):
    memory_id: str
    agent: str
    query: Optional[str] = None


class MessageIn(_Base):
    content: str
    sender: str
    recipient: str
    derived_from: List[str]
    thread_id: Optional[str] = None
    sensitivity: Optional[Sensitivity] = None
    coverage: ProvenanceCoverage = ProvenanceCoverage.FULL_CONTEXT


class SinkIn(BaseModel):
    destination: str
    kind: Optional[str] = None
    external: bool = True


class ActionIn(_Base):
    action_type: str
    agent: str
    destination: List[str] = Field(default_factory=list, description="Datum ids")
    payload: List[str] = Field(default_factory=list, description="Datum ids")
    extra_args: Dict[str, List[str]] = Field(default_factory=dict)
    sink: Optional[SinkIn] = None
    status: ActionStatus = ActionStatus.PROPOSED


class ActionStatusIn(BaseModel):
    status: ActionStatus


class ApprovalIn(BaseModel):
    approver: str
    endorses: List[str] = Field(..., min_length=1)
    reason: Optional[str] = None
    action_id: Optional[str] = None
    id: Optional[str] = None


class GuardApprovalIn(BaseModel):
    approver: str
    reason: Optional[str] = None


class RevokeIn(BaseModel):
    approver: str
    reason: Optional[str] = None


class EndorseIn(BaseModel):
    approver: str
    datum_ids: List[str] = Field(..., min_length=1)
    reason: Optional[str] = None
    # also pre-approve sending secret data to the destination value these Datums hold
    egress: bool = False
