"""Recorder: the single write path for provenance.

Every piece of information an agent sees or produces is recorded as a ``Datum``
linked to the ``Source`` it came from and to the ``Datum``\\s it was derived from.
Memories, recalls, LLM outputs and messages are all Datums, so they form ONE
continuous ``DERIVED_FROM`` graph that crosses sessions and agents::

    web page ─┐
    user msg ─┴─< llm output <─save── Memory <─recall── Recall <─ llm output (other session)
                                                                   ▲
                                         Message <─derive──────────┘ (other agent)

Sensitivity is inherited: unless set explicitly, a derived Datum takes the
highest sensitivity among its parents. Trust is NOT copied onto data; it lives
on Sources and is computed by walking lineage (see ``GraphRepository.lineage``).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from collections.abc import Sequence

from custody.graph.model import (
    DATUM_SUBTYPE_LABEL,
    MODEL_OUTPUT_KINDS,
    ActionArg,
    ProvenanceCoverage,
    Attribution,
    RiskTier,
    ActionRecord,
    ActionStatus,
    ActionTrace,
    ApprovalRecord,
    ArgRole,
    DatumKind,
    DatumRecord,
    DerivationOp,
    Lineage,
    ProvenancePath,
    Sensitivity,
    SinkRecord,
    SourceKind,
    SourceRecord,
    Trust,
    fingerprint,
    new_id,
    safe_preview,
    utcnow_iso,
)
from custody.graph.repository import GraphRepository
from custody.graph import traversal
from custody.recorder.attribution import value_supplied_by
from custody.memory.errors import MemoryQuarantined
from custody.recorder.quarantine import validate_typed_value

MEMORY_STORE_SOURCE_ID = "system:memory-store"
QUARANTINE_SOURCE_ID = "system:quarantined-reader"


def agent_source_id(agent: str) -> str:
    return f"system:agent:{agent}"


def sink_id(kind: str, destination: str, workspace: Optional[str] = None) -> str:
    key = f"{kind}|{destination}" if not workspace else f"{kind}|{workspace}|{destination}"
    return "sink_" + fingerprint(key)[7:23]


class Recorder:
    def __init__(self, repo: GraphRepository, max_trace_depth: int = 25) -> None:
        self.repo = repo
        self.max_trace_depth = max_trace_depth

    # ============================================================== sources
    def register_source(self, source_id: str, kind: SourceKind | str, trust: Trust | str,
                        metadata: Optional[Dict[str, Any]] = None) -> SourceRecord:
        return self.repo.upsert_source(source_id, SourceKind(kind), Trust(trust), metadata)

    def _agent_source(self, agent: str) -> str:
        sid = agent_source_id(agent)
        self.repo.upsert_source(sid, SourceKind.SYSTEM, Trust.TRUSTED, {"agent": agent})
        return sid

    # ======================================================= core primitive
    def record_datum(
        self,
        *,
        kind: DatumKind,
        value: str,
        source_id: str,
        derived_from: Sequence[str] = (),
        op: DerivationOp = DerivationOp.DERIVE,
        sensitivity: Optional[Sensitivity | str] = None,
        agent: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        datum_id: Optional[str] = None,
        endorsed: bool = False,
        attribution: Attribution | str = Attribution.INHERIT,
        extra: Optional[Dict[str, Any]] = None,
        coverage: ProvenanceCoverage | str = ProvenanceCoverage.FULL_CONTEXT,
    ) -> DatumRecord:
        """Record any Datum. All typed ``record_*`` methods funnel through here.

        ``attribution="exact"`` enables exact-value attribution (see
        ``custody.recorder.attribution``): if a trusted Datum in (or behind) the context
        supplied this exact value, the new Datum is attributed to that supplier and the
        remaining context parents are linked as ``attribution: "context"`` only.

        ``coverage`` (model-produced kinds only; see ``ProvenanceCoverage``) records whether
        ``derived_from`` is the whole context window (``FULL_CONTEXT``, the contract) or a
        narrower attribution (``REDUCED``). Exact-value attribution keeps every context edge,
        so it does not reduce coverage.
        """
        parents = self.repo.require_data(derived_from)
        edges = [(pid, DerivationOp(op).value, Attribution.INHERIT.value) for pid in parents]
        inherit_from = list(parents.values())
        mode = Attribution(attribution)
        meta = dict(metadata or {})
        if mode == Attribution.EXACT:
            suppliers = self.exact_suppliers(value, list(parents))
            if suppliers:
                sup_ids = [s.id for s in suppliers]
                edges = [(sid, DerivationOp.ATTRIBUTE.value, Attribution.EXACT.value)
                         for sid in sup_ids]
                edges += [(pid, DerivationOp(op).value, Attribution.CONTEXT.value)
                          for pid in parents if pid not in sup_ids]
                inherit_from = suppliers
                meta["attribution"] = {"mode": "exact", "suppliers": sup_ids}
            else:
                mode = Attribution.INHERIT
                meta["attribution"] = {"mode": "inherit",
                                       "reason": "no trusted supplier of this exact value"}
        if sensitivity is None:
            sensitivity = Sensitivity.max(*(p.sensitivity for p in inherit_from))
        sensitivity = Sensitivity(sensitivity)
        kind = DatumKind(kind)
        labels = ["Datum"] + ([DATUM_SUBTYPE_LABEL[kind]] if kind in DATUM_SUBTYPE_LABEL else [])
        datum = DatumRecord(
            id=datum_id or new_id("d"),
            kind=kind,
            labels=labels,
            value=None if sensitivity == Sensitivity.SECRET else value,
            preview=safe_preview(value, sensitivity),
            fingerprint=fingerprint(value),
            sensitivity=sensitivity,
            endorsed=endorsed,
            created_at=utcnow_iso(),
            agent=agent,
            session_id=session_id,
            metadata=meta,
            attribution=mode.value,
            coverage=(ProvenanceCoverage(coverage).value if kind.value in MODEL_OUTPUT_KINDS
                      else None),
            **(extra or {}),
        )
        return self.repo.create_datum(datum, source_id, edges)

    def exact_suppliers(self, value: str, context_ids: Sequence[str]) -> List[DatumRecord]:
        """Trusted Datums (in or behind ``context_ids``) that supplied exactly ``value``."""
        v = value.strip()
        if not v or not context_ids:
            return []
        fps = {fingerprint(value), fingerprint(v)}
        out: List[DatumRecord] = []
        for cand, _depth in self.repo.find_value_candidates(context_ids, v, fingerprint(v),
                                                            self.max_trace_depth):
            exact = cand.fingerprint in fps or (cand.value is not None
                                                and value_supplied_by(v, cand.value))
            if not exact:
                continue
            # supplier must be *proven* clean: an untrusted origin at any depth, or an
            # incomplete search, disqualifies it (fail closed: edges stay 'inherit')
            if not traversal.untrusted_origin(self.repo.graph, [cand.id]).proves_no_path:
                continue
            out.append(cand)
        return out

    # ============================================================== inputs
    def record_user_input(self, text: str, *, user: str, session_id: Optional[str] = None,
                          agent: Optional[str] = None, sensitivity: Sensitivity | str = "normal",
                          metadata: Optional[Dict[str, Any]] = None,
                          datum_id: Optional[str] = None) -> DatumRecord:
        sid = f"user:{user}"
        self.repo.upsert_source(sid, SourceKind.USER, Trust.TRUSTED, {"user": user})
        return self.record_datum(kind=DatumKind.USER_INPUT, value=text, source_id=sid,
                                 sensitivity=sensitivity, agent=agent, session_id=session_id,
                                 metadata=metadata, datum_id=datum_id)

    def record_web_content(self, content: str, *, url: str, session_id: Optional[str] = None,
                           agent: Optional[str] = None,
                           metadata: Optional[Dict[str, Any]] = None,
                           datum_id: Optional[str] = None) -> DatumRecord:
        sid = f"web:{url}"
        self.repo.upsert_source(sid, SourceKind.WEB, Trust.UNTRUSTED, {"url": url})
        return self.record_datum(kind=DatumKind.WEB_CONTENT, value=content, source_id=sid,
                                 sensitivity=Sensitivity.NORMAL, agent=agent,
                                 session_id=session_id, metadata={"url": url, **(metadata or {})},
                                 datum_id=datum_id)

    def record_external_content(self, content: str, *, kind: SourceKind | str, ref: str,
                                trust: Trust | str = Trust.UNTRUSTED,
                                sensitivity: Sensitivity | str = "normal",
                                session_id: Optional[str] = None, agent: Optional[str] = None,
                                metadata: Optional[Dict[str, Any]] = None,
                                datum_id: Optional[str] = None) -> DatumRecord:
        """Content from email / github / slack etc. (untrusted by default)."""
        kind = SourceKind(kind)
        sid = f"{kind.value}:{ref}"
        self.repo.upsert_source(sid, kind, Trust(trust), {"ref": ref})
        return self.record_datum(kind=DatumKind.TOOL_OUTPUT, value=content, source_id=sid,
                                 sensitivity=sensitivity, agent=agent, session_id=session_id,
                                 metadata=metadata, datum_id=datum_id)

    def record_vault_secret(self, secret: str, *, path: str, session_id: Optional[str] = None,
                            agent: Optional[str] = None,
                            metadata: Optional[Dict[str, Any]] = None,
                            datum_id: Optional[str] = None) -> DatumRecord:
        """The raw secret is never stored: only a masked preview and a fingerprint."""
        sid = f"vault:{path}"
        self.repo.upsert_source(sid, SourceKind.VAULT, Trust.TRUSTED, {"path": path})
        return self.record_datum(kind=DatumKind.SECRET, value=secret, source_id=sid,
                                 sensitivity=Sensitivity.SECRET, agent=agent,
                                 session_id=session_id, metadata={"path": path, **(metadata or {})},
                                 datum_id=datum_id)

    # ============================================================= derived
    def record_llm_output(self, text: str, *, agent: str, derived_from: Sequence[str],
                          session_id: Optional[str] = None, model: Optional[str] = None,
                          sensitivity: Optional[Sensitivity | str] = None,
                          metadata: Optional[Dict[str, Any]] = None,
                          datum_id: Optional[str] = None,
                          attribution: Attribution | str = Attribution.INHERIT,
                          coverage: ProvenanceCoverage | str = ProvenanceCoverage.FULL_CONTEXT
                          ) -> DatumRecord:
        """``derived_from`` MUST be every Datum that was in the model's context window.

        This is the soundness contract behind every negative result ("no provenance path"):
        Custody can only reason about dependencies that were recorded. The agent runtime
        (``custody.runtime.AgentSession``) fills ``derived_from`` with the whole context
        automatically; integrators calling the Recorder or HTTP API directly are
        responsible for passing the complete context. Over-approximating is safe (extra
        possible influence); omitting a context item is not.

        Pass ``attribution="exact"`` for tool-call arguments so that values the user (or
        another trusted source) supplied verbatim are not tainted by the rest of the
        context. The other context items are still linked (``attribution: "context"``).

        Pass ``coverage="REDUCED"`` if ``derived_from`` is deliberately narrower than the
        context window (e.g. only cited sources). It is recorded on the Datum, and any
        certificate whose ancestry contains it is downgraded (not exhaustive).
        """
        meta = {**({"model": model} if model else {}), **(metadata or {})}
        return self.record_datum(kind=DatumKind.LLM_OUTPUT, value=text,
                                 source_id=self._agent_source(agent), derived_from=derived_from,
                                 op=DerivationOp.DERIVE, sensitivity=sensitivity, agent=agent,
                                 session_id=session_id, metadata=meta, datum_id=datum_id,
                                 attribution=attribution, coverage=coverage)

    def record_typed_value(self, value: str, *, value_type: str, derived_from: Sequence[str],
                           agent: str, session_id: Optional[str] = None,
                           allowed_values: Optional[Sequence[str]] = None,
                           field: Optional[str] = None,
                           max_risk: RiskTier | str = RiskTier.LOW,
                           metadata: Optional[Dict[str, Any]] = None,
                           datum_id: Optional[str] = None,
                           coverage: ProvenanceCoverage | str = ProvenanceCoverage.FULL_CONTEXT
                           ) -> DatumRecord:
        """Quarantined reader: extract a validated, narrowly typed value from (usually
        untrusted) content. Raises ``QuarantineViolation`` if it does not fit the type."""
        canonical = validate_typed_value(value, value_type, allowed_values)
        self.repo.upsert_source(QUARANTINE_SOURCE_ID, SourceKind.SYSTEM, Trust.TRUSTED,
                                {"component": "quarantined-reader"})
        meta = {"value_type": value_type, "extractor_agent": agent,
                **({"field": field} if field else {}),
                **({"allowed_values": list(allowed_values)} if allowed_values else {}),
                **(metadata or {})}
        return self.record_datum(kind=DatumKind.TYPED_VALUE, value=canonical,
                                 source_id=QUARANTINE_SOURCE_ID, derived_from=derived_from,
                                 op=DerivationOp.EXTRACT, sensitivity=None, agent=agent,
                                 session_id=session_id, metadata=meta, datum_id=datum_id,
                                 extra={"quarantined": True, "value_type": value_type,
                                        "max_risk": RiskTier(max_risk)}, coverage=coverage)

    def record_memory(self, content: str, *, agent: str, derived_from: Sequence[str],
                      session_id: Optional[str] = None, key: Optional[str] = None,
                      sensitivity: Optional[Sensitivity | str] = None,
                      metadata: Optional[Dict[str, Any]] = None,
                      datum_id: Optional[str] = None,
                      coverage: ProvenanceCoverage | str = ProvenanceCoverage.FULL_CONTEXT
                      ) -> DatumRecord:
        """Save a memory. It must point at the Datum(s) it was distilled from."""
        meta = {**({"key": key} if key else {}), **(metadata or {})}
        return self.record_datum(kind=DatumKind.MEMORY, value=content,
                                 source_id=self._agent_source(agent), derived_from=derived_from,
                                 op=DerivationOp.SAVE, sensitivity=sensitivity, agent=agent,
                                 session_id=session_id, metadata=meta, datum_id=datum_id,
                                 coverage=coverage)

    def record_memory_recall(self, memory_id: str, *, agent: str,
                             session_id: Optional[str] = None,
                             query: Optional[str] = None,
                             metadata: Optional[Dict[str, Any]] = None,
                             datum_id: Optional[str] = None,
                             allow_quarantined: bool = False) -> DatumRecord:
        """A memory surfacing in a (possibly different) session/agent.

        Creates a ``Datum:Recall`` -[:DERIVED_FROM {op:'recall'}]-> ``Datum:Memory`` so the
        recalling session's outputs chain back to the original evidence.

        Memories in Warden quarantine are refused (``MemoryQuarantined``) unless
        ``allow_quarantined`` is set (forensic access, recorded in the recall metadata).
        """
        memory = self.repo.require_data([memory_id])[memory_id]
        if not memory.is_memory:
            raise ValueError(f"{memory_id!r} is a {memory.kind.value}, not a memory")
        if memory.in_quarantine and not allow_quarantined:
            raise MemoryQuarantined(f"memory {memory_id} is quarantined "
                                    f"({memory.quarantine_id}); it cannot be recalled")
        if memory.in_quarantine:
            metadata = {**(metadata or {}), "forensic_recall_of_quarantined": True}
        self.repo.upsert_source(MEMORY_STORE_SOURCE_ID, SourceKind.SYSTEM, Trust.TRUSTED,
                                {"component": "memory-store"})
        meta = {"memory_id": memory_id, **({"query": query} if query else {}), **(metadata or {})}
        # Recalled content is the memory's content; for secrets only the preview exists.
        value = memory.value if memory.value is not None else memory.preview
        return self.record_datum(kind=DatumKind.RECALL, value=value,
                                 source_id=MEMORY_STORE_SOURCE_ID, derived_from=[memory_id],
                                 op=DerivationOp.RECALL, agent=agent, session_id=session_id,
                                 metadata=meta, datum_id=datum_id)

    def record_message(self, content: str, *, sender: str, recipient: str,
                       derived_from: Sequence[str], session_id: Optional[str] = None,
                       thread_id: Optional[str] = None,
                       sensitivity: Optional[Sensitivity | str] = None,
                       metadata: Optional[Dict[str, Any]] = None,
                       datum_id: Optional[str] = None,
                       coverage: ProvenanceCoverage | str = ProvenanceCoverage.FULL_CONTEXT
                       ) -> DatumRecord:
        """Inter-agent message. The recipient's later outputs should derive from it."""
        meta = {"sender": sender, "recipient": recipient,
                **({"thread_id": thread_id} if thread_id else {}), **(metadata or {})}
        return self.record_datum(kind=DatumKind.MESSAGE, value=content,
                                 source_id=self._agent_source(sender), derived_from=derived_from,
                                 op=DerivationOp.SEND, sensitivity=sensitivity, agent=sender,
                                 session_id=session_id, metadata=meta, datum_id=datum_id,
                                 coverage=coverage)

    # ============================================================= actions
    def record_action(self, action_type: str, *, agent: str,
                      destination: Sequence[str] | str = (),
                      payload: Sequence[str] | str = (),
                      extra_args: Optional[Dict[str, Sequence[str]]] = None,
                      sink_destination: Optional[str] = None, sink_kind: Optional[str] = None,
                      sink_external: bool = True, sink_workspace: Optional[str] = None,
                      session_id: Optional[str] = None,
                      status: ActionStatus | str = ActionStatus.PROPOSED,
                      metadata: Optional[Dict[str, Any]] = None,
                      action_id: Optional[str] = None) -> ActionRecord:
        """Record a proposed action and which Datums supplied its destination/payload."""
        args: List[ActionArg] = []
        for role, ids in [(ArgRole.DESTINATION.value, destination),
                          (ArgRole.PAYLOAD.value, payload),
                          *((extra_args or {}).items())]:
            for did in ([ids] if isinstance(ids, str) else ids):
                args.append(ActionArg(role=role, datum_id=did))
        self.repo.require_data(a.datum_id for a in args)
        sink = None
        if sink_destination is not None:
            kind = sink_kind or action_type
            sink = SinkRecord(id=sink_id(kind, sink_destination, sink_workspace),
                              destination=sink_destination, kind=kind, external=sink_external,
                              workspace=sink_workspace)
        action = ActionRecord(id=action_id or new_id("act"), action_type=action_type, agent=agent,
                              status=ActionStatus(status), created_at=utcnow_iso(),
                              session_id=session_id, args=args, sink=sink,
                              metadata=metadata or {})
        return self.repo.create_action(action)

    def update_action_status(self, action_id: str, status: ActionStatus | str) -> ActionRecord:
        self.repo.set_action_status(action_id, ActionStatus(status))
        return self.repo.get_action(action_id)

    def record_approval(self, *, approver: str, endorses: Sequence[str] = (),
                        reason: Optional[str] = None, action_id: Optional[str] = None,
                        checks: Sequence[str] = (), approver_kind: str = "human",
                        approval_id: Optional[str] = None,
                        egress: bool = False) -> ApprovalRecord:
        """Record an Approval.

        - ``endorses``: Datums a human vouches for (ENDORSES edge, ``endorsed = true``).
          Clears integrity paths through those Datums, for this and future actions.
        - ``action_id`` + ``checks``: an action-scoped approval (APPROVES edge) that
          clears the listed Guard checks for that one action only.

        Policy (what may be approved) is enforced by the Guard, not here.
        """
        if not endorses and not (action_id and checks):
            raise ValueError("an approval must endorse at least one datum "
                             "or approve specific checks on an action")
        self.repo.require_data(endorses)
        if action_id:
            self.repo.get_action(action_id)
        approval = ApprovalRecord(id=approval_id or new_id("apv"), approver=approver,
                                  approver_kind=approver_kind,
                                  reason=reason, created_at=utcnow_iso(),
                                  endorsed_ids=list(dict.fromkeys(endorses)),
                                  action_id=action_id, checks=list(dict.fromkeys(checks)),
                                  egress=bool(egress and endorses))
        return self.repo.create_approval(approval)

    def record_rejection(self, *, approver: str, action_id: str,
                         reason: Optional[str] = None) -> ApprovalRecord:
        """A human rejected an action: (:Approval {verdict:'rejected'})-[:REJECTS]->(:Action).
        Clears nothing; kept so the audit trail shows who said no and why."""
        self.repo.get_action(action_id)
        rec = ApprovalRecord(id=new_id("rej"), approver=approver, approver_kind="human",
                             reason=reason, created_at=utcnow_iso(), action_id=action_id,
                             verdict="rejected")
        return self.repo.create_approval(rec)

    # ============================================================== reads
    def get_datum(self, datum_id: str) -> DatumRecord:
        return self.repo.get_datum(datum_id)

    def lineage(self, datum_id: str, max_depth: Optional[int] = None) -> Lineage:
        return self.repo.lineage(datum_id, max_depth or self.max_trace_depth)

    def find_path(self, from_id: str, to_id: str,
                  max_depth: Optional[int] = None) -> Optional[ProvenancePath]:
        return self.repo.find_path(from_id, to_id, max_depth or self.max_trace_depth)

    def search_path(self, from_id: str, to_id: str,
                    max_depth: Optional[int] = None) -> traversal.ProvenanceSearch:
        """Complete reachability search (unbounded unless ``max_depth`` is given). Unlike
        ``find_path`` it distinguishes NO_PATH from INDETERMINATE."""
        return traversal.path_to(self.repo.graph, from_id, to_id, max_depth=max_depth)

    def find_paths(self, from_id: str, to_id: str, max_depth: Optional[int] = None,
                   limit: int = 10) -> List[ProvenancePath]:
        return self.repo.find_paths(from_id, to_id, max_depth or self.max_trace_depth, limit)

    def trace_action(self, action_id: str, max_depth: Optional[int] = None) -> ActionTrace:
        return self.repo.trace_action(action_id, max_depth or self.max_trace_depth)
