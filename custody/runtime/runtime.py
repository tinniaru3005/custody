"""Agent runtime with Guard enforcement.

Every side-effecting tool call follows one lifecycle::

    propose  → record the Action (+ its argument Datums, exact-value attributed)
    check    → Guard.enforce: ALLOW / REQUIRE_HUMAN_APPROVAL / BLOCK  (status updated)
    execute  → only when the latest Guard decision is ALLOW and status is ``approved``

The runtime is model-agnostic: an ``AgentSession`` records what an agent saw (user input,
web pages, vault reads, recalls, messages) and what it emitted (LLM outputs, tool calls).
Plug a real LLM in by feeding its text/tool calls to ``think`` / ``call_tool``; tests and
the demo script the calls deterministically, which is what a compromised model would do.

Raw values (including secrets) live only in this process (``AgentRuntime.values``); the
graph stores previews and fingerprints, never raw secrets.

Recording soundness (the assumption behind every "no provenance path" result)
------------------------------------------------------------------------------
Every output an ``AgentSession`` records — LLM outputs (``think``), tool-call arguments
(``arg`` / ``call_tool``), memories (``remember``) and messages (``send_message``) — gets a
``DERIVED_FROM`` edge to **every Datum in the session's context window**, automatically.
``derived_from=`` can only *add* parents; it never narrows the context. Everything that
reaches the model enters the context: user input, fetched pages, vault reads, recalls,
received messages, typed values and memory-search results.

This deliberately over-approximates influence: the graph may report possible influence
that did not happen, but it does not silently omit a known context dependency. The one
narrowing is explicit and recorded: exact-value attribution (``attribution="exact"``, the
default for tool-call arguments) still writes an edge to every context Datum, but marks
the non-supplying ones ``attribution: "context"``, which the Guard does not follow
(see ``custody.recorder.attribution``). Influence that is never shown to the runtime
(e.g. a model's hidden state, or an integrator calling the Recorder directly with an
incomplete ``derived_from``) is outside what Custody can see.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from collections.abc import Sequence

from custody.graph.model import (ActionStatus, Attribution, DatumRecord, SinkRecord,
                                  fingerprint, new_id)
from custody.guard.models import GuardDecision, Verdict
from custody.guard.service import Guard
from custody.recorder.service import Recorder
from custody.runtime.tools import Delivery, Outbox, ToolSpec, default_tools


class ExecutionDenied(PermissionError):
    pass


class Vault:
    """In-memory secret store. ``rotate`` issues a new deterministic value."""

    def __init__(self, secrets: Optional[Dict[str, str]] = None) -> None:
        self._secrets = dict(secrets or {})
        self._counter = itertools.count(1)

    def read(self, path: str) -> str:
        return self._secrets[path]

    def rotate(self, path: str) -> str:
        n = next(self._counter)
        new = f"AKIAROTATED{n:04d}{fingerprint(path)[7:15].upper()}KEY"
        self._secrets[path] = new
        return new


@dataclass
class ProposalResult:
    action_id: str
    decision: GuardDecision
    executed: bool = False
    delivery: Optional[Delivery] = None
    status: Optional[str] = None  # action status after the lifecycle step

    def __post_init__(self) -> None:
        if self.status is None:
            self.status = self.decision.action_status

    @property
    def verdict(self) -> Verdict:
        return self.decision.decision


class AgentRuntime:
    def __init__(self, recorder: Recorder, guard: Guard, *, vault: Optional[Vault] = None,
                 web: Optional[Dict[str, str]] = None,
                 tools: Optional[Dict[str, ToolSpec]] = None,
                 outbox: Optional[Outbox] = None) -> None:
        self.recorder = recorder
        self.guard = guard
        self.vault = vault or Vault()
        self.web = dict(web or {})
        self.tools = tools or default_tools()
        self.outbox = outbox or Outbox()
        self.values: Dict[str, str] = {}  # datum id -> raw value (process memory only)

    def session(self, agent: str, session_id: Optional[str] = None,
                metadata: Optional[dict] = None) -> "AgentSession":
        """``metadata`` is merged into every Datum/Action the session records (e.g. a
        simulated timestamp or demo step)."""
        return AgentSession(self, agent, session_id or new_id("sess"), metadata=dict(metadata or {}))

    # ------------------------------------------------------------- lifecycle
    def propose(self, *, agent: str, session_id: str, tool: str, arg_datums: Dict[str, str],
                metadata: Optional[dict] = None, auto_execute: bool = True) -> ProposalResult:
        """Record → Guard.enforce → execute on ALLOW (unless ``auto_execute`` is False, in
        which case an ALLOWed action stays ``approved`` until ``execute`` is called)."""
        spec = self.tools.get(tool)
        if spec is None:
            raise KeyError(f"unknown tool {tool!r}")
        dest_id = arg_datums.get("destination")
        sink_kwargs = {}
        if spec.sink_for is not None:
            kind, dest, ws = spec.sink_for(self.values[dest_id] if dest_id else "")
            cls = self.guard.policy.classify_sink(
                SinkRecord(id="probe", destination=dest, kind=kind, external=True, workspace=ws))
            sink_kwargs = dict(sink_destination=dest, sink_kind=kind, sink_workspace=ws,
                               sink_external=cls.external)
        extra = {r: [d] for r, d in arg_datums.items() if r not in ("destination", "payload")}
        action = self.recorder.record_action(
            tool, agent=agent, session_id=session_id,
            destination=[dest_id] if dest_id else [],
            payload=[arg_datums["payload"]] if "payload" in arg_datums else [],
            extra_args=extra or None, metadata=metadata, **sink_kwargs)
        decision = self.guard.enforce(action.id)
        result = ProposalResult(action_id=action.id, decision=decision)
        if decision.decision == Verdict.ALLOW and auto_execute:
            result.delivery = self.execute(action.id)
            result.executed = True
            result.status = ActionStatus.EXECUTED.value
        return result

    def execute(self, action_id: str) -> Delivery:
        """Execute only if a fresh Guard decision is ALLOW (re-checked here: no TOCTOU)."""
        action = self.recorder.repo.get_action(action_id)
        if action.status not in (ActionStatus.APPROVED, ActionStatus.PROPOSED,
                                 ActionStatus.PENDING_APPROVAL):
            raise ExecutionDenied(f"action {action_id} is {action.status.value}")
        decision = self.guard.enforce(action_id)
        if decision.decision != Verdict.ALLOW:
            raise ExecutionDenied(f"Guard: {decision.decision.value} — {decision.explanation}")
        spec = self.tools[action.action_type]
        args: Dict[str, str] = {}
        for a in action.args:
            if a.datum_id not in self.values:
                raise ExecutionDenied(f"raw value for {a.datum_id} not available in this runtime")
            args[a.role] = self.values[a.datum_id]
        try:
            delivery = spec.execute(self.outbox, action_id, args)
        except Exception:
            self.recorder.update_action_status(action_id, ActionStatus.FAILED)
            raise
        self.recorder.update_action_status(action_id, ActionStatus.EXECUTED)
        return delivery

    def approve(self, action_id: str, *, approver: str, reason: Optional[str] = None,
                execute: bool = True) -> ProposalResult:
        """Human approval: Guard applies the allowed approval, re-checks, then executes."""
        decision = self.guard.approve(action_id, approver=approver, reason=reason)
        result = ProposalResult(action_id=action_id, decision=decision)
        if execute and decision.decision == Verdict.ALLOW:
            result.delivery = self.execute(action_id)
            result.executed = True
            result.status = ActionStatus.EXECUTED.value
        return result

    def reject(self, action_id: str, *, approver: str, reason: Optional[str] = None):
        return self.guard.reject(action_id, approver=approver, reason=reason)


@dataclass
class AgentSession:
    runtime: AgentRuntime
    agent: str
    session_id: str
    context: List[str] = field(default_factory=list)  # datum ids in the model's context
    metadata: Dict[str, object] = field(default_factory=dict)  # merged into every record

    def _meta(self, extra: Optional[dict] = None) -> Optional[dict]:
        merged = {**self.metadata, **(extra or {})}
        return merged or None

    @property
    def r(self) -> Recorder:
        return self.runtime.recorder

    def _add(self, d: DatumRecord, raw: str) -> DatumRecord:
        self.runtime.values[d.id] = raw
        self._enter_context(d.id)
        return d

    def _enter_context(self, datum_id: str) -> None:
        if datum_id not in self.context:
            self.context.append(datum_id)

    def _parents(self, extra: Optional[Sequence[str]] = None) -> List[str]:
        """Soundness rule: the whole context window, plus any extra parents. Never fewer."""
        return list(dict.fromkeys([*self.context, *(extra or [])]))

    # ---------------------------------------------------------------- inputs
    def user(self, text: str, *, user: str) -> DatumRecord:
        return self._add(self.r.record_user_input(text, user=user, agent=self.agent,
                                                  session_id=self.session_id,
                                                  metadata=self._meta()), text)

    def fetch(self, url: str) -> DatumRecord:
        content = self.runtime.web[url]
        return self._add(self.r.record_web_content(content, url=url, agent=self.agent,
                                                   session_id=self.session_id,
                                                   metadata=self._meta()), content)

    def read_secret(self, path: str) -> DatumRecord:
        raw = self.runtime.vault.read(path)
        return self._add(self.r.record_vault_secret(raw, path=path, agent=self.agent,
                                                    session_id=self.session_id,
                                                    metadata=self._meta()), raw)

    def rotate_secret(self, path: str) -> DatumRecord:
        raw = self.runtime.vault.rotate(path)
        return self._add(self.r.record_vault_secret(raw, path=path, agent=self.agent,
                                                    session_id=self.session_id,
                                                    metadata=self._meta({"rotated": True})), raw)

    def recall(self, memory_id: str, query: Optional[str] = None) -> DatumRecord:
        d = self.r.record_memory_recall(memory_id, agent=self.agent, session_id=self.session_id,
                                        query=query, metadata=self._meta())
        raw = self.runtime.values.get(memory_id, d.value or d.preview)
        return self._add(d, raw)

    def search_memory(self, text: Optional[str] = None, *, key: Optional[str] = None,
                      limit: int = 20) -> List[DatumRecord]:
        """Shared-memory retrieval (quarantined memories are never returned)."""
        from custody.memory import SharedMemory

        found = SharedMemory(self.r).search(text, key=key, limit=limit)
        for m in found:  # search results are shown to the model, so they are in context
            self._enter_context(m.id)
        return found

    def receive(self, message_id: str) -> DatumRecord:
        """Put an inter-agent message into this session's context."""
        self._enter_context(message_id)
        return self.r.get_datum(message_id)

    # --------------------------------------------------------------- outputs
    def think(self, text: str, *, derived_from: Optional[Sequence[str]] = None) -> DatumRecord:
        """An LLM output, derived from the entire context (``derived_from`` adds parents)."""
        d = self.r.record_llm_output(text, agent=self.agent, session_id=self.session_id,
                                     derived_from=self._parents(derived_from),
                                     metadata=self._meta())
        return self._add(d, text)

    def remember(self, content: str, *, key: Optional[str] = None,
                 derived_from: Optional[Sequence[str]] = None) -> DatumRecord:
        d = self.r.record_memory(content, agent=self.agent, session_id=self.session_id, key=key,
                                 derived_from=self._parents(derived_from),
                                 metadata=self._meta())
        self.runtime.values[d.id] = content
        return d

    def send_message(self, recipient: str, content: str, *,
                     derived_from: Optional[Sequence[str]] = None) -> DatumRecord:
        d = self.r.record_message(content, sender=self.agent, recipient=recipient,
                                  session_id=self.session_id,
                                  derived_from=self._parents(derived_from),
                                  metadata=self._meta())
        self.runtime.values[d.id] = content
        return d

    def extract_typed(self, value: str, *, value_type: str, from_ids: Sequence[str],
                      allowed_values: Optional[Sequence[str]] = None,
                      field_name: Optional[str] = None) -> DatumRecord:
        """Quarantined reader: a validated typed value pulled out of (untrusted) content.

        Derived from ``from_ids`` only: the quarantined reader is a separate model call whose
        context is exactly that content (not this session's context window)."""
        d = self.r.record_typed_value(value, value_type=value_type, derived_from=from_ids,
                                      agent=self.agent, session_id=self.session_id,
                                      allowed_values=allowed_values, field=field_name,
                                      metadata=self._meta())
        return self._add(d, d.value or value)

    # ----------------------------------------------------------------- tools
    def arg(self, role: str, value: str, *, tool: str,
            derived_from: Optional[Sequence[str]] = None,
            attribution: str = Attribution.EXACT.value) -> DatumRecord:
        """Record one tool-call argument the model emitted (exact-value attributed).
        Derived from the whole context window (``derived_from`` adds parents)."""
        d = self.r.record_llm_output(value, agent=self.agent, session_id=self.session_id,
                                     derived_from=self._parents(derived_from),
                                     attribution=attribution,
                                     metadata=self._meta({"tool": tool, "tool_arg": role}))
        self.runtime.values[d.id] = value
        return d

    def call_tool(self, tool: str, *, attribution: str = Attribution.EXACT.value,
                  arg_datums: Optional[Dict[str, str]] = None, **args: str) -> ProposalResult:
        """The model asks to call ``tool`` with literal argument values.

        Each literal becomes an argument Datum derived from the current context, with
        exact-value attribution; ``arg_datums`` can pass existing Datums verbatim instead
        (e.g. a typed value from the quarantined reader).
        """
        ids = dict(arg_datums or {})
        for role, value in args.items():
            ids[role] = self.arg(role, value, tool=tool, attribution=attribution).id
        return self.runtime.propose(agent=self.agent, session_id=self.session_id, tool=tool,
                                    arg_datums=ids, metadata=self._meta())
