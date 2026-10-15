"""Recorder endpoints: /tenants/{tenant}/record/* and provenance reads."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from custody.api import schemas as I
from custody.api.deps import get_recorder
from custody.graph.model import (
    ActionRecord,
    ActionTrace,
    ApprovalRecord,
    DatumRecord,
    Lineage,
    ProvenancePath,
    SourceRecord,
)
from custody.recorder.service import Recorder

router = APIRouter(prefix="/tenants/{tenant}", tags=["recorder"])


@router.post("/sources", response_model=SourceRecord, status_code=201)
def register_source(body: I.SourceIn, r: Recorder = Depends(get_recorder)):
    return r.register_source(body.id, body.kind, body.trust, body.metadata)


@router.post("/record/user-input", response_model=DatumRecord, status_code=201)
def record_user_input(body: I.UserInputIn, r: Recorder = Depends(get_recorder)):
    return r.record_user_input(body.text, user=body.user, agent=body.agent,
                               session_id=body.session_id, sensitivity=body.sensitivity,
                               metadata=body.metadata, datum_id=body.id)


@router.post("/record/web-content", response_model=DatumRecord, status_code=201)
def record_web_content(body: I.WebContentIn, r: Recorder = Depends(get_recorder)):
    return r.record_web_content(body.content, url=body.url, agent=body.agent,
                                session_id=body.session_id, metadata=body.metadata,
                                datum_id=body.id)


@router.post("/record/external-content", response_model=DatumRecord, status_code=201)
def record_external_content(body: I.ExternalContentIn, r: Recorder = Depends(get_recorder)):
    return r.record_external_content(body.content, kind=body.kind, ref=body.ref,
                                     trust=body.trust, sensitivity=body.sensitivity,
                                     agent=body.agent, session_id=body.session_id,
                                     metadata=body.metadata, datum_id=body.id)


@router.post("/record/vault-secret", response_model=DatumRecord, status_code=201)
def record_vault_secret(body: I.VaultSecretIn, r: Recorder = Depends(get_recorder)):
    return r.record_vault_secret(body.secret, path=body.path, agent=body.agent,
                                 session_id=body.session_id, metadata=body.metadata,
                                 datum_id=body.id)


@router.post("/record/llm-output", response_model=DatumRecord, status_code=201)
def record_llm_output(body: I.LLMOutputIn, r: Recorder = Depends(get_recorder)):
    return r.record_llm_output(body.text, agent=body.agent, derived_from=body.derived_from,
                               session_id=body.session_id, model=body.model,
                               sensitivity=body.sensitivity, metadata=body.metadata,
                               datum_id=body.id, coverage=body.coverage)


@router.post("/record/memory", response_model=DatumRecord, status_code=201)
def record_memory(body: I.MemoryIn, r: Recorder = Depends(get_recorder)):
    return r.record_memory(body.content, agent=body.agent, derived_from=body.derived_from,
                           session_id=body.session_id, key=body.key,
                           sensitivity=body.sensitivity, metadata=body.metadata,
                           datum_id=body.id, coverage=body.coverage)


@router.post("/record/memory-recall", response_model=DatumRecord, status_code=201)
def record_memory_recall(body: I.RecallIn, r: Recorder = Depends(get_recorder)):
    return r.record_memory_recall(body.memory_id, agent=body.agent, session_id=body.session_id,
                                  query=body.query, metadata=body.metadata, datum_id=body.id)


@router.post("/record/message", response_model=DatumRecord, status_code=201)
def record_message(body: I.MessageIn, r: Recorder = Depends(get_recorder)):
    return r.record_message(body.content, sender=body.sender, recipient=body.recipient,
                            derived_from=body.derived_from, session_id=body.session_id,
                            thread_id=body.thread_id, sensitivity=body.sensitivity,
                            metadata=body.metadata, datum_id=body.id, coverage=body.coverage)


@router.post("/record/action", response_model=ActionRecord, status_code=201)
def record_action(body: I.ActionIn, r: Recorder = Depends(get_recorder)):
    sink = body.sink
    return r.record_action(
        body.action_type, agent=body.agent, destination=body.destination, payload=body.payload,
        extra_args=body.extra_args,
        sink_destination=sink.destination if sink else None,
        sink_kind=sink.kind if sink else None,
        sink_external=sink.external if sink else True,
        session_id=body.session_id, status=body.status, metadata=body.metadata,
        action_id=body.id,
    )


@router.post("/record/approval", response_model=ApprovalRecord, status_code=201)
def record_approval(body: I.ApprovalIn, r: Recorder = Depends(get_recorder)):
    return r.record_approval(approver=body.approver, endorses=body.endorses,
                             reason=body.reason, action_id=body.action_id,
                             approval_id=body.id)


@router.patch("/actions/{action_id}/status", response_model=ActionRecord)
def update_action_status(action_id: str, body: I.ActionStatusIn,
                         r: Recorder = Depends(get_recorder)):
    return r.update_action_status(action_id, body.status)


# ------------------------------------------------------------------ reads
@router.get("/data/{datum_id}", response_model=DatumRecord)
def get_datum(datum_id: str, r: Recorder = Depends(get_recorder)):
    return r.get_datum(datum_id)


@router.get("/data/{datum_id}/lineage", response_model=Lineage)
def get_lineage(datum_id: str, max_depth: Optional[int] = Query(None, ge=1, le=100),
                r: Recorder = Depends(get_recorder)):
    return r.lineage(datum_id, max_depth)


@router.get("/data/{datum_id}/path-to/{target_id:path}", response_model=ProvenancePath)
def get_path(datum_id: str, target_id: str, max_depth: Optional[int] = Query(None, ge=1, le=100),
             r: Recorder = Depends(get_recorder)):
    path = r.find_path(datum_id, target_id, max_depth)
    if path is not None:
        return path
    # Nothing within the bounded query's depth. Only claim "no path" after a complete search.
    search = r.search_path(datum_id, target_id, max_depth)
    if search.path_found:
        return ProvenancePath(node_ids=search.witness_node_ids, ops=search.witness_ops,
                              length=len(search.witness_ops))
    meta = search.model_dump(mode="json", exclude={"witness_node_ids", "witness_ops"})
    if search.search_complete:
        raise HTTPException(status_code=404, detail={"message": "no provenance path", **meta})
    raise HTTPException(status_code=503, detail={
        "message": "provenance search incomplete; cannot say whether a path exists", **meta})


@router.get("/actions/{action_id}", response_model=ActionRecord)
def get_action(action_id: str, r: Recorder = Depends(get_recorder)):
    return r.repo.get_action(action_id)


@router.get("/actions/{action_id}/trace", response_model=ActionTrace)
def trace_action(action_id: str, max_depth: Optional[int] = Query(None, ge=1, le=100),
                 r: Recorder = Depends(get_recorder)):
    return r.trace_action(action_id, max_depth)
