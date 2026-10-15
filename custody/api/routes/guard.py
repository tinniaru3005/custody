"""Guard endpoints: /tenants/{tenant}/guard/*.

The Guard decides from Cypher provenance queries plus the tenant's static policy; no
model is involved. Approving a lethal-trifecta action returns 403.
"""
from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query

from custody.api import schemas as I
from custody.api.deps import get_guard
from custody.graph.model import ActionRecord, ApprovalRecord
from custody.guard import Guard, GuardDecision
from custody.guard.readjudicate import (ReadjudicationReport, latest_reports,
                                        revoke_and_readjudicate)

router = APIRouter(prefix="/tenants/{tenant}/guard", tags=["guard"])


@router.post("/actions/{action_id}/check", response_model=GuardDecision)
def check_action(action_id: str,
                 enforce: bool = Query(False, description="also update the action's status"),
                 g: Guard = Depends(get_guard)):
    return g.enforce(action_id) if enforce else g.check(action_id)


@router.post("/actions/{action_id}/approve", response_model=GuardDecision)
def approve_action(action_id: str, body: I.GuardApprovalIn, g: Guard = Depends(get_guard)):
    return g.approve(action_id, approver=body.approver, reason=body.reason)


@router.post("/actions/{action_id}/reject", response_model=ActionRecord)
def reject_action(action_id: str, body: I.GuardApprovalIn, g: Guard = Depends(get_guard)):
    return g.reject(action_id, approver=body.approver, reason=body.reason)


@router.post("/endorse", response_model=ApprovalRecord, status_code=201)
def endorse_data(body: I.EndorseIn, g: Guard = Depends(get_guard)):
    return g.endorse(body.datum_ids, approver=body.approver, reason=body.reason,
                     egress=body.egress)


@router.post("/sources/{source_id:path}/revoke", response_model=ReadjudicationReport,
             status_code=201)
def revoke_source(source_id: str, body: I.RevokeIn, g: Guard = Depends(get_guard)):
    """Mark a previously trusted Source compromised and re-adjudicate every historical
    action downstream of it (original verdicts are kept; current verdicts are added)."""
    return revoke_and_readjudicate(g, source_id, approver=body.approver, reason=body.reason)


@router.get("/readjudications", response_model=List[ReadjudicationReport])
def readjudications(limit: int = Query(10, ge=1, le=50), g: Guard = Depends(get_guard)):
    return latest_reports(g, limit)


@router.get("/actions/{action_id}/decisions", response_model=List[Dict[str, Any]])
def list_decisions(action_id: str, g: Guard = Depends(get_guard)):
    g.repo.get_action(action_id)  # 404 if missing
    return g.decisions(action_id)
