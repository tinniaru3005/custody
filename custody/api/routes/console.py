"""Console endpoints used by the React UI: /tenants/{tenant}/console/*.

Reads shape graph facts for display; writes either run the scripted demo scenario, run the
Warden agent over MCP, or send an already human-approved disclosure. Approve/reject go
through the Guard routes (/tenants/{tenant}/guard/actions/{id}/approve|reject).
"""
from __future__ import annotations

import threading
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from pydantic import BaseModel, Field

from custody.api.deps import get_provider, get_recorder
from custody.console import service as svc
from custody.console.views import (ActionExplain, ActionSummary, ConsoleViews, GraphView,
                                   MemorySummary, Metrics, Overview)
from custody.db import GraphProvider, validate_tenant
from custody.demo.attack import CLEANUP_REQUEST, DemoRun, PRIYA, latest_demo
from custody.console.influence import InfluenceView
from custody.console.influence import build as build_influence
from custody.demo.worlds import WorldsRun, build_worlds, latest_worlds
from custody.warden.chokepoints import ChokepointResult
from custody.guard import policy_for_tenant
from custody.recorder.service import Recorder
from custody.warden.models import SendDisclosureResult

router = APIRouter(prefix="/tenants/{tenant}/console", tags=["console"])
_write_lock = threading.Lock()


def get_views(request: Request, tenant: str = Path(...),
              recorder: Recorder = Depends(get_recorder)) -> ConsoleViews:
    provider: GraphProvider = request.app.state.graph_provider
    return ConsoleViews(recorder, policy_for_tenant(tenant), tenant, db=provider.db)


class InvestigateIn(BaseModel):
    request: str = Field(default=CLEANUP_REQUEST, min_length=3, max_length=2000)
    operator: str = PRIYA
    planner: svc.PlannerName = "auto"


class ApprovalItem(BaseModel):
    explain: ActionExplain
    can_approve: bool
    why: str


class ApprovalQueue(BaseModel):
    pending: List[ApprovalItem]
    blocked: List[ApprovalItem]
    resolved: List[ActionSummary]


# ------------------------------------------------------------------- reads
@router.get("/overview", response_model=Overview)
def overview(v: ConsoleViews = Depends(get_views)):
    return v.overview()


@router.get("/graph", response_model=GraphView)
def graph(include_decisions: bool = Query(False), v: ConsoleViews = Depends(get_views)):
    return v.graph(include_decisions)


@router.get("/actions", response_model=List[ActionSummary])
def actions(v: ConsoleViews = Depends(get_views)):
    return v.actions()


@router.get("/actions/{action_id}/explain", response_model=ActionExplain)
def explain(action_id: str, v: ConsoleViews = Depends(get_views)):
    return v.explain(action_id)


@router.get("/memories", response_model=List[MemorySummary])
def memories(v: ConsoleViews = Depends(get_views)):
    return v.memories()


@router.get("/approvals", response_model=ApprovalQueue)
def approvals(v: ConsoleViews = Depends(get_views)):
    pending, blocked, resolved = [], [], []
    decided = v.human_decided_action_ids()
    for a in v.actions():
        if a.status == "pending_approval":
            ex = v.explain(a.id)
            pending.append(ApprovalItem(explain=ex, can_approve=ex.decision.approval.available,
                                        why=ex.decision.approval.reason))
        elif a.status == "blocked":
            ex = v.explain(a.id)
            blocked.append(ApprovalItem(explain=ex, can_approve=False,
                                        why=ex.decision.approval.reason))
        elif a.id in decided or a.status == "rejected":
            resolved.append(a)
    return ApprovalQueue(pending=pending, blocked=blocked, resolved=resolved)


@router.get("/metrics", response_model=Metrics)
def metrics(runs: int = Query(5, ge=1, le=50), v: ConsoleViews = Depends(get_views)):
    return v.metrics(runs)


@router.get("/demo", response_model=Optional[DemoRun])
def demo(r: Recorder = Depends(get_recorder)):
    return latest_demo(r)


@router.get("/influence", response_model=InfluenceView)
def influence(r: Recorder = Depends(get_recorder)):
    """The provenance graph collapsed to agent-level influence (derived on every call)."""
    return build_influence(r.repo)


@router.get("/worlds", response_model=Optional[WorldsRun])
def worlds(r: Recorder = Depends(get_recorder)):
    """The three-worlds comparison (same request and bytes, three histories)."""
    return latest_worlds(r)


@router.get("/actions/{action_id}/chokepoints", response_model=ChokepointResult)
def chokepoints(action_id: str, request: Request, tenant: str = Path(...)):
    from custody.warden import Warden

    provider: GraphProvider = request.app.state.graph_provider
    return Warden.for_tenant(provider, tenant, policy=policy_for_tenant(tenant)) \
        .find_chokepoints(action_id)


@router.get("/warden", response_model=Optional[svc.WardenRun])
def warden_last(r: Recorder = Depends(get_recorder)):
    return svc.latest_warden_run(r)


# ------------------------------------------------------------------ writes
@router.post("/demo/reset", status_code=204)
def demo_reset(request: Request, tenant: str = Path(...),
               provider: GraphProvider = Depends(get_provider)):
    """Empty the tenant. In public-demo mode: restore the initial demo state instead
    (deterministic: identical graph every time), rate-limited."""
    validate_tenant(tenant)
    settings = request.app.state.settings
    if settings.public_demo:
        wait = request.app.state.reset_limiter.try_acquire()
        if wait is not None:
            raise HTTPException(status_code=429, detail=f"demo was just reset; retry in {wait}s",
                                headers={"Retry-After": str(int(wait) + 1)})
        with _write_lock:
            svc.restore_public_demo(provider, tenant)
        return
    with _write_lock:
        svc.reset_tenant(provider, tenant)


@router.post("/demo/attack", response_model=DemoRun, status_code=201)
def demo_attack(tenant: str = Path(...), scenario: svc.ScenarioName = Query("primary"),
                mode: Optional[svc.DemoMode] = Query(None),
                provider: GraphProvider = Depends(get_provider)):
    """Wipe the tenant and run a scenario: ``primary`` (the one-story demo, default) or
    ``extended`` (multi-incident version used for the Warden). ``mode`` (primary only):
    ``recorded`` replays the recorded real-LLM run without calling a model, ``scripted`` the
    scripted simulation, ``auto`` (default) the recording when one exists."""
    validate_tenant(tenant)
    with _write_lock:
        return svc.run_demo(provider, tenant, scenario, mode=mode)


@router.post("/worlds", response_model=WorldsRun, status_code=201)
def worlds_build(tenant: str = Path(...), provider: GraphProvider = Depends(get_provider)):
    """(Re)build the three worlds into ``<tenant>-worlds`` and store the report here."""
    validate_tenant(tenant)
    with _write_lock:
        return build_worlds(provider, tenant, deterministic=True)


@router.post("/warden/investigate", response_model=svc.WardenRun, status_code=201)
async def warden_investigate(body: InvestigateIn, tenant: str = Path(...),
                             provider: GraphProvider = Depends(get_provider)):
    validate_tenant(tenant)
    try:
        return await svc.investigate(provider, tenant, body.request, operator=body.operator,
                                     planner=body.planner)
    except RuntimeError as exc:  # e.g. planner=anthropic without the SDK / key
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/warden/disclosures/{action_id}/send", response_model=SendDisclosureResult)
def warden_send(action_id: str, tenant: str = Path(...),
                provider: GraphProvider = Depends(get_provider)):
    validate_tenant(tenant)
    with _write_lock:
        return svc.send_disclosure(provider, tenant, action_id)
