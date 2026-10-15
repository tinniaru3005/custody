"""FastAPI dependencies: one Recorder per request, bound to the tenant's graph."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Path, Request

from custody.db import GraphProvider, InvalidTenant
from custody.graph.repository import GraphRepository
from custody.recorder.service import Recorder


def get_provider(request: Request) -> GraphProvider:
    return request.app.state.graph_provider


def get_recorder(
    tenant: str = Path(..., description="Tenant slug; maps to graph custody:<tenant>"),
    provider: GraphProvider = Depends(get_provider),
) -> Recorder:
    try:
        graph = provider.graph(tenant)
    except InvalidTenant as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return Recorder(GraphRepository(graph), max_trace_depth=provider.max_trace_depth)


def get_guard(
    tenant: str = Path(..., description="Tenant slug; maps to graph custody:<tenant>"),
    recorder: Recorder = Depends(get_recorder),
):
    from custody.guard import Guard, policy_for_tenant

    return Guard(recorder, policy_for_tenant(tenant))
