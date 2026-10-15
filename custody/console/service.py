"""Write-side operations the console triggers: demo reset/run, Warden investigations,
sending approved disclosures. Approvals themselves go through the Guard HTTP API."""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from custody.db import GraphProvider
from custody.demo.attack import CLEANUP_REQUEST, DemoRun, PRIYA, run_attack
from custody.demo.extended import run_extended
from custody.graph.model import new_id, utcnow_iso
from custody.graph.repository import GraphRepository
from custody.guard.policy import policy_for_tenant
from custody.recorder.service import Recorder
from custody.warden import Warden
from custody.warden.agent import AnthropicPlanner, PlaybookPlanner, run_warden
from custody.warden.models import SendDisclosureResult

log = logging.getLogger(__name__)
PlannerName = Literal["auto", "playbook", "anthropic"]
ScenarioName = Literal["primary", "extended"]
DemoMode = Literal["auto", "recorded", "scripted"]


class WardenStepView(BaseModel):
    n: int
    tool: str
    arguments: Dict[str, Any]
    is_error: bool = False
    result: Any = None


class WardenRun(BaseModel):
    id: str
    created_at: str
    request: str
    operator: str
    planner: str
    final_text: str
    steps: List[WardenStepView]
    tools_used: List[str]
    quarantined_memory_ids: List[str] = Field(default_factory=list)
    quarantine_verdicts: List[str] = Field(default_factory=list)
    external_executed_actions: List[str] = Field(default_factory=list)
    drafts: List[str] = Field(default_factory=list)
    pending_approvals: List[Dict[str, Any]] = Field(default_factory=list)


def recorder_for(provider: GraphProvider, tenant: str) -> Recorder:
    return Recorder(GraphRepository(provider.graph(tenant)),
                    max_trace_depth=provider.max_trace_depth)


def reset_tenant(provider: GraphProvider, tenant: str) -> None:
    provider.drop(tenant)


def run_demo(provider: GraphProvider, tenant: str, scenario: ScenarioName = "primary",
             deterministic: bool = False, mode: Optional[DemoMode] = None) -> DemoRun:
    """Wipe the tenant graph and run a scenario (default: the one-story primary demo).
    ``deterministic`` (primary only) restores an identical graph every time.

    ``mode`` (primary only; default ``$CUSTODY_DEMO_MODE`` or ``auto``): ``recorded`` replays
    the recorded real-LLM run (``custody/demo/fixtures/llm_run.json``) with no model call;
    ``auto`` does so when a valid real recording exists; ``scripted`` (and the fallback when
    there is no recording or its replay diverges) runs the scripted simulation."""
    provider.drop(tenant)
    rec = recorder_for(provider, tenant)
    if scenario == "extended":
        return run_extended(rec, tenant=tenant)
    mode = mode or os.environ.get("CUSTODY_DEMO_MODE", "auto")  # type: ignore[assignment]
    if mode != "scripted":
        from custody.demo import llm_run

        fx = llm_run.load_fixture(require_real=(mode == "auto"))
        if fx is not None:
            try:
                return llm_run.replay_demo(rec, fx, tenant=tenant)
            except llm_run.ReplayDivergence:
                log.warning("recorded LLM run no longer replays; using the scripted demo")
                provider.drop(tenant)
                rec = recorder_for(provider, tenant)
    return run_attack(rec, tenant=tenant, deterministic=deterministic)


def ensure_public_demo(provider: GraphProvider, tenant: str) -> None:
    """Public-demo startup: make sure the demo tenant holds the deterministic demo (and the
    three-worlds comparison)."""
    if latest_demo_run(provider, tenant) is None:
        restore_public_demo(provider, tenant)


def restore_public_demo(provider: GraphProvider, tenant: str) -> None:
    """Deterministic initial state: the primary demo, then the three worlds."""
    from custody.demo.worlds import build_worlds

    run_demo(provider, tenant, "primary", deterministic=True)
    build_worlds(provider, tenant, deterministic=True)


def latest_demo_run(provider: GraphProvider, tenant: str) -> Optional[DemoRun]:
    from custody.demo.attack import latest_demo

    return latest_demo(recorder_for(provider, tenant))


def choose_planner(name: PlannerName = "auto"):
    if name == "playbook":
        return PlaybookPlanner()
    if name == "anthropic" or (name == "auto" and os.environ.get("ANTHROPIC_API_KEY")):
        try:
            return AnthropicPlanner()
        except RuntimeError:
            if name == "anthropic":
                raise
    return PlaybookPlanner()


async def investigate(provider: GraphProvider, tenant: str, request: str = CLEANUP_REQUEST, *,
                      operator: str = PRIYA, planner: PlannerName = "auto",
                      max_steps: int = 20) -> WardenRun:
    """Run the Warden agent over an in-process MCP client bound to this tenant."""
    warden = Warden.for_tenant(provider, tenant, operator=operator,
                               policy=policy_for_tenant(tenant))
    report = await run_warden(warden, request, choose_planner(planner), max_steps=max_steps)
    run = WardenRun(
        id=new_id("wrun"), created_at=utcnow_iso(), request=request, operator=operator,
        planner=report.planner, final_text=report.final_text,
        steps=[WardenStepView(n=i + 1, tool=s.tool, arguments=s.arguments, is_error=s.is_error,
                              result=s.result) for i, s in enumerate(report.steps)],
        tools_used=report.tools_used, quarantined_memory_ids=report.quarantined_memory_ids,
        quarantine_verdicts=report.quarantine_verdicts,
        external_executed_actions=report.external_executed_actions, drafts=report.drafts,
        pending_approvals=report.pending_approvals)
    warden.repo.save_run(run.id, "warden", json.dumps(run.model_dump(mode="json"), default=str))
    return run


def latest_warden_run(recorder: Recorder) -> Optional[WardenRun]:
    raw = recorder.repo.latest_run("warden")
    return WardenRun.model_validate_json(raw) if raw else None


def send_disclosure(provider: GraphProvider, tenant: str, action_id: str) -> SendDisclosureResult:
    warden = Warden.for_tenant(provider, tenant, policy=policy_for_tenant(tenant))
    return warden.send_approved_disclosure(action_id)
