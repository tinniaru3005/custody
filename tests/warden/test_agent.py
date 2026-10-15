"""The LLM-driven Warden agent, end to end over MCP.

The agent sees only MCP tools; every action it takes is checked by the Guard
server-side; it can propose but never approve or silently send a disclosure.
"""
import asyncio
from types import SimpleNamespace

import pytest

pytest.importorskip("mcp")

from custody.demo.acme_warden import CLEANUP_REQUEST, MSP_ADDRESS  # noqa: E402
from custody.memory import MemoryQuarantined, SharedMemory  # noqa: E402
from custody.warden.agent import (AnthropicPlanner, PlaybookPlanner, WardenAgent,  # noqa: E402
                                  run_warden)

pytestmark = pytest.mark.integration


def test_full_cleanup_scenario(warden, incident):
    """User: 'That vendor page was malicious. Clean it up.'"""
    vendor, msp = incident["vendor_source"], incident["msp"]["action"]
    report = asyncio.run(run_warden(warden, CLEANUP_REQUEST, PlaybookPlanner()))

    # 1-8: locate → trace forward → rank → cluster → quarantine → (external?) → draft → propose
    assert report.tools_used == ["find_sources", "trace_forward", "rank_risky_memories",
                                 "cluster_incidents", "quarantine", "draft_disclosure",
                                 "propose_disclosure"]
    assert not any(s.is_error for s in report.steps)
    assert report.steps[1].arguments == {"source_id": vendor}

    # contaminated memories are quarantined — via a Guard-ALLOWed Warden action
    mems = {incident["dangerous"]["memory"], incident["msp"]["memory2"]}
    assert set(report.quarantined_memory_ids) == mems and report.quarantine_verdicts == ["ALLOW"]
    shared = SharedMemory(warden.recorder)
    assert not mems & {m.id for m in shared.search()}
    with pytest.raises(MemoryQuarantined):
        incident["runtime"].session("ops", "acme-later").recall(incident["dangerous"]["memory"])
    # unrelated incident and clean memory are untouched
    assert {m.metadata["key"] for m in shared.search()} == {"supplier-bank-details",
                                                           "board-meeting"}

    # 7-9: the executed external email was found, a disclosure drafted and proposed,
    # and the human is asked for approval; nothing was sent
    assert report.external_executed_actions == [msp]
    assert len(report.drafts) == 1
    [pending] = report.pending_approvals
    assert pending["recipient"] == MSP_ADDRESS
    assert pending["verdict"] == "REQUIRE_HUMAN_APPROVAL" and pending["status"] == "pending_approval"
    assert report.sent is False and len(warden.runtime.outbox) == 0
    assert "APPROVAL NEEDED" in report.final_text and pending["action_id"] in report.final_text
    assert "inc_" in report.final_text and "Other open incidents" in report.final_text

    # every Warden action was recorded and evaluated by the deterministic Guard
    rows = warden.repo.graph.ro_query(
        "MATCH (a:Action {agent: 'warden'}) RETURN a.id, a.action_type").result_set
    assert {t for _, t in rows} == {"quarantine_memory", "send_disclosure"}
    for aid, _ in rows:
        assert warden.guard.decisions(aid), f"{aid} was not checked by the Guard"
    # and they all derive from the operator's recorded request
    instr = warden.recorder.get_datum(warden.instruction_id)
    assert instr.value == CLEANUP_REQUEST and instr.source_id == "user:priya@acme-robotics.example"

    # the human approves; only then does the disclosure go out (fresh Guard ALLOW)
    warden.approve_disclosure(pending["action_id"], approver="priya@acme-robotics.example")
    sent = warden.send_approved_disclosure(pending["action_id"])
    assert sent.sent and warden.runtime.outbox.to(MSP_ADDRESS)


# --------------------------------------------------------------- Anthropic adapter
class FakeMessages:
    """Mimics anthropic.Anthropic().messages: replays scripted assistant turns."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def create(self, **kw):
        self.calls.append(kw)
        content = self.script.pop(0)(kw) if callable(self.script[0]) else self.script.pop(0)
        stop = "tool_use" if any(b.type == "tool_use" for b in content) else "end_turn"
        return SimpleNamespace(content=content, stop_reason=stop)


def text(t):
    return SimpleNamespace(type="text", text=t)


def tool(i, name, **inp):
    return SimpleNamespace(type="tool_use", id=i, name=name, input=inp)


def last_result(kw, idx=0):
    import json
    return json.loads(kw["messages"][-1]["content"][idx]["content"])


def test_llm_planner_drives_mcp_tools_and_cannot_send(warden, incident):
    vendor = incident["vendor_source"]
    script = [
        [text("Locating the source."), tool("t1", "find_sources", trust="untrusted", kind="web")],
        lambda kw: [tool("t2", "trace_forward", source_id=last_result(kw)["sources"][0]["id"])],
        lambda kw: [tool("t3", "quarantine",
                         memory_ids=[m["id"] for m in last_result(kw)["memories"]],
                         reason="malicious vendor page"),
                    tool("t4", "draft_disclosure",
                         action_ids=last_result(kw)["external_executed_actions"])],
        lambda kw: [tool("t5", "propose_disclosure",
                         draft_id=last_result(kw, 1)["drafts"][0]["draft_id"])],
        # a prompt-injected model tries to send without approval: the Guard refuses
        lambda kw: [tool("t6", "send_approved_disclosure",
                         action_id=last_result(kw)["action_id"])],
        [text("Quarantined 2 memories. A disclosure to the MSP awaits your approval.")],
    ]
    fake = SimpleNamespace(messages=FakeMessages(script))
    planner = AnthropicPlanner(client=fake, model="claude-test")
    report = asyncio.run(run_warden(warden, CLEANUP_REQUEST, planner))

    calls = fake.messages.calls
    assert calls[0]["model"] == "claude-test" and "Warden" in calls[0]["system"]
    names = {t["name"] for t in calls[0]["tools"]}
    assert "trace_forward" in names and "begin_investigation" not in names
    assert all("input_schema" in t and t["description"] for t in calls[0]["tools"])
    assert calls[0]["messages"][0] == {"role": "user", "content": CLEANUP_REQUEST}
    # assistant turns echo tool_use blocks; results come back as tool_result blocks
    assert calls[1]["messages"][1]["content"][1]["type"] == "tool_use"
    assert calls[1]["messages"][2]["content"][0]["tool_use_id"] == "t1"

    assert report.planner == "anthropic"
    assert report.steps[1].arguments == {"source_id": vendor}
    assert len(report.quarantined_memory_ids) == 2
    assert report.pending_approvals[0]["verdict"] == "REQUIRE_HUMAN_APPROVAL"
    send = report.steps[-1]
    assert send.tool == "send_approved_disclosure" and send.result["sent"] is False
    assert report.sent is False and len(warden.runtime.outbox) == 0
    assert report.final_text.startswith("Quarantined 2 memories")


def test_agent_step_limit_and_unknown_source(warden):
    report = asyncio.run(run_warden(warden, "The page at https://nowhere.example was bad.",
                                    PlaybookPlanner()))
    assert report.tools_used == ["find_sources"]
    assert "could not find" in report.final_text

    class Looping:
        name = "loop"

        def plan(self, system, messages, tools):
            from custody.warden.agent import PlannerTurn, ToolCall
            return PlannerTurn(tool_calls=[ToolCall(id="x", name="cluster_incidents")],
                               assistant_content=[{"type": "tool_use", "id": "x",
                                                   "name": "cluster_incidents", "input": {}}])

    from mcp import Client
    from custody.warden.mcp_server import build_server

    async def go():
        async with Client(build_server(warden)) as c:
            return await WardenAgent(Looping(), max_steps=3).run(c, "loop")

    r = asyncio.run(go())
    assert len(r.steps) == 3 and r.final_text == "Stopped: step limit reached."
