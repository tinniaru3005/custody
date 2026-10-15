"""The Warden MCP server: tool definitions, schemas, and every tool over the protocol."""
import asyncio
import os
import sys

import pytest

mcp = pytest.importorskip("mcp")
from mcp import Client  # noqa: E402

from custody.warden.mcp_server import TOOL_NAMES, build_server  # noqa: E402


def run(coro):
    return asyncio.run(coro)


async def _with_client(warden, fn):
    async with Client(build_server(warden)) as client:
        return await fn(client)


def payload(res):
    sc = res.structured_content
    return sc.get("result", sc) if isinstance(sc, dict) and set(sc) == {"result"} else sc


def test_tool_definitions_and_schemas(warden):
    tools = run(_with_client(warden, lambda c: c.list_tools())).tools
    by = {t.name: t for t in tools}
    assert sorted(by) == sorted(TOOL_NAMES)
    for t in tools:
        assert t.description and len(t.description) > 40, t.name
        assert t.input_schema["type"] == "object"
        assert t.output_schema is not None, t.name
    assert by["trace_back"].input_schema["required"] == ["action_id"]
    assert by["trace_forward"].input_schema["required"] == ["source_id"]
    assert by["quarantine"].input_schema["properties"]["memory_ids"]["type"] == "array"
    assert by["draft_disclosure"].input_schema["required"] == ["action_ids"]
    assert "policy" in by["simulate_policy"].input_schema["required"]
    assert by["trace_back"].annotations.read_only_hint is True
    assert by["quarantine"].annotations.read_only_hint is False
    # no approval/endorse tool is exposed to MCP clients
    assert not any(n.startswith(("approve", "endorse")) for n in by)
    assert "human approval" in by["propose_disclosure"].description


def test_every_tool_over_mcp(warden, incident):
    msp, danger = incident["msp"]["action"], incident["dangerous"]["action"]
    vendor = incident["vendor_source"]

    async def go(c):
        out = {}
        out["begin"] = payload(await c.call_tool("begin_investigation",
                                                 {"request": "That vendor page was malicious."}))
        out["find"] = payload(await c.call_tool("find_sources", {"query": "vaultsync",
                                                                 "trust": "untrusted"}))
        out["back"] = payload(await c.call_tool("trace_back", {"action_id": danger}))
        out["fwd"] = payload(await c.call_tool("trace_forward", {"source_id": vendor}))
        out["rank"] = payload(await c.call_tool("rank_risky_memories", {"limit": 3}))
        out["clusters"] = payload(await c.call_tool("cluster_incidents", {}))
        out["sim"] = payload(await c.call_tool("simulate_policy", {"policy": {
            "name": "review-email", "human_review_action_types": ["send_email"]}}))
        mems = [m["id"] for m in out["fwd"]["memories"]]
        out["q"] = payload(await c.call_tool("quarantine", {"memory_ids": mems,
                                                            "reason": "malicious vendor page"}))
        out["draft"] = payload(await c.call_tool("draft_disclosure", {"action_ids": [msp]}))
        did = out["draft"]["drafts"][0]["draft_id"]
        out["prop"] = payload(await c.call_tool("propose_disclosure", {"draft_id": did}))
        out["send"] = payload(await c.call_tool("send_approved_disclosure",
                                                {"action_id": out["prop"]["action_id"]}))
        return out

    o = run(_with_client(warden, go))
    assert o["begin"]["operator"] == "priya@acme-robotics.example"
    assert o["find"]["sources"][0]["id"] == vendor
    assert o["back"]["untrusted_sources"][0]["id"] == vendor
    assert o["fwd"]["external_executed_actions"] == [msp]
    assert o["rank"]["memories"][0]["memory"]["key"] == "vaultsync-backup"
    assert len(o["clusters"]["incidents"]) == 2
    assert msp in o["sim"]["newly_require_approval"] and o["sim"]["live_graph_unchanged"]
    assert o["q"]["status"] == "quarantined" and o["q"]["guard_verdict"] == "ALLOW"
    assert o["draft"]["drafts"][0]["recipient"] == "it-support@northwind-msp.example"
    assert o["prop"]["verdict"] == "REQUIRE_HUMAN_APPROVAL" and o["prop"]["sent"] is False
    assert o["send"]["sent"] is False  # no human approval yet
    assert len(warden.runtime.outbox) == 0
    # Warden actions created over MCP derive from the recorded operator request
    qa = warden.repo.get_action(o["q"]["action_id"])
    target = warden.recorder.get_datum(qa.args[0].datum_id)
    assert o["begin"]["instruction_id"] in target.parent_ids


def test_tool_errors_are_reported(warden, incident):
    async def go(c):
        return (await c.call_tool("trace_back", {"action_id": "act_nope"}),
                await c.call_tool("propose_disclosure", {"draft_id": incident["msp"]["action"]}),
                await c.call_tool("quarantine", {"memory_ids": []}))

    nf, bad, empty = run(_with_client(warden, go))
    assert nf.is_error and "NotFound" in nf.content[0].text
    assert bad.is_error
    assert empty.is_error  # schema validation: min_length=1


def test_stdio_server_subprocess(tmp_path, falkordb_client):
    """Start the real server over stdio (as an MCP client like Claude Desktop would)."""
    if os.environ.get("CUSTODY_TEST_FALKORDB_HOST"):
        env_db = {"CUSTODY_FALKORDB_HOST": os.environ["CUSTODY_TEST_FALKORDB_HOST"],
                  "CUSTODY_FALKORDB_PORT": os.environ.get("CUSTODY_TEST_FALKORDB_PORT", "6379")}
    else:
        pytest.importorskip("redislite")
        env_db = {"CUSTODY_FALKORDB_EMBEDDED_PATH": str(tmp_path / "stdio.db")}
    from mcp.client.stdio import StdioServerParameters

    tenant = "stdio-" + os.urandom(4).hex()
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "custody.warden", "serve", "--tenant", tenant, "--seed-demo",
              "--operator", "priya@acme-robotics.example"],
        env={**os.environ, **env_db, "CUSTODY_GRAPH_PREFIX": "custody-test"},
        cwd=os.getcwd())

    async def go():
        async with Client(params) as c:
            names = {t.name for t in (await c.list_tools()).tools}
            fwd = payload(await c.call_tool("trace_forward", {
                "source_id": "web:https://docs.vaultsync-backup.example/setup"}))
            return names, fwd

    try:
        names, fwd = run(go())
    finally:
        if "CUSTODY_FALKORDB_HOST" in env_db:
            try:
                falkordb_client.select_graph(f"custody-test:{tenant}").delete()
            except Exception:
                pass
    assert names == set(TOOL_NAMES)
    assert fwd["counts"]["memories"] == 2 and len(fwd["external_executed_actions"]) == 1
