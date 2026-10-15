"""check_action / explain_decision: the existing Guard, over MCP."""
import asyncio
from dataclasses import replace

import pytest

mcp = pytest.importorskip("mcp")
from mcp import Client  # noqa: E402

from custody.console import service as svc  # noqa: E402
from custody.guard import ACME_POLICY  # noqa: E402
from custody.warden import Warden  # noqa: E402
from custody.warden.mcp_server import build_server  # noqa: E402

VENDOR = "web:https://docs.vaultsync-backup.example/setup"


def payload(res):
    sc = res.structured_content
    return sc.get("result", sc) if isinstance(sc, dict) and set(sc) == {"result"} else sc


def call(warden, *calls):
    async def go():
        async with Client(build_server(warden)) as c:
            out = []
            for name, args in calls:
                r = await c.call_tool(name, args)
                out.append(r if r.is_error else payload(r))
            return out
    return asyncio.run(go())


@pytest.fixture
def demo(provider, tenant):
    return svc.run_demo(provider, tenant, deterministic=True)


def test_check_action_returns_the_guard_verdict_and_evidence(provider, tenant, demo):
    w = Warden.for_tenant(provider, tenant, policy=ACME_POLICY)
    blocked, allowed = call(w, ("check_action", {"action_id": demo.ids["blocked_action"]}),
                            ("check_action", {"action_id": demo.ids["slack_action"]}))
    assert blocked["verdict"] == "BLOCK" and not blocked["fail_closed"]
    assert set(blocked["triggered"]) == {"integrity", "confidentiality", "lethal_trifecta"}
    assert blocked["untrusted_sources"] == [VENDOR]
    assert any(p["status"] == "violating" and p["node_ids"][-1] == VENDOR
               for p in blocked["paths"])
    assert blocked["approval"]["available"] is False and blocked["recorded"] is True
    assert "caller must enforce" in blocked["enforcement"]
    c = blocked["contamination"]
    assert c["root_count"] == 1 and c["roots"][0]["source"] == VENDOR
    assert c["independence"] == "converging" and c["shared_datum_id"] == demo.ids["memory"]
    assert allowed["contamination"] is None
    assert allowed["verdict"] == "ALLOW" and allowed["certificate"]["root_sources_checked"] > 0
    # same verdict as the HTTP/runtime Guard (one implementation)
    assert blocked["verdict"] == "BLOCK" == demo.blocked_decision["decision"]
    # the action itself is untouched (status from the demo's own enforcement)
    assert w.repo.get_action(demo.ids["slack_action"]).status.value == "executed"


def test_check_action_reports_fail_closed(provider, tenant, demo):
    w = Warden.for_tenant(provider, tenant, policy=replace(ACME_POLICY, search_max_depth=0))
    (r,) = call(w, ("check_action", {"action_id": demo.ids["slack_action"]}))
    assert r["verdict"] == "REQUIRE_APPROVAL" and r["fail_closed"] is True
    assert r["search_complete"] is False and "integrity" in r["indeterminate_checks"]
    assert r["checks"]["integrity"]["search_outcome"] == "INDETERMINATE"
    assert r["certificate"] is None


def test_explain_decision(provider, tenant, demo):
    w = Warden.for_tenant(provider, tenant, policy=ACME_POLICY)
    (r,) = call(w, ("explain_decision", {"action_id": demo.ids["blocked_action"]}))
    assert r["recorded"]["verdict"] == "BLOCK" and r["current"]["verdict"] == "BLOCK"
    assert r["matches_recorded"] is True and r["current"]["recorded"] is False
    assert any(p["node_ids"][-1] == VENDOR for p in r["current"]["paths"])
    assert r["graph_version"].endswith(f"@v{w.repo.graph_version().finished}")
    # explain does not write: no new Decision
    n = len(w.repo.decisions_for(demo.ids["blocked_action"]))
    call(w, ("explain_decision", {"action_id": demo.ids["blocked_action"]}))
    assert len(w.repo.decisions_for(demo.ids["blocked_action"])) == n


def test_errors_are_tool_errors(provider, tenant, demo):
    w = Warden.for_tenant(provider, tenant, policy=ACME_POLICY)
    missing, unknown_dec = call(
        w, ("check_action", {"action_id": "act_nope"}),
        ("explain_decision", {"action_id": demo.ids["blocked_action"], "decision_id": "dec_x"}))
    assert missing.is_error and unknown_dec.is_error
