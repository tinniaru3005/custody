"""End-to-end tests of the console API over HTTP.

Primary demo (one story): attack scenario → dashboard → graph → Guard decision +
provenance chain → lethal-trifecta block is never approvable.
Extended scenario (``?scenario=extended``): approvals, Warden investigation over MCP →
quarantine → disclosure approval → send.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from custody.api.app import create_app
from custody.config import Settings
from custody.demo.attack import ATTACKER_URL, CLEANUP_REQUEST, PRIYA, VENDOR_SOURCE_ID
from custody.guard import ACME_POLICY, register_policy


@pytest.fixture
def client(falkordb_client, tenant):
    register_policy(tenant, ACME_POLICY)
    app = create_app(db=falkordb_client, settings=Settings(graph_prefix="custody-test"))
    with TestClient(app) as c:
        yield c


@pytest.fixture
def base(tenant):
    return f"/api/tenants/{tenant}/console"


@pytest.fixture
def demo(client, base):
    r = client.post(f"{base}/demo/attack")
    assert r.status_code == 201, r.text
    return r.json()


@pytest.fixture
def extended(client, base):
    r = client.post(f"{base}/demo/attack?scenario=extended")
    assert r.status_code == 201, r.text
    assert r.json()["scenario"] == "extended"
    return r.json()


def test_empty_tenant_overview(client, base):
    ov = client.get(f"{base}/overview").json()
    assert ov["empty"] is True
    assert ov["agents"] == [] and ov["actions"] == []
    assert client.get(f"{base}/demo").json() is None


def test_primary_demo_is_one_story(demo):
    steps = demo["steps"]
    assert demo["scenario"] == "primary"
    assert [s["key"] for s in steps] == ["scout_reads", "memory_saved", "ops_asked",
                                         "secret_read", "slack_allowed", "exfil_blocked",
                                         "explain"]
    by_key = {s["key"]: s for s in steps}
    assert by_key["slack_allowed"]["verdict"] == "ALLOW"
    assert by_key["slack_allowed"]["status"] == "executed"
    assert by_key["exfil_blocked"]["verdict"] == "BLOCK"
    assert by_key["exfil_blocked"]["status"] == "blocked"
    assert [s["day"] for s in steps] == ["Day 1"] * 2 + ["Day 4"] * 5
    # only two actions in the whole story; only the internal Slack post was delivered
    assert {s["action_id"] for s in steps if s["action_id"]} == {
        demo["ids"]["slack_action"], demo["ids"]["blocked_action"]}
    d = demo["blocked_decision"]
    assert d["decision"] == "BLOCK"
    assert set(d["triggered_checks"]) == {"integrity", "confidentiality", "lethal_trifecta"}
    assert d["approval"]["available"] is False
    assert d["deterministic"] is True and d["search_complete"] is True
    assert [o["tool"] for o in demo["outbox"]] == ["post_slack"]
    assert all(o["destination"] != ATTACKER_URL and o["simulated"] for o in demo["outbox"])
    # the path the story ends on goes back across sessions to the vendor page
    assert "scout-day1" in by_key["explain"]["narrative"]
    assert VENDOR_SOURCE_ID in by_key["explain"]["narrative"]


def test_demo_discloses_simulation(demo):
    text = " ".join(demo["simulation"]).lower()
    for word in ("synthetic", "simulated", "scripted", "slack", "vault", "no llm"):
        assert word in text
    by_key = {s["key"]: s for s in demo["steps"]}
    assert by_key["scout_reads"]["simulated"] and by_key["slack_allowed"]["simulated"]
    assert by_key["exfil_blocked"]["simulated"]


def test_dashboard_overview(client, base, demo):
    ov = client.get(f"{base}/overview").json()
    assert ov["empty"] is False
    assert [a["name"] for a in ov["agents"]] == ["scout", "ops"]
    c = ov["counts"]
    assert c["blocked"] == 1 and c["allowed"] == 1 and c["approval"] == 0
    assert c["quarantined_memories"] == 0 and c["tainted_memories"] == 1
    assert [tuple(i["sources"]) for i in ov["incidents"]] == [(VENDOR_SOURCE_ID,)]
    assert ov["demo"]["blocked_action"] == demo["ids"]["blocked_action"]


def test_graph_view_has_all_node_types_and_flags(client, base, demo):
    g = client.get(f"{base}/graph").json()
    labels = {n["label"] for n in g["nodes"]}
    assert {"Source", "Datum", "Memory", "Recall", "Action", "Sink"} <= labels
    types = {e["type"] for e in g["edges"]}
    assert {"DERIVED_FROM", "FROM", "ARG", "TO"} <= types
    nodes = {n["id"]: n for n in g["nodes"]}
    assert "untrusted" in nodes[VENDOR_SOURCE_ID]["flags"]
    assert "tainted" in nodes[demo["ids"]["memory"]]["flags"]
    assert "secret" in nodes[demo["ids"]["secret"]]["flags"]
    assert "blocked" in nodes[demo["ids"]["blocked_action"]]["flags"]
    assert nodes[demo["ids"]["memory"]]["step"] == 2
    assert all(n["label"] != "Message" for n in g["nodes"])   # no extra agents/messages
    # raw secret values never reach the UI
    assert "sk_staging" not in str(g)
    assert "Decision" not in labels
    assert "Decision" in {n["label"] for n in
                          client.get(f"{base}/graph?include_decisions=true").json()["nodes"]}


def test_blocked_action_explain_chain(client, base, demo):
    aid = demo["ids"]["blocked_action"]
    ex = client.get(f"{base}/actions/{aid}/explain").json()
    d = ex["decision"]
    assert d["decision"] == "BLOCK"
    assert d["checks"]["integrity"]["violated"] and d["checks"]["confidentiality"]["violated"]
    assert d["checks"]["lethal_trifecta"]["violated"]
    assert d["latency_ms"]["total"] > 0
    roles = [c["role"] for c in ex["chain"]]
    # Action → destination sink → destination arg (Day 4) → Day-1 memory (previous session)
    # → vendor page → untrusted Source
    assert roles == ["action", "sink", "destination", "previous-session memory", "web page",
                     "source"]
    assert ex["chain"][-1]["id"] == VENDOR_SOURCE_ID and ex["chain"][-1]["trust"] == "untrusted"
    assert ex["chain"][0]["path_length"] == 2
    assert ex["history"] and ex["history"][-1]["decision"] == "BLOCK"


def test_lethal_trifecta_never_approvable(client, base, demo, tenant):
    q = client.get(f"{base}/approvals").json()
    assert q["pending"] == []
    assert len(q["blocked"]) == 1 and q["blocked"][0]["can_approve"] is False
    aid = demo["ids"]["blocked_action"]
    r = client.post(f"/api/tenants/{tenant}/guard/actions/{aid}/approve",
                    json={"approver": PRIYA})
    assert r.status_code == 403


def test_extended_scenario_has_the_approval_case(client, base, extended):
    q = client.get(f"{base}/approvals").json()
    assert len(q["pending"]) == 1 and q["pending"][0]["can_approve"] is True
    assert q["pending"][0]["explain"]["action"]["action_type"] == "configure_backup"
    assert len(q["blocked"]) == 1 and q["blocked"][0]["can_approve"] is False


def test_approve_records_endorsement_in_graph(client, base, extended, tenant):
    demo = extended
    aid = demo["ids"]["configure_action"]
    pending = client.get(f"{base}/approvals").json()["pending"][0]["explain"]
    assert pending["chain"][-1]["id"] == VENDOR_SOURCE_ID
    r = client.post(f"/api/tenants/{tenant}/guard/actions/{aid}/approve",
                    json={"approver": PRIYA, "reason": "verified with vendor"})
    assert r.status_code == 200 and r.json()["decision"] == "ALLOW"
    # the Guard re-ran: the endorsed path is now certified as cleared, not ignored
    cert = r.json()["certificate"]
    roots = {x["id"]: x["status"] for x in cert["root_sources"]}
    assert roots[VENDOR_SOURCE_ID] == "cleared"
    ex = client.get(f"{base}/actions/{aid}/explain").json()
    assert any(a["relation"] == "ENDORSES" for a in ex["approvals"])
    g = client.get(f"{base}/graph").json()
    assert any(e["type"] == "ENDORSES" for e in g["edges"])


def test_reject_records_rejection_in_graph(client, base, extended, tenant):
    aid = extended["ids"]["configure_action"]
    r = client.post(f"/api/tenants/{tenant}/guard/actions/{aid}/reject",
                    json={"approver": PRIYA, "reason": "unknown backup host"})
    assert r.status_code == 200 and r.json()["status"] == "rejected"
    ex = client.get(f"{base}/actions/{aid}/explain").json()
    assert [a["relation"] for a in ex["approvals"]] == ["REJECTS"]
    assert ex["approvals"][0]["verdict"] == "rejected"
    q = client.get(f"{base}/approvals").json()
    assert q["pending"] == [] and any(a["id"] == aid for a in q["resolved"])


def test_warden_investigation_quarantines_and_drafts(client, base, extended, tenant):
    demo = extended
    r = client.post(f"{base}/warden/investigate",
                    json={"request": CLEANUP_REQUEST, "planner": "playbook"})
    assert r.status_code == 201, r.text
    run = r.json()
    tools = run["tools_used"]
    assert tools[:4] == ["find_sources", "trace_forward", "rank_risky_memories",
                         "cluster_incidents"]
    assert "quarantine" in tools and "draft_disclosure" in tools
    assert "propose_disclosure" in tools
    ids = demo["ids"]
    assert sorted(run["quarantined_memory_ids"]) == sorted([ids["memory"], ids["runbook_memory"]])
    assert run["quarantine_verdicts"] == ["ALLOW"]
    assert run["external_executed_actions"] == [ids["msp_action"]]
    assert len(run["pending_approvals"]) == 1
    assert client.get(f"{base}/warden").json()["id"] == run["id"]

    ov = client.get(f"{base}/overview").json()
    q = {m["id"]: m for m in ov["memories"]}
    assert q[ids["memory"]]["in_quarantine"] and q[ids["runbook_memory"]]["in_quarantine"]
    assert not q[ids["phish_memory"]]["in_quarantine"]      # separate incident untouched
    assert not q[ids["clean_memory"]]["in_quarantine"]
    assert ov["counts"]["quarantined_memories"] == 2

    # the disclosure waits for a human, then sends after approval
    disc = run["pending_approvals"][0]["action_id"]
    queue = client.get(f"{base}/approvals").json()
    item = next(i for i in queue["pending"] if i["explain"]["action"]["id"] == disc)
    assert item["can_approve"] and "human_review" in item["explain"]["decision"]["triggered_checks"]
    not_yet = client.post(f"{base}/warden/disclosures/{disc}/send").json()
    assert not_yet["sent"] is False
    assert client.post(f"/api/tenants/{tenant}/guard/actions/{disc}/approve",
                       json={"approver": PRIYA}).json()["decision"] == "ALLOW"
    sent = client.post(f"{base}/warden/disclosures/{disc}/send").json()
    assert sent["sent"] is True


def test_metrics(client, base, demo):
    m = client.get(f"{base}/metrics?runs=3").json()
    assert m["focus_action"] == demo["ids"]["blocked_action"]
    assert m["path_length"] == 2
    assert m["deterministic_runs"] == 3 and m["deterministic_identical"] is True
    assert m["guard_latency_ms"] > 0 and m["guard_latency_samples"]
    assert set(m["affected_agents"]) == {"scout", "ops"}
    assert m["affected_memories"] == 1
    assert m["blocked_actions"] == 1
    assert {"scout-day1", "ops-day4"} <= set(m["sessions_crossed"])


def test_reset(client, base, demo):
    assert client.post(f"{base}/demo/reset").status_code == 204
    assert client.get(f"{base}/overview").json()["empty"] is True


def test_unknown_action_404(client, base, demo):
    assert client.get(f"{base}/actions/nope/explain").status_code == 404


def test_root_paths_still_work_without_api_prefix(client, tenant, demo):
    assert client.get(f"/tenants/{tenant}/console/actions").status_code == 200
    assert client.get("/api/health").json()["falkordb"] is True


def test_warden_plain_language_request(client, base, extended):
    run = client.post(f"{base}/warden/investigate",
                      json={"request": "That vendor page was malicious. Clean it up.",
                            "planner": "playbook"}).json()
    assert run["steps"][0]["tool"] == "find_sources"
    assert run["steps"][1]["arguments"]["source_id"] == VENDOR_SOURCE_ID
    assert len(run["quarantined_memory_ids"]) == 2


def test_settings_cloud_options():
    s = Settings(falkordb_username="u", falkordb_ssl=True, cors_origins="http://a, http://b")
    assert s.cors_origin_list == ["http://a", "http://b"] and s.falkordb_ssl


def test_demo_allow_carries_a_completeness_certificate(client, base, demo):
    c = demo["slack_decision"]["certificate"]
    assert c["untrusted_influence"] == "NONE_FOUND" and c["frontier_exhausted"]
    roots = {r["id"]: r for r in c["root_sources"]}
    assert roots[VENDOR_SOURCE_ID]["trust"] == "untrusted"
    assert roots[VENDOR_SOURCE_ID]["status"] == "context_only"
    assert demo["blocked_decision"]["certificate"] is None
    # a later re-check is tied to the later graph version, over the same ancestry
    ex = client.get(f"{base}/actions/{demo['ids']['slack_action']}/explain").json()
    later = ex["decision"]["certificate"]
    assert later["graph_version"] > c["graph_version"]
    assert later["ancestry_digest"] == c["ancestry_digest"]
