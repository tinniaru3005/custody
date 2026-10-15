"""Agent-level influence projection, derived from the provenance graph."""
from fastapi.testclient import TestClient

from custody.api.app import create_app
from custody.config import Settings
from custody.console import service as svc
from custody.console.influence import build
from custody.demo.attack import VENDOR_SOURCE_ID
from custody.guard import ACME_POLICY, register_policy


def test_primary_demo_collapses_to_scout_memory_ops(provider, tenant):
    run = svc.run_demo(provider, tenant, deterministic=True)
    v = build(svc.recorder_for(provider, tenant).repo)
    assert v.search.search_complete
    cross = [i for i in v.influences if i.kind != "entry"]
    assert [(i.source, i.via, i.target) for i in cross] == \
        [("agent:scout", run.ids["memory"], "agent:ops")]
    m = cross[0]
    assert m.via_label == "Memory" and m.tainted and m.followed and m.edges >= 2
    assert set(m.sessions) == {"scout-day1", "ops-day4"}
    # the revealed path is real provenance: ops datum → Day-1 memory → … → vendor page
    assert m.path[0].agent == "ops" and m.path[1].id == run.ids["memory"]
    assert m.path[-1].id == VENDOR_SOURCE_ID and m.path[-1].trust == "untrusted"
    entry = next(i for i in v.influences if i.kind == "entry")
    assert (entry.source, entry.target) == (f"source:{VENDOR_SOURCE_ID}", "agent:scout")
    agents = {p.label: p for p in v.participants if p.type == "agent"}
    assert set(agents) == {"scout", "ops"} and agents["ops"].tainted
    assert "1 carrying untrusted influence" in v.summary


def test_extended_scenario_shows_messages_and_separate_incident(provider, tenant):
    svc.run_demo(provider, tenant, "extended")
    v = build(svc.recorder_for(provider, tenant).repo)
    kinds = {(i.source, i.kind, i.target) for i in v.influences}
    assert ("agent:courier", "message", "agent:ops") in kinds
    assert ("agent:scout", "memory", "agent:ops") in kinds
    assert any(i.source.startswith("source:email:") for i in v.influences)


def test_clean_cross_agent_flow_is_not_tainted(recorder):
    u = recorder.record_user_input("Q4 board meeting is Oct 15", user="marcus", agent="scout",
                                   session_id="s1")
    mem = recorder.record_memory("board meeting Oct 15", agent="scout", derived_from=[u.id],
                                 session_id="s1")
    recorder.record_llm_output("noted", agent="ops", derived_from=[mem.id], session_id="s2")
    v = build(recorder.repo)
    (i,) = v.influences
    assert (i.source, i.via, i.target, i.tainted) == ("agent:scout", mem.id, "agent:ops", False)
    assert [s.id for s in i.path] == [i.path[0].id, mem.id]


def test_influence_endpoint(falkordb_client, tenant):
    register_policy(tenant, ACME_POLICY)
    with TestClient(create_app(db=falkordb_client,
                               settings=Settings(graph_prefix="custody-test"))) as c:
        c.post(f"/api/tenants/{tenant}/console/demo/attack")
        r = c.get(f"/api/tenants/{tenant}/console/influence").json()
        assert any(i["kind"] == "memory" and i["tainted"] for i in r["influences"])

