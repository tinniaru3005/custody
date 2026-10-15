"""simulate_policy: GRAPH.COPY sandbox, never alters the live tenant graph."""
import pytest

from custody.warden import PolicySpec
from custody.warden.sandbox import GraphSandbox, ReadOnlyGraph
from custody.warden.simulate import build_policy


def _decisions(repo):
    return repo.counts().get("node:Decision", 0)


def test_simulate_human_review_for_email(warden, incident, falkordb_client):
    graphs_before = set(falkordb_client.list_graphs())
    counts_before = warden.repo.counts()
    msp = incident["msp"]["action"]
    res = warden.simulate_policy({"name": "review-external-email",
                                  "human_review_action_types": ["send_email"]})
    assert res.isolation["mode"] == "graph_copy" and res.isolation["sandbox_deleted"] is True
    assert res.live_graph_unchanged and warden.repo.counts() == counts_before
    assert set(falkordb_client.list_graphs()) == graphs_before
    row = next(a for a in res.actions if a.action_id == msp)
    assert (row.baseline, row.simulated, row.changed) == ("ALLOW", "REQUIRE_HUMAN_APPROVAL", True)
    assert "human_review" in row.simulated_triggered
    assert msp in res.newly_require_approval and msp in res.executed_but_would_have_been_stopped
    assert incident["dangerous"]["action"] in res.would_block
    assert warden.repo.get_action(msp).status.value == "executed"  # live status untouched


def test_simulate_sink_policy_and_quarantine(warden, incident):
    before = _decisions(warden.repo)
    spec = PolicySpec(name="northwind-internal", internal_email_domains=[
        "acme-robotics.example", "northwind-msp.example"],
        quarantined_memory_ids=[incident["dangerous"]["memory"]])
    res = warden.simulate_policy(spec)
    assert _decisions(warden.repo) == before  # no Decision nodes written to the live graph
    prevented = set(res.prevented_by_quarantine)
    assert {incident["dangerous"]["action"], incident["msp"]["action"]} <= prevented
    assert incident["safe"]["action"] not in prevented  # only context-influenced
    assert "Would not have been proposed" in next(
        a for a in res.actions if a.action_id == incident["msp"]["action"]).explanation


def test_simulate_read_only_fallback(warden, incident):
    from custody.warden.simulate import simulate_policy

    res = simulate_policy(warden.db, warden.repo, warden.guard.policy,
                          PolicySpec(human_review_action_types=["send_email"]),
                          prefer_copy=False)
    assert res.isolation["mode"] == "read_only_live" and res.live_graph_unchanged
    assert incident["msp"]["action"] in res.newly_require_approval


def test_read_only_sandbox_rejects_writes(warden, incident):
    ro = ReadOnlyGraph(warden.repo.graph)
    with pytest.raises(Exception):
        ro.query("CREATE (:Evil {id: 'x'})")
    with pytest.raises(PermissionError):
        ro.delete()
    assert "node:Evil" not in warden.repo.counts()


def test_sandbox_copy_is_isolated(warden, incident, falkordb_client):
    with GraphSandbox(falkordb_client, warden.repo.graph) as sb:
        assert sb.mode == "graph_copy"
        sb.graph.query("CREATE (:Scratch {id: 's'})")
        assert sb.graph.query("MATCH (n:Scratch) RETURN count(n)").result_set[0][0] == 1
    assert "node:Scratch" not in warden.repo.counts()
    assert sb.clone_name not in falkordb_client.list_graphs()


def test_build_policy_overrides(warden):
    p = build_policy(warden.guard.policy, PolicySpec(
        internal_hosts=["Example.COM"], actions={"post_slack": {"outbound": True,
                                                                "irreversible": True,
                                                                "risk": "low"}},
        human_review_action_types=["http_post"]))
    assert p.internal_hosts == frozenset({"example.com"})
    assert p.action("post_slack").risk.value == "low"
    assert p.action("http_post").human_review
    assert p.internal_email_domains == warden.guard.policy.internal_email_domains
