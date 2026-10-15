"""rank_risky_memories (algo.betweenness) and cluster_incidents (algo.WCC)."""
from tests.warden.conftest import by_key


def test_rank_risky_memories(warden, incident):
    res = warden.rank_risky_memories()
    assert res.centrality["available"] is True
    assert "betweenness" in res.centrality["algorithm"]
    keys = [m.memory.key for m in res.memories]
    assert keys[0] == "vaultsync-backup"
    top = res.memories[0]
    assert top.tainted and top.untrusted_sources == [incident["vendor_source"]]
    assert top.betweenness > 0 and top.betweenness_normalized == 1.0
    assert top.downstream_recalls == 3
    assert incident["msp"]["action"] in top.executed_external_actions
    assert incident["dangerous"]["action"] in top.downstream_actions
    clean = next(m for m in res.memories if m.memory.key == "board-meeting")
    assert not clean.tainted and clean.risk_score < 1 and keys[-1] == "board-meeting"
    phish = next(m for m in res.memories if m.memory.key == "supplier-bank-details")
    assert phish.tainted and phish.untrusted_sources == [incident["phish_source"]]


def test_rank_excludes_quarantined_unless_asked(warden, incident):
    warden.quarantine([incident["dangerous"]["memory"]])
    keys = [m.memory.key for m in warden.rank_risky_memories().memories]
    assert "vaultsync-backup" not in keys
    both = warden.rank_risky_memories(include_quarantined=True).memories
    assert by_key([m.memory for m in both], "vaultsync-backup").in_quarantine
    assert len(warden.rank_risky_memories(limit=1).memories) == 1


def test_cluster_incidents(warden, incident, falkordb_client):
    graphs_before = set(falkordb_client.list_graphs())
    counts_before = warden.repo.counts()
    res = warden.cluster_incidents()
    assert "algo.WCC" in res.method and "GRAPH.COPY" in res.method
    assert len(res.incidents) == 2
    vendor, phish = res.incidents  # sorted by severity
    assert [s.id for s in vendor.sources] == [incident["vendor_source"]]
    assert vendor.severity == "high"
    assert vendor.executed_external_actions == [incident["msp"]["action"]]
    assert vendor.blocked_actions == [incident["dangerous"]["action"]]
    assert {m.key for m in vendor.memories} == {"vaultsync-backup", "nightly-backup-target"}
    assert incident["safe"]["action"] not in {a.id for a in vendor.actions}  # context only
    assert [s.id for s in phish.sources] == [incident["phish_source"]]
    assert phish.severity == "medium" and [m.key for m in phish.memories] == ["supplier-bank-details"]
    # the sandbox clone is gone and the live graph is untouched (no :Contaminated labels)
    assert set(falkordb_client.list_graphs()) == graphs_before
    assert warden.repo.counts() == counts_before
    assert "node:Contaminated" not in warden.repo.counts()


def test_cluster_wcc_matches_union_find(warden, incident):
    wcc = warden.analysis.cluster_incidents(use_falkordb_wcc=True)
    uf = warden.analysis.cluster_incidents(use_falkordb_wcc=False)
    assert "union-find" in uf.method
    norm = lambda r: sorted((i.id, i.node_count, i.severity) for i in r.incidents)
    assert norm(wcc) == norm(uf)


def test_cluster_incidents_empty_graph(warden):
    res = warden.cluster_incidents()
    assert res.incidents == [] and res.method == "none"
