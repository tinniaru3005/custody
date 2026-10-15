"""Split-source destination: two untrusted sources each supply half of the URL."""
import random

from bench import baselines as B
from bench.cases import d_split_source
from bench.common import export_graph
from custody.graph import traversal as T
from custody.guard import Verdict


def test_custody_traces_assembled_destination_to_both_roots(runtime, guard, recorder):
    case = d_split_source(runtime, random.Random(11), 0)
    ex = export_graph(recorder)
    untrusted = [d for d in ex.docs.values() if d.source_trust == "untrusted"]
    # no untrusted document contains the final destination (or its host)
    assert not B.string_exact(case.destination, untrusted)
    assert not B.string_host(case.destination, untrusted)
    d = guard.check(case.action_id)
    assert d.decision == Verdict.REQUIRE_HUMAN_APPROVAL
    roots = {p.nodes[-1].id for p in d.checks["integrity"].paths if p.status == "violating"}
    assert len(roots) == 2
    assert any(r.startswith("web:") for r in roots) and any(r.startswith("email:") for r in roots)
    # the two halves came through different agents
    assert {"scout", "courier"} <= {a for p in d.checks["integrity"].paths for a in p.agents}
    # complete ancestry lists both as reachable roots too
    dest = next(a.datum_id for a in guard.repo.get_action(case.action_id).args
                if a.role == "destination")
    anc = T.ancestor_graph(guard.repo.graph, [dest])
    assert roots <= {s["id"] for s in anc.sources.values()}
    # the complete root search finds exactly these two, with one route each, and the two
    # routes (scout's message, courier's message) share no Datum besides the argument
    c = d.contamination
    assert c.root_count == 2 and c.roots_complete
    assert {r.source_id for r in c.roots} == roots
    assert {a for r in c.roots for a in r.path.agents} >= {"scout", "courier"}
    assert c.independence == "independent"
    assert "Untrusted roots detected: 2" in d.explanation
