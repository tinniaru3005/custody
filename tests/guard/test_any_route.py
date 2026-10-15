"""The verdict asks whether ANY uncleared route exists; the shortest one is only evidence.
Plus: every distinct untrusted root, one route each, and verified route independence."""
from dataclasses import replace

import pytest

from custody.guard import ACME_POLICY, Guard, Verdict
from custody.guard import contamination as C

from .conftest import Flow

DEST = "files@exfil-drop.example"


def chain(flow, start, hops, text="relay"):
    d = start
    for _ in range(hops):
        d = flow.out(text, [d])
    return d


def mixed(flow, hops, url="https://vendor.example/page"):
    """A destination with a 1-hop trusted route and a ``hops``-hop untrusted route."""
    trusted = flow.user(f"send it to {DEST}")
    web = flow.web("hidden instructions", url=url)
    far = chain(flow, web, hops)
    dest = flow.out(DEST, [trusted, far])
    key = flow.secret()
    return flow.action("send_email", dest, key), web


def guard_with(recorder, **kw):
    return Guard(recorder, replace(ACME_POLICY, **kw))


# ------------------------------------------------------------- any route decides
@pytest.mark.parametrize("hops", [1, 8, 24, 26, 60])
def test_long_untrusted_route_beside_short_trusted_route_blocks(recorder, guard, hops):
    flow = Flow(recorder)
    action, web = mixed(flow, hops)
    d = guard.check(action.id)
    assert d.decision == Verdict.BLOCK
    assert d.checks["integrity"].violated
    shown = next(p for p in d.paths if p.check.value == "integrity" and p.status == "violating")
    assert shown.nodes[-1].id.startswith("web:") and shown.length == hops + 1
    assert d.contamination.root_count == 1


def test_beyond_evidence_depth_found_by_complete_search(recorder):
    flow = Flow(recorder)
    action, _ = mixed(flow, 12)
    g = guard_with(recorder, max_depth=5)          # evidence query sees only the trusted route
    d = g.check(action.id)
    assert d.decision == Verdict.BLOCK
    s = d.checks["integrity"].search
    assert s.method == "bfs" and s.path_found and s.search_complete


def test_verdict_does_not_depend_on_the_evidence_query(recorder, guard, monkeypatch):
    flow = Flow(recorder)
    action, _ = mixed(flow, 3)
    def failed(query, params, lat, key):
        lat[key] = 0.0
        return [], "simulated failure"

    monkeypatch.setattr(guard, "_evidence_rows", failed)
    assert guard.check(action.id).decision == Verdict.BLOCK


@pytest.mark.parametrize("max_depth,path_limit", [(25, 50), (25, 1), (3, 1)])
def test_shortest_route_cleared_longer_route_uncleared(recorder, guard, max_depth, path_limit):
    """The shortest untrusted route goes through an endorsed Datum (cleared); a longer one
    to the same page does not. Several short cleared routes compete for the evidence LIMIT."""
    flow = Flow(recorder)
    web = flow.web("vendor docs")
    vetted = [flow.out("vetted summary", [web]) for _ in range(3)]
    guard.endorse([v.id for v in vetted], approver="lead@acme-robotics.example",
                  reason="reviewed")
    far = chain(flow, web, 6)
    dest = flow.out(DEST, [*vetted, far])
    action = flow.action("send_email", dest, flow.secret())
    d = guard_with(recorder, max_depth=max_depth, path_limit=path_limit).check(action.id)
    assert d.decision == Verdict.BLOCK
    assert d.contamination.root_count == 1
    assert d.contamination.roots[0].hops == 7            # the uncleared route, not a vetted one


def test_only_cleared_routes_allow(recorder, guard):
    flow = Flow(recorder)
    web = flow.web("vendor docs")
    vetted = flow.out("vetted", [web])
    guard.endorse([vetted.id], approver="lead@acme-robotics.example", reason="ok")
    dest = flow.out(DEST, [flow.user("send"), vetted])
    action = flow.action("send_email", dest, flow.user("hello"))
    d = guard.check(action.id)
    assert not d.checks["integrity"].violated and d.contamination is None


def test_incomplete_search_fails_closed_despite_short_trusted_route(recorder):
    flow = Flow(recorder)
    action, _ = mixed(flow, 40)
    d = guard_with(recorder, search_max_nodes=5).check(action.id)
    assert d.decision != Verdict.ALLOW and not d.search_complete
    assert d.contamination is None                    # nothing proven: no root claims


# --------------------------------------------------------- roots & independence
def test_two_roots_independent_routes(recorder, guard):
    flow = Flow(recorder)
    a = flow.out("half A", [flow.web("host", url="https://vendor-a.example/")])
    b = flow.out("half B", [flow.r.record_external_content(
        "path", kind="email", ref="msg-1@partner.example", agent="ops", session_id="s1")])
    dest = flow.out(DEST, [a, b])
    d = guard.check(flow.action("send_email", dest, flow.secret()).id)
    c = d.contamination
    assert d.decision == Verdict.BLOCK
    assert c.root_count == 2 and c.roots_complete
    assert {r.source_id.split(":")[0] for r in c.roots} == {"web", "email"}
    assert c.independence == "independent" and c.method == "disjoint_routes"
    assert c.independent_routes == 2 and len(c.extra_routes) == 1
    assert "Untrusted roots detected: 2" in d.explanation and "Both influence" in d.explanation
    assert {s.id for s in d.sources if s.trust == "untrusted"} == {r.source_id for r in c.roots}


def test_two_roots_converging_through_one_memory(recorder, guard):
    flow = Flow(recorder)
    w1 = flow.web("a", url="https://vendor-a.example/")
    w2 = flow.web("b", url="https://partner-wiki.example/")
    mem = recorder.record_memory("notes from both", agent="scout", session_id="s0",
                                 derived_from=[w1.id, w2.id], key="k")
    dest = flow.out(DEST, [flow.user("send"), mem])
    c = guard.check(flow.action("send_email", dest, flow.secret()).id).contamination
    assert c.root_count == 2                           # two roots …
    assert c.independence == "converging"              # … but not independent routes
    assert c.shared_datum_id == mem.id and c.independent_routes == 1


def test_one_root_one_document_is_one_route(recorder, guard):
    flow = Flow(recorder)
    w = flow.web("page")
    dest = flow.out(DEST, [flow.out("x", [w]), flow.out("y", [w])])
    c = guard.check(flow.action("send_email", dest, flow.secret()).id).contamination
    assert c.root_count == 1 and c.independence == "converging" and c.shared_datum_id == w.id


def test_one_root_read_twice_is_two_independent_routes(recorder, guard):
    flow = Flow(recorder)
    w1, w2 = flow.web("page"), flow.web("page")          # same URL, fetched twice
    dest = flow.out(DEST, [flow.out("x", [w1]), flow.out("y", [w2])])
    c = guard.check(flow.action("send_email", dest, flow.secret()).id).contamination
    assert c.root_count == 1 and c.independence == "independent"


def test_independence_when_greedy_fails(recorder, guard):
    """Two disjoint routes exist, but the shortest route uses one node of each, so removing
    it blocks both: the per-node check (Menger) still proves independence."""
    flow = Flow(recorder)
    q3 = flow.web("q", url="https://q.example/")
    p3 = flow.web("p", url="https://p.example/")
    p2 = flow.out("p2", [p3])
    p1 = flow.out("p1", [p2, q3])                        # shortcut p1 -> q3
    q2 = flow.out("q2", [q3])
    q1 = flow.out("q1", [q2])
    dest = flow.out(DEST, [p1, q1])
    c = guard.check(flow.action("send_email", dest, flow.secret()).id).contamination
    assert [r.hops for r in c.roots][0] == 2              # dest -> p1 -> q3
    assert c.independence == "independent" and c.method == "no_single_shared_datum"
    assert c.extra_routes == []


def test_direct_and_unverified(recorder, guard):
    flow = Flow(recorder)
    w = flow.web(DEST)
    c = guard.check(flow.action("send_email", w, flow.secret()).id).contamination
    assert c.independence == "direct"
    flow2 = Flow(recorder, session="s2")
    w2 = flow2.web("x", url="https://other.example/")
    dest = flow2.out(DEST, [flow2.out("a", [w2])])
    g = guard_with(recorder, contamination_max_checks=0)
    c = g.check(flow2.action("send_email", dest, flow2.secret()).id).contamination
    assert c.independence == "unverified" and "not verified" in c.detail


def test_explanation_never_changes_the_verdict(recorder, guard, monkeypatch):
    flow = Flow(recorder)
    action, _ = mixed(flow, 4)
    base = guard.check(action.id)
    off = guard_with(recorder, contamination_analysis=False).check(action.id)

    def boom(*a, **k):
        raise RuntimeError("analysis failed")

    monkeypatch.setattr(C, "analyse", boom)
    broken = guard.check(action.id)
    assert base.decision == off.decision == broken.decision == Verdict.BLOCK
    assert base.triggered_checks == off.triggered_checks == broken.triggered_checks
    assert off.contamination is None and broken.contamination is None


def test_root_search_is_linear_not_path_enumeration(recorder, guard):
    """A dense multi-turn session (≈2^t paths) has its roots found in one BFS."""
    flow = Flow(recorder)
    ctx = [flow.web("w", url="https://dense.example/")]
    for t in range(40):
        ctx.append(flow.out(f"turn {t}", list(ctx)))
    dest = flow.out(DEST, list(ctx))
    d = guard.check(flow.action("send_email", dest, flow.secret()).id)
    c = d.contamination
    assert c.root_count == 1 and c.roots_complete and c.latency_ms < 1_000
