"""Chokepoint analysis: verified single-node cuts of every recorded untrusted path."""
import random

from bench.cases import d_split_source
from custody.console import service as svc
from custody.db import GraphProvider
from custody.guard import ACME_POLICY
from custody.warden import Warden


def test_primary_demo_memory_is_the_chokepoint(falkordb_client, tenant):
    provider = GraphProvider(falkordb_client, prefix="custody-test")
    run = svc.run_demo(provider, tenant, deterministic=True)
    w = Warden.for_tenant(provider, tenant, policy=ACME_POLICY)
    r = w.find_chokepoints(run.ids["blocked_action"])
    assert r.dangerous and r.search.search_complete
    assert r.untrusted_sources == ["web:https://docs.vaultsync-backup.example/setup"]
    assert r.recommended == run.ids["memory"]
    top = r.chokepoints[0]
    assert top.id == run.ids["memory"] and top.quarantinable and not top.trivial
    assert top.verified and top.path_share == 1.0 and top.paths_through == r.total_paths
    assert "100% of the" in top.explanation and "NO_PATH" in top.explanation
    assert "not a dominator" in r.method
    # every reported chokepoint was verified by an exclusion re-run
    assert all(c.verified for c in r.chokepoints)
    # the Slack ALLOW has nothing to break
    clean = w.find_chokepoints(run.ids["slack_action"])
    assert not clean.dangerous and clean.chokepoints == []


def test_two_independent_sources_have_no_single_nontrivial_chokepoint(recorder):
    from custody.guard import Guard
    from custody.runtime import AgentRuntime

    runtime = AgentRuntime(recorder, Guard(recorder, ACME_POLICY))
    case = d_split_source(runtime, random.Random(3), 0)
    from custody.warden.analysis import WardenAnalysis
    from custody.warden.chokepoints import find_chokepoints

    r = find_chokepoints(WardenAnalysis(recorder.repo, ACME_POLICY), case.action_id)
    assert r.dangerous and len(r.untrusted_sources) == 2
    assert all(c.trivial for c in r.chokepoints)   # only the action's own argument
    assert r.recommended is None
    assert "no single non-trivial node" in r.summary


def test_chokepoint_mcp_tool_is_registered():
    from custody.warden.mcp_server import TOOL_NAMES

    assert "find_chokepoints" in TOOL_NAMES
