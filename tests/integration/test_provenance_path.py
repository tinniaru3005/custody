"""Integration: provenance crosses sessions and agents through many DERIVED_FROM hops."""
import pytest

from custody.graph.model import Sensitivity, Trust
from custody.seeds.acme import seed_acme

pytestmark = pytest.mark.integration

WEB_SOURCE = "web:https://rivalbots.example/pricing"


def test_destination_traces_to_untrusted_web_across_sessions_and_agents(recorder):
    ids = seed_acme(recorder)

    paths = recorder.find_paths(ids["dest"], ids["web"])
    assert len(paths) == 2

    # Shortest route is via the inter-agent message:
    # dest (ops, S2) -> message (research, S1) -> summary (S1) -> web
    via_msg = paths[0]
    assert via_msg.node_ids == [ids["dest"], ids["message"], ids["summary"], ids["web"]]
    assert via_msg.ops == ["derive", "send", "derive"]

    # The other route goes through shared memory:
    # dest (ops, S2) -> recall (S2) -> memory (S1) -> summary (research, S1) -> web
    path = paths[1]
    assert path.node_ids == [ids["dest"], ids["recall"], ids["memory"], ids["summary"], ids["web"]]
    assert path.ops == ["derive", "recall", "save", "derive"]
    assert path.length == 4  # four DERIVED_FROM hops

    # ...and all the way to the Source node (shortest: 3 DERIVED_FROM via message + 1 FROM).
    to_source = recorder.find_path(ids["dest"], WEB_SOURCE)
    assert to_source.length == 4 and to_source.ops[-1] == "FROM"

    # The path really spans two sessions and two agents.
    sessions = {recorder.get_datum(n).session_id for n in path.node_ids}
    agents = {recorder.get_datum(n).agent for n in path.node_ids}
    assert sessions == {"acme-s1-research", "acme-s2-ops"}
    assert {"research", "ops"} <= agents


def test_action_trace_exposes_destination_and_payload_origins(recorder):
    ids = seed_acme(recorder)
    trace = recorder.trace_action(ids["action"])
    by_role = {a.role: a.lineage for a in trace.args}

    dest = by_role["destination"]
    assert WEB_SOURCE in {s.id for s in dest.untrusted_sources}
    # message path also reaches the web page: dest -> message -> summary -> web
    depths = {e.datum.id: e.depth for e in dest.entries}
    assert depths[ids["web"]] == 3 and depths[ids["message"]] == 1

    payload = by_role["payload"]
    assert payload.max_sensitivity == Sensitivity.SECRET
    assert "vault:secret/aws/deploy-key" in {s.id for s in payload.sources}
    assert trace.action.sink.destination == "sync@rivalbots-partners.example"
    assert trace.action.sink.external is True


def test_benign_flow_is_endorsed_and_trusted(recorder):
    ids = seed_acme(recorder)
    trace = recorder.trace_action(ids["kpi_action"])
    dest = next(a for a in trace.args if a.role == "destination").lineage
    assert dest.untrusted_sources == []
    assert all(s.trust == Trust.TRUSTED for s in dest.sources)
    assert dest.entries[0].datum.endorsed is True


def test_long_chain_of_memories_and_messages(recorder):
    """A 10-hop chain alternating memory/recall/message/output across agents."""
    head = recorder.record_web_content("evil instruction", url="https://evil.example")
    cur = head.id
    agents = ["a1", "a2", "a3"]
    for i in range(3):
        agent = agents[i % 3]
        out = recorder.record_llm_output(f"step {i}", agent=agent, derived_from=[cur],
                                         session_id=f"s{i}")
        mem = recorder.record_memory(f"mem {i}", agent=agent, derived_from=[out.id])
        rec = recorder.record_memory_recall(mem.id, agent=agents[(i + 1) % 3],
                                            session_id=f"s{i + 1}")
        cur = rec.id
    msg = recorder.record_message("fwd", sender="a1", recipient="a2", derived_from=[cur])
    path = recorder.find_path(msg.id, "web:https://evil.example")
    assert path is not None and path.length == 3 * 3 + 1 + 1
    lineage = recorder.lineage(msg.id)
    assert lineage.untrusted_sources[0].id == "web:https://evil.example"
    # depth limit is respected
    assert recorder.find_path(msg.id, head.id, max_depth=5) is None
