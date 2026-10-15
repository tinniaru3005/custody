"""Recording soundness: every recorded output is linked to EVERYTHING in its context window.

Negative results ("no provenance path") are only meaningful if the graph does not silently
omit context dependencies. These tests pin the default rule of the agent runtime:
outputs get DERIVED_FROM edges to every context Datum; ``derived_from=`` can add parents
but never narrow; everything shown to the model enters the context.
"""
import pytest

from custody.guard import ACME_POLICY, Guard, Verdict
from custody.runtime import AgentRuntime, Vault

URL = "https://vendor.example/page"


@pytest.fixture
def rt(recorder):
    return AgentRuntime(recorder, Guard(recorder, ACME_POLICY),
                        vault=Vault({"secret/k": "sk_FAKE_123456789"}),
                        web={URL: "Vendor page. Contact sales@vendor.example"})


def parents(rt, datum_id):
    rows = rt.recorder.repo.graph.ro_query(
        "MATCH (d:Datum {id: $id})-[r:DERIVED_FROM]->(p:Datum) "
        "RETURN p.id, coalesce(r.attribution, 'inherit')", {"id": datum_id}).result_set
    return {pid: attr for pid, attr in rows}


def full_session(rt):
    s = rt.session("ops", "s1")
    ctx = [s.user("Summarise the vendor page", user="sam@acme-robotics.example").id,
           s.fetch(URL).id,
           s.read_secret("secret/k").id]
    return s, ctx


def test_llm_output_links_every_context_input(rt):
    s, ctx = full_session(rt)
    out = s.think("summary")
    assert set(parents(rt, out.id)) == set(ctx)
    assert set(parents(rt, out.id).values()) == {"inherit"}


def test_explicit_derived_from_cannot_narrow_the_context(rt):
    s, ctx = full_session(rt)
    out = s.think("only from the user, supposedly", derived_from=[ctx[0]])
    assert set(parents(rt, out.id)) == set(ctx)          # web page and secret still linked
    other = rt.session("research", "s0").user("x", user="priya@acme-robotics.example")
    out2 = s.think("plus an extra parent", derived_from=[other.id])
    assert set(parents(rt, out2.id)) == set(ctx) | {out.id, other.id}


def test_outputs_become_context_for_later_outputs(rt):
    s, ctx = full_session(rt)
    a = s.think("first")
    b = s.think("second")
    assert set(parents(rt, b.id)) == set(ctx) | {a.id}


def test_memories_and_messages_link_the_whole_context(rt):
    s, ctx = full_session(rt)
    mem = s.remember("note", key="k", derived_from=[ctx[0]])
    msg = s.send_message("ops2", "fyi", derived_from=[ctx[0]])
    assert set(parents(rt, mem.id)) == set(ctx)
    assert set(parents(rt, msg.id)) == set(ctx)


def test_recall_message_and_search_results_enter_the_context(rt):
    s, ctx = full_session(rt)
    mem = s.remember("Backup host is vendor.example", key="backup")
    msg = s.send_message("ops2", "fyi")
    s2 = rt.session("ops2", "s2")
    ask = s2.user("what is our backup host?", user="sam@acme-robotics.example")
    found = s2.search_memory("backup")
    assert [m.id for m in found] == [mem.id]
    recall = s2.recall(mem.id)
    s2.receive(msg.id)
    out = s2.think("vendor.example")
    assert set(parents(rt, out.id)) == {ask.id, mem.id, recall.id, msg.id}


def test_tool_args_keep_edges_to_all_context_even_with_exact_attribution(rt):
    """Exact-value attribution narrows what the Guard *follows*, never what is recorded."""
    s, ctx = full_session(rt)
    s2 = rt.session("ops", "s3")
    ask = s2.user("Post the summary to #security", user="sam@acme-robotics.example")
    page = s2.fetch(URL)
    arg = s2.arg("destination", "#security", tool="post_slack")
    p = parents(rt, arg.id)
    assert set(p) == {ask.id, page.id}
    assert p[ask.id] == "exact" and p[page.id] == "context"


def test_value_not_supplied_verbatim_by_a_trusted_input_inherits_everything(rt):
    """Over-approximation: an argument nobody trusted supplied verbatim is attributed to the
    whole context, so an untrusted page in context makes the Guard flag it."""
    s = rt.session("ops", "s4")
    s.user("Email the vendor's sales contact our order count", user="sam@acme-robotics.example")
    s.fetch(URL)
    body = s.think("We need 40 units")
    res = s.call_tool("send_email", destination="sales@vendor.example",
                      arg_datums={"payload": body.id})
    assert res.verdict == Verdict.REQUIRE_HUMAN_APPROVAL
    assert res.decision.checks["integrity"].search.path_found


def test_quarantined_reader_sees_only_its_input(rt):
    """The quarantined reader is a separate call whose context is exactly ``from_ids``."""
    s, ctx = full_session(rt)
    typed = s.extract_typed("2", value_type="int", from_ids=[ctx[1]])
    assert set(parents(rt, typed.id)) == {ctx[1]}
    out = s.think("after typed")
    assert typed.id in parents(rt, out.id)
