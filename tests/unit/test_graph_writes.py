"""Unit tests for graph writes: each Recorder method produces the expected nodes/edges."""
import pytest

from custody.graph.model import ActionStatus, DatumKind, Sensitivity, SourceKind, Trust
from custody.graph.repository import NotFound


def q(graph, cypher, params=None):
    return graph.query(cypher, params or {}).result_set


# ------------------------------------------------------------------ sources
def test_schema_indexes_created(graph):
    res = graph.query("CALL db.indexes() YIELD label, properties RETURN label, properties")
    indexed = {(label, p) for label, props in res.result_set for p in props}
    assert ("Datum", "id") in indexed and ("Source", "id") in indexed


def test_source_upsert_is_idempotent_and_immutable(recorder, graph):
    a = recorder.register_source("slack:#ops", SourceKind.SLACK, Trust.UNTRUSTED, {"ch": "ops"})
    b = recorder.register_source("slack:#ops", SourceKind.SLACK, Trust.TRUSTED)
    assert a.trust == b.trust == Trust.UNTRUSTED
    assert b.metadata == {"ch": "ops"}
    assert q(graph, "MATCH (s:Source {id:'slack:#ops'}) RETURN count(s)") == [[1]]


# ------------------------------------------------------------------ inputs
def test_user_input_creates_datum_from_trusted_user_source(recorder, graph):
    d = recorder.record_user_input("hello", user="priya", session_id="s1")
    rows = q(graph, "MATCH (d:Datum {id:$id})-[:FROM]->(s:Source) "
                    "RETURN d.kind, d.value, d.sensitivity, d.endorsed, s.kind, s.trust",
             {"id": d.id})
    assert rows == [["user_input", "hello", "normal", False, "user", "trusted"]]
    assert d.created_at.endswith("Z")


def test_web_content_is_untrusted(recorder):
    d = recorder.record_web_content("<html/>", url="https://x.example")
    src = recorder.repo.get_source(d.source_id)
    assert (src.kind, src.trust) == (SourceKind.WEB, Trust.UNTRUSTED)


def test_external_content_kinds(recorder):
    d = recorder.record_external_content("PR body", kind="github", ref="acme/robot#12")
    src = recorder.repo.get_source(d.source_id)
    assert src.id == "github:acme/robot#12" and src.trust == Trust.UNTRUSTED
    assert d.kind == DatumKind.TOOL_OUTPUT


def test_vault_secret_never_stores_raw_value(recorder, graph):
    secret = "AKIAACMEROBOTICS0000EXAMPLEKEY"
    d = recorder.record_vault_secret(secret, path="secret/aws")
    assert d.value is None and d.sensitivity == Sensitivity.SECRET
    props = q(graph, "MATCH (d:Datum {id:$id}) RETURN d", {"id": d.id})[0][0].properties
    assert "value" not in props
    assert all(secret not in str(v) for v in props.values())
    assert props["fingerprint"].startswith("sha256:")


# ----------------------------------------------------------------- derived
def test_llm_output_derives_from_context_and_inherits_sensitivity(recorder, graph):
    u = recorder.record_user_input("use the key", user="priya")
    s = recorder.record_vault_secret("supersecretvalue123", path="secret/x")
    out = recorder.record_llm_output("done", agent="ops", derived_from=[u.id, s.id])
    assert out.sensitivity == Sensitivity.SECRET and out.value is None
    parents = q(graph, "MATCH (:Datum {id:$id})-[r:DERIVED_FROM]->(p) "
                       "RETURN p.id, r.op ORDER BY p.id", {"id": out.id})
    assert sorted(parents) == sorted([[u.id, "derive"], [s.id, "derive"]])
    assert recorder.repo.get_source(out.source_id).id == "system:agent:ops"


def test_explicit_sensitivity_overrides_inheritance(recorder):
    u = recorder.record_user_input("x", user="u", sensitivity="sensitive")
    out = recorder.record_llm_output("y", agent="a", derived_from=[u.id], sensitivity="normal")
    assert out.sensitivity == Sensitivity.NORMAL


def test_memory_has_memory_label_and_save_edge(recorder, graph):
    u = recorder.record_user_input("remember: standup at 10", user="priya")
    m = recorder.record_memory("standup 10:00", agent="research", derived_from=[u.id], key="k")
    labels = q(graph, "MATCH (m {id:$id}) RETURN labels(m)", {"id": m.id})[0][0]
    assert set(labels) == {"Datum", "Memory"}
    assert q(graph, "MATCH (:Memory {id:$id})-[r:DERIVED_FROM]->(:Datum {id:$u}) RETURN r.op",
             {"id": m.id, "u": u.id}) == [["save"]]
    assert m.metadata["key"] == "k"


def test_recall_links_back_to_memory(recorder, graph):
    u = recorder.record_user_input("x", user="priya")
    m = recorder.record_memory("x", agent="a", derived_from=[u.id])
    r = recorder.record_memory_recall(m.id, agent="b", session_id="s2", query="x?")
    assert set(r.labels) == {"Datum", "Recall"}
    assert r.parent_ids == [m.id]
    assert q(graph, "MATCH (:Recall {id:$r})-[e:DERIVED_FROM]->(:Memory {id:$m}) RETURN e.op",
             {"r": r.id, "m": m.id}) == [["recall"]]


def test_recall_of_non_memory_rejected(recorder):
    u = recorder.record_user_input("x", user="priya")
    with pytest.raises(ValueError):
        recorder.record_memory_recall(u.id, agent="b")


def test_message_is_a_datum(recorder, graph):
    u = recorder.record_user_input("ping ops", user="priya")
    msg = recorder.record_message("ops: please check", sender="research", recipient="ops",
                                  derived_from=[u.id], thread_id="t1")
    labels = q(graph, "MATCH (m {id:$id}) RETURN labels(m)", {"id": msg.id})[0][0]
    assert set(labels) == {"Datum", "Message"}
    assert msg.metadata == {"sender": "research", "recipient": "ops", "thread_id": "t1"}


def test_missing_parent_raises_and_writes_nothing(recorder, graph):
    before = q(graph, "MATCH (d:Datum) RETURN count(d)")[0][0]
    with pytest.raises(NotFound):
        recorder.record_llm_output("x", agent="a", derived_from=["nope"])
    assert q(graph, "MATCH (d:Datum) RETURN count(d)")[0][0] == before


# ----------------------------------------------------------------- actions
def test_action_args_and_sink(recorder, graph):
    dest = recorder.record_user_input("a@b.example", user="u")
    body = recorder.record_user_input("hi", user="u")
    act = recorder.record_action("send_email", agent="ops", destination=dest.id,
                                 payload=[body.id], sink_destination="a@b.example",
                                 sink_kind="email", session_id="s")
    rows = q(graph, "MATCH (a:Action {id:$id})-[r:ARG]->(d) RETURN r.role, d.id ORDER BY r.role",
             {"id": act.id})
    assert rows == [["destination", dest.id], ["payload", body.id]]
    sink = q(graph, "MATCH (:Action {id:$id})-[:TO]->(k:Sink) RETURN k.destination, k.kind, "
                    "k.external", {"id": act.id})
    assert sink == [["a@b.example", "email", True]]
    stored = recorder.repo.get_action(act.id)
    assert stored.status == ActionStatus.PROPOSED and stored.agent == "ops"
    assert stored.sink.destination == "a@b.example"


def test_sinks_are_shared_between_actions(recorder, graph):
    d = recorder.record_user_input("x", user="u")
    for _ in range(2):
        recorder.record_action("http_post", agent="a", payload=[d.id],
                               sink_destination="https://hook.example")
    assert q(graph, "MATCH (k:Sink) RETURN count(k)") == [[1]]
    assert q(graph, "MATCH (:Action)-[:TO]->(k:Sink) RETURN count(*)") == [[2]]


def test_action_status_update(recorder):
    d = recorder.record_user_input("x", user="u")
    act = recorder.record_action("noop", agent="a", payload=[d.id])
    assert recorder.update_action_status(act.id, "blocked").status == ActionStatus.BLOCKED


def test_action_with_unknown_datum_rejected(recorder):
    with pytest.raises(NotFound):
        recorder.record_action("send_email", agent="a", destination=["missing"])


# --------------------------------------------------------------- approvals
def test_approval_endorses_datum(recorder, graph):
    d = recorder.record_user_input("board@acme.example", user="u")
    act = recorder.record_action("send_email", agent="a", destination=[d.id])
    apv = recorder.record_approval(approver="marcus", endorses=[d.id], reason="ok",
                                   action_id=act.id)
    assert q(graph, "MATCH (:Approval {id:$a})-[:ENDORSES]->(d:Datum) RETURN d.id, d.endorsed",
             {"a": apv.id}) == [[d.id, True]]
    assert q(graph, "MATCH (:Approval {id:$a})-[:APPROVES]->(x:Action) RETURN x.id",
             {"a": apv.id}) == [[act.id]]
    assert recorder.get_datum(d.id).endorsed is True


def test_approval_requires_data(recorder):
    with pytest.raises(ValueError):
        recorder.record_approval(approver="m", endorses=[])
    with pytest.raises(NotFound):
        recorder.record_approval(approver="m", endorses=["ghost"])


# ------------------------------------------------------------------ tenancy
def test_tenants_are_isolated(provider, tenant):
    from custody.graph.repository import GraphRepository
    from custody.recorder.service import Recorder

    other = tenant + "-b"
    try:
        a = Recorder(GraphRepository(provider.graph(tenant)))
        b = Recorder(GraphRepository(provider.graph(other)))
        d = a.record_user_input("only in A", user="u")
        with pytest.raises(NotFound):
            b.get_datum(d.id)
    finally:
        provider.drop(other)
