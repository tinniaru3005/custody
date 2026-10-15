"""Three worlds (same bytes, three histories), secret-egress endorsements and deterministic
precedent escalation."""
from dataclasses import replace

import pytest

from custody.db import GraphProvider
from custody.demo.worlds import DESTINATION, build_worlds, latest_worlds
from custody.graph.model import fingerprint
from custody.graph.repository import GraphRepository
from custody.guard import ACME_POLICY, ApprovalRefused, Guard, Verdict
from custody.recorder.service import Recorder

EXT = "auditor@kpmg-audit.example"
KEY = "AKIASECRETVALUE0001KEY"
SAM = "sam@acme-robotics.example"


# ======================================================================= three worlds
@pytest.fixture
def worlds(falkordb_client, tenant):
    provider = GraphProvider(falkordb_client, prefix="custody-test")
    run = build_worlds(provider, tenant)
    yield run, provider
    provider.drop(run.graph_tenant)


def test_three_worlds_same_bytes_three_verdicts(worlds):
    run, provider = worlds
    by = {w.key: w for w in run.worlds}
    assert [by[k].verdict for k in "ABC"] == ["ALLOW", "REQUIRE_HUMAN_APPROVAL", "BLOCK"]
    # the content is identical: destination bytes and the rotated key
    assert run.identical_destination and run.identical_payload
    assert {w.destination for w in run.worlds} == {DESTINATION}
    assert {w.destination_fingerprint for w in run.worlds} == {fingerprint(DESTINATION)}
    # ... and so is the Day-4 request and the Sink they go to
    g = provider.graph(run.graph_tenant)
    sinks = {r[0] for r in g.ro_query(
        "MATCH (a:Action)-[:TO]->(k:Sink) WHERE a.id IN $ids RETURN k.id",
        {"ids": [w.action_id for w in run.worlds]}).result_set}
    assert len(sinks) == 1
    # only the provenance differs
    assert by["A"].provenance[-1].trust == "trusted" and by["A"].certificate is not None
    assert by["A"].provenance[-1].id.startswith("github:")
    assert by["B"].provenance[-1].id == "user:priya@acme-robotics.example"
    assert by["B"].triggered == ["confidentiality"] and by["B"].approval["available"]
    assert by["C"].provenance[-1].trust == "untrusted"
    assert by["C"].provenance[-1].id.startswith("web:")
    assert "lethal_trifecta" in by["C"].triggered and not by["C"].approval["available"]
    assert run.message == "The content can be identical. The provenance changes the decision."


def test_three_worlds_are_deterministic_and_stored(worlds, falkordb_client, tenant):
    run, provider = worlds
    again = build_worlds(provider, tenant)
    assert [(w.action_id, w.verdict) for w in again.worlds] == \
        [(w.action_id, w.verdict) for w in run.worlds]
    stored = latest_worlds(Recorder(GraphRepository(provider.graph(tenant))))
    assert stored is not None and stored.id == again.id


# ============================================================ secret-egress endorsement
def _secret_email(flow, guard, dest_text, endorse=None, egress=True):
    ask = flow.user(f"Send the deploy key to {dest_text}")
    if endorse:
        guard.endorse([ask.id], approver="dana@acme-robotics.example", egress=egress)
    key = flow.secret(KEY)
    dest = flow.out(dest_text, [ask, key], attribution="exact")
    body = flow.out(KEY, [ask, key], attribution="exact")
    return guard.check(flow.action("send_email", dest, body, sink_dest=EXT).id), ask


def test_secret_to_external_needs_approval_without_egress_endorsement(flow, guard):
    d, _ = _secret_email(flow, guard, EXT)
    assert d.decision == Verdict.REQUIRE_HUMAN_APPROVAL


def test_egress_endorsement_must_match_the_destination_exactly(flow, guard):
    # the endorsed datum holds "Send the deploy key to …", not the destination value itself
    d, _ = _secret_email(flow, guard, EXT, endorse=True)
    assert d.decision == Verdict.REQUIRE_HUMAN_APPROVAL
    assert d.checks["confidentiality"].cleared_by_endorsement == []


def test_egress_endorsement_of_the_exact_value_clears_confidentiality(flow, guard):
    reg = flow.r.record_external_content(EXT, kind="github", ref="acme/infra/targets.yaml",
                                         trust="trusted", agent="ops", session_id="s1")
    apv = guard.endorse([reg.id], approver="dana@acme-robotics.example", egress=True)
    key = flow.secret(KEY)
    dest = flow.out(EXT, [reg, key], attribution="exact")
    body = flow.out(KEY, [key], attribution="exact")
    d = guard.check(flow.action("send_email", dest, body, sink_dest=EXT).id)
    assert d.decision == Verdict.ALLOW
    assert d.checks["confidentiality"].cleared_by_endorsement == [apv.id]
    assert d.certificate is not None and apv.id in d.certificate.payload
    # a plain (non-egress) endorsement of the same value does not clear it
    reg2 = flow.r.record_external_content(EXT, kind="github", ref="acme/infra/other.yaml",
                                          trust="trusted", agent="ops", session_id="s2")
    guard.endorse([reg2.id], approver="dana@acme-robotics.example")
    dest2 = flow.out(EXT, [reg2, key], attribution="exact")
    d2 = guard.check(flow.action("send_email", dest2, body, sink_dest=EXT).id)
    assert d2.decision == Verdict.REQUIRE_HUMAN_APPROVAL


# ================================================================ precedent escalation
def _secret_to(flow, dest_value, sink=None):
    ask = flow.user(f"Send the deploy key to {dest_value}")
    key = flow.secret(KEY)
    dest = flow.out(dest_value, [ask, key], attribution="exact")
    body = flow.out(KEY, [ask, key], attribution="exact")
    return flow.action("send_email", dest, body, sink_dest=sink or dest_value)


def test_rejected_secret_to_same_sink_escalates_to_block(flow, guard):
    first = _secret_to(flow, EXT)
    assert guard.enforce(first.id).decision == Verdict.REQUIRE_HUMAN_APPROVAL
    guard.reject(first.id, approver=SAM, reason="auditors never get raw keys")
    second = _secret_to(flow, EXT)
    d = guard.check(second.id)
    assert d.decision == Verdict.BLOCK
    assert "precedent" in [c.value for c in d.triggered_checks]
    p = d.checks["precedent"].precedents[0]
    assert p.rejected_action_id == first.id and p.approver == SAM
    assert p.reason == "auditors never get raw keys" and p.secret_payload_datum_ids
    assert f"(:Approval {{id:'{p.approval_id}', verdict:'rejected'}})-[:REJECTS]->" \
           f"(:Action {{id:'{first.id}'}})-[:TO]->(:Sink {{id:'{p.sink_id}'}})<-[:TO]-" \
           f"(:Action {{id:'{second.id}'}})" in p.relationship
    assert not d.approval.available and p.approval_id in d.approval.reason
    assert p.approval_id in d.explanation
    with pytest.raises(ApprovalRefused):
        guard.approve(second.id, approver=SAM)
    # deterministic: same answer on every re-check
    assert guard.check(second.id).checks["precedent"].precedents == d.checks["precedent"].precedents


def test_precedent_is_narrow(flow, guard, recorder):
    first = _secret_to(flow, EXT)
    guard.enforce(first.id)
    guard.reject(first.id, approver=SAM)
    # different sink: not escalated
    other = guard.check(_secret_to(flow, "partner@other-audit.example").id)
    assert other.decision == Verdict.REQUIRE_HUMAN_APPROVAL
    assert other.checks["precedent"].evaluated and not other.checks["precedent"].violated
    # same sink, non-secret payload: not escalated (nothing to escalate)
    ask = flow.user(f"Send our price list to {EXT}")
    dest = flow.out(EXT, [ask], attribution="exact")
    body = flow.out("Starter $49", [ask])
    assert guard.check(flow.action("send_email", dest, body).id).decision == Verdict.ALLOW
    # policy switch off
    g2 = Guard(recorder, replace(ACME_POLICY, precedent_escalation=False))
    assert g2.check(_secret_to(flow, EXT).id).decision == Verdict.REQUIRE_HUMAN_APPROVAL


def test_rejection_of_a_non_secret_action_is_not_a_precedent(flow, guard):
    page = flow.web(f"Contact {EXT}")
    dest = flow.out(EXT, [page])
    act = flow.action("send_email", dest, flow.user("hello"))
    guard.enforce(act.id)
    guard.reject(act.id, approver=SAM)
    d = guard.check(_secret_to(flow, EXT).id)
    assert d.decision == Verdict.REQUIRE_HUMAN_APPROVAL and not d.checks["precedent"].violated
