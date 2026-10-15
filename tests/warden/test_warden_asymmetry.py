"""Asymmetric remediation, quarantine never rewrites history, citation-grounded
disclosures, and the deterministic "why was this allowed?"."""
from dataclasses import replace

import pytest

from custody.demo.attack import VENDOR_SOURCE_ID, run_attack
from custody.graph.repository import GraphRepository
from custody.guard import ACME_POLICY, ApprovalRefused, Guard
from custody.guard.policy import ActionPolicy
from custody.graph.model import RiskTier
from custody.memory import MemoryQuarantined, SharedMemory
from custody.recorder.service import Recorder
from custody.warden import Warden
from custody.warden.mcp_server import TOOL_NAMES
from custody.warden.remediation import LOOSENING, REMEDIATION_POLICY, TIGHTENING

HUMAN = "lead@acme-robotics.example"


@pytest.fixture
def demo(provider, tenant):
    """The primary Day-1 / Day-4 story in this tenant, plus a Warden over it."""
    rec = Recorder(GraphRepository(provider.graph(tenant)))
    run = run_attack(rec, tenant=tenant, deterministic=True)
    w = Warden.for_tenant(provider, tenant, policy=ACME_POLICY, operator=HUMAN)
    return run, w


# ======================================================== 1. asymmetric permissions
def test_policy_table_is_explicit_and_asymmetric():
    tight = {k for k, v in REMEDIATION_POLICY.items() if v["direction"] == TIGHTENING}
    loose = {k for k, v in REMEDIATION_POLICY.items() if v["direction"] == LOOSENING}
    assert tight == {"quarantine_memory", "disable_memory_recall", "revoke_source_trust"}
    assert loose == {"unquarantine_memory", "endorse_data", "restore_source_trust",
                     "weaken_restriction"}
    # there is no approval tool over MCP; loosening can only be proposed
    assert "propose_loosening" in TOOL_NAMES and not any("approve" in t and "send" not in t
                                                         for t in TOOL_NAMES)


def test_tightening_executes_on_guard_allow(warden, incident):
    mem = incident["dangerous"]["memory"]
    q = warden.disable_memory_recall([mem], reason="poisoned")
    assert q.status == "quarantined" and q.guard_verdict == "ALLOW"
    r = warden.revoke_source_trust(incident["vendor_source"], reason="malicious")
    assert r.direction == "tightening" and r.status == "executed" and r.guard_verdict == "ALLOW"
    assert warden.repo.get_source(incident["vendor_source"]).trust == "untrusted"
    assert r.detail["revocation_id"] and "summary" in r.detail
    action = warden.repo.get_action(r.action_id)
    assert action.agent == "warden" and action.action_type == "revoke_source_trust"
    assert warden.repo.decisions_for(r.action_id)        # the Guard decided it


def test_trusted_source_revocation_reruns_history(warden, incident):
    """Revoking a previously trusted Source (tightening) re-adjudicates downstream actions."""
    src = next(s.id for s in warden.find_sources(trust="trusted").sources
               if s.id.startswith("user:"))
    r = warden.revoke_source_trust(src, reason="account takeover")
    assert r.status == "executed" and r.detail["trust_before"] == "trusted"
    assert warden.repo.get_source(src).trust == "untrusted"


def test_loosening_always_needs_a_human(warden, incident):
    mem = incident["dangerous"]["memory"]
    assert warden.quarantine([mem]).status == "quarantined"
    p = warden.propose_loosening("unquarantine_memory", [mem], reason="false positive?")
    assert p.direction == "loosening" and p.status == "pending_approval"
    assert p.guard_verdict == "REQUIRE_HUMAN_APPROVAL" and p.how_to_approve
    assert warden.recorder.get_datum(mem).in_quarantine            # nothing changed
    # not executable without a human; the Warden and agents cannot approve
    assert warden.execute_approved_remediation(p.action_id).status == "not_executed"
    assert warden.recorder.get_datum(mem).in_quarantine
    with pytest.raises(ApprovalRefused):
        warden.approve_remediation(p.action_id, approver="warden")
    with pytest.raises(ApprovalRefused):
        warden.guard.approve(p.action_id, approver="system:agent:warden")
    # a human approves; execution re-runs the Guard
    warden.approve_remediation(p.action_id, approver=HUMAN, reason="reviewed")
    done = warden.execute_approved_remediation(p.action_id)
    assert done.status == "executed" and done.detail == {"unquarantined": [mem]}
    assert not warden.recorder.get_datum(mem).in_quarantine
    g = warden.repo.graph
    assert g.ro_query("MATCH (:QuarantineLift)-[:LIFTS]->(m {id: $m}) RETURN count(*)",
                      {"m": mem}).result_set[0][0] == 1
    assert g.ro_query("MATCH (:Quarantine)-[:QUARANTINES]->(m {id: $m}) RETURN count(*)",
                      {"m": mem}).result_set[0][0] == 1                  # history kept


def test_restore_trust_endorse_and_weaken_need_a_human(warden, incident):
    src = incident["vendor_source"]
    assert warden.revoke_source_trust(src).status == "executed"
    # restore trust (it was untrusted to begin with: restores the original label)
    p = warden.propose_loosening("restore_source_trust", [src])
    assert p.status == "pending_approval" and warden.repo.get_source(src).trust == "untrusted"
    warden.approve_remediation(p.action_id, approver=HUMAN)
    assert warden.execute_approved_remediation(p.action_id).status == "executed"
    assert warden.repo.graph.ro_query("MATCH (:TrustRestoration)-[:RESTORES]->(:Source {id: $s}) "
                                      "RETURN count(*)", {"s": src}).result_set[0][0] == 1
    # endorse previously untrusted data (the phishing memory)
    datum = incident["phish"]["memory"]
    e = warden.propose_loosening("endorse_data", [datum])
    assert e.status == "pending_approval" and not warden.recorder.get_datum(datum).endorsed
    warden.approve_remediation(e.action_id, approver=HUMAN)
    assert warden.execute_approved_remediation(e.action_id).status == "executed"
    assert warden.recorder.get_datum(datum).endorsed
    # ...but even an approved proposal cannot endorse data feeding a BLOCKed action
    bad = warden.propose_loosening("endorse_data", [incident["dangerous"]["memory"]])
    warden.approve_remediation(bad.action_id, approver=HUMAN)
    with pytest.raises(ApprovalRefused, match="blocked"):
        warden.execute_approved_remediation(bad.action_id)
    assert not warden.recorder.get_datum(incident["dangerous"]["memory"]).endorsed
    # weaken a restriction: approvable, never applied by the Warden
    wk = warden.propose_loosening("weaken_restriction", ["precedent_escalation=false"])
    assert wk.status == "pending_approval"
    warden.approve_remediation(wk.action_id, approver=HUMAN)
    assert warden.execute_approved_remediation(wk.action_id).status == "approved_not_applied"
    with pytest.raises(ValueError):
        warden.propose_loosening("quarantine_memory", ["x"])
    with pytest.raises(ValueError):
        warden.propose_loosening("delete_everything", ["x"])


def test_tenant_policy_cannot_make_loosening_automatic(provider, tenant):
    from custody.demo.acme_warden import build_incident

    actions = dict(ACME_POLICY.actions)
    actions["unquarantine_memory"] = ActionPolicy(False, False, RiskTier.LOW)   # "auto"
    w = Warden.for_tenant(provider, tenant, policy=replace(ACME_POLICY, actions=actions))
    mem = build_incident(w.recorder)["dangerous"]["memory"]
    w.quarantine([mem])
    p = w.propose_loosening("unquarantine_memory", [mem])
    assert p.status == "pending_approval" and w.recorder.get_datum(mem).in_quarantine


def test_tightening_still_obeys_the_guard(provider, tenant):
    """The Warden never bypasses the Guard: if policy wants a human for revocation, it waits."""
    from custody.demo.acme_warden import build_incident

    actions = dict(ACME_POLICY.actions)
    actions["revoke_source_trust"] = ActionPolicy(False, True, RiskTier.LOW, human_review=True)
    w = Warden.for_tenant(provider, tenant, policy=replace(ACME_POLICY, actions=actions))
    src = build_incident(w.recorder)["vendor_source"]
    before = w.repo.get_source(src).trust
    r = w.revoke_source_trust(src)
    assert r.status == "pending_approval" and w.repo.get_source(src).trust == before


# ===================================================== 2. quarantine keeps history
def test_quarantine_does_not_rewrite_history(demo):
    run, w = demo
    aid, mem = run.ids["blocked_action"], run.ids["memory"]
    g = w.repo.graph
    fresh = Guard(w.recorder, ACME_POLICY, record_decisions=False)
    before = fresh.check(aid)
    footprint = w._provenance_footprint([mem])
    decisions = w.repo.decisions_for(aid)
    trace_before = w.trace_back(aid)
    assert before.decision.value == "BLOCK"

    q = w.quarantine([mem], reason="poisoned vendor memory")
    assert q.status == "quarantined"

    after = fresh.check(aid)
    assert after.decision == before.decision
    assert after.triggered_checks == before.triggered_checks
    path = lambda d: [[n.id for n in p.nodes] for p in d.paths if p.status == "violating"]  # noqa: E731
    assert path(after) == path(before) and mem in path(after)[0]
    assert w._provenance_footprint([mem]) == footprint                 # edges untouched
    assert w.repo.decisions_for(aid) == decisions                      # audit trail kept
    assert w.recorder.get_datum(mem).value is not None                 # node not deleted
    assert [p.node_ids for p in w.trace_back(aid).paths] == \
        [p.node_ids for p in trace_before.paths]
    # only future retrieval changes
    assert mem not in [m.id for m in SharedMemory(w.recorder).search("backup")]
    with pytest.raises(MemoryQuarantined):
        w.recorder.record_memory_recall(mem, agent="ops", session_id="day5")
    assert g.ro_query("MATCH (m:Datum {id: $m}) RETURN m.in_quarantine", {"m": mem}
                      ).result_set[0][0] is True


# ===================================================== 3. citation-grounded disclosure
def test_disclosure_claims_are_cited_and_verified(warden, incident):
    msp = incident["msp"]["action"]
    action = warden.repo.get_action(msp)
    d = warden.draft_disclosure([msp]).drafts[0]
    assert d.claims and d.rejected_claims == [] and d.citation_scope_complete
    for c in d.claims:
        assert c["verified"] and c["citations"]
        assert c["rendered"] in d.body
        for cid in c["citations"]:                                      # every id exists
            assert warden.repo.graph.ro_query("MATCH (n {id: $i}) RETURN count(n)",
                                              {"i": cid}).result_set[0][0] == 1
    sent = d.claims[0]
    assert set(sent["citations"]) == {msp, action.sink.id}
    assert f"Action {msp}" in sent["rendered"] and f"Sink {action.sink.id}" in sent["rendered"]
    path = next(c for c in d.claims if c["chain"])
    assert path["citations"][-1] == incident["vendor_source"]
    assert any(warden.recorder.get_datum(x).is_memory for x in path["citations"][:-1])
    assert " → " in path["rendered"] and "Memory " in path["rendered"]


def test_unsupported_claims_are_removed(warden, incident):
    msp = incident["msp"]["action"]
    other = incident["safe"]["action"]               # exists, but not this incident
    phish = incident["phish_source"]
    d = warden.draft_disclosure(
        [msp],
        notes=(f"The page told agents to forward rotated keys [{incident['vendor_source']}]. "
               "Your systems were fully compromised. "
               f"Also our CEO was phished [{phish}]."),
        claims=[{"text": "A second message was sent", "citations": [other]},
                {"text": "The attacker is a nation state", "citations": ["src_nope"]},
                {"text": "The message went to your mailbox",
                 "citations": [warden.repo.get_action(msp).sink.id]}]).drafts[0]
    kept = {c["text"] for c in d.claims if c["origin"] == "model"}
    gone = {c["text"]: c["rejected_reason"] for c in d.rejected_claims}
    assert kept == {"The page told agents to forward rotated keys",
                    "The message went to your mailbox"}
    assert "no citation" in gone["Your systems were fully compromised"]
    assert "not part of the traced incident" in gone["Also our CEO was phished"]
    assert "not part of the traced incident" in gone["A second message was sent"]
    assert "do not exist" in gone["The attacker is a nation state"]
    for text in gone:
        assert text not in d.body
    assert "Additional details" in d.body


# ===================================================== 4. why was this allowed?
def test_why_allowed_renders_the_certificate(demo):
    run, w = demo
    aid = run.ids["slack_action"]
    r = w.why_allowed(aid)
    cert = Guard(w.recorder, ACME_POLICY, record_decisions=False).check(aid).certificate
    assert r.allowed and r.verdict == "ALLOW" and r.matches_recorded is True
    assert r.certificate["certificate_id"] == cert.certificate_id    # the source of truth
    text = "\n".join(r.evidence)
    assert "Policy result: ALLOW under acme-robotics@1" in text
    assert "Traversal: COMPLETE, frontier EXHAUSTED" in text
    assert "Context-edge coverage:" in text and "FULL_CONTEXT" in text
    assert cert.graph_version_label in text and "trust labels are policy inputs" in text
    for root in cert.root_sources:
        assert f"{root.id} [{root.trust}]" in text
    assert "No untrusted influence was found relative to the recorded provenance graph" in text


def test_why_allowed_for_a_blocked_action_says_so(demo):
    run, w = demo
    r = w.why_allowed(run.ids["blocked_action"])
    assert not r.allowed and r.certificate is None
    assert r.evidence[0].startswith("Not allowed: the Guard's verdict is BLOCK")
    assert VENDOR_SOURCE_ID in r.evidence[0]
