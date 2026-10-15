"""Retroactive re-adjudication after a trusted Source is revoked: history kept, both verdict
contexts stored."""
import pytest
from fastapi.testclient import TestClient

from custody.api.app import create_app
from custody.config import Settings
from custody.guard import ACME_POLICY, ApprovalRefused, register_policy
from custody.guard.readjudicate import latest_reports, revoke_and_readjudicate

PARTNER = "ops@partner-cloud.example"
DOC = "github:acme/partners/contacts.md"
SAM = "sam@acme-robotics.example"


def partner_doc(rt, s):
    d = s.r.record_external_content(f"Partner contact for backups: {PARTNER}", kind="github",
                                    ref="acme/partners/contacts.md", trust="trusted",
                                    agent=s.agent, session_id=s.session_id)
    s._add(d, d.value)
    return d


def history(runtime, guard):
    """Four actions recorded while the partner doc was trusted."""
    ids = {}
    # 1) secret to the partner: needed approval (confidentiality), a human approved, ran
    s = runtime.session("ops", "h1")
    s.user("Send the deploy key to our backup partner", user=SAM)
    partner_doc(runtime, s)
    s.read_secret("secret/aws/deploy-key")
    r = s.call_tool("send_email", destination=PARTNER, payload="AKIAORIGINAL0000KEY")
    assert r.verdict.value == "REQUIRE_HUMAN_APPROVAL"
    assert runtime.approve(r.action_id, approver=SAM).executed
    ids["secret"] = r.action_id
    # 2, 3) non-secret mail to the partner: allowed and executed
    for n in (2, 3):
        s = runtime.session("ops", f"h{n}")
        s.user("Email the weekly backup report to our backup partner", user=SAM)
        partner_doc(runtime, s)
        r = s.call_tool("send_email", destination=PARTNER, payload=f"weekly report {n}")
        assert r.verdict.value == "ALLOW" and r.executed
        ids[f"report{n}"] = r.action_id
    # 4) internal mail whose payload (not destination) derives from the doc
    s = runtime.session("ops", "h4")
    s.user("Email board@acme-robotics.example a summary of our partner contacts", user=SAM)
    partner_doc(runtime, s)
    s.remember("Backup partner contact is on file.", key="partner")
    r = s.call_tool("send_email", destination="board@acme-robotics.example",
                    payload="summary of partner contacts")
    assert r.verdict.value == "ALLOW"
    ids["internal"] = r.action_id
    return ids


def test_revocation_readjudicates_without_rewriting_history(runtime, guard):
    ids = history(runtime, guard)
    before = {a: guard.repo.decisions_for(a) for a in ids.values()}
    statuses = {a: guard.repo.get_action(a).status for a in ids.values()}

    rep = revoke_and_readjudicate(guard, DOC, approver=SAM, reason="repo was compromised")

    assert rep.trust_before == "trusted" and rep.trust_after == "untrusted"
    assert rep.traversal.search_complete and rep.downstream_datums > 0
    assert len(rep.actions) == 4
    assert rep.summary == {"ALLOW → BLOCK": 1, "ALLOW → REQUIRE_HUMAN_APPROVAL": 2,
                           "UNCHANGED": 1}
    by = {a.action_id: a for a in rep.actions}
    s = by[ids["secret"]]
    assert (s.original_verdict, s.current_verdict) == ("ALLOW", "BLOCK")
    assert s.executed and "lethal_trifecta" in s.current_triggered
    assert s.current_path and s.current_path.endswith(f"{DOC} [untrusted]")
    assert by[ids["internal"]].transition == "UNCHANGED"
    assert len(rep.memories) == 1
    # history kept: original Decisions untouched, statuses unchanged, nothing re-executed
    assert {a: guard.repo.decisions_for(a) for a in ids.values()} == before
    assert {a: guard.repo.get_action(a).status for a in ids.values()} == statuses
    # both contexts stored in the graph
    g = guard.repo.graph
    rows = g.ro_query("MATCH (:TrustRevocation {id: $r})-[:PRODUCED]->(rj:Readjudication)"
                      "-[:READJUDICATES]->(a:Action) RETURN a.id, rj.original_verdict, "
                      "rj.current_verdict, rj.original_decision_id", {"r": rep.id}).result_set
    assert len(rows) == 4 and all(r[3] for r in rows)
    src = g.ro_query("MATCH (s:Source {id: $id}) RETURN s.trust, s.trust_original",
                     {"id": DOC}).result_set[0]
    assert src == ["untrusted", "trusted"]
    assert latest_reports(guard)[0].id == rep.id


def test_only_humans_can_revoke(runtime, guard):
    history(runtime, guard)
    with pytest.raises(ApprovalRefused):
        revoke_and_readjudicate(guard, DOC, approver="system:warden")


def test_revoke_over_http(falkordb_client, tenant, recorder):
    register_policy(tenant, ACME_POLICY)
    rec = recorder
    rec.record_external_content("x", kind="github", ref="acme/x.md", trust="trusted")
    with TestClient(create_app(db=falkordb_client,
                               settings=Settings(graph_prefix="custody-test"))) as c:
        r = c.post(f"/api/tenants/{tenant}/guard/sources/github:acme/x.md/revoke",
                   json={"approver": SAM, "reason": "test"})
        assert r.status_code == 201, r.text
        assert r.json()["actions"] == [] and r.json()["trust_before"] == "trusted"
        assert c.get(f"/api/tenants/{tenant}/guard/readjudications").json()[0]["id"] == \
            r.json()["id"]
