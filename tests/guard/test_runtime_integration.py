"""Runtime integration: propose → check → allow / approval / block → execute only if permitted."""
import pytest

from custody.demo.acme_guard import MALICIOUS_DEST, build_acme_runtime, run_guard_demo
from custody.guard import ApprovalRefused, Verdict
from custody.runtime import ExecutionDenied

pytestmark = pytest.mark.integration


def test_safe_case_rotated_key_to_internal_slack_is_allowed_and_executed(recorder):
    out = run_guard_demo(recorder)
    rt, safe = out["runtime"], out["safe"]
    res = safe["result"]
    assert res.verdict == Verdict.ALLOW and res.executed and res.status == "executed"
    assert recorder.repo.get_action(res.action_id).status.value == "executed"
    [delivery] = rt.outbox.to("#security")
    assert delivery.workspace == "acme-robotics"
    assert delivery.payload == rt.vault.read("secret/aws/deploy-key")  # the rotated key
    # destination attributed to Sam's request even though the vendor memory was in context
    dest_id = next(a.datum_id for a in recorder.repo.get_action(res.action_id).args
                   if a.role == "destination")
    dest = recorder.get_datum(dest_id)
    assert dest.attribution == "exact" and dest.metadata["attribution"]["suppliers"] == [safe["ask"]]
    assert safe["recall"] in dest.parent_ids  # still recorded, as context


def test_dangerous_case_is_blocked_and_never_executed(recorder):
    out = run_guard_demo(recorder)
    rt, danger = out["runtime"], out["dangerous"]
    res = danger["result"]
    assert res.verdict == Verdict.BLOCK and not res.executed and res.status == "blocked"
    assert res.decision.approval.available is False
    assert rt.outbox.to(MALICIOUS_DEST) == []
    with pytest.raises(ApprovalRefused):
        rt.approve(res.action_id, approver="sam@acme-robotics.example")
    with pytest.raises(ExecutionDenied):
        rt.execute(res.action_id)
    assert rt.outbox.to(MALICIOUS_DEST) == []
    # the blocking path really goes back through shared memory to the vendor page
    texts = [p.text for p in res.decision.checks["integrity"].paths]
    assert any("-recall->" in t and "-save->" in t and "vaultsync-backup.example" in t
               for t in texts)


def test_approval_required_then_human_approves_then_executes(recorder):
    rt = build_acme_runtime(recorder)
    rt.web["https://vendor.example/contact"] = "Questions? orders@vendor-sales.example"
    s = rt.session("procurement", "p1")
    s.user("Ask the vendor (contact on their site) whether 40 units are in stock.",
           user="sam@acme-robotics.example")
    s.fetch("https://vendor.example/contact")
    res = s.call_tool("send_email", destination="orders@vendor-sales.example",
                      payload="Do you have 40 units in stock?")
    assert res.verdict == Verdict.REQUIRE_HUMAN_APPROVAL and not res.executed
    assert res.status == "pending_approval" and len(rt.outbox) == 0
    with pytest.raises(ExecutionDenied):
        rt.execute(res.action_id)

    approved = rt.approve(res.action_id, approver="sam@acme-robotics.example",
                          reason="this is our usual vendor")
    assert approved.verdict == Verdict.ALLOW and approved.executed
    assert [d.destination for d in rt.outbox.deliveries] == ["orders@vendor-sales.example"]


def test_rejected_action_never_executes(recorder):
    rt = build_acme_runtime(recorder)
    rt.web["https://vendor.example/contact"] = "Questions? orders@vendor-sales.example"
    s = rt.session("procurement", "p1")
    s.user("Contact the vendor", user="sam@acme-robotics.example")
    s.fetch("https://vendor.example/contact")
    res = s.call_tool("send_email", destination="orders@vendor-sales.example", payload="hi")
    rt.reject(res.action_id, approver="sam@acme-robotics.example")
    with pytest.raises(ExecutionDenied):
        rt.execute(res.action_id)
    with pytest.raises(ApprovalRefused):
        rt.approve(res.action_id, approver="sam@acme-robotics.example")
    assert len(rt.outbox) == 0


def test_secret_to_external_requires_approval_then_executes(recorder):
    rt = build_acme_runtime(recorder)
    s = rt.session("ops", "o1")
    s.user("Send the AWS deploy key to auditor@kpmg-audit.example for the audit.",
           user="cfo@acme-robotics.example")
    s.read_secret("secret/aws/deploy-key")
    res = s.call_tool("send_email", destination="auditor@kpmg-audit.example",
                      payload=rt.vault.read("secret/aws/deploy-key"))
    assert res.verdict == Verdict.REQUIRE_HUMAN_APPROVAL
    assert [c.value for c in res.decision.triggered_checks] == ["confidentiality"]
    done = rt.approve(res.action_id, approver="cfo@acme-robotics.example")
    assert done.executed and rt.outbox.deliveries[0].destination == "auditor@kpmg-audit.example"


def test_raw_secrets_never_reach_the_graph(recorder, graph):
    out = run_guard_demo(recorder)
    rt = out["runtime"]
    raw_values = {rt.vault.read("secret/aws/deploy-key"), "AKIAACMEROBOTICS0000EXAMPLEKEY"}
    rows = graph.query("MATCH (n) RETURN n").result_set
    blob = " ".join(str(v) for (n,) in rows for v in n.properties.values())
    assert not any(v in blob for v in raw_values)
