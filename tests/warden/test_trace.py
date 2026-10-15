"""trace_back / trace_forward / find_sources."""
import pytest

from custody.graph.repository import NotFound
from tests.warden.conftest import by_key


def test_find_sources_locates_vendor_page(warden, incident):
    res = warden.find_sources("vaultsync")
    assert res.sources[0].id == incident["vendor_source"]  # untrusted, most influence first
    assert {s.id for s in res.sources} >= {"user:priya@acme-robotics.example"}
    assert [s.id for s in warden.find_sources("vaultsync", trust="untrusted").sources] == \
        [incident["vendor_source"]]
    assert res.sources[0].trust == "untrusted" and res.sources[0].downstream_count > 5

    untrusted = warden.find_sources(trust="untrusted").sources
    assert {s.id for s in untrusted} == {incident["vendor_source"], incident["phish_source"]}
    assert untrusted[0].id == incident["vendor_source"]  # most downstream influence first
    assert all(s.kind == "web" for s in warden.find_sources(kind="web").sources)
    assert warden.find_sources("no-such-thing").sources == []


def test_trace_back_dangerous_action(warden, incident):
    tb = warden.trace_back(incident["dangerous"]["action"])
    assert tb.action.status == "blocked" and tb.action.external
    assert tb.latest_guard_decision["decision"] == "BLOCK"
    assert [s.id for s in tb.untrusted_sources] == [incident["vendor_source"]]
    assert any(s.id == "vault:secret/aws/deploy-key" for s in tb.secret_sources)
    assert any(s.id.startswith("user:") for s in tb.trusted_sources)
    # the destination path crosses agents/sessions through a memory or a message
    dest = [p for p in tb.paths if p.arg_role == "destination" and p.guard_relevant
            and p.source_trust == "untrusted"]
    assert dest and dest[0].node_ids[-1] == incident["vendor_source"]
    assert incident["dangerous"]["memory"] in {m.id for m in tb.memories}
    assert incident["dangerous"]["recall"] in {r.id for r in tb.recalls}
    assert incident["dangerous"]["message"] in {m.id for m in tb.messages}
    assert "UNTRUSTED" in tb.explanation and "BLOCK" in tb.explanation
    assert "AKIA" not in tb.model_dump_json()  # secrets never leave as values


def test_trace_back_safe_action_is_context_only(warden, incident):
    tb = warden.trace_back(incident["safe"]["action"])
    vendor = [p for p in tb.paths if p.source_id == incident["vendor_source"]]
    assert vendor and not any(p.guard_relevant for p in vendor)
    assert all("context" in p.attributions for p in vendor)
    assert "only in model context" in tb.explanation


def test_trace_back_unknown_action(warden, incident):
    with pytest.raises(NotFound):
        warden.trace_back("act_missing")


def test_trace_forward_from_malicious_source(warden, incident):
    tf = warden.trace_forward(incident["vendor_source"])
    assert tf.start_kind == "source" and tf.source.trust == "untrusted"
    assert [d.id for d in tf.origin_data] == [incident["dangerous"]["vendor_page"]]
    mems = {m.key: m for m in tf.memories}
    assert set(mems) == {"vaultsync-backup", "nightly-backup-target"}
    assert all(m.influence == "direct" for m in mems.values())
    assert len(tf.recalls) == 3 and len(tf.messages) == 1
    acts = {a.id: a for a in tf.actions}
    danger, msp, safe = (incident[k]["action"] for k in ("dangerous", "msp", "safe"))
    assert acts[danger].status == "blocked" and acts[danger].influence == "direct"
    assert "destination" in acts[danger].influenced_roles
    assert acts[msp].executed and acts[msp].external and acts[msp].influence == "direct"
    assert acts[msp].influenced_roles == ["payload"]
    assert acts[safe].influence == "context_only"
    assert tf.external_executed_actions == [msp]
    assert tf.blocked_actions == [danger]
    # the unrelated phishing incident is not part of this trace
    assert incident["phish"]["memory"] not in {m.id for m in tf.memories}
    assert "ALREADY EXECUTED" in tf.explanation


def test_trace_forward_from_datum_and_errors(warden, incident):
    tf = warden.trace_forward(incident["phish"]["email"])
    assert tf.start_kind == "datum"
    assert [m.key for m in tf.memories] == ["supplier-bank-details"] and tf.actions == []
    with pytest.raises(NotFound):
        warden.trace_forward("web:https://never-seen.example")


def test_trace_forward_reports_warden_actions_separately(warden, incident):
    tf = warden.trace_forward(incident["vendor_source"])
    q = warden.quarantine([m.id for m in tf.memories])
    after = warden.trace_forward(incident["vendor_source"])
    assert q.action_id in after.remediation_actions
    assert q.action_id not in {a.id for a in after.actions}
    assert after.counts["memories_in_quarantine"] == 2
    assert after.counts["warden_artifacts"] >= 1
    assert all(by_key(after.memories, k).in_quarantine
               for k in ("vaultsync-backup", "nightly-backup-target"))
