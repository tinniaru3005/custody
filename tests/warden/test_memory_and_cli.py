"""Shared-memory retrieval layer and the Warden CLI."""
import json

from custody.memory import SharedMemory


def test_shared_memory_search_filters(warden, incident):
    shared = SharedMemory(warden.recorder)
    assert [m.metadata["key"] for m in shared.search(key="board-meeting")] == ["board-meeting"]
    assert {m.metadata["key"] for m in shared.search("IBAN")} == {"supplier-bank-details"}
    assert {m.agent for m in shared.search(agent="finance")} == {"finance"}
    assert shared.get(incident["clean"]["memory"]).metadata["key"] == "board-meeting"


def test_cli_seed_approve_and_send(warden, provider, tenant, monkeypatch, capsys):
    import custody.warden.__main__ as cli

    monkeypatch.setattr(cli, "_provider", lambda: provider)
    assert cli.main(["seed", "--tenant", tenant]) == 0
    assert "seeded" in capsys.readouterr().out
    msp = warden.trace_forward("web:https://docs.vaultsync-backup.example/setup") \
        .external_executed_actions[0]
    # Warden in another "process" proposes the disclosure
    draft = warden.draft_disclosure([msp]).drafts[0]
    prop = warden.propose_disclosure(draft.draft_id)
    assert cli.main(["approve", prop.action_id, "--tenant", tenant, "--policy", "acme",
                     "--approver", "priya@acme-robotics.example", "--send"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["decision"] == "ALLOW" and out["send"]["sent"] is True
    assert warden.repo.get_action(prop.action_id).status.value == "executed"


def test_http_guard_approval_releases_disclosure(warden, incident, falkordb_client, tenant):
    """The approval path a human uses: the existing Guard HTTP endpoint."""
    from fastapi.testclient import TestClient

    from custody.api.app import create_app
    from custody.config import Settings
    from custody.guard import ACME_POLICY, register_policy

    register_policy(tenant, ACME_POLICY)
    draft = warden.draft_disclosure([incident["msp"]["action"]]).drafts[0]
    prop = warden.propose_disclosure(draft.draft_id)
    app = create_app(db=falkordb_client, settings=Settings(graph_prefix="custody-test"))
    with TestClient(app) as c:
        r = c.post(f"/tenants/{tenant}/guard/actions/{prop.action_id}/approve",
                   json={"approver": "priya@acme-robotics.example"})
    assert r.status_code == 200, r.text
    assert r.json()["decision"] == "ALLOW"
    assert warden.send_approved_disclosure(prop.action_id).sent
