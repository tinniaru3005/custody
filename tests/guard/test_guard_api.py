"""Guard API through FastAPI's TestClient (real embedded FalkorDB)."""
import pytest
from fastapi.testclient import TestClient

from custody.api.app import create_app
from custody.config import Settings
from custody.guard import ACME_POLICY, register_policy
from custody.seeds.acme import seed_acme


@pytest.fixture
def client(falkordb_client, tenant, provider, recorder):
    register_policy(tenant, ACME_POLICY)
    app = create_app(db=falkordb_client, settings=Settings(graph_prefix="custody-test"))
    with TestClient(app) as c:
        yield c


def test_check_blocks_trifecta_and_refuses_approval(client, tenant, recorder):
    ids = seed_acme(recorder)
    base = f"/tenants/{tenant}/guard"
    r = client.post(f"{base}/actions/{ids['action']}/check?enforce=true")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["decision"] == "BLOCK"
    assert body["triggered_checks"] == ["integrity", "confidentiality", "lethal_trifecta"]
    assert body["approval"]["available"] is False
    assert body["sink"]["external"] is True and body["action_status"] == "blocked"
    assert body["paths"] and body["sources"] and "total" in body["latency_ms"]

    r = client.post(f"{base}/actions/{ids['action']}/approve", json={"approver": "priya"})
    assert r.status_code == 403
    r = client.post(f"{base}/endorse", json={"approver": "priya", "datum_ids": [ids["dest"]]})
    assert r.status_code == 403

    decisions = client.get(f"{base}/actions/{ids['action']}/decisions").json()
    assert decisions and all(d["decision"] == "BLOCK" for d in decisions)


def test_approval_flow_via_api(client, tenant):
    base = f"/tenants/{tenant}"
    ask = client.post(f"{base}/record/user-input",
                      json={"text": "mail the vendor", "user": "sam"}).json()
    page = client.post(f"{base}/record/web-content",
                       json={"content": "orders@vendor-sales.example", "url": "https://v.ex"}).json()
    dest = client.post(f"{base}/record/llm-output",
                       json={"text": "orders@vendor-sales.example", "agent": "ops",
                             "derived_from": [ask["id"], page["id"]]}).json()
    act = client.post(f"{base}/record/action",
                      json={"action_type": "send_email", "agent": "ops",
                            "destination": [dest["id"]],
                            "sink": {"destination": "orders@vendor-sales.example",
                                     "kind": "email"}}).json()
    d = client.post(f"{base}/guard/actions/{act['id']}/check").json()
    assert d["decision"] == "REQUIRE_HUMAN_APPROVAL"
    assert d["approval"]["endorse_datum_ids"] == [dest["id"]]

    d2 = client.post(f"{base}/guard/actions/{act['id']}/approve",
                     json={"approver": "sam@acme-robotics.example", "reason": "known"}).json()
    assert d2["decision"] == "ALLOW" and d2["action_status"] == "approved"
    assert client.get(f"{base}/data/{dest['id']}").json()["endorsed"] is True


def test_guard_404_for_missing_action(client, tenant):
    assert client.post(f"/tenants/{tenant}/guard/actions/nope/check").status_code == 404
