"""API smoke tests through FastAPI's TestClient (real embedded FalkorDB)."""
import pytest
from fastapi.testclient import TestClient

from custody.api.app import create_app
from custody.config import Settings


@pytest.fixture
def client(falkordb_client, tenant, provider):
    app = create_app(db=falkordb_client, settings=Settings(graph_prefix="custody-test"))
    with TestClient(app) as c:
        yield c


def test_health(client):
    assert client.get("/health").json()["falkordb"] is True


def test_record_and_trace_via_api(client, tenant):
    base = f"/tenants/{tenant}"
    u = client.post(f"{base}/record/user-input", json={"text": "hi", "user": "priya"})
    assert u.status_code == 201, u.text
    w = client.post(f"{base}/record/web-content", json={"content": "x", "url": "https://w.ex"})
    out = client.post(f"{base}/record/llm-output",
                      json={"text": "a@b.ex", "agent": "r", "derived_from": [u.json()["id"],
                                                                         w.json()["id"]]})
    mem = client.post(f"{base}/record/memory",
                      json={"content": "m", "agent": "r", "derived_from": [out.json()["id"]]})
    rec = client.post(f"{base}/record/memory-recall",
                      json={"memory_id": mem.json()["id"], "agent": "ops"})
    act = client.post(f"{base}/record/action",
                      json={"action_type": "send_email", "agent": "ops",
                            "destination": [rec.json()["id"]],
                            "sink": {"destination": "a@b.ex", "kind": "email"}})
    assert act.status_code == 201, act.text

    trace = client.get(f"{base}/actions/{act.json()['id']}/trace").json()
    srcs = {e["source"]["id"] for e in trace["args"][0]["lineage"]["entries"] if e["source"]}
    assert "web:https://w.ex" in srcs

    path = client.get(f"{base}/data/{rec.json()['id']}/path-to/web:https://w.ex")
    assert path.status_code == 200 and path.json()["length"] == 4


def test_errors(client, tenant):
    assert client.get(f"/tenants/{tenant}/data/missing").status_code == 404
    assert client.get("/tenants/Bad Tenant/data/x").status_code == 400
    r = client.post(f"/tenants/{tenant}/record/llm-output",
                    json={"text": "x", "agent": "a", "derived_from": ["ghost"]})
    assert r.status_code == 404


def test_path_to_only_claims_no_path_after_complete_search(client, tenant):
    base = f"/tenants/{tenant}"
    w = client.post(f"{base}/record/web-content", json={"content": "x", "url": "https://w.ex"})
    top = w.json()["id"]
    for _ in range(30):  # deeper than the default max_trace_depth (25)
        top = client.post(f"{base}/record/llm-output",
                          json={"text": "x", "agent": "r", "derived_from": [top]}).json()["id"]
    deep = client.get(f"{base}/data/{top}/path-to/web:https://w.ex")
    assert deep.status_code == 200 and deep.json()["length"] == 31
    other = client.post(f"{base}/record/user-input", json={"text": "hi", "user": "p"}).json()["id"]
    none = client.get(f"{base}/data/{top}/path-to/{other}")
    assert none.status_code == 404 and none.json()["detail"]["search_complete"] is True
    bounded = client.get(f"{base}/data/{top}/path-to/{other}?max_depth=5")
    assert bounded.status_code == 503
    assert bounded.json()["detail"]["termination_reason"] == "depth_limit"
