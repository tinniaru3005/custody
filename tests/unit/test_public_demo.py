"""Public-demo mode: one read-only synthetic tenant, deterministic reset, nothing else."""
import json

import pytest
from fastapi.testclient import TestClient

from custody.api.app import create_app
from custody.config import Settings
from custody.demo.attack import INITIAL_STAGING_KEY
from custody.graph.repository import GraphRepository
from custody.recorder.service import Recorder


@pytest.fixture
def demo_tenant(tenant):
    return tenant


@pytest.fixture
def public(falkordb_client, demo_tenant):
    settings = Settings(graph_prefix="custody-test", public_demo=True, demo_tenant=demo_tenant,
                        demo_reset_min_interval_s=0)
    app = create_app(db=falkordb_client, settings=settings)
    with TestClient(app) as c:
        yield c


def _strip(x):
    """Drop measured timings (Guard latency) from nested JSON."""
    if isinstance(x, dict):
        return {k: _strip(v) for k, v in x.items()
                if not k.endswith("latency_ms") and k != "seq"}
    if isinstance(x, list):
        return [_strip(v) for v in x]
    return x


def snapshot(provider, tenant):
    """Every node and relationship with its properties, minus measured timings."""
    g = provider.graph(tenant)
    volatile = {"latency_ms", "seq"}

    def props(p):
        out = []
        for k, v in p.items():
            if k in volatile:
                continue
            if k == "payload":  # stored demo report (JSON) includes measured latencies
                v = json.dumps(_strip(json.loads(v)), sort_keys=True)
            out.append((k, str(v)))
        return sorted(out)

    nodes = sorted((sorted(n.labels), props(n.properties))
                   for (n,) in g.ro_query("MATCH (n) RETURN n").result_set)
    rels = sorted(
        (a, r.relation, b, sorted((k, str(v)) for k, v in r.properties.items() if k not in volatile))
        for a, r, b in g.ro_query("MATCH (x)-[r]->(y) RETURN x.id, r, y.id").result_set)
    return nodes, rels


def test_startup_seeds_the_demo_and_health_says_public(public, demo_tenant):
    h = public.get("/api/health").json()
    assert h["public_demo"] is True and h["demo_tenant"] == demo_tenant
    assert set(h) == {"status", "falkordb", "version", "public_demo", "demo_tenant"}
    demo = public.get(f"/api/tenants/{demo_tenant}/console/demo").json()
    assert demo["scenario"] == "primary" and len(demo["steps"]) == 7
    assert public.get(f"/api/tenants/{demo_tenant}/console/overview").json()["empty"] is False
    worlds = public.get(f"/api/tenants/{demo_tenant}/console/worlds").json()
    assert [w["verdict"] for w in worlds["worlds"]] == ["ALLOW", "REQUIRE_HUMAN_APPROVAL", "BLOCK"]
    ck = public.get(f"/api/tenants/{demo_tenant}/console/actions/"
                    f"{demo['ids']['blocked_action']}/chokepoints").json()
    assert ck["recommended"] == demo["ids"]["memory"]


def test_other_tenants_are_invisible(public):
    for path in ("/api/tenants/other/console/overview", "/tenants/other/console/demo",
                 "/api/tenants/other/data/x", "/api/tenants/other/console/demo/reset"):
        r = public.get(path) if not path.endswith("reset") else public.post(path)
        assert r.status_code == 404, path


@pytest.mark.parametrize("path,body", [
    ("record/user-input", {"text": "hi", "user": "x"}),
    ("record/web-content", {"content": "x", "url": "https://w.ex"}),
    ("guard/actions/any/approve", {"approver": "priya@acme-robotics.example"}),
    ("guard/actions/any/reject", {"approver": "priya@acme-robotics.example"}),
    ("guard/actions/any/check", None),
    ("guard/endorse", {"datum_ids": ["d"], "approver": "p"}),
    ("console/demo/attack", None),
    ("console/demo/attack?scenario=extended", None),
    ("console/warden/investigate", {"planner": "anthropic"}),
    ("console/worlds", None),
    ("guard/sources/user:sam@acme-robotics.example/revoke", {"approver": "visitor"}),
    ("console/warden/disclosures/any/send", None),
])
def test_mutations_are_refused(public, demo_tenant, path, body):
    r = public.post(f"/api/tenants/{demo_tenant}/{path}", json=body)
    assert r.status_code == 403, (path, r.text)
    for method in ("put", "patch", "delete"):
        assert getattr(public, method)(f"/api/tenants/{demo_tenant}/{path}").status_code == 403


def test_blocked_action_cannot_be_approved_by_visitors(public, demo_tenant):
    demo = public.get(f"/api/tenants/{demo_tenant}/console/demo").json()
    aid = demo["ids"]["blocked_action"]
    r = public.post(f"/api/tenants/{demo_tenant}/guard/actions/{aid}/approve",
                    json={"approver": "visitor"})
    assert r.status_code == 403


def test_no_server_configuration_or_api_schema(public):
    for path in ("/docs", "/redoc", "/openapi.json", "/api/docs", "/api/openapi.json"):
        assert public.get(path).status_code == 404, path


def test_no_raw_secret_values_in_any_read(public, demo_tenant):
    base = f"/api/tenants/{demo_tenant}"
    demo = public.get(f"{base}/console/demo").json()
    bodies = [public.get(f"{base}/console/{p}").text
              for p in ("overview", "graph?include_decisions=true", "actions", "approvals",
                        "memories", "metrics", "demo")]
    for aid in (demo["ids"]["blocked_action"], demo["ids"]["slack_action"]):
        bodies.append(public.get(f"{base}/console/actions/{aid}/explain").text)
    bodies.append(public.get(f"{base}/data/{demo['ids']['secret']}").text)
    blob = "\n".join(bodies)
    assert INITIAL_STAGING_KEY not in blob
    assert "AKIAROTATED" not in blob          # the rotated (fake) key's raw value


def test_reset_restores_an_identical_graph(public, demo_tenant, provider):
    first = snapshot(provider, demo_tenant)
    # simulate tampering behind the API's back
    rec = Recorder(GraphRepository(provider.graph(demo_tenant)))
    rec.record_web_content("tampered", url="https://tamper.example")
    assert snapshot(provider, demo_tenant) != first
    r = public.post(f"/api/tenants/{demo_tenant}/console/demo/reset")
    assert r.status_code == 204
    assert snapshot(provider, demo_tenant) == first
    assert public.post(f"/api/tenants/{demo_tenant}/console/demo/reset").status_code == 204
    assert snapshot(provider, demo_tenant) == first


def test_reset_is_rate_limited(falkordb_client, demo_tenant):
    settings = Settings(graph_prefix="custody-test", public_demo=True, demo_tenant=demo_tenant,
                        demo_reset_min_interval_s=60)
    with TestClient(create_app(db=falkordb_client, settings=settings)) as c:
        url = f"/api/tenants/{demo_tenant}/console/demo/reset"
        assert c.post(url).status_code == 204
        r = c.post(url)
        assert r.status_code == 429 and "Retry-After" in r.headers


def test_normal_mode_is_unchanged(falkordb_client, tenant):
    with TestClient(create_app(db=falkordb_client,
                               settings=Settings(graph_prefix="custody-test"))) as c:
        assert c.get("/api/health").json()["public_demo"] is False
        assert c.get("/openapi.json").status_code == 200
        assert c.post(f"/api/tenants/{tenant}/record/user-input",
                      json={"text": "hi", "user": "u"}).status_code == 201
