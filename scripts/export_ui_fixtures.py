#!/usr/bin/env python3
"""Regenerate the JSON fixtures the frontend unit tests use (frontend/src/test/fixtures).

Runs the primary demo, and the extended scenario + a Warden investigation, on an embedded
FalkorDB and saves the console API responses, so the UI tests exercise real backend shapes.

    CUSTODY_FALKORDB_EMBEDDED_PATH=/tmp/fixtures.db python scripts/export_ui_fixtures.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient  # noqa: E402

from custody.api.app import create_app  # noqa: E402
from custody.config import Settings  # noqa: E402
from custody.db import connect  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "frontend" / "src" / "test" / "fixtures"


def main() -> None:
    path = os.environ.get("CUSTODY_FALKORDB_EMBEDDED_PATH") or \
        os.path.join(tempfile.mkdtemp(), "fixtures.db")
    s = Settings(falkordb_embedded_path=path, graph_prefix="custody-fixtures")
    app = create_app(db=connect(s), settings=s)
    OUT.mkdir(parents=True, exist_ok=True)
    base = "/api/tenants/acme/console"
    with TestClient(app) as c:
        save = lambda name, data: (OUT / f"{name}.json").write_text(  # noqa: E731
            json.dumps(data, indent=1, sort_keys=True))
        # extended scenario: the approval queue and the Warden (outside the primary demo)
        c.post(f"{base}/demo/attack?scenario=extended")
        save("approvals", c.get(f"{base}/approvals").json())
        save("warden", c.post(f"{base}/warden/investigate", json={"planner": "playbook"}).json())
        save("overview_after", c.get(f"{base}/overview").json())
        # primary demo (one story): everything else
        demo = c.post(f"{base}/demo/attack?mode=scripted").json()
        save("demo", demo)
        save("overview", c.get(f"{base}/overview").json())
        save("graph", c.get(f"{base}/graph").json())
        save("explain_blocked", c.get(f"{base}/actions/{demo['ids']['blocked_action']}/explain").json())
        save("explain_slack", c.get(f"{base}/actions/{demo['ids']['slack_action']}/explain").json())
        save("metrics", c.get(f"{base}/metrics?runs=3").json())
        save("worlds", c.post(f"{base}/worlds").json())
        save("influence", c.get(f"{base}/influence").json())
        c.post(f"{base}/demo/reset")
    print(f"wrote fixtures to {OUT}")


if __name__ == "__main__":
    main()
