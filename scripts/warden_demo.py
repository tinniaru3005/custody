"""Warden demo: build the Acme incident, then ask the Warden to clean it up.

    python scripts/warden_demo.py                 # PlaybookPlanner (offline)
    ANTHROPIC_API_KEY=... python scripts/warden_demo.py --planner anthropic

Uses CUSTODY_* settings (an embedded FalkorDB if CUSTODY_FALKORDB_EMBEDDED_PATH is set).
"""
from __future__ import annotations

import argparse
import asyncio

from custody.config import get_settings
from custody.db import GraphProvider, connect
from custody.demo.acme_warden import CLEANUP_REQUEST, build_incident
from custody.guard import ACME_POLICY
from custody.warden import Warden
from custody.warden.agent import AnthropicPlanner, PlaybookPlanner, run_warden


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tenant", default="acme-warden-demo")
    ap.add_argument("--planner", default="playbook", choices=["playbook", "anthropic"])
    ap.add_argument("--approve", action="store_true", help="approve + send as the human")
    a = ap.parse_args()

    s = get_settings()
    provider = GraphProvider(connect(s), s.graph_prefix, s.max_trace_depth)
    provider.drop(a.tenant)
    warden = Warden.for_tenant(provider, a.tenant, policy=ACME_POLICY,
                               operator="priya@acme-robotics.example")
    ids = build_incident(warden.recorder)
    print("Scenario:")
    for k in ("dangerous", "safe", "msp"):
        r = ids[k]["result"]
        print(f"  {k:10s} {r.action_id}: {r.verdict.value} → {r.status}")

    planner = AnthropicPlanner() if a.planner == "anthropic" else PlaybookPlanner()
    print(f"\nUser: {CLEANUP_REQUEST}\n")
    report = asyncio.run(run_warden(warden, CLEANUP_REQUEST, planner))
    print("Warden tools:", " → ".join(report.tools_used), "\n")
    print(report.final_text)

    if a.approve and report.pending_approvals:
        aid = report.pending_approvals[0]["action_id"]
        warden.approve_disclosure(aid, approver="priya@acme-robotics.example")
        print("\nHuman approved →", warden.send_approved_disclosure(aid).detail)


if __name__ == "__main__":
    main()
