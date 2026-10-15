#!/usr/bin/env python3
"""Run the primary demo (one story) from the command line and print it.

    python scripts/attack_demo.py                       # uses CUSTODY_* env / .env
    python scripts/attack_demo.py --embedded .data/custody.db
    python scripts/attack_demo.py --extended --investigate   # multi-incident + Warden

Everything is simulated (synthetic company, in-process web/Slack/vault/attacker server,
simulated days, scripted agents); the graph and the Guard decisions are real.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from custody.config import get_settings  # noqa: E402
from custody.console import service as svc  # noqa: E402
from custody.db import GraphProvider, connect  # noqa: E402
from custody.demo.attack import TENANT  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--embedded", help="path for an embedded FalkorDB (falkordblite)")
    ap.add_argument("--tenant", default=TENANT)
    ap.add_argument("--extended", action="store_true",
                    help="run the extended multi-incident scenario instead of the primary demo")
    ap.add_argument("--investigate", action="store_true", help="run the Warden afterwards")
    a = ap.parse_args()
    s = get_settings()
    if a.embedded:
        os.makedirs(os.path.dirname(os.path.abspath(a.embedded)), exist_ok=True)
        s = s.model_copy(update={"falkordb_embedded_path": a.embedded})
    provider = GraphProvider(connect(s), s.graph_prefix, s.max_trace_depth)
    run = svc.run_demo(provider, a.tenant, "extended" if a.extended else "primary")
    print("SIMULATION:")
    for line in run.simulation:
        print("  -", line)
    print()
    for st in run.steps:
        tag = f" [{st.verdict}]" if st.verdict and st.key != "explain" else ""
        print(f"{st.n:>2}. {st.day:<8} {st.title}{tag}")
    d = run.blocked_decision
    print(f"\nGuard: {d['decision']} in {d['latency_ms']['total']:.1f} ms; "
          f"approval available: {d['approval']['available']}")
    for p in d["paths"]:
        print(f"  [{p['check']}/{p['status']}] {p['text']}")
    if a.investigate:
        w = asyncio.run(svc.investigate(provider, a.tenant, planner="playbook"))
        print("\nWarden:", " → ".join(w.tools_used))
        print(w.final_text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
