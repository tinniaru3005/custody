#!/usr/bin/env python3
"""Run the Acme Guard demo: a safe internal Slack post (ALLOW) and a lethal-trifecta
backup exfiltration (BLOCK), through the agent runtime.

Usage:
    python scripts/guard_demo.py                     # uses CUSTODY_* env / .env
    python scripts/guard_demo.py --embedded .data/custody.db
    python scripts/guard_demo.py --json              # print full decisions as JSON
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from custody.config import Settings, get_settings  # noqa: E402
from custody.db import GraphProvider, connect  # noqa: E402
from custody.demo.acme_guard import run_guard_demo  # noqa: E402
from custody.graph.repository import GraphRepository  # noqa: E402
from custody.recorder.service import Recorder  # noqa: E402
from custody.seeds.acme import TENANT, seed_acme  # noqa: E402


def show(title: str, result) -> None:
    d = result.decision
    print(f"\n=== {title}: {d.decision.value}  (status: {result.status}, "
          f"executed: {result.executed}, guard {d.latency_ms['total']:.1f} ms)")
    print(f"  checks triggered: {', '.join(c.value for c in d.triggered_checks) or 'none'}")
    print(f"  sink: {d.sink.destination} → {d.sink.zone} ({d.sink.reason})")
    print(f"  approval: {'available — ' if d.approval.available else 'not available — '}"
          f"{d.approval.reason}")
    print(f"  {d.explanation}")
    for p in d.paths:
        print(f"   [{p.check.value}/{p.status}] {p.text}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--embedded", help="path for an embedded FalkorDB (falkordblite)")
    ap.add_argument("--tenant", default=TENANT)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    settings: Settings = get_settings()
    if args.embedded:
        os.makedirs(os.path.dirname(os.path.abspath(args.embedded)), exist_ok=True)
        settings = settings.model_copy(update={"falkordb_embedded_path": args.embedded})
    provider = GraphProvider(connect(settings), settings.graph_prefix, settings.max_trace_depth)
    provider.drop(args.tenant)
    recorder = Recorder(GraphRepository(provider.graph(args.tenant)), settings.max_trace_depth)
    seed_acme(recorder)
    out = run_guard_demo(recorder)

    if args.json:
        print(json.dumps({k: out[k]["result"].decision.model_dump(mode="json")
                          for k in ("safe", "dangerous")}, indent=2))
        return 0
    show("SAFE CASE — rotated key to #security in Acme Slack", out["safe"]["result"])
    show("DANGEROUS CASE — vault secret to vendor-page backup URL", out["dangerous"]["result"])
    print(f"\nOutbox: {[(x.tool, x.destination) for x in out['runtime'].outbox.deliveries]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
