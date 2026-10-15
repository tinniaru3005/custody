#!/usr/bin/env python3
"""Seed the synthetic Acme Robotics tenant into graph ``custody:acme``.

Usage:
    python scripts/seed_acme.py                 # uses CUSTODY_* env / .env
    python scripts/seed_acme.py --embedded .data/custody.db
    python scripts/seed_acme.py --keep          # don't wipe the existing graph first
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from custody.config import Settings, get_settings  # noqa: E402
from custody.db import GraphProvider, connect  # noqa: E402
from custody.graph.repository import GraphRepository  # noqa: E402
from custody.recorder.service import Recorder  # noqa: E402
from custody.seeds.acme import TENANT, seed_acme  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--embedded", help="path for an embedded FalkorDB (falkordblite)")
    ap.add_argument("--tenant", default=TENANT)
    ap.add_argument("--keep", action="store_true", help="do not drop the graph first")
    args = ap.parse_args()

    settings: Settings = get_settings()
    if args.embedded:
        os.makedirs(os.path.dirname(os.path.abspath(args.embedded)), exist_ok=True)
        settings = settings.model_copy(update={"falkordb_embedded_path": args.embedded})

    provider = GraphProvider(connect(settings), settings.graph_prefix, settings.max_trace_depth)
    if not args.keep:
        provider.drop(args.tenant)
    recorder = Recorder(GraphRepository(provider.graph(args.tenant)), settings.max_trace_depth)
    ids = seed_acme(recorder)

    print(f"Seeded graph {settings.graph_prefix}:{args.tenant}")
    for k, v in sorted(recorder.repo.counts().items()):
        print(f"  {k:<22} {v}")

    trace = recorder.trace_action(ids["action"])
    print(f"\nTrace of action {trace.action.id} ({trace.action.action_type} -> "
          f"{trace.action.sink.destination if trace.action.sink else '?'}):")
    for arg in trace.args:
        lin = arg.lineage
        print(f"  [{arg.role}] {arg.datum_id}")
        print(f"     sources:   {', '.join(f'{s.id} ({s.trust.value})' for s in lin.sources)}")
        print(f"     max sensitivity: {lin.max_sensitivity.value}")
    path = recorder.find_path(ids["dest"], "web:https://rivalbots.example/pricing")
    if path:
        print("\nDestination -> untrusted web source:")
        print("  " + "".join(f"{n} -[{o}]-> " for n, o in zip(path.node_ids, path.ops))
              + path.node_ids[-1])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
