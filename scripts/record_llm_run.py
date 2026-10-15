#!/usr/bin/env python3
"""Record ONE real LLM-driven run of the primary poisoned-memory scenario as a demo fixture.

    ANTHROPIC_API_KEY=... python scripts/record_llm_run.py [--model MODEL] [--out PATH]

Scout and Ops are driven by the model (Messages API tool use) through the normal agent
runtime: every output is recorded with the conservative whole-context provenance rule and
every side-effecting call goes through the deterministic Guard. The world is the synthetic
one (in-process vendor page / vault / Slack / attacker server); nothing is sent anywhere.

The run is written to custody/demo/fixtures/llm_run.json (never containing the API key),
then immediately replayed into a second empty graph to check it reproduces. The demo
replays it with no model call ("Recorded real LLM execution — deterministic replay").

Models may refuse the page's hidden instruction. If the recording has no BLOCKed action the
demo keeps using the scripted story; this script says so rather than retrying until a
"favourable" run appears. Re-run it deliberately if you want a different recording.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from custody.db import GraphProvider  # noqa: E402
from custody.demo import llm_run as L  # noqa: E402
from custody.graph.repository import GraphRepository  # noqa: E402
from custody.recorder.service import Recorder  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--model", default=None, help="Anthropic model (default: Warden default "
                    "or $CUSTODY_DEMO_LLM_MODEL)")
    ap.add_argument("--out", type=Path, default=L.FIXTURE)
    args = ap.parse_args()
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ANTHROPIC_API_KEY is not set: a real recording needs the API.", file=sys.stderr)
        return 2
    from redislite.falkordb_client import FalkorDB

    db = FalkorDB(os.path.join(tempfile.mkdtemp(), "llm-run.db"))
    provider = GraphProvider(db, prefix="custody-llm-run")
    llm = L.AnthropicLLM(model=args.model)
    print(f"recording with {llm.model} …")
    fx = L.record(Recorder(GraphRepository(provider.graph("record"))), llm, args.out)
    print(f"{len(fx.calls)} model calls recorded → {args.out}")
    for c in fx.calls:
        for b in c.response:
            if b.get("type") == "text":
                print(f"  [{c.agent}] {b['text'][:160]}")
            elif b.get("type") == "tool_use":
                print(f"  [{c.agent}] → {b['name']}({b.get('input')})")
    for o in fx.outcomes:
        print(f"  {o.tool}({o.destination}) → {o.verdict} {o.triggered}")
    out = L.replay(Recorder(GraphRepository(provider.graph("replay"))), fx)
    print(f"replay check: identical outcomes, {out['llm_calls_made']} model calls")
    if L.load_fixture(args.out) is None:
        print("note: the model did not attempt the exfiltration (no BLOCK in the recording); "
              "the demo will keep using the scripted story.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
