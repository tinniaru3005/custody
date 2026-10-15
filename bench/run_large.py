"""Large-graph benchmark: 100k+ node provenance graphs, high fan-in, summaries of summaries.

    python -m bench.run_large                  # full grid (~15–25 min on 2 vCPU, embedded)
    python -m bench.run_large --quick          # the 10k-scale points only
    python -m bench.run_large --host localhost # a FalkorDB server

Same infrastructure as ``run_scaling`` (one tenant per point, ``bench.common`` helpers,
SQLite CTE over the exported graph), with one difference that matters for honesty:

  The *bulk* of each graph (tens of thousands of documents and summaries) is written with
  batched Cypher (UNWIND … CREATE) using the Recorder's exact schema (Datum properties,
  FROM, DERIVED_FROM {op, attribution}). Recording 100k Datums one by one through the
  Recorder takes far too long for a benchmark. The memory recall, the destination argument
  and the action itself are recorded through the normal Recorder.

Each point is measured under two limit sets:
  default  the shipped GuardPolicy limits (max 100,000 nodes, 2 s per search)
  raised   max 2,000,000 nodes, 120 s per search
An INDETERMINATE result is reported as such (fail-closed, not "wrong").

Writes bench/results/large.json and bench/results/large.md.
"""
from __future__ import annotations

import argparse
import json
import random
import time
from dataclasses import replace
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from bench.common import SqlMirror, connect, export_graph, fresh, machine_info, ms, summary
from custody.graph import traversal as T
from custody.graph.model import MODEL_OUTPUT_KINDS, fingerprint, utcnow_iso
from custody.guard import ACME_POLICY, Guard
from custody.recorder.service import Recorder

RESULTS = Path(__file__).resolve().parent / "results"
ATTACKER = "https://drop.attacker-mirror.example/v1/upload"
TRUSTED_SRC = "github:acme/runbooks"
AGENT_SRC = "system:agent:summariser"
BATCH = 5_000
LIMITS = {
    "default": {"max_depth": ACME_POLICY.search_max_depth, "max_nodes": ACME_POLICY.search_max_nodes,
                "timeout_ms": ACME_POLICY.search_timeout_ms},
    "raised": {"max_depth": None, "max_nodes": 2_000_000, "timeout_ms": 120_000},
}


# ------------------------------------------------------------------------ bulk writer
class Bulk:
    """Batched writes in the Recorder's schema (bypasses per-Datum recording for speed)."""

    def __init__(self, rec: Recorder, tag: str) -> None:
        self.g = rec.repo.graph
        self.tag = tag
        self.n = 0
        rec.repo.upsert_source(TRUSTED_SRC, "github", "trusted")
        rec.repo.upsert_source(AGENT_SRC, "system", "trusted")
        rec.repo.upsert_source(f"web:https://vendor.example/{tag}", "web", "untrusted")

    def datums(self, count: int, kind: str, source: str, text: str) -> List[str]:
        ids = [f"b_{self.tag}_{self.n + i}" for i in range(count)]
        self.n += count
        now = utcnow_iso()
        for k in range(0, count, BATCH):
            rows = [{"id": i, "fp": fingerprint(i)} for i in ids[k:k + BATCH]]
            self.g.query(
                "UNWIND $rows AS r MATCH (s:Source {id: $sid}) "
                "CREATE (d:Datum {id: r.id, kind: $kind, sensitivity: 'normal', preview: $text, "
                "value: $text, fingerprint: r.fp, created_at: $now, agent: 'summariser', "
                "session_id: 'bulk', coverage: $cov})-[:FROM {created_at: $now}]->(s)",
                {"rows": rows, "sid": source, "kind": kind, "text": text, "now": now,
                 # same schema as the Recorder: model outputs carry their coverage
                 "cov": "FULL_CONTEXT" if kind in MODEL_OUTPUT_KINDS else None})
        return ids

    def edges(self, pairs: List[Tuple[str, str]], op: str = "derive") -> None:
        now = utcnow_iso()
        for k in range(0, len(pairs), BATCH):
            rows = [{"c": c, "p": p} for c, p in pairs[k:k + BATCH]]
            self.g.query(
                "UNWIND $rows AS r MATCH (c:Datum {id: r.c}) WITH c, r "
                "MATCH (p:Datum {id: r.p}) "
                "CREATE (c)-[:DERIVED_FROM {op: $op, attribution: 'inherit', created_at: $now}]->(p)",
                {"rows": rows, "op": op, "now": now})

    def poison(self, datum_id: str) -> None:
        """Re-point one document's FROM at the untrusted Source."""
        self.g.query("MATCH (d:Datum {id: $id})-[f:FROM]->() DELETE f", {"id": datum_id})
        self.g.query("MATCH (d:Datum {id: $id}), (s:Source {id: $sid}) CREATE (d)-[:FROM]->(s)",
                     {"id": datum_id, "sid": f"web:https://vendor.example/{self.tag}"})


def _finish(rec: Recorder, root: str) -> str:
    """Memory recall → destination argument → action, through the normal Recorder."""
    mem = rec.record_memory(f"Backup policy. Destination {ATTACKER}.", agent="scout",
                            derived_from=[root], session_id="s-mem", key="policy")
    recall = rec.record_memory_recall(mem.id, agent="ops", session_id="s-act")
    dest = rec.record_llm_output(ATTACKER, agent="ops", derived_from=[recall.id],
                                 session_id="s-act")
    payload = rec.record_user_input("nightly manifest", user="sam@acme-robotics.example",
                                    agent="ops", session_id="s-act")
    return rec.record_action("upload_backup", agent="ops", session_id="s-act",
                             destination=[dest.id], payload=[payload.id],
                             sink_destination=ATTACKER, sink_kind="backup").id


# ------------------------------------------------------------------------ generators
def gen_tree(rec: Recorder, b: Bulk, dangerous: bool, branching: int, depth: int) -> Dict:
    leaves = b.datums(branching ** depth, "tool_output", TRUSTED_SRC, "Runbook section.")
    if dangerous:
        b.poison(random.Random(len(leaves)).choice(leaves))
    level = leaves
    for _lv in range(depth):
        parents = b.datums(len(level) // branching, "llm_output", AGENT_SRC, "Summary.")
        b.edges([(parents[k // branching], c) for k, c in enumerate(level)], "summarise")
        level = parents
    return {"action": _finish(rec, level[0]), "leaves": len(leaves)}


def gen_fanin(rec: Recorder, b: Bulk, dangerous: bool, n: int) -> Dict:
    docs = b.datums(n, "tool_output", TRUSTED_SRC, "Runbook.")
    if dangerous:
        b.poison(random.Random(n).choice(docs))
    (summary_id,) = b.datums(1, "llm_output", AGENT_SRC, "Summary of everything.")
    b.edges([(summary_id, d) for d in docs], "summarise")
    return {"action": _finish(rec, summary_id), "parents": n}


def gen_chain(rec: Recorder, b: Bulk, dangerous: bool, length: int, noise: int) -> Dict:
    """A chain of ``length`` hops inside a graph padded with ``noise`` unrelated Datums."""
    if noise:
        b.datums(noise, "tool_output", TRUSTED_SRC, "Unrelated document.")
    ids = b.datums(length + 1, "llm_output", AGENT_SRC, "Relay.")
    b.edges([(ids[k], ids[k + 1]) for k in range(length)], "derive")
    if dangerous:
        b.poison(ids[-1])
    return {"action": _finish(rec, ids[0]), "hops": length, "noise": noise}


GRID = [
    ("fan_in", gen_fanin, [(1_000,), (10_000,), (100_000,)]),
    ("summary_tree", gen_tree, [(10, 3), (10, 4), (10, 5), (50, 3)]),
    ("chain_in_100k", gen_chain, [(100, 100_000), (1_000, 100_000), (3_000, 100_000)]),
]
QUICK = {"fan_in": [(1_000,), (10_000,)], "summary_tree": [(10, 3), (10, 4)],
         "chain_in_100k": [(100, 10_000), (1_000, 10_000)]}


# ---------------------------------------------------------------------------- runner
def measure(db, name, gen, params, dangerous, reps) -> Dict:
    tag = f"{name}-{'d' if dangerous else 'c'}-{'-'.join(map(str, params))}".replace("_", "")
    provider, rec, _guard, _ = fresh(db, f"large-{tag}")
    t0 = time.perf_counter()
    meta = gen(rec, Bulk(rec, tag), dangerous, *params)
    build_ms = ms(t0)
    aid = meta["action"]
    dest = next(a.datum_id for a in rec.repo.get_action(aid).args if a.role == "destination")
    total_nodes = rec.repo.graph.ro_query("MATCH (d:Datum) RETURN count(d)").result_set[0][0]
    out: Dict = {"scenario": name, "params": list(params),
                 "variant": "dangerous" if dangerous else "clean", "datums": total_nodes,
                 "build_ms": round(build_ms), **{k: v for k, v in meta.items() if k != "action"},
                 "configs": {}}
    for cfg, lim in LIMITS.items():
        lat, res = [], None
        for _ in range(reps):
            t = time.perf_counter()
            res = T.untrusted_origin(rec.repo.graph, [dest], risk_rank=1, **lim)
            lat.append(ms(t))
        policy = replace(ACME_POLICY, search_max_depth=lim["max_depth"],
                         search_max_nodes=lim["max_nodes"], search_timeout_ms=lim["timeout_ms"])
        guard = Guard(rec, policy, record_decisions=False)
        g_lat, d = [], None
        for _ in range(max(1, min(reps, 3))):
            t = time.perf_counter()
            d = guard.check(aid)
            g_lat.append(ms(t))
        correct = None if not res.search_complete else (res.path_found == dangerous)
        out["configs"][cfg] = {
            "search": {"outcome": res.outcome.value, "termination": res.termination_reason.value,
                       "complete": res.search_complete, "nodes_visited": res.nodes_visited,
                       "queries": res.queries, "depth": res.depth_explored,
                       "latency": summary(lat)},
            "correct": correct,
            "guard": {"verdict": d.decision.value, "search_complete": d.search_complete,
                      "certificate": d.certificate is not None,
                      "certificate_unavailable": d.certificate_unavailable,
                      "latency": summary(g_lat)},
        }
    ex = export_graph(rec)
    sql = SqlMirror(ex)
    c_lat = []
    for _ in range(reps):
        t = time.perf_counter()
        found, visited = sql.untrusted_destination(aid)
        c_lat.append(ms(t))
    out["sql_cte"] = {"found": found, "visited": visited, "latency": summary(c_lat)}
    provider.drop(f"large-{tag}")
    return out


def render(r: Dict) -> str:
    m = r["machine"]
    lines = [f"# Large-graph benchmark (generated {m['date_utc']})", "",
             f"`{r['command'].strip()}` · {m['backend']}, Python {m['python']}, {m['cpu']} "
             f"×{m['cpus']} · search repetitions {r['reps']} (Guard checks ≤3)", "",
             "Bulk of each graph written with batched Cypher in the Recorder's schema; the "
             "recall, destination and action through the Recorder. `default` = shipped limits "
             "(100k nodes, 2 s); `raised` = 2M nodes, 120 s. Search = the complete integrity "
             "search alone; Guard = full `Guard.check` (evidence query, both searches, "
             "certificate on ALLOW).", "",
             "| scenario | params | variant | datums | limits | outcome (termination) | correct "
             "| nodes visited | search p50 / p95 | Guard verdict | Guard p50 | certificate "
             "| CTE p50 |", "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for x in r["rows"]:
        for cfg, c in x["configs"].items():
            s, gd = c["search"], c["guard"]
            corr = {True: "yes", False: "**NO**", None: "n/a (incomplete)"}[c["correct"]]
            lines.append(
                f"| {x['scenario']} | {x['params']} | {x['variant']} | {x['datums']:,} | {cfg} "
                f"| {s['outcome']} ({s['termination']}) | {corr} | {s['nodes_visited']:,} "
                f"| {s['latency']['median_ms']:,} / {s['latency']['p95_ms']:,} ms "
                f"| {gd['verdict']} | {gd['latency']['median_ms']:,} ms "
                f"| {'yes' if gd['certificate'] else '—'} "
                f"| {x['sql_cte']['latency']['median_ms']:,} ms |")
    return "\n".join(lines) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int, default=6379)
    ap.add_argument("--out", default=str(RESULTS))
    a = ap.parse_args(argv)
    db, backend = connect(a.host, a.port)
    result = {"command": "python -m bench.run_large " + " ".join(argv or []),
              "machine": machine_info(backend), "reps": a.reps, "rows": []}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, gen, grid in GRID:
        for params in (QUICK[name] if a.quick else grid):
            for dangerous in (True, False):
                row = measure(db, name, gen, params, dangerous, a.reps)
                result["rows"].append(row)
                c = row["configs"]
                print(f"{name:14s} {str(params):16s} {row['variant']:9s} {row['datums']:>8,} "
                      f"build {row['build_ms'] / 1000:6.1f}s | default "
                      f"{c['default']['search']['outcome']:13s} "
                      f"{c['default']['search']['latency']['median_ms']:9.1f} ms | raised "
                      f"{c['raised']['search']['outcome']:13s} "
                      f"{c['raised']['search']['latency']['median_ms']:9.1f} ms | guard "
                      f"{c['raised']['guard']['verdict']}", flush=True)
                (out / "large.json").write_text(json.dumps(result, indent=1))
                (out / "large.md").write_text(render(result))
    print(render(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
