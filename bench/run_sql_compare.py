"""SQL (recursive CTE) vs FalkorDB for the *practical* parts of provenance queries.

    python -m bench.run_sql_compare

run_correctness already shows the recursive CTE and Custody's FalkorDB search agree case
for case on reachability. This script measures what else a provenance store has to do:

1. Cycle handling: a tiny graph with a DERIVED_FROM cycle (a -> b -> c -> a, c -> page).
   Recorded provenance is acyclic in practice, but a store should not hang on bad data.
2. Explanation path extraction on dense multi-turn sessions (every turn derives from every
   earlier one: about 2^t paths). Four ways to get "a path to the untrusted page":
     falkordb_bfs        Custody's level-by-level BFS with a visited set (witness path)
     falkordb_varlength  a variable-length Cypher pattern (*1..N) returning the shortest
     sqlite_levels       recursive CTE over (node, depth) pairs with UNION (deduplicated),
                         then the path rebuilt from the levels in Python
     sqlite_pathstring   the textbook recursive CTE that carries the path as a string with
                         an instr() cycle guard (UNION ALL)
   each with a per-query time cap.
3. Query complexity: the size of each query (and of the driver loop for the BFS).

Writes bench/results/sql_compare.{json,md}. Embedded FalkorDB and in-process SQLite: no
network hop for either, which favours SQLite less than a remote database would.
"""
from __future__ import annotations

import argparse
import inspect
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from bench.common import connect, fresh, machine_info, ms
from custody.graph import traversal as T

RESULTS = Path(__file__).resolve().parent / "results"
TURNS = [6, 10, 14, 18, 22]
CAP_S = 10.0

SQL_REACH = """
WITH RECURSIVE reach(id) AS (
  SELECT :start
  UNION
  SELECT e.dst FROM reach r JOIN edges e ON e.src = r.id
)
SELECT EXISTS (SELECT 1 FROM reach r JOIN nodes n ON n.id = r.id WHERE n.untrusted = 1)
"""
SQL_LEVELS = """
WITH RECURSIVE lvl(id, d) AS (
  SELECT :start, 0
  UNION
  SELECT e.dst, l.d + 1 FROM lvl l JOIN edges e ON e.src = l.id
   WHERE l.d < :maxd
)
SELECT id, min(d) FROM lvl GROUP BY id
"""
SQL_PATHSTRING = """
WITH RECURSIVE walk(id, d, path) AS (
  SELECT :start, 0, ',' || :start || ','
  UNION ALL
  SELECT e.dst, w.d + 1, w.path || e.dst || ',' FROM walk w JOIN edges e ON e.src = w.id
   WHERE instr(w.path, ',' || e.dst || ',') = 0
)
SELECT w.path, w.d FROM walk w JOIN nodes n ON n.id = w.id WHERE n.untrusted = 1
ORDER BY w.d LIMIT 1
"""
CYPHER_VARLEN = ("MATCH p = (a:Datum {id: $start})-[:DERIVED_FROM*1..%d]->(x:Datum)-[:FROM]->"
                 "(:Source {trust: 'untrusted'}) RETURN [n IN nodes(p) | n.id], length(p) "
                 "ORDER BY length(p) LIMIT 1")


def _sqlite(edges: List[Tuple[str, str]], nodes: Dict[str, bool]) -> sqlite3.Connection:
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.executescript("CREATE TABLE nodes (id TEXT PRIMARY KEY, untrusted INTEGER);"
                     "CREATE TABLE edges (src TEXT, dst TEXT); CREATE INDEX e_src ON edges(src);")
    db.executemany("INSERT INTO nodes VALUES (?, ?)", [(k, int(v)) for k, v in nodes.items()])
    db.executemany("INSERT INTO edges VALUES (?, ?)", edges)
    return db


def _timed_sql(db: sqlite3.Connection, q: str, params: dict) -> Tuple[Optional[list], float, str]:
    """Run with a wall-clock cap (sqlite3 interrupt from a timer thread)."""
    timer = threading.Timer(CAP_S, db.interrupt)
    t = time.perf_counter()
    timer.start()
    try:
        rows = db.execute(q, params).fetchall()
        return rows, ms(t), "ok"
    except sqlite3.OperationalError as exc:
        return None, ms(t), "timeout" if "interrupt" in str(exc) else f"error: {exc}"
    finally:
        timer.cancel()


def _graph_export(rec) -> Tuple[List[Tuple[str, str]], Dict[str, bool]]:
    q = rec.repo.graph.ro_query
    nodes = {r[0]: bool(r[1]) for r in q(
        "MATCH (d:Datum) OPTIONAL MATCH (d)-[:FROM]->(s:Source {trust: 'untrusted'}) "
        "RETURN d.id, s IS NOT NULL").result_set}
    edges = [tuple(r) for r in q("MATCH (a:Datum)-[:DERIVED_FROM]->(b:Datum) "
                                 "RETURN a.id, b.id").result_set]
    return edges, nodes


def cycle_check(db) -> Dict:
    provider, rec, _, _ = fresh(db, "sqlcmp-cycle")
    g = rec.repo.graph
    page = rec.record_web_content("hidden instructions", url="https://cycle.example/")
    g.query("CREATE (:Datum {id: 'a', kind: 'llm_output'}), (:Datum {id: 'b', kind: "
            "'llm_output'}), (:Datum {id: 'c', kind: 'llm_output'})")
    g.query("MATCH (a:Datum {id: 'a'}), (b:Datum {id: 'b'}), (c:Datum {id: 'c'}), "
            "(p:Datum {id: $p}) CREATE (a)-[:DERIVED_FROM {op: 'derive'}]->(b), "
            "(b)-[:DERIVED_FROM {op: 'derive'}]->(c), (c)-[:DERIVED_FROM {op: 'derive'}]->(a), "
            "(c)-[:DERIVED_FROM {op: 'derive'}]->(p)", {"p": page.id})
    g.query("CREATE (:Datum {id: 'z', kind: 'llm_output'})-[:DERIVED_FROM {op: 'derive'}]->"
            "(:Datum {id: 'y', kind: 'llm_output'})-[:DERIVED_FROM {op: 'derive'}]->"
            "(:Datum {id: 'x', kind: 'llm_output'})")
    g.query("MATCH (x:Datum {id: 'x'}), (z:Datum {id: 'z'}) "
            "CREATE (x)-[:DERIVED_FROM {op: 'derive'}]->(z)")   # cycle with no untrusted exit
    edges, nodes = _graph_export(rec)
    sdb = _sqlite(edges, nodes)
    out = {}
    for start, truth in (("a", True), ("z", False)):
        t = time.perf_counter()
        bfs = T.untrusted_origin(g, [start])
        bfs_ms = ms(t)
        reach, r_ms, r_st = _timed_sql(sdb, SQL_REACH, {"start": start})
        path, p_ms, p_st = _timed_sql(sdb, SQL_PATHSTRING, {"start": start})
        out[start] = {
            "truth": truth,
            "falkordb_bfs": {"found": bfs.path_found, "complete": bfs.search_complete,
                             "ms": round(bfs_ms, 3), "witness": bfs.witness_node_ids},
            "sqlite_reach_union": {"found": bool(reach[0][0]) if reach else None,
                                   "status": r_st, "ms": round(r_ms, 3)},
            "sqlite_pathstring": {"found": bool(path) if path is not None else None,
                                  "status": p_st, "ms": round(p_ms, 3),
                                  "path": path[0][0] if path else None},
        }
    provider.drop("sqlcmp-cycle")
    return out


def dense(db, turns: int) -> Dict:
    """One session where turn k derives from the page and every earlier turn."""
    provider, rec, _, rt = fresh(db, f"sqlcmp-dense-{turns}")
    rt.web["https://dense.example/"] = "vendor page"
    s = rt.session("ops", "dense")
    s.fetch("https://dense.example/")
    for k in range(turns):
        s.think(f"turn {k}")
    start = s.context[-1]
    g = rec.repo.graph
    edges, nodes = _graph_export(rec)
    sdb = _sqlite(edges, nodes)
    res: Dict[str, Dict] = {"turns": turns, "edges": len(edges)}

    t = time.perf_counter()
    bfs = T.untrusted_origin(g, [start])
    res["falkordb_bfs"] = {"ms": round(ms(t), 3), "status": "ok" if bfs.search_complete
                           else bfs.termination_reason.value,
                           "hops": len(bfs.witness_ops) - 1 if bfs.path_found else None}
    t = time.perf_counter()
    try:
        rows = g.ro_query(CYPHER_VARLEN % (turns + 1), {"start": start},
                          timeout=int(CAP_S * 1000)).result_set
        res["falkordb_varlength"] = {"ms": round(ms(t), 3), "status": "ok",
                                     "hops": rows[0][1] if rows else None}
    except Exception as exc:  # noqa: BLE001
        res["falkordb_varlength"] = {"ms": round(ms(t), 3),
                                     "status": "timeout" if "timed out" in str(exc).lower()
                                     else f"error: {exc}", "hops": None}
    t = time.perf_counter()
    lv, l_ms, l_st = _timed_sql(sdb, SQL_LEVELS, {"start": start, "maxd": len(nodes)})
    hops = None
    if lv is not None:   # rebuild: deepest-first walk is not needed; shortest = min level
        level = dict(lv)
        hops = min((d for i, d in level.items() if nodes.get(i)), default=None)
    res["sqlite_levels"] = {"ms": round(ms(t), 3), "status": l_st, "hops": hops}
    ps, p_ms, p_st = _timed_sql(sdb, SQL_PATHSTRING, {"start": start})
    res["sqlite_pathstring"] = {"ms": round(p_ms, 3), "status": p_st,
                                "hops": ps[0][1] if ps else None}
    provider.drop(f"sqlcmp-dense-{turns}")
    return res


def complexity() -> Dict[str, Dict[str, int]]:
    def size(text: str) -> Dict[str, int]:
        lines = [ln for ln in text.strip().splitlines() if ln.strip()]
        return {"lines": len(lines), "chars": len(" ".join(x.strip() for x in lines))}
    return {"sqlite_reach_union": size(SQL_REACH), "sqlite_levels": size(SQL_LEVELS),
            "sqlite_pathstring": size(SQL_PATHSTRING),
            "falkordb_varlength": size(CYPHER_VARLEN),
            "falkordb_bfs (one level query)": size(
                "UNWIND $ids AS i MATCH (n:Datum {id: i}) WITH n\n"
                "MATCH (n)-[r:DERIVED_FROM]->(m:Datum) WHERE <edge_ok> AND <node_ok>\n"
                "RETURN DISTINCT n.id, m.id, r.op, r.attribution, <hit>, <tail>"),
            "falkordb_bfs (Python driver: traversal.search)": size(
                inspect.getsource(T.search))}


def render(r: Dict) -> str:
    m = r["machine"]
    L = [f"# SQL vs FalkorDB: practical comparison (generated {m['date_utc']})", "",
         f"{m['backend']} vs SQLite {m['sqlite']} (in-process), Python {m['python']}, "
         f"{m['cpu']} ×{m['cpus']}; per-query cap {CAP_S:.0f} s.", "",
         "## Cycle handling", "",
         "| start | truth | FalkorDB BFS | SQLite reach (UNION) | SQLite path-string CTE |",
         "|---|---|---|---|---|"]
    for s, x in r["cycles"].items():
        b, u, p = x["falkordb_bfs"], x["sqlite_reach_union"], x["sqlite_pathstring"]
        L.append(f"| {s} | {x['truth']} | {b['found']} ({b['ms']} ms) | {u['found']} "
                 f"({u['status']}, {u['ms']} ms) | {p['found']} ({p['status']}, {p['ms']} ms) |")
    L += ["", "## Explanation path on dense multi-turn sessions (≈2^t paths)", "",
          "| turns | edges | FalkorDB BFS | FalkorDB *1..N pattern | SQLite levels CTE | "
          "SQLite path-string CTE |", "|---|---|---|---|---|---|"]
    for d in r["dense"]:
        def cell(k: str, d: Dict = d) -> str:
            x = d[k]
            return f"{x['ms']} ms" + ("" if x["status"] == "ok" else f" **{x['status']}**")
        L.append(f"| {d['turns']} | {d['edges']} | {cell('falkordb_bfs')} | "
                 f"{cell('falkordb_varlength')} | {cell('sqlite_levels')} | "
                 f"{cell('sqlite_pathstring')} |")
    L += ["", "## Query size", "", "| query | lines | characters |", "|---|---|---|"]
    for k, v in r["complexity"].items():
        L.append(f"| {k} | {v['lines']} | {v['chars']} |")
    return "\n".join(L) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host")
    ap.add_argument("--port", type=int, default=6379)
    ap.add_argument("--out", default=str(RESULTS))
    a = ap.parse_args(argv)
    db, backend = connect(a.host, a.port)
    r = {"command": "python -m bench.run_sql_compare " + " ".join(argv or []),
         "machine": machine_info(backend), "cap_s": CAP_S, "cycles": cycle_check(db),
         "dense": [dense(db, t) for t in TURNS], "complexity": complexity()}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "sql_compare.json").write_text(json.dumps(r, indent=1))
    (out / "sql_compare.md").write_text(render(r))
    print(render(r))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
