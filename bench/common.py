"""Shared helpers: FalkorDB connection, graph export, SQLite mirror, timing, machine info."""
from __future__ import annotations

import os
import platform
import sqlite3
import statistics
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from custody.db import GraphProvider
from custody.graph.repository import GraphRepository
from custody.guard import ACME_POLICY, Guard
from custody.recorder.service import Recorder
from custody.runtime import AgentRuntime, Vault


def connect(host: Optional[str] = None, port: int = 6379):
    """A FalkorDB server (``host``) or an embedded one (falkordblite, Python 3.12+)."""
    if host:
        from falkordb import FalkorDB

        return FalkorDB(host=host, port=port), f"falkordb server {host}:{port}"
    from redislite.falkordb_client import FalkorDB as Embedded

    path = os.path.join(tempfile.mkdtemp(prefix="custody-bench-"), "bench.db")
    return Embedded(path), "embedded falkordblite"


def fresh(db, tenant: str):
    """Recorder + Guard (decisions not recorded) + runtime on an empty tenant graph."""
    provider = GraphProvider(db, prefix="custody-bench")
    provider.drop(tenant)
    rec = Recorder(GraphRepository(provider.graph(tenant)))
    guard = Guard(rec, ACME_POLICY, record_decisions=False)
    rt = AgentRuntime(rec, guard, vault=Vault({"secret/k": "sk_FAKE_bench_000"}))
    return provider, rec, guard, rt


def ms(t0: float) -> float:
    return (time.perf_counter() - t0) * 1000.0


def summary(xs: Sequence[float]) -> Dict[str, float]:
    xs = sorted(xs)
    if not xs:
        return {}
    p95 = xs[min(len(xs) - 1, int(round(0.95 * (len(xs) - 1))))]
    return {"n": len(xs), "median_ms": round(statistics.median(xs), 3),
            "p95_ms": round(p95, 3), "min_ms": round(xs[0], 3), "max_ms": round(xs[-1], 3)}


def machine_info(backend: str) -> Dict[str, Any]:
    cpu = platform.processor() or ""
    try:
        with open("/proc/cpuinfo") as f:
            cpu = next((ln.split(":", 1)[1].strip() for ln in f if ln.startswith("model name")),
                       cpu)
    except OSError:
        pass
    try:
        from importlib.metadata import version

        lite = version("falkordblite")
    except Exception:  # noqa: BLE001
        lite = None
    return {"date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "python": platform.python_version(), "platform": platform.platform(),
            "cpu": cpu, "cpus": os.cpu_count(), "backend": backend,
            "falkordblite": lite, "sqlite": sqlite3.sqlite_version}


# ------------------------------------------------------------------------ graph export
@dataclass
class Doc:
    id: str
    text: str
    session_id: Optional[str]
    kind: str
    source_id: Optional[str]
    source_trust: Optional[str]
    created_at: str = ""


@dataclass
class Export:
    docs: Dict[str, Doc]
    nodes: List[Tuple[str, bool, bool, str, bool]]   # id, endorsed, quarantined, max_risk, untrusted
    edges: List[Tuple[str, str, str]]                # src, dst, attribution
    args: List[Tuple[str, str, str]]                 # action id, role, datum id


def export_graph(rec: Recorder) -> Export:
    """Plain records of what the Recorder stored: what the baselines get to see."""
    q = rec.repo.graph.ro_query
    docs: Dict[str, Doc] = {}
    nodes = []
    for did, value, preview, sid, kind, end, quar, risk, src, trust, created in q(
            "MATCH (d:Datum) OPTIONAL MATCH (d)-[:FROM]->(s:Source) "
            "RETURN d.id, d.value, d.preview, d.session_id, d.kind, coalesce(d.endorsed, false), "
            "coalesce(d.quarantined, false), coalesce(d.max_risk, 'low'), s.id, s.trust, "
            "d.created_at ORDER BY d.created_at"
    ).result_set:
        docs[did] = Doc(did, value if value is not None else (preview or ""), sid, kind, src, trust,
                        created or "")
        nodes.append((did, bool(end), bool(quar), risk, trust == "untrusted"))
    edges = [tuple(r) for r in q("MATCH (a:Datum)-[r:DERIVED_FROM]->(b:Datum) "
                                 "RETURN a.id, b.id, coalesce(r.attribution, 'inherit')").result_set]
    args = [tuple(r) for r in q("MATCH (a:Action)-[r:ARG]->(d:Datum) "
                                "RETURN a.id, r.role, d.id").result_set]
    return Export(docs, nodes, edges, args)


# ------------------------------------------------------------- relational baseline (SQL)
class SqlMirror:
    """The same provenance in SQLite tables, queried with a recursive CTE."""

    CTE = """
    WITH RECURSIVE reach(id) AS (
        SELECT n.id FROM args a JOIN nodes n ON n.id = a.datum_id
         WHERE a.action_id = :aid AND a.role = 'destination' AND n.blocked_high = 0
        UNION
        SELECT e.dst FROM reach r
          JOIN edges e ON e.src = r.id
          JOIN nodes n ON n.id = e.dst
         WHERE e.attribution <> 'context' AND n.blocked_high = 0
    )
    SELECT EXISTS (SELECT 1 FROM reach r JOIN nodes n ON n.id = r.id
                    WHERE n.untrusted_origin = 1),
           (SELECT count(*) FROM reach)
    """

    def __init__(self, ex: Export, path: str = ":memory:") -> None:
        self.db = sqlite3.connect(path)
        c = self.db
        c.executescript("""
            CREATE TABLE nodes (id TEXT PRIMARY KEY, blocked_high INTEGER, untrusted_origin INTEGER);
            CREATE TABLE edges (src TEXT, dst TEXT, attribution TEXT);
            CREATE TABLE args (action_id TEXT, role TEXT, datum_id TEXT);
            CREATE INDEX edges_src ON edges(src);
            CREATE INDEX args_action ON args(action_id);
        """)
        # blocked for a high-risk action: endorsed, or typed with max_risk 'high'
        c.executemany("INSERT INTO nodes VALUES (?, ?, ?)",
                      [(i, int(end or (quar and risk == "high")), int(untr))
                       for i, end, quar, risk, untr in ex.nodes])
        c.executemany("INSERT INTO edges VALUES (?, ?, ?)", ex.edges)
        c.executemany("INSERT INTO args VALUES (?, ?, ?)", ex.args)
        c.commit()

    def untrusted_destination(self, action_id: str) -> Tuple[bool, int]:
        found, visited = self.db.execute(self.CTE, {"aid": action_id}).fetchone()
        return bool(found), int(visited)
