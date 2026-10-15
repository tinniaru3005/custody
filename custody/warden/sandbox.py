"""Isolated graph sandboxes for Warden what-if analysis.

Preferred: ``GRAPH.COPY <live> <clone>`` (FalkorDB ≥ 4.2; exposed by falkordb-py as
``Graph.copy``). The analysis runs on the clone, which is deleted afterwards, so it can
even write (e.g. label nodes for ``algo.WCC``) without touching the live tenant graph.

Fallback, if GRAPH.COPY is unavailable or fails: a ``ReadOnlyGraph`` proxy over the live
graph that sends every query through ``GRAPH.RO_QUERY``. The server rejects any write
issued that way, so the live graph still cannot change; analyses that need writes (the
WCC labelling) switch to their pure-read fallback.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Optional

from falkordb import Graph

log = logging.getLogger(__name__)

MODE_COPY = "graph_copy"
MODE_READ_ONLY = "read_only_live"


class ReadOnlyGraph:
    """Proxy that routes ``query`` to ``ro_query``: writes fail on the server."""

    read_only = True

    def __init__(self, graph: Graph) -> None:
        self._graph = graph
        self.name = graph.name

    def query(self, q: str, params: Optional[Dict[str, Any]] = None, **kw: Any):
        return self._graph.ro_query(q, params or {}, **kw)

    def ro_query(self, q: str, params: Optional[Dict[str, Any]] = None, **kw: Any):
        return self._graph.ro_query(q, params or {}, **kw)

    def __getattr__(self, item: str) -> Any:
        if item in {"delete", "copy", "create_node_range_index"} or item.startswith(("create_", "drop_")):
            raise PermissionError(f"{item} is not allowed on a read-only sandbox")
        return getattr(self._graph, item)


class GraphSandbox:
    """``with GraphSandbox(db, live_graph) as sb: sb.graph ...``

    ``sb.mode`` is ``graph_copy`` or ``read_only_live``; ``sb.info()`` documents it.
    """

    def __init__(self, db: Any, live: Graph, *, prefer_copy: bool = True) -> None:
        self.db = db
        self.live = live
        self.prefer_copy = prefer_copy
        self.graph: Any = None
        self.mode: str = MODE_READ_ONLY
        self.clone_name: Optional[str] = None
        self.copy_error: Optional[str] = None
        self.deleted: Optional[bool] = None

    def __enter__(self) -> "GraphSandbox":
        if self.prefer_copy:
            name = f"{self.live.name}::sandbox::{uuid.uuid4().hex[:12]}"
            try:
                self.graph = self.live.copy(name)       # GRAPH.COPY live clone
                self.clone_name = name
                self.mode = MODE_COPY
                return self
            except Exception as exc:  # unsupported server / permissions
                self.copy_error = f"{type(exc).__name__}: {exc}"
                log.warning("GRAPH.COPY failed, using read-only sandbox: %s", exc)
        self.graph = ReadOnlyGraph(self.live)
        self.mode = MODE_READ_ONLY
        return self

    def __exit__(self, *exc: Any) -> None:
        if self.mode == MODE_COPY and self.clone_name:
            try:
                self.graph.delete()
                self.deleted = True
            except Exception as e:  # pragma: no cover - best effort cleanup
                log.error("could not delete sandbox graph %s: %s", self.clone_name, e)
                self.deleted = False

    def info(self) -> Dict[str, Any]:
        if self.mode == MODE_COPY:
            note = (f"GRAPH.COPY {self.live.name} -> {self.clone_name}; analysis ran on the "
                    "clone, which was deleted afterwards. The live graph was never written.")
        else:
            note = ("GRAPH.COPY unavailable"
                    + (f" ({self.copy_error})" if self.copy_error else "")
                    + "; analysis ran against the live graph through GRAPH.RO_QUERY only, "
                    "so the server rejects any write.")
        return {"mode": self.mode, "sandbox_graph": self.clone_name,
                "sandbox_deleted": self.deleted, "note": note}
