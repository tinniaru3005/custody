"""FalkorDB connection management and tenant -> graph mapping.

Every tenant gets its own graph, named ``<prefix>:<tenant>`` (e.g. ``custody:acme``),
so provenance never leaks across tenants and a tenant can be dropped atomically.
"""
from __future__ import annotations

import re
import threading
from typing import Optional

from falkordb import FalkorDB, Graph

from custody.config import Settings, get_settings

TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


class InvalidTenant(ValueError):
    pass


def validate_tenant(tenant: str) -> str:
    if not isinstance(tenant, str) or not TENANT_RE.match(tenant):
        raise InvalidTenant(
            f"invalid tenant {tenant!r}: use 1-63 chars of lowercase letters, digits, '-' or '_'"
        )
    return tenant


def graph_name(tenant: str, prefix: str = "custody") -> str:
    return f"{prefix}:{validate_tenant(tenant)}"


def connect(settings: Optional[Settings] = None) -> FalkorDB:
    """Create a FalkorDB client from settings (server or embedded)."""
    s = settings or get_settings()
    if s.falkordb_embedded_path:
        try:
            from redislite.falkordb_client import FalkorDB as EmbeddedFalkorDB
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise RuntimeError(
                "CUSTODY_FALKORDB_EMBEDDED_PATH is set but falkordblite is not installed"
            ) from exc
        return EmbeddedFalkorDB(s.falkordb_embedded_path)
    if s.falkordb_url:
        return FalkorDB.from_url(s.falkordb_url)
    # FalkorDB Cloud: host/port/username/password from the instance page, ssl if TLS is on
    return FalkorDB(host=s.falkordb_host, port=s.falkordb_port, username=s.falkordb_username,
                    password=s.falkordb_password, ssl=s.falkordb_ssl)


class GraphProvider:
    """Hands out per-tenant graphs, ensuring the schema exists once per graph."""

    def __init__(self, db: FalkorDB, prefix: str = "custody", max_trace_depth: int = 25) -> None:
        self.db = db
        self.prefix = prefix
        self.max_trace_depth = max_trace_depth
        self._initialised: set[str] = set()
        self._lock = threading.Lock()

    def graph(self, tenant: str) -> Graph:
        from custody.graph.schema import ensure_schema

        name = graph_name(tenant, self.prefix)
        g = self.db.select_graph(name)
        if name not in self._initialised:
            with self._lock:
                if name not in self._initialised:
                    ensure_schema(g)
                    self._initialised.add(name)
        return g

    def drop(self, tenant: str) -> None:
        name = graph_name(tenant, self.prefix)
        try:
            self.db.select_graph(name).delete()
        except Exception:  # graph may not exist yet
            pass
        self._initialised.discard(name)
