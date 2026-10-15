"""Runtime configuration (env vars prefixed with CUSTODY_)."""
from __future__ import annotations

from functools import lru_cache
from typing import List, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CUSTODY_", env_file=".env", extra="ignore")

    # --- FalkorDB: local server, FalkorDB Cloud, or embedded -------------------------
    falkordb_host: str = "localhost"
    falkordb_port: int = 6379
    falkordb_username: Optional[str] = None   # FalkorDB Cloud: the instance user
    falkordb_password: Optional[str] = None
    falkordb_ssl: bool = False                # FalkorDB Cloud with TLS enabled
    # Full URL wins over host/port: redis://user:pass@host:port or rediss://… (TLS)
    falkordb_url: Optional[str] = None
    # When set, an embedded FalkorDB (falkordblite) is started using this file.
    falkordb_embedded_path: Optional[str] = None

    graph_prefix: str = "custody"
    max_trace_depth: int = 25

    # --- HTTP -------------------------------------------------------------------------
    # Comma-separated origins allowed by CORS (only needed when the UI is served elsewhere)
    cors_origins: str = ""
    # Directory with the built React UI (frontend/dist); served at / when set
    static_dir: Optional[str] = None

    # --- Public demo mode (see custody/api/public_demo.py) ------------------------------
    # One read-only synthetic tenant + a deterministic "Reset Demo"; no auth system.
    public_demo: bool = False
    demo_tenant: str = "acme"
    demo_reset_min_interval_s: float = 10.0

    @property
    def cors_origin_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
