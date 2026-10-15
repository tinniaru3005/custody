"""FastAPI application factory.

Run:  uvicorn custody.api.app:app --reload

Every route is also served under ``/api`` (the React UI uses ``/api/...``), and when
``CUSTODY_STATIC_DIR`` points at a built UI (``frontend/dist``) it is served at ``/`` with
an SPA fallback, so one container can host both.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from falkordb import FalkorDB

from custody import __version__
from custody.api.public_demo import PublicDemoGuard, ResetLimiter
from custody.api.routes import console, guard, recorder
from custody.config import Settings, get_settings
from custody.db import GraphProvider, InvalidTenant, connect
from custody.graph.repository import NotFound
from custody.guard.models import ApprovalRefused
from custody.memory.errors import MemoryQuarantined

API_PREFIX = "/api"
_API_ROOTS = ("/tenants", "/health", "/docs", "/openapi.json", "/redoc")


class StripApiPrefix:
    """ASGI middleware: ``/api/x`` → ``/x`` so the UI can use one origin-relative prefix."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            path = scope.get("path", "")
            if path == API_PREFIX or path.startswith(API_PREFIX + "/"):
                scope = dict(scope)
                scope["path"] = path[len(API_PREFIX):] or "/"
                scope["raw_path"] = scope["path"].encode()
        await self.app(scope, receive, send)


def create_app(db: Optional[FalkorDB] = None, settings: Optional[Settings] = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        client = db if db is not None else connect(settings)
        app.state.graph_provider = GraphProvider(client, settings.graph_prefix,
                                                 settings.max_trace_depth)
        if settings.public_demo:
            from custody.console import service as svc

            svc.ensure_public_demo(app.state.graph_provider, settings.demo_tenant)
        yield

    public = settings.public_demo
    app = FastAPI(title="Custody", version=__version__, lifespan=lifespan,
                  description="Provenance-tracked shared memory and a deterministic Guard for "
                              "teams of AI agents.",
                  **({"docs_url": None, "redoc_url": None, "openapi_url": None} if public else {}))
    app.state.settings = settings
    app.state.reset_limiter = ResetLimiter(settings.demo_reset_min_interval_s)
    if settings.cors_origin_list:
        app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origin_list,
                           allow_methods=["GET", "POST"] if public else ["*"],
                           allow_headers=["*"])
    if public:  # added before StripApiPrefix, so it sees paths without /api
        app.add_middleware(PublicDemoGuard, tenant=settings.demo_tenant)
    app.add_middleware(StripApiPrefix)

    @app.exception_handler(NotFound)
    async def _not_found(_: Request, exc: NotFound):
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(InvalidTenant)
    async def _bad_tenant(_: Request, exc: InvalidTenant):
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(ApprovalRefused)
    async def _refused(_: Request, exc: ApprovalRefused):
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(MemoryQuarantined)
    async def _quarantined(_: Request, exc: MemoryQuarantined):
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(ValueError)
    async def _bad_value(_: Request, exc: ValueError):
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.get("/health", tags=["meta"])
    def health(request: Request):
        provider: GraphProvider = request.app.state.graph_provider
        try:
            provider.db.connection.ping()
            ok = True
        except Exception:
            ok = False
        out = {"status": "ok" if ok else "degraded", "falkordb": ok, "version": __version__,
               "public_demo": settings.public_demo}
        if settings.public_demo:
            out["demo_tenant"] = settings.demo_tenant
        return out

    app.include_router(recorder.router)
    app.include_router(guard.router)
    app.include_router(console.router)

    static = Path(settings.static_dir) if settings.static_dir else None
    if static is not None and (static / "index.html").is_file():
        index = static / "index.html"

        @app.get("/{full_path:path}", include_in_schema=False)
        def spa(full_path: str):
            if full_path.startswith(tuple(r.lstrip("/") for r in _API_ROOTS)):
                return JSONResponse(status_code=404, content={"detail": "not found"})
            candidate = (static / full_path).resolve()
            if full_path and candidate.is_file() and static.resolve() in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(index)

    return app


app = create_app()
