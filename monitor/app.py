"""FastAPI application factory.

Intentionally thin: builds the AppState, configures lifespan, wires
middleware, includes the route packages from `monitor.api`, mounts the
static SPA bundle. Routes, request validation, business logic, and
syscalls all live in their own modules.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .api import (
    health_router,
    network_router,
    processes_router,
    security_router,
    signal_router,
    timeline_router,
)
from .api.signal import kill_rejected_handler
from .api.ws import router as ws_router
from .collector import set_redact_patterns
from .ebpf import EbpfTracer
from .enrichment import Enricher
from .fswatch import FsAggregator
from .history import History
from .middleware import DEFAULT_RULES, RateLimitMiddleware, SecurityHeadersMiddleware
from .netwatch import ConnectionLog
from .scanner import Scanner
from .security import SecurityConfig, config_from_toml
from .signaling import KillRejected
from .state import AppState

log = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).parent / "static"


def _build_state(
    *,
    scan_interval: float,
    redact_patterns: list[str] | None,
    security_table: dict | None,
    allow_kill: bool,
    kill_acl: str,
) -> AppState:
    """Construct the AppState. Dependency order is visible in one place:
    Enricher → ConnectionLog (gets the enricher) → AppState → Scanner
    and EbpfTracer (both reference state).
    """
    if redact_patterns:
        set_redact_patterns(redact_patterns)
    security_cfg = (
        config_from_toml(security_table) if security_table is not None else SecurityConfig()
    )
    enricher = Enricher()
    connections = ConnectionLog(enricher=enricher)
    state = AppState(
        security_cfg=security_cfg,
        history=History(),
        connections=connections,
        fs=FsAggregator(),
        enricher=enricher,
        allow_kill=allow_kill,
        kill_acl=kill_acl,
    )
    state.scanner = Scanner(state, interval=scan_interval)
    state.tracer = EbpfTracer(state)
    return state


def create_app(
    scan_interval: float = 2.0,
    redact_patterns: list[str] | None = None,
    security_table: dict | None = None,
    allow_kill: bool = False,
    kill_acl: str = "same_user",
    ebpf_enabled: bool = False,
) -> FastAPI:
    state = _build_state(
        scan_interval=scan_interval,
        redact_patterns=redact_patterns,
        security_table=security_table,
        allow_kill=allow_kill,
        kill_acl=kill_acl,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        assert state.scanner is not None
        await state.scanner.start()
        if ebpf_enabled and state.tracer is not None:
            await state.tracer.start()
        try:
            yield
        finally:
            try:
                state.scanner.broadcast_raw({"type": "shutdown"})
                await asyncio.sleep(0.1)
            except Exception:
                pass
            if state.tracer is not None:
                await state.tracer.stop()
            await state.scanner.stop()

    app = FastAPI(title="monitor", lifespan=lifespan)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware, rules=DEFAULT_RULES)
    app.state.monitor = state

    # Routes. Order doesn't matter for correctness — FastAPI looks up
    # by path — but grouping by concern keeps the include section
    # readable.
    app.include_router(health_router)
    app.include_router(processes_router)
    app.include_router(security_router)
    app.include_router(network_router)
    app.include_router(timeline_router)
    app.include_router(signal_router)
    app.include_router(ws_router)

    # Typed exceptions raised from signaling become structured 4xx replies.
    app.add_exception_handler(KillRejected, kill_rejected_handler)

    # SPA mount goes LAST so /api/* and /ws win the routing race.
    if STATIC_DIR.is_dir():
        app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
    else:

        @app.get("/")
        async def _no_frontend() -> JSONResponse:
            return JSONResponse(
                {"error": "frontend_not_built",
                 "hint": "cd web && pnpm install && pnpm build"},
                status_code=503,
            )

    return app
