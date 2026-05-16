"""FastAPI application: REST + WebSocket + static frontend.

This module is intentionally thin. Long-lived state lives on `AppState`
(see `monitor.state`); routes receive it via `Depends(get_state)`. Wire
formats are Pydantic models from `monitor.types`. The factory wires
middleware, mounts the static bundle, and that's it.
"""

from __future__ import annotations

import asyncio
import json as _json
import logging
import os
import secrets
import signal as signal_mod
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from .collector import collect, collect_env, set_redact_patterns
from .ebpf import EbpfTracer
from .enrichment import Enricher
from .fswatch import FsAggregator
from .history import History
from .metrics import (
    EXTERNAL_CONNECTIONS,
    FLAGS_FIRING,
    KILLS_SENT,
    PARANOID_HIDDEN,
    PROCS_TRACKED,
    SCAN_TIMEOUTS,
    WS_SUBSCRIBERS,
)
from .middleware import DEFAULT_RULES, RateLimitMiddleware, SecurityHeadersMiddleware
from .netwatch import ConnectionLog
from .scanner import Scanner
from .security import SecurityConfig, config_from_toml
from .state import AppState, get_state
from .types import (
    ConnectionsResponse,
    CsrfResponse,
    EnvResponse,
    HealthResponse,
    HistoryResponse,
    ParanoidResponse,
    ProcessDetail,
    ProcessListResponse,
    SignalRequest,
    SignalResponse,
    TimelineResponse,
)

log = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).parent / "static"

_ALLOWED_SIGNALS = {
    "SIGTERM": signal_mod.SIGTERM,
    "SIGINT": signal_mod.SIGINT,
    "SIGHUP": signal_mod.SIGHUP,
    "SIGKILL": signal_mod.SIGKILL,
    "SIGSTOP": signal_mod.SIGSTOP,
    "SIGCONT": signal_mod.SIGCONT,
}


def _proc_start_time(pid: int) -> float | None:
    """Read /proc/<pid>/stat field 22. Stable per-process identifier the
    kill endpoint uses to detect pid recycling.
    """
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            data = f.read()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None
    rparen = data.rfind(b")")
    if rparen < 0:
        return None
    rest = data[rparen + 2 :].split()
    if len(rest) < 20:
        return None
    try:
        return float(rest[19])
    except ValueError:
        return None


def _build_state(
    *,
    scan_interval: float,
    redact_patterns: list[str] | None,
    security_table: dict | None,
    allow_kill: bool,
    kill_acl: str,
) -> AppState:
    """Construct the AppState before lifespan starts. Collaborators that
    depend on each other (Scanner needs ConnectionLog; ConnectionLog
    wants Enricher) get wired here so the dependency direction is
    visible in one place.
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

    # ─── routes ────────────────────────────────────────────────────────

    @app.get("/api/csrf", response_model=CsrfResponse)
    async def csrf_token(state: AppState = Depends(get_state)) -> CsrfResponse:
        return CsrfResponse(csrf=state.csrf_token)

    @app.get("/api/health", response_model=HealthResponse)
    async def health(state: AppState = Depends(get_state)) -> HealthResponse:
        assert state.scanner is not None
        return HealthResponse(ok=True, scanner_lag_ms=round(state.scanner.last_scan_ms, 1))

    @app.get("/metrics")
    async def metrics(state: AppState = Depends(get_state)) -> Response:
        scanner = state.scanner
        assert scanner is not None
        PROCS_TRACKED.set(len(scanner.snapshot))
        WS_SUBSCRIBERS.set(len(scanner._subscribers))
        PARANOID_HIDDEN.set(len(scanner.hidden_pids))
        EXTERNAL_CONNECTIONS.set(state.connections.count_external())
        SCAN_TIMEOUTS._value.set(scanner.scan_timeout_count)
        flag_counts: dict[str, int] = {}
        for row in scanner.snapshot.values():
            for fid in row.get("flags", []):
                flag_counts[fid] = flag_counts.get(fid, 0) + 1
        for fid in (
            "exe_suspicious_path", "exe_deleted", "exe_memfd",
            "kthread_impersonation", "argv_exe_mismatch", "dangerous_env",
            "external_egress_from_suspicious",
            "fs_write_burst", "fs_mass_delete",
        ):
            FLAGS_FIRING.labels(flag=fid).set(flag_counts.get(fid, 0))
        return PlainTextResponse(
            generate_latest().decode("utf-8"), media_type=CONTENT_TYPE_LATEST,
        )

    @app.get("/api/security/paranoid", response_model=ParanoidResponse)
    async def paranoid_status(state: AppState = Depends(get_state)) -> ParanoidResponse:
        scanner = state.scanner
        assert scanner is not None
        last = scanner.last_paranoid_at
        stale_secs = (time.time() - last) if last > 0 else None
        return ParanoidResponse(
            enabled=state.security_cfg.paranoid,
            hidden_pids=list(scanner.hidden_pids),
            last_scan_at=last,
            stale_seconds=round(stale_secs, 1) if stale_secs is not None else None,
            error_count=scanner.paranoid_error_count,
            healthy=(
                not state.security_cfg.paranoid
                or (stale_secs is not None and stale_secs < 30.0)
            ),
        )

    @app.get("/api/processes/{pid}/history", response_model=HistoryResponse)
    async def process_history(
        pid: int, state: AppState = Depends(get_state),
    ) -> HistoryResponse:
        samples = state.history.get(pid)
        return HistoryResponse(
            samples=[{"at": s.at, "cpu": s.cpu, "rss": s.rss} for s in samples],
        )

    @app.get("/api/connections", response_model=ConnectionsResponse)
    async def connections(
        external_only: int = 1, state: AppState = Depends(get_state),
    ) -> ConnectionsResponse:
        scanner = state.scanner
        assert scanner is not None
        return ConnectionsResponse(
            connections=state.connections.items(external_only=bool(external_only)),
            last_scan_at=scanner.last_netwatch_at,
            error_count=scanner.netwatch_error_count,
        )

    @app.get("/api/timeline", response_model=TimelineResponse)
    async def timeline(
        since: float | None = None, state: AppState = Depends(get_state),
    ) -> TimelineResponse:
        return TimelineResponse(
            events=[
                {
                    "at": e.at, "pid": e.pid, "ppid": e.ppid,
                    "name": e.name, "exe": e.exe, "cmd": e.cmd,
                    "source": e.source,
                }
                for e in state.history.timeline(since)
            ],
            ebpf_running=state.tracer.running if state.tracer else False,
        )

    @app.post("/api/processes/{pid}/signal", response_model=SignalResponse)
    async def send_signal(
        pid: int, body: SignalRequest, state: AppState = Depends(get_state),
    ):
        # Phase 14 will extract this validator into a typed function. For
        # now keep it inline — same behavior as pre-refactor.
        if not state.allow_kill:
            raise HTTPException(
                status_code=403,
                detail={"error": "kill_disabled",
                        "hint": "set [security].allow_kill = true"},
            )
        if not secrets.compare_digest(body.csrf or "", state.csrf_token):
            raise HTTPException(status_code=403, detail={"error": "bad_csrf"})
        if body.signal not in _ALLOWED_SIGNALS:
            raise HTTPException(
                status_code=400,
                detail={"error": "bad_signal", "allowed": list(_ALLOWED_SIGNALS.keys())},
            )
        scanner = state.scanner
        assert scanner is not None
        row = scanner.snapshot.get(pid)
        if row is None:
            raise HTTPException(status_code=404, detail={"error": "not_found"})
        live_start = _proc_start_time(pid)
        if live_start is None:
            raise HTTPException(status_code=404, detail={"error": "not_found"})
        if (
            body.expected_start is not None
            and abs(body.expected_start - row["started"]) > 0.5
        ):
            raise HTTPException(
                status_code=409,
                detail={"error": "pid_recycled", "snapshot_start": row["started"]},
            )
        acl = state.kill_acl
        if acl == "none":
            raise HTTPException(status_code=403, detail={"error": "acl_blocked"})
        if acl == "same_user":
            try:
                target_uid = os.stat(f"/proc/{pid}").st_uid
            except (FileNotFoundError, PermissionError):
                raise HTTPException(status_code=404, detail={"error": "not_found"}) from None
            if target_uid != os.getuid():
                raise HTTPException(
                    status_code=403,
                    detail={"error": "acl_blocked",
                            "reason": "different user",
                            "target_uid": target_uid,
                            "our_uid": os.getuid()},
                )
        sig = _ALLOWED_SIGNALS[body.signal]
        recheck = _proc_start_time(pid)
        if recheck is None or abs(recheck - live_start) > 0.5:
            raise HTTPException(status_code=409, detail={"error": "pid_recycled"})
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            raise HTTPException(status_code=404, detail={"error": "not_found"}) from None
        except PermissionError as e:
            raise HTTPException(
                status_code=403,
                detail={"error": "permission_denied", "msg": str(e)},
            ) from None
        KILLS_SENT.labels(signal=body.signal).inc()
        return SignalResponse(ok=True, pid=pid, signal=body.signal, sent_at=time.time())

    @app.get("/api/processes", response_model=ProcessListResponse)
    async def processes(state: AppState = Depends(get_state)) -> ProcessListResponse:
        scanner = state.scanner
        assert scanner is not None
        return ProcessListResponse(procs=scanner.public_snapshot())

    @app.get("/api/processes/{pid}", response_model=ProcessDetail)
    async def process_detail(pid: int, state: AppState = Depends(get_state)):
        data = await asyncio.to_thread(collect, pid, state.security_cfg)
        if data is None:
            raise HTTPException(status_code=404, detail={"error": "not_found", "pid": pid})
        scanner = state.scanner
        assert scanner is not None
        data["flag_detail"] = scanner.flag_detail(pid)
        return data

    @app.get("/api/processes/{pid}/env", response_model=EnvResponse)
    async def process_env(
        pid: int, show_env: int = 0, state: AppState = Depends(get_state),
    ) -> EnvResponse:
        data = await asyncio.to_thread(collect_env, pid, bool(show_env))
        if data is None:
            raise HTTPException(status_code=404, detail={"error": "not_found", "pid": pid})
        return EnvResponse(count=data["count"], env=data["env"])

    @app.websocket("/ws")
    async def ws(websocket: WebSocket) -> None:
        # Cross-origin browser connections are refused. CLI clients that don't
        # send Origin are allowed through.
        origin = websocket.headers.get("origin")
        if origin:
            host_hdr = websocket.headers.get("host", "")
            try:
                origin_host = urlparse(origin).netloc
            except ValueError:
                origin_host = ""
            if origin_host and origin_host != host_hdr:
                await websocket.close(code=1008)
                return
        await websocket.accept()
        scanner = state.scanner
        assert scanner is not None
        q = scanner.subscribe()
        try:
            await websocket.send_text(
                _json.dumps(
                    {"type": "snapshot", "procs": scanner.public_snapshot()},
                    separators=(",", ":"),
                ),
            )
            while True:
                payload = await q.get()
                await websocket.send_text(payload)
        except WebSocketDisconnect:
            pass
        except Exception:
            log.exception("ws send failed")
        finally:
            scanner.unsubscribe(q)

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
