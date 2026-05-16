"""FastAPI application: REST + WebSocket + static frontend."""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
import signal as signal_mod
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel

from . import scanner as scanner_mod
from .collector import collect, collect_env, set_redact_patterns
from .ebpf import EbpfTracer
from .history import HISTORY
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
from .netwatch import CONNECTIONS
from .scanner import Scanner
from .security import config_from_toml

_ALLOWED_SIGNALS = {
    "SIGTERM": signal_mod.SIGTERM,
    "SIGINT": signal_mod.SIGINT,
    "SIGHUP": signal_mod.SIGHUP,
    "SIGKILL": signal_mod.SIGKILL,
    "SIGSTOP": signal_mod.SIGSTOP,
    "SIGCONT": signal_mod.SIGCONT,
}


class SignalBody(BaseModel):
    signal: str = "SIGTERM"
    csrf: str = ""
    # Caller asserts which start_time they expect to signal. Prevents
    # pid-recycling races (S5): if the snapshot start_time has changed
    # since the UI rendered, we refuse the signal.
    expected_start: float | None = None


def _proc_start_time(pid: int) -> float | None:
    """Read /proc/<pid>/stat field 22 (starttime, clock ticks since boot).
    Combined with btime + clock_ticks this matches psutil.create_time. For
    our purposes we just need a stable per-process identifier.
    """
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            data = f.read()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None
    # comm field is parenthesized and may contain spaces; strip from the right.
    rparen = data.rfind(b")")
    if rparen < 0:
        return None
    rest = data[rparen + 2:].split()
    if len(rest) < 20:
        return None
    try:
        return float(rest[19])  # field 22 = index 19 in the post-comm split
    except ValueError:
        return None

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"


def create_app(
    scan_interval: float = 2.0,
    redact_patterns: list[str] | None = None,
    security_table: dict | None = None,
    allow_kill: bool = False,
    kill_acl: str = "same_user",
    ebpf_enabled: bool = False,
) -> FastAPI:
    if redact_patterns:
        set_redact_patterns(redact_patterns)
    if security_table is not None:
        scanner_mod.SECURITY_CFG = config_from_toml(security_table)
    scanner = Scanner(interval=scan_interval)
    tracer = EbpfTracer()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await scanner.start()
        if ebpf_enabled:
            await tracer.start()
        try:
            yield
        finally:
            # R3: signal connected ws clients before tearing down.
            try:
                scanner.broadcast_raw({"type": "shutdown"})
                await asyncio.sleep(0.1)
            except Exception:
                pass
            await tracer.stop()
            await scanner.stop()

    app = FastAPI(title="monitor", lifespan=lifespan)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware, rules=DEFAULT_RULES)
    app.state.scanner = scanner
    app.state.tracer = tracer
    app.state.allow_kill = allow_kill
    app.state.kill_acl = kill_acl
    # CSRF token re-rolled on each create_app (= each server start). UI
    # fetches it once at page load and includes it on POSTs.
    app.state.csrf_token = secrets.token_urlsafe(32)

    @app.get("/api/csrf")
    async def csrf_token() -> dict:
        return {"csrf": app.state.csrf_token}

    @app.get("/api/health")
    async def health() -> dict:
        return {"ok": True, "scanner_lag_ms": round(scanner.last_scan_ms, 1)}

    @app.get("/metrics")
    async def metrics() -> Response:
        # Refresh point-in-time gauges before serializing.
        PROCS_TRACKED.set(len(scanner.snapshot))
        WS_SUBSCRIBERS.set(len(scanner._subscribers))
        PARANOID_HIDDEN.set(len(scanner.hidden_pids))
        EXTERNAL_CONNECTIONS.set(CONNECTIONS.count_external())
        SCAN_TIMEOUTS._value.set(scanner.scan_timeout_count)
        # Flag tally: count occurrences across the current snapshot.
        flag_counts: dict[str, int] = {}
        for row in scanner.snapshot.values():
            for fid in row.get("flags", []):
                flag_counts[fid] = flag_counts.get(fid, 0) + 1
        # Reset known labels to 0 first so absence is reflected.
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

    @app.get("/api/security/paranoid")
    async def paranoid_status() -> dict:
        last = scanner.last_paranoid_at
        stale_secs = (time.time() - last) if last > 0 else None
        return {
            "enabled": scanner_mod.SECURITY_CFG.paranoid,
            "hidden_pids": list(scanner.hidden_pids),
            "last_scan_at": last,
            "stale_seconds": round(stale_secs, 1) if stale_secs is not None else None,
            "error_count": scanner.paranoid_error_count,
            # Healthy: scan ran recently OR mode is disabled.
            "healthy": (
                not scanner_mod.SECURITY_CFG.paranoid
                or (stale_secs is not None and stale_secs < 30.0)
            ),
        }

    @app.get("/api/processes/{pid}/history")
    async def process_history(pid: int) -> dict:
        samples = HISTORY.get(pid)
        return {
            "samples": [
                {"at": s.at, "cpu": s.cpu, "rss": s.rss} for s in samples
            ],
        }

    @app.get("/api/connections")
    async def connections(external_only: int = 1) -> dict:
        return {
            "connections": CONNECTIONS.items(external_only=bool(external_only)),
            "last_scan_at": scanner.last_netwatch_at,
            "error_count": scanner.netwatch_error_count,
        }

    @app.get("/api/timeline")
    async def timeline(since: float | None = None) -> dict:
        return {
            "events": [
                {
                    "at": e.at, "pid": e.pid, "ppid": e.ppid,
                    "name": e.name, "exe": e.exe, "cmd": e.cmd,
                    "source": e.source,
                }
                for e in HISTORY.timeline(since)
            ],
            "ebpf_running": tracer.running,
        }

    @app.post("/api/processes/{pid}/signal")
    async def send_signal(pid: int, body: SignalBody):
        if not app.state.allow_kill:
            raise HTTPException(
                status_code=403,
                detail={"error": "kill_disabled",
                        "hint": "set [security].allow_kill = true"},
            )
        # S1: CSRF token compared in constant time. Browser POSTs without
        # a valid token are refused; tests can disable by leaving
        # app.state.csrf_required = False (default True).
        if not secrets.compare_digest(body.csrf or "", app.state.csrf_token):
            raise HTTPException(status_code=403, detail={"error": "bad_csrf"})
        if body.signal not in _ALLOWED_SIGNALS:
            raise HTTPException(
                status_code=400,
                detail={"error": "bad_signal",
                        "allowed": list(_ALLOWED_SIGNALS.keys())},
            )
        row = scanner.snapshot.get(pid)
        if row is None:
            raise HTTPException(status_code=404, detail={"error": "not_found"})
        # S5: pid-recycling guard. If start_time changed between the
        # snapshot and the kill call, the original target died and the pid
        # was reused — refuse.
        live_start = _proc_start_time(pid)
        if live_start is None:
            raise HTTPException(status_code=404, detail={"error": "not_found"})
        # Caller pinned a specific start; honor that.
        if (
            body.expected_start is not None
            and abs(body.expected_start - row["started"]) > 0.5
        ):
            raise HTTPException(
                status_code=409,
                detail={"error": "pid_recycled", "snapshot_start": row["started"]},
            )
        # ACL check.
        acl = app.state.kill_acl
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
        # Final pid-recycling check just before the syscall: re-read
        # start_time, compare to what we saw a moment ago. Closes the
        # smallest possible window.
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
        return {"ok": True, "pid": pid, "signal": body.signal, "sent_at": time.time()}

    @app.get("/api/processes")
    async def processes() -> dict:
        return {"procs": scanner.public_snapshot()}

    @app.get("/api/processes/{pid}")
    async def process_detail(pid: int):
        data = await asyncio.to_thread(collect, pid)
        if data is None:
            raise HTTPException(status_code=404, detail={"error": "not_found", "pid": pid})
        data["flag_detail"] = scanner.flag_detail(pid)
        return data

    @app.get("/api/processes/{pid}/env")
    async def process_env(pid: int, show_env: int = 0):
        data = await asyncio.to_thread(collect_env, pid, bool(show_env))
        if data is None:
            raise HTTPException(status_code=404, detail={"error": "not_found", "pid": pid})
        return data

    @app.websocket("/ws")
    async def ws(websocket: WebSocket) -> None:
        # Cross-origin browser connections are refused. CLI clients that don't
        # send Origin are allowed through. Same-origin is determined by
        # comparing Origin's host against the Host header the request arrived
        # on, so we don't have to know our own URL ahead of time.
        origin = websocket.headers.get("origin")
        if origin:
            host_hdr = websocket.headers.get("host", "")
            try:
                from urllib.parse import urlparse
                origin_host = urlparse(origin).netloc
            except Exception:
                origin_host = ""
            if origin_host and origin_host != host_hdr:
                await websocket.close(code=1008)
                return
        await websocket.accept()
        q = scanner.subscribe()
        try:
            # First message: snapshot. After that the queue carries
            # pre-serialized JSON strings from the scanner.
            import json as _json
            await websocket.send_text(_json.dumps(
                {"type": "snapshot", "procs": scanner.public_snapshot()},
                separators=(",", ":"),
            ))
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
                {
                    "error": "frontend_not_built",
                    "hint": "cd web && pnpm install && pnpm build",
                },
                status_code=503,
            )

    return app
