"""Health and metrics endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from ..metrics import (
    EXTERNAL_CONNECTIONS,
    FLAGS_FIRING,
    PARANOID_HIDDEN,
    PROCS_TRACKED,
    SCAN_TIMEOUTS,
    WS_SUBSCRIBERS,
)
from ..state import AppState, get_state
from ..types import CsrfResponse, HealthResponse

router = APIRouter()

# Flag IDs we explicitly export to /metrics so absence shows as zero
# instead of "missing label." Kept in sync with the security module.
_KNOWN_FLAGS = (
    "exe_suspicious_path", "exe_deleted", "exe_memfd",
    "kthread_impersonation", "argv_exe_mismatch", "dangerous_env",
    "external_egress_from_suspicious",
    "fs_write_burst", "fs_mass_delete",
)


@router.get("/api/csrf", response_model=CsrfResponse)
async def csrf_token(state: AppState = Depends(get_state)) -> CsrfResponse:
    return CsrfResponse(csrf=state.csrf_token)


@router.get("/api/health", response_model=HealthResponse)
async def health(state: AppState = Depends(get_state)) -> HealthResponse:
    assert state.scanner is not None
    return HealthResponse(ok=True, scanner_lag_ms=round(state.scanner.last_scan_ms, 1))


@router.get("/metrics")
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
    for fid in _KNOWN_FLAGS:
        FLAGS_FIRING.labels(flag=fid).set(flag_counts.get(fid, 0))
    return PlainTextResponse(
        generate_latest().decode("utf-8"), media_type=CONTENT_TYPE_LATEST,
    )
