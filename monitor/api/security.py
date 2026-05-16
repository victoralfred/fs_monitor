"""Security-status endpoints (currently just paranoid-mode health)."""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends

from ..state import AppState, get_state
from ..types import ParanoidResponse

router = APIRouter()

_STALE_THRESHOLD_S = 30.0


@router.get("/api/security/paranoid", response_model=ParanoidResponse)
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
            or (stale_secs is not None and stale_secs < _STALE_THRESHOLD_S)
        ),
    )
