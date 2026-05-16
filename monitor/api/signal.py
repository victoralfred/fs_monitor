"""POST /api/processes/{pid}/signal.

The route is intentionally tiny — validate, deliver, return. All
guarding lives in `monitor.signaling`; all errors flow through one
exception handler registered by the app factory.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from ..metrics import KILLS_SENT
from ..signaling import KillRejected, deliver_signal, validate_kill_request
from ..state import AppState, get_state
from ..types import SignalRequest, SignalResponse

router = APIRouter()


@router.post("/api/processes/{pid}/signal", response_model=SignalResponse)
async def send_signal(
    pid: int, body: SignalRequest, state: AppState = Depends(get_state),
) -> SignalResponse:
    target = validate_kill_request(pid, body, state)
    sent_at = deliver_signal(target)
    KILLS_SENT.labels(signal=target.signal_name).inc()
    return SignalResponse(ok=True, pid=pid, signal=target.signal_name, sent_at=sent_at)


async def kill_rejected_handler(_request: Request, exc: KillRejected) -> JSONResponse:
    """Turn a KillRejected into a structured 4xx response. Registered on
    the app via `app.add_exception_handler(KillRejected, …)`.
    """
    return JSONResponse(
        {"detail": {"error": exc.reason, **exc.detail}},
        status_code=exc.status_code,
    )
