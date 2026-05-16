"""Exec-event timeline endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ..state import AppState, get_state
from ..types import TimelineResponse

router = APIRouter()


@router.get("/api/timeline", response_model=TimelineResponse)
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
