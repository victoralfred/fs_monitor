"""Process inspection endpoints (list, detail, env, history)."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException

from ..collector import collect, collect_env
from ..state import AppState, get_state
from ..types import (
    EnvResponse,
    HistoryResponse,
    ProcessDetail,
    ProcessListResponse,
)

router = APIRouter()


@router.get("/api/processes", response_model=ProcessListResponse)
async def processes(state: AppState = Depends(get_state)) -> ProcessListResponse:
    scanner = state.scanner
    assert scanner is not None
    return ProcessListResponse(procs=scanner.public_snapshot())


@router.get("/api/processes/{pid}", response_model=ProcessDetail)
async def process_detail(pid: int, state: AppState = Depends(get_state)):
    data = await asyncio.to_thread(collect, pid, state.security_cfg)
    if data is None:
        raise HTTPException(status_code=404, detail={"error": "not_found", "pid": pid})
    scanner = state.scanner
    assert scanner is not None
    data["flag_detail"] = scanner.flag_detail(pid)
    return data


@router.get("/api/processes/{pid}/env", response_model=EnvResponse)
async def process_env(
    pid: int, show_env: int = 0, state: AppState = Depends(get_state),
) -> EnvResponse:
    data = await asyncio.to_thread(collect_env, pid, bool(show_env))
    if data is None:
        raise HTTPException(status_code=404, detail={"error": "not_found", "pid": pid})
    return EnvResponse(count=data["count"], env=data["env"])


@router.get("/api/processes/{pid}/history", response_model=HistoryResponse)
async def process_history(
    pid: int, state: AppState = Depends(get_state),
) -> HistoryResponse:
    samples = state.history.get(pid)
    return HistoryResponse(
        samples=[{"at": s.at, "cpu": s.cpu, "rss": s.rss} for s in samples],
    )
