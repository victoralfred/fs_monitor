"""External-egress connection log endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ..state import AppState, get_state
from ..types import ConnectionsResponse

router = APIRouter()


@router.get("/api/connections", response_model=ConnectionsResponse)
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
