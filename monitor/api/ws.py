"""WebSocket handler. Lives on its own because it has no response_model
and needs the raw `WebSocket` object instead of `Depends(get_state)`.
"""

from __future__ import annotations

import json as _json
import logging
from urllib.parse import urlparse

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

log = logging.getLogger(__name__)
router = APIRouter()


def _origin_ok(origin: str | None, host_hdr: str) -> bool:
    """No Origin = CLI client, allowed. Origin present = require host match."""
    if not origin:
        return True
    try:
        origin_host = urlparse(origin).netloc
    except ValueError:
        return False
    return not origin_host or origin_host == host_hdr


@router.websocket("/ws")
async def ws(websocket: WebSocket) -> None:
    if not _origin_ok(
        websocket.headers.get("origin"),
        websocket.headers.get("host", ""),
    ):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    state = websocket.app.state.monitor
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
