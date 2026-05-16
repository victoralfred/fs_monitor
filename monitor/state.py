"""Central application state.

One `AppState` dataclass owns every long-lived collaborator (security
config, history buffers, connection log, fs aggregator, IP enricher,
the scanner itself). It's constructed once in `create_app` and reached
from routes via FastAPI's `Depends(get_state)`.

Why this exists: before Phase 11, each of these lived as a module-level
mutable singleton (`monitor.scanner.SECURITY_CFG`,
`monitor.history.HISTORY`, etc.). Modules imported each other's
singletons via late `from .X import Y` calls to break cycles, making
the dependency graph hard to read and the codebase hard to test. With
`AppState`, ownership is explicit, tests can construct a fresh state
per case, and adding a new collaborator means adding a field here
rather than introducing a new global.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from fastapi import Request

from .enrichment import Enricher
from .fswatch import FsAggregator
from .history import History
from .netwatch import ConnectionLog
from .security import SecurityConfig

if TYPE_CHECKING:
    from .ebpf import EbpfTracer
    from .scanner import Scanner


@dataclass
class AppState:
    """Owned by exactly one `create_app` call. All long-lived state lives here."""

    security_cfg: SecurityConfig = field(default_factory=SecurityConfig)
    history: History = field(default_factory=History)
    connections: ConnectionLog = field(default_factory=ConnectionLog)
    fs: FsAggregator = field(default_factory=FsAggregator)
    enricher: Enricher = field(default_factory=Enricher)

    # Kill-endpoint policy. Populated from config at startup.
    allow_kill: bool = False
    kill_acl: str = "same_user"

    # CSRF token issued once at startup; constant-time compared on POSTs.
    csrf_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))

    # Constructed after the rest of state exists (they reference state).
    scanner: Scanner | None = None
    tracer: EbpfTracer | None = None


def get_state(request: Request) -> AppState:
    """FastAPI dependency. Routes declare `state: AppState = Depends(get_state)`."""
    return request.app.state.monitor
