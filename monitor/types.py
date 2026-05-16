"""Pydantic models for the API boundary.

These are the *wire* types — what the REST endpoints return and what
the WebSocket emits. Internal scanner state stays as plain dicts
because building 1000 Pydantic models on every 2-second tick has
measurable overhead. The conversion happens at the route layer.

Splitting wire types from internal types also means that internal
field renames or additions don't automatically change the public API.
The mapping is explicit, which is the right default for anything
clients will integrate against.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class FlagDetail(BaseModel):
    """One security indicator firing on one process."""

    model_config = ConfigDict(extra="forbid")
    id: str
    severity: Literal["low", "medium", "high"]
    evidence: str


class ProcessSummary(BaseModel):
    """One row in the process tree. Returned by `GET /api/processes` and
    embedded in WebSocket snapshot/diff messages.
    """

    model_config = ConfigDict(extra="forbid")
    pid: int
    ppid: int
    name: str
    user: str
    status: str
    cpu: float
    rss: int
    started: float
    cmd: str
    flags: list[str] = Field(default_factory=list)


class FdEntryOut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fd: int
    target: str
    kind: str
    deleted: bool
    addr: str | None = None


class SocketRowOut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fd: int | None
    family: str
    type: str
    laddr: str | None
    raddr: str | None
    status: str | None


class MapEntryOut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    size: int
    executable: bool
    deleted: bool
    is_system: bool


class ProcessDetail(BaseModel):
    """Full per-process view from `GET /api/processes/{pid}`."""

    model_config = ConfigDict(extra="allow")  # metadata fields vary
    pid: int
    ppid: int
    name: str
    exe: str
    cwd: str
    username: str
    status: str
    cmdline: list[str]
    create_time: float
    num_threads: int
    num_fds: int
    cpu_percent: float
    memory_rss: int
    fds: list[FdEntryOut]
    sockets: list[SocketRowOut]
    maps: list[MapEntryOut]
    flag_detail: list[FlagDetail] = Field(default_factory=list)


class ConnectionRow(BaseModel):
    """One row in `GET /api/connections`. Mirrors `netwatch.Conn`."""

    model_config = ConfigDict(extra="forbid")
    pid: int
    comm: str
    proto: str
    laddr: str | None
    raddr: str
    state: str | None
    external: bool
    first_seen: float
    last_seen: float
    ptr: str | None = None
    asn: int | None = None
    asn_org: str | None = None


class SignalRequest(BaseModel):
    """Body of `POST /api/processes/{pid}/signal`. Already a BaseModel
    pre-Phase-12; formalized here so it lives with the other types.
    """

    model_config = ConfigDict(extra="forbid")
    signal: str = "SIGTERM"
    csrf: str = ""
    expected_start: float | None = None


# WebSocket messages — discriminated union via `type`.


class SnapshotMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["snapshot"] = "snapshot"
    procs: list[ProcessSummary]


class DiffMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["diff"] = "diff"
    added: list[ProcessSummary] = Field(default_factory=list)
    removed: list[int] = Field(default_factory=list)
    changed: list[ProcessSummary] = Field(default_factory=list)
    execed: list[int] = Field(default_factory=list)


class ShutdownMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["shutdown"] = "shutdown"


WsMessage = SnapshotMessage | DiffMessage | ShutdownMessage


# Response wrappers — every list-returning route gets one so the
# OpenAPI schema reflects the real shape and the response gets
# validated on the way out.


class ProcessListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    procs: list[ProcessSummary]


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ok: bool
    scanner_lag_ms: float


class CsrfResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    csrf: str


class HistorySample(BaseModel):
    model_config = ConfigDict(extra="forbid")
    at: float
    cpu: float
    rss: int


class HistoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    samples: list[HistorySample]


class ConnectionsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    connections: list[ConnectionRow]
    last_scan_at: float
    error_count: int


class TimelineEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    at: float
    pid: int
    ppid: int
    name: str
    exe: str | None
    cmd: str
    source: str


class TimelineResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: list[TimelineEvent]
    ebpf_running: bool


class ParanoidResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool
    hidden_pids: list[int]
    last_scan_at: float
    stale_seconds: float | None
    error_count: int
    healthy: bool


class SignalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ok: bool
    pid: int
    signal: str
    sent_at: float


class EnvResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    count: int
    env: dict[str, str]
