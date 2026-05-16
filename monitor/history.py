"""In-memory ring buffers for the visibility features.

Per-pid history powers the detail-panel sparklines (#2). A single global
exec-event log powers the timeline (#3). Both live in-process; nothing is
persisted across restarts.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from threading import Lock


@dataclass
class HistorySample:
    at: float       # unix seconds
    cpu: float
    rss: int


@dataclass
class ExecEvent:
    at: float
    pid: int
    ppid: int
    name: str
    exe: str | None
    cmd: str
    source: str     # "scanner" | "ebpf"


@dataclass
class History:
    samples_per_pid: int = 60                       # ≈ 2 min at 2 s tick
    timeline_max: int = 2000                        # global exec log cap (SC2)
    _per_pid: dict[int, deque] = field(default_factory=dict, repr=False, compare=False)
    _timeline: deque[ExecEvent] = field(
        default_factory=lambda: deque(maxlen=2000), repr=False, compare=False,
    )
    _lock: Lock = field(default_factory=Lock, repr=False, compare=False)

    def record(self, pid: int, cpu: float, rss: int) -> None:
        with self._lock:
            q = self._per_pid.get(pid)
            if q is None:
                q = deque(maxlen=self.samples_per_pid)
                self._per_pid[pid] = q
            q.append(HistorySample(at=time.time(), cpu=cpu, rss=rss))

    def drop(self, pid: int) -> None:
        with self._lock:
            self._per_pid.pop(pid, None)

    def prune(self, live_pids: set[int]) -> None:
        with self._lock:
            for pid in list(self._per_pid.keys()):
                if pid not in live_pids:
                    del self._per_pid[pid]

    def get(self, pid: int) -> list[HistorySample]:
        with self._lock:
            q = self._per_pid.get(pid)
            return list(q) if q else []

    def add_exec(self, ev: ExecEvent) -> None:
        with self._lock:
            self._timeline.append(ev)

    def timeline(self, since: float | None = None) -> list[ExecEvent]:
        with self._lock:
            if since is None:
                return list(self._timeline)
            return [e for e in self._timeline if e.at >= since]
