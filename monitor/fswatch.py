"""Per-process filesystem write/unlink burst tracking.

Fed by the eBPF tracer (bpftrace probes on `sys_enter_openat` filtered
to O_TRUNC|O_CREAT, and on `sys_enter_unlinkat`). Maintains a rolling
window of recent events keyed by pid, exposes two security flags:

  fs_write_burst — too many distinct files opened-for-write in a short
                   window. Matches the shape of an overwrite payload.
  fs_mass_delete — too many unlinks in a short window. Matches a wiper.

Designed to be cheap to query: scanner asks "is pid P in burst state
right now?" once per scan tick. The aggregator runs as part of the
eBPF reader's append path, so cost stays O(events received).
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from threading import Lock

WINDOW_SECONDS = 5.0
WRITE_BURST_THRESHOLD = 25      # distinct paths in WINDOW_SECONDS
MASS_DELETE_THRESHOLD = 10      # unlinks in WINDOW_SECONDS

# Binaries that legitimately write/delete a lot of files. Matched as a
# basename substring on the recorded comm.
BIN_ALLOWLIST = (
    "cc", "gcc", "clang", "g++", "ld", "ar", "make", "ninja",
    "tar", "git", "rsync", "cp", "mv", "rm",
    "npm", "pnpm", "yarn", "pip", "poetry", "cargo",
    "rustc", "go", "node", "python", "ruby", "java",
    "firefox", "chrome", "chromium",
    "rg", "find",
)

# Path prefixes for "build / cache / install" activity that's expected
# to involve many writes.
PATH_ALLOWLIST = (
    "/tmp/",                       # caller scope — security.py handles tmp exes
    "/.git/", "/node_modules/",
    "/target/", "/build/", "/dist/", "/out/",
    "/.cache/", "/.local/share/",
    "/.npm/", "/.yarn/", "/.cargo/", "/.rustup/",
    "/var/cache/",
)


def _is_allowlisted_comm(comm: str) -> bool:
    c = comm.lower()
    return any(b in c for b in BIN_ALLOWLIST)


def _is_allowlisted_path(path: str) -> bool:
    return any(prefix in path for prefix in PATH_ALLOWLIST)


@dataclass
class FsWindow:
    """Rolling per-pid window of (timestamp, path) for writes and unlinks."""
    writes: deque = field(default_factory=deque)
    unlinks: deque = field(default_factory=deque)


@dataclass
class FsAggregator:
    by_pid: dict[int, FsWindow] = field(default_factory=lambda: defaultdict(FsWindow))
    by_pid_comm: dict[int, str] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock, repr=False, compare=False)

    def record_write(self, pid: int, comm: str, path: str) -> None:
        if _is_allowlisted_comm(comm) or _is_allowlisted_path(path):
            return
        now = time.monotonic()
        with self._lock:
            self.by_pid_comm[pid] = comm
            w = self.by_pid[pid]
            w.writes.append((now, path))
            self._prune_window(w, now)

    def record_unlink(self, pid: int, comm: str, path: str) -> None:
        if _is_allowlisted_comm(comm) or _is_allowlisted_path(path):
            return
        now = time.monotonic()
        with self._lock:
            self.by_pid_comm[pid] = comm
            w = self.by_pid[pid]
            w.unlinks.append((now, path))
            self._prune_window(w, now)

    @staticmethod
    def _prune_window(w: FsWindow, now: float) -> None:
        cutoff = now - WINDOW_SECONDS
        while w.writes and w.writes[0][0] < cutoff:
            w.writes.popleft()
        while w.unlinks and w.unlinks[0][0] < cutoff:
            w.unlinks.popleft()

    def flag(self, pid: int) -> list[dict]:
        """Return any security flags currently firing for `pid`.
        Called by compute_flags on the scanner hot path.
        """
        now = time.monotonic()
        with self._lock:
            w = self.by_pid.get(pid)
            if w is None:
                return []
            self._prune_window(w, now)
            flags = []
            distinct_writes = len({p for _t, p in w.writes})
            if distinct_writes >= WRITE_BURST_THRESHOLD:
                sample = next(iter({p for _t, p in w.writes}), "")
                flags.append({
                    "id": "fs_write_burst",
                    "severity": "high",
                    "evidence": (
                        f"{distinct_writes} distinct files opened for write "
                        f"in {WINDOW_SECONDS:.0f}s (example: {sample})"
                    ),
                })
            if len(w.unlinks) >= MASS_DELETE_THRESHOLD:
                sample = w.unlinks[-1][1] if w.unlinks else ""
                flags.append({
                    "id": "fs_mass_delete",
                    "severity": "high",
                    "evidence": (
                        f"{len(w.unlinks)} unlinks in {WINDOW_SECONDS:.0f}s "
                        f"(latest: {sample})"
                    ),
                })
            return flags

    def prune_pids(self, live_pids: set[int]) -> None:
        with self._lock:
            for pid in list(self.by_pid.keys()):
                if pid not in live_pids:
                    del self.by_pid[pid]
                    self.by_pid_comm.pop(pid, None)


