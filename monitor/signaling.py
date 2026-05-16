"""Process-signalling logic, kept separate from the HTTP layer.

The route handler calls `validate_kill_request()` (pure function over
state) and then `deliver_signal()` (the syscall). Both can raise
`KillRejected` with a structured reason; a single FastAPI exception
handler translates that into JSON. The route ends up as three lines.

Compared to the pre-Phase-14 implementation this:
- separates pure validation from the syscall (so validation is
  unit-testable without any /proc or TestClient setup);
- collapses 60 lines of nested ifs into a flat list of guard clauses
  with one early return per failure mode;
- gives every error a structured `reason` field instead of ad-hoc
  string detail dicts, which makes client error-handling sane.
"""

from __future__ import annotations

import os
import secrets
import signal as signal_mod
import time
from dataclasses import dataclass, field
from typing import Any

ALLOWED_SIGNALS: dict[str, int] = {
    "SIGTERM": signal_mod.SIGTERM,
    "SIGINT": signal_mod.SIGINT,
    "SIGHUP": signal_mod.SIGHUP,
    "SIGKILL": signal_mod.SIGKILL,
    "SIGSTOP": signal_mod.SIGSTOP,
    "SIGCONT": signal_mod.SIGCONT,
}


@dataclass
class KillRejected(Exception):
    """Raised when a signal request can't proceed. Caught by a FastAPI
    exception handler and converted to a structured 4xx response.
    """

    status_code: int
    reason: str
    detail: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.reason} ({self.status_code})"


@dataclass
class KillTarget:
    """Validated kill request. Carries everything `deliver_signal` needs."""

    pid: int
    signum: int
    signal_name: str
    start_time: float


def _read_start_time(pid: int) -> float | None:
    """Read /proc/<pid>/stat field 22. Returns None on race/perm/parse failures."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            data = f.read()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None
    rparen = data.rfind(b")")
    if rparen < 0:
        return None
    rest = data[rparen + 2 :].split()
    if len(rest) < 20:
        return None
    try:
        return float(rest[19])
    except ValueError:
        return None


def validate_kill_request(pid: int, body, state) -> KillTarget:
    """Run every guard. Returns a KillTarget on success; raises
    KillRejected on any failure. Pure(-ish) — only reads from /proc and
    the snapshot, never mutates anything.

    Body is a `monitor.types.SignalRequest`; state is an AppState.
    """
    # 1. Feature gate.
    if not state.allow_kill:
        raise KillRejected(
            403, "kill_disabled",
            {"hint": "set [security].allow_kill = true"},
        )

    # 2. CSRF.
    if not secrets.compare_digest(body.csrf or "", state.csrf_token):
        raise KillRejected(403, "bad_csrf")

    # 3. Signal name in allowlist.
    if body.signal not in ALLOWED_SIGNALS:
        raise KillRejected(
            400, "bad_signal",
            {"allowed": list(ALLOWED_SIGNALS.keys())},
        )

    # 4. Pid alive in the snapshot.
    scanner = state.scanner
    if scanner is None:
        raise KillRejected(503, "scanner_not_running")
    row = scanner.snapshot.get(pid)
    if row is None:
        raise KillRejected(404, "not_found")

    # 5. Pid still alive on disk (snapshot might be stale by a few seconds).
    live_start = _read_start_time(pid)
    if live_start is None:
        raise KillRejected(404, "not_found")

    # 6. Caller-pinned start_time matches snapshot (defeats pid recycling).
    if (
        body.expected_start is not None
        and abs(body.expected_start - row["started"]) > 0.5
    ):
        raise KillRejected(
            409, "pid_recycled",
            {"snapshot_start": row["started"]},
        )

    # 7. ACL.
    acl = state.kill_acl
    if acl == "none":
        raise KillRejected(403, "acl_blocked")
    if acl == "same_user":
        try:
            target_uid = os.stat(f"/proc/{pid}").st_uid
        except (FileNotFoundError, PermissionError) as e:
            raise KillRejected(404, "not_found") from e
        if target_uid != os.getuid():
            raise KillRejected(
                403, "acl_blocked",
                {"reason": "different user",
                 "target_uid": target_uid, "our_uid": os.getuid()},
            )
    # acl == "all" → fall through.

    return KillTarget(
        pid=pid,
        signum=ALLOWED_SIGNALS[body.signal],
        signal_name=body.signal,
        start_time=live_start,
    )


def deliver_signal(target: KillTarget) -> float:
    """Send the signal after a final pid-recycling recheck. Returns the
    sent-at timestamp. Raises KillRejected on any failure mode.
    """
    recheck = _read_start_time(target.pid)
    if recheck is None or abs(recheck - target.start_time) > 0.5:
        raise KillRejected(409, "pid_recycled")
    try:
        os.kill(target.pid, target.signum)
    except ProcessLookupError as e:
        raise KillRejected(404, "not_found") from e
    except PermissionError as e:
        raise KillRejected(403, "permission_denied", {"msg": str(e)}) from e
    return time.time()
