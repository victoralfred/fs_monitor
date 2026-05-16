"""Unit tests for the signal validator.

Phase 14: the validator is a pure function over `AppState`, so we can
test every rejection path without booting a real FastAPI app.
"""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from monitor.signaling import (
    KillRejected,
    KillTarget,
    validate_kill_request,
)
from monitor.types import SignalRequest


def _state(
    *,
    allow_kill: bool = True,
    kill_acl: str = "same_user",
    csrf: str = "tok",
    snapshot_pid: int | None = None,
    snapshot_started: float = 0.0,
):
    """Build a minimal AppState-shaped object for the validator."""
    snapshot = {}
    if snapshot_pid is not None:
        snapshot[snapshot_pid] = {"started": snapshot_started}
    scanner = SimpleNamespace(snapshot=snapshot)
    return SimpleNamespace(
        allow_kill=allow_kill,
        kill_acl=kill_acl,
        csrf_token=csrf,
        scanner=scanner,
    )


def _body(signal: str = "SIGCONT", csrf: str = "tok", expected_start: float | None = None):
    return SignalRequest(signal=signal, csrf=csrf, expected_start=expected_start)


def test_rejects_when_kill_disabled():
    s = _state(allow_kill=False, snapshot_pid=os.getpid())
    with pytest.raises(KillRejected) as exc:
        validate_kill_request(os.getpid(), _body(), s)
    assert exc.value.reason == "kill_disabled"
    assert exc.value.status_code == 403


def test_rejects_bad_csrf():
    s = _state(snapshot_pid=os.getpid())
    with pytest.raises(KillRejected) as exc:
        validate_kill_request(os.getpid(), _body(csrf="nope"), s)
    assert exc.value.reason == "bad_csrf"


def test_rejects_bad_signal():
    s = _state(snapshot_pid=os.getpid())
    with pytest.raises(KillRejected) as exc:
        validate_kill_request(os.getpid(), _body(signal="SIGNUKE"), s)
    assert exc.value.reason == "bad_signal"
    assert "SIGTERM" in exc.value.detail["allowed"]


def test_rejects_unknown_pid():
    s = _state(snapshot_pid=None)
    with pytest.raises(KillRejected) as exc:
        validate_kill_request(99999, _body(), s)
    assert exc.value.reason == "not_found"


def test_rejects_pid_recycled_when_expected_start_mismatches():
    s = _state(snapshot_pid=os.getpid(), snapshot_started=12345.0)
    with pytest.raises(KillRejected) as exc:
        validate_kill_request(os.getpid(), _body(expected_start=99999.0), s)
    assert exc.value.reason == "pid_recycled"
    assert exc.value.status_code == 409


def test_rejects_acl_none():
    s = _state(snapshot_pid=os.getpid(), kill_acl="none")
    with pytest.raises(KillRejected) as exc:
        validate_kill_request(os.getpid(), _body(), s)
    assert exc.value.reason == "acl_blocked"


def test_accepts_own_pid_with_same_user_acl():
    """Happy path: own pid, SIGCONT, same-user ACL. SIGCONT is harmless
    and verifies the validator returns a populated KillTarget.
    """
    s = _state(snapshot_pid=os.getpid())
    target = validate_kill_request(os.getpid(), _body(), s)
    assert isinstance(target, KillTarget)
    assert target.pid == os.getpid()
    assert target.signal_name == "SIGCONT"
    assert target.signum > 0
