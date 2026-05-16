import os

from monitor.collector import collect, collect_env


def test_collect_self():
    data = collect(os.getpid())
    assert data is not None
    assert data["pid"] == os.getpid()
    assert data["cwd"]                       # we always have a cwd
    assert data["exe"]                       # python binary
    assert data["num_threads"] >= 1
    assert isinstance(data["fds"], list)
    # 0/1/2 should always be present as fds
    fd_nums = {f["fd"] for f in data["fds"]}
    assert {0, 1, 2}.issubset(fd_nums)
    assert isinstance(data["sockets"], list)
    # Socket addresses must be strings or None — not namedtuples.
    for s in data["sockets"]:
        assert s["laddr"] is None or isinstance(s["laddr"], str)
        assert s["raddr"] is None or isinstance(s["raddr"], str)


def test_collect_missing_pid():
    # PID 0 is never a real process; psutil raises NoSuchProcess.
    assert collect(0) is None


def test_collect_env_hidden_by_default():
    out = collect_env(os.getpid(), show=False)
    assert out is not None
    assert out["env"] == {}
    assert out["count"] >= 0


def test_collect_env_redacts_secret_values(monkeypatch):
    import psutil

    fake = {
        "DATABASE_URL": "postgres://user:hunter2@host/db",
        "API_TOKEN": "supersecret",
        "GITHUB_PAT": "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
        "PATH": "/usr/bin",
        "INNOCENT": "just a regular value",
    }
    monkeypatch.setattr(psutil.Process, "environ", lambda self: fake)

    out = collect_env(os.getpid(), show=True)
    assert out is not None
    # Key-based redactions still fire.
    assert out["env"]["API_TOKEN"] == "<redacted: key>"
    # Value-based redactions fire for URL creds + GitHub tokens.
    assert out["env"]["DATABASE_URL"] == "<redacted: value>"
    assert out["env"]["GITHUB_PAT"] == "<redacted: value>"
    # Innocent values pass through.
    assert out["env"]["PATH"] == "/usr/bin"
    assert out["env"]["INNOCENT"] == "just a regular value"


def test_collect_env_shown_redacts_secret_keys(monkeypatch):
    # psutil.Process.environ() reads /proc/<pid>/environ, which is captured at
    # exec time, so we can't influence it by mutating os.environ. Patch the
    # bound method to return a controlled dict instead.
    import psutil

    fake = {"MY_API_TOKEN": "supersecret", "PATH": "/usr/bin", "DB_PASSWORD": "x"}
    monkeypatch.setattr(psutil.Process, "environ", lambda self: fake)

    out = collect_env(os.getpid(), show=True)
    assert out is not None
    assert out["count"] == 3
    assert out["env"]["MY_API_TOKEN"] == "<redacted: key>"
    assert out["env"]["DB_PASSWORD"] == "<redacted: key>"
    assert out["env"]["PATH"] == "/usr/bin"
