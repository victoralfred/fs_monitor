from monitor.scanner import _diff


def _p(pid, **kw):
    base = {"pid": pid, "ppid": 1, "name": "x", "user": "u", "status": "S",
            "cpu": 0.0, "rss": 100, "started": 0.0, "cmd": "/bin/x"}
    base.update(kw)
    return base


def test_diff_added_removed():
    a = {1: _p(1)}
    b = {2: _p(2)}
    d = _diff(a, b)
    assert [p["pid"] for p in d.added] == [2]
    assert d.removed == [1]
    assert d.changed == []


def test_diff_changed_only_when_meaningful():
    a = {1: _p(1, cpu=1.0, rss=100)}
    b = {1: _p(1, cpu=1.1, rss=100)}  # cpu delta < 0.5 → no change
    assert _diff(a, b).changed == []

    c = {1: _p(1, cpu=5.0, rss=100)}
    assert [p["pid"] for p in _diff(a, c).changed] == [1]

    d = {1: _p(1, cpu=1.0, rss=200)}
    assert [p["pid"] for p in _diff(a, d).changed] == [1]


def test_diff_detects_exec_without_fork():
    a = {1: _p(1, cmd="/bin/bash", started=100.0)}
    b = {1: _p(1, cmd="/usr/bin/curl evil.example.com", started=100.0)}
    diff = _diff(a, b)
    assert diff.execed == [1]
    # exec also counts as a change so the row gets new data.
    assert [p["pid"] for p in diff.changed] == [1]


def test_diff_no_exec_when_start_time_differs():
    # Same pid reused after exit + new process — not an exec.
    a = {1: _p(1, cmd="/bin/old", started=100.0)}
    b = {1: _p(1, cmd="/bin/new", started=200.0)}
    assert _diff(a, b).execed == []
