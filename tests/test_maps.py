import os

from monitor.maps import read_maps


def test_read_maps_self_has_libc_or_python():
    entries = read_maps(os.getpid())
    assert entries, "expected at least one mapped file for the test process"
    paths = [e.path for e in entries]
    # Either libc or a python shared object must be mapped.
    assert any("libc" in p or "python" in p.lower() for p in paths)
    # Aggregation invariants: no duplicate paths, sizes are positive.
    assert len(paths) == len(set(paths))
    assert all(e.size > 0 for e in entries)


def test_read_maps_missing_pid():
    assert read_maps(0) == []
