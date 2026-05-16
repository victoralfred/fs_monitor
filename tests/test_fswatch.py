
from monitor.fswatch import (
    MASS_DELETE_THRESHOLD,
    WRITE_BURST_THRESHOLD,
    FsAggregator,
)


def test_no_flag_below_threshold():
    agg = FsAggregator()
    for i in range(WRITE_BURST_THRESHOLD - 1):
        agg.record_write(42, "evil", f"/home/u/doc-{i}.txt")
    assert agg.flag(42) == []


def test_write_burst_fires_above_threshold():
    agg = FsAggregator()
    for i in range(WRITE_BURST_THRESHOLD):
        agg.record_write(42, "evil", f"/home/u/doc-{i}.txt")
    flags = agg.flag(42)
    assert any(f["id"] == "fs_write_burst" for f in flags)


def test_mass_delete_fires_above_threshold():
    agg = FsAggregator()
    for i in range(MASS_DELETE_THRESHOLD):
        agg.record_unlink(42, "evil", f"/home/u/doc-{i}.txt")
    flags = agg.flag(42)
    assert any(f["id"] == "fs_mass_delete" for f in flags)


def test_comm_allowlist_suppresses_compilers():
    agg = FsAggregator()
    for i in range(WRITE_BURST_THRESHOLD + 10):
        agg.record_write(99, "gcc", f"/tmp/build/obj-{i}.o")
    assert agg.flag(99) == []


def test_path_allowlist_suppresses_node_modules():
    agg = FsAggregator()
    for i in range(WRITE_BURST_THRESHOLD + 10):
        agg.record_write(42, "node", f"/proj/node_modules/foo/{i}.js")
    assert agg.flag(42) == []


def test_path_allowlist_suppresses_git_clone():
    agg = FsAggregator()
    for i in range(WRITE_BURST_THRESHOLD + 10):
        agg.record_write(42, "evil-but-targeting-git", f"/proj/.git/objects/{i}")
    assert agg.flag(42) == []


def test_distinct_paths_not_count_repeats():
    agg = FsAggregator()
    # Same path written 100 times shouldn't count as a burst.
    for _ in range(100):
        agg.record_write(42, "evil", "/home/u/doc.txt")
    assert agg.flag(42) == []


def test_prune_drops_dead_pids():
    agg = FsAggregator()
    agg.record_write(42, "x", "/home/u/d.txt")
    agg.prune_pids({1, 2, 3})  # 42 not alive
    assert agg.flag(42) == []


def test_old_events_outside_window_are_dropped():
    agg = FsAggregator()
    # Stuff some writes in, mutate the deque timestamps to look ancient,
    # then verify the rolling window drops them.
    for i in range(WRITE_BURST_THRESHOLD + 5):
        agg.record_write(42, "evil", f"/home/u/d-{i}.txt")
    # Backdate every entry by 30 s.
    with agg._lock:
        w = agg.by_pid[42]
        w.writes = type(w.writes)((t - 30.0, p) for (t, p) in w.writes)
    assert agg.flag(42) == []
    # And the prune ran.
    with agg._lock:
        assert len(agg.by_pid[42].writes) == 0
