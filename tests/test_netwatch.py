from monitor.netwatch import Conn, ConnectionLog, is_external


def test_is_external_loopback():
    assert is_external("127.0.0.1") is False
    assert is_external("::1") is False


def test_is_external_rfc1918():
    assert is_external("10.0.0.1") is False
    assert is_external("172.16.5.5") is False
    assert is_external("192.168.1.1") is False


def test_is_external_link_local():
    assert is_external("169.254.1.1") is False
    assert is_external("fe80::1") is False


def test_is_external_routable():
    assert is_external("8.8.8.8") is True
    assert is_external("1.1.1.1") is True
    assert is_external("2606:4700:4700::1111") is True


def test_is_external_cgnat_counts_as_external():
    # 100.64/10 is RFC6598 — used in tunnels, technically NOT is_private,
    # so our policy counts it as external. Documented in module doc.
    assert is_external("100.64.1.1") is True


def test_is_external_bogus():
    assert is_external(None) is False
    assert is_external("") is False
    assert is_external("not-an-ip") is False


def test_connection_log_dedupes_by_key():
    log = ConnectionLog()
    c1 = Conn(
        pid=42, comm="x", proto="tcp", laddr="127.0.0.1:5555",
        raddr="8.8.8.8:443", state="ESTABLISHED",
        external=True, first_seen=0, last_seen=0,
    )
    log.update([c1])
    first_first_seen = log.seen[(42, "8.8.8.8:443", "tcp")].first_seen
    # Same key updated again should preserve first_seen, bump last_seen.
    log.update([c1])
    record = log.seen[(42, "8.8.8.8:443", "tcp")]
    assert record.first_seen == first_first_seen
    assert record.last_seen >= first_first_seen


def test_connection_log_prune_drops_stale():
    log = ConnectionLog(max_age=0.001)
    log.seen[(1, "1.1.1.1:80", "tcp")] = Conn(
        pid=1, comm="x", proto="tcp", laddr=None,
        raddr="1.1.1.1:80", state=None, external=True,
        first_seen=0, last_seen=0,
    )
    log.prune()
    assert log.seen == {}


def test_connection_log_items_filters_external():
    log = ConnectionLog()
    log.seen[(1, "1.1.1.1:80", "tcp")] = Conn(
        pid=1, comm="x", proto="tcp", laddr=None,
        raddr="1.1.1.1:80", state=None, external=True,
        first_seen=0, last_seen=1,
    )
    log.seen[(2, "127.0.0.1:80", "tcp")] = Conn(
        pid=2, comm="y", proto="tcp", laddr=None,
        raddr="127.0.0.1:80", state=None, external=False,
        first_seen=0, last_seen=2,
    )
    ext = log.items(external_only=True)
    assert len(ext) == 1
    assert ext[0]["pid"] == 1
    all_rows = log.items(external_only=False)
    assert len(all_rows) == 2


def test_connection_log_constructs_independently():
    # Phase 11: there's no more module-level singleton; each AppState
    # owns its own ConnectionLog. Two instances must be independent.
    a = ConnectionLog()
    b = ConnectionLog()
    assert a is not b
    assert a.seen is not b.seen
