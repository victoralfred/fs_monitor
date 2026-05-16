from monitor.sockets import (
    _parse_v4,
    _parse_v6,
    inode_from_target,
    invalidate_cache,
    load_socket_map,
)


def test_parse_v4():
    # 127.0.0.1:8080 → little-endian hex 0100007F:1F90
    assert _parse_v4("0100007F:1F90") == "127.0.0.1:8080"


def test_parse_v6_loopback():
    # ::1 little-endian groups → 00000000 00000000 00000000 01000000
    out = _parse_v6("00000000000000000000000001000000:0050")
    assert out.endswith(":80")
    assert "::1" in out


def test_inode_from_target():
    assert inode_from_target("socket:[12345]") == 12345
    assert inode_from_target("socket:[bogus]") is None
    assert inode_from_target("pipe:[7]") is None


def test_load_socket_map_runs():
    invalidate_cache()
    m = load_socket_map()
    assert isinstance(m, dict)
    for info in m.values():
        assert info.proto in {"tcp", "tcp6", "udp", "udp6", "unix", "netlink"}


def test_load_socket_map_caches():
    invalidate_cache()
    m1 = load_socket_map()
    m2 = load_socket_map()
    # Same object reference: returned from cache.
    assert m1 is m2
