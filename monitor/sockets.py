"""Build an inode → socket-info map from /proc/net/*.

Used by the fd reader to refine the generic `socket` kind into
`tcp_socket` / `udp_socket` / `unix_socket` / `netlink_socket`, and to
annotate the Files tab with the socket's address tuple.
"""

from __future__ import annotations

import socket as pysocket
import threading
import time
from dataclasses import dataclass


@dataclass
class SocketInfo:
    inode: int
    proto: str          # tcp | tcp6 | udp | udp6 | unix | netlink
    laddr: str | None
    raddr: str | None
    state: str | None


# /proc/net/tcp state codes (hex).
_TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
    "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
    "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}


def _parse_v4(hex_addr: str) -> str:
    ip_hex, port_hex = hex_addr.split(":")
    octets = [int(ip_hex[i:i + 2], 16) for i in (6, 4, 2, 0)]
    return f"{'.'.join(str(o) for o in octets)}:{int(port_hex, 16)}"


def _parse_v6(hex_addr: str) -> str:
    ip_hex, port_hex = hex_addr.split(":")
    # /proc/net/tcp6 stores 4 little-endian 32-bit groups.
    groups = [ip_hex[i:i + 8] for i in range(0, 32, 8)]
    raw = b"".join(bytes.fromhex(g)[::-1] for g in groups)
    try:
        ip = pysocket.inet_ntop(pysocket.AF_INET6, raw)
    except OSError:
        ip = hex_addr
    return f"[{ip}]:{int(port_hex, 16)}"


def _parse_inet(path: str, proto: str, parser) -> dict[int, SocketInfo]:
    out: dict[int, SocketInfo] = {}
    try:
        with open(path) as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) < 10:
                    continue
                try:
                    laddr = parser(parts[1])
                    raddr = parser(parts[2])
                    state = (
                        _TCP_STATES.get(parts[3].upper(), parts[3])
                        if proto.startswith("tcp") else None
                    )
                    inode = int(parts[9])
                except (ValueError, IndexError):
                    continue
                if inode:
                    out[inode] = SocketInfo(inode, proto, laddr, raddr, state)
    except (FileNotFoundError, PermissionError):
        pass
    return out


def _parse_unix(path: str = "/proc/net/unix") -> dict[int, SocketInfo]:
    # Columns: Num RefCount Protocol Flags Type St Inode Path
    out: dict[int, SocketInfo] = {}
    try:
        with open(path) as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) < 7:
                    continue
                try:
                    inode = int(parts[6])
                except ValueError:
                    continue
                path_field = parts[7] if len(parts) >= 8 else None
                if inode:
                    out[inode] = SocketInfo(inode, "unix", path_field, None, None)
    except (FileNotFoundError, PermissionError):
        pass
    return out


def _parse_netlink(path: str = "/proc/net/netlink") -> dict[int, SocketInfo]:
    out: dict[int, SocketInfo] = {}
    try:
        with open(path) as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) < 10:
                    continue
                try:
                    inode = int(parts[9])
                except ValueError:
                    continue
                if inode:
                    out[inode] = SocketInfo(inode, "netlink", None, None, None)
    except (FileNotFoundError, PermissionError):
        pass
    return out


_CACHE: dict[int, SocketInfo] | None = None
_CACHE_AT: float = 0.0
_CACHE_TTL = 0.5    # seconds — coarse enough to amortize bursts, fresh enough for detail polls
_CACHE_LOCK = threading.Lock()


def load_socket_map() -> dict[int, SocketInfo]:
    """Build (or return cached) inode → SocketInfo map.

    Caches for _CACHE_TTL seconds. Concurrent calls during a cache miss
    will all wait on the lock and then read the freshly populated map.
    """
    global _CACHE, _CACHE_AT
    now = time.monotonic()
    if _CACHE is not None and now - _CACHE_AT < _CACHE_TTL:
        return _CACHE
    with _CACHE_LOCK:
        now = time.monotonic()
        if _CACHE is not None and now - _CACHE_AT < _CACHE_TTL:
            return _CACHE
        m: dict[int, SocketInfo] = {}
        m.update(_parse_inet("/proc/net/tcp",  "tcp",  _parse_v4))
        m.update(_parse_inet("/proc/net/tcp6", "tcp6", _parse_v6))
        m.update(_parse_inet("/proc/net/udp",  "udp",  _parse_v4))
        m.update(_parse_inet("/proc/net/udp6", "udp6", _parse_v6))
        m.update(_parse_unix())
        m.update(_parse_netlink())
        _CACHE = m
        _CACHE_AT = now
        return m


def invalidate_cache() -> None:
    """Force the next load_socket_map call to rebuild. Test-only."""
    global _CACHE
    _CACHE = None


def inode_from_target(target: str) -> int | None:
    """Extract the inode from a `socket:[N]` readlink target, or None."""
    if not target.startswith("socket:[") or not target.endswith("]"):
        return None
    try:
        return int(target[len("socket:["):-1])
    except ValueError:
        return None
