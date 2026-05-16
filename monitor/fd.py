"""File-descriptor target classification.

Reads /proc/<pid>/fd/* and turns each symlink target string into a typed
record. Kept pure and side-effect-free so it can be table-tested.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Literal

FdKind = Literal[
    "file",
    "dir",
    "pipe",
    "socket",            # generic socket; only when /proc/net/* lookup misses
    "tcp_socket",
    "udp_socket",
    "unix_socket",
    "netlink_socket",
    "device",
    "anon",
    "deleted",
    "unknown",
]


@dataclass
class FdEntry:
    fd: int
    target: str
    kind: FdKind
    deleted: bool = False
    addr: str | None = None       # socket address tuple, when resolved


_ANON_RE = re.compile(r"^(anon_inode:|\[)")


def classify(target: str) -> tuple[FdKind, bool]:
    """Map a readlink() result to (kind, deleted)."""
    deleted = target.endswith(" (deleted)")
    if deleted:
        target = target[: -len(" (deleted)")]

    if target.startswith("socket:["):
        return "socket", deleted
    if target.startswith("pipe:["):
        return "pipe", deleted
    if target.startswith("anon_inode:") or target.startswith("["):
        return "anon", deleted
    if target.startswith("/dev/"):
        return "device", deleted
    if deleted:
        return "deleted", True
    # Filesystem path — stat to distinguish file vs dir; tolerate missing.
    try:
        st = os.stat(target)
        if os.path.isdir(target):
            return "dir", False
        # block/char devices end up here too if not under /dev
        from stat import S_ISBLK, S_ISCHR

        if S_ISBLK(st.st_mode) or S_ISCHR(st.st_mode):
            return "device", False
        return "file", False
    except (FileNotFoundError, PermissionError, OSError):
        return "unknown", deleted


def read_fds(pid: int, socket_map: dict | None = None) -> list[FdEntry]:
    """Enumerate /proc/<pid>/fd. Non-fatal on races/permission errors.

    When `socket_map` (inode → SocketInfo, from sockets.load_socket_map) is
    provided, generic `socket` kinds are refined to tcp/udp/unix/netlink and
    `addr` is populated with the socket's address tuple.
    """
    from .sockets import inode_from_target  # local import to avoid cycle

    base = f"/proc/{pid}/fd"
    out: list[FdEntry] = []
    try:
        entries = os.listdir(base)
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return out
    for name in entries:
        try:
            fd_num = int(name)
        except ValueError:
            continue
        try:
            target = os.readlink(f"{base}/{name}")
        except (FileNotFoundError, PermissionError, OSError):
            continue
        kind, deleted = classify(target)
        addr: str | None = None
        if kind == "socket" and socket_map is not None:
            inode = inode_from_target(target)
            info = socket_map.get(inode) if inode is not None else None
            if info is not None:
                proto = info.proto
                if proto.startswith("tcp"):
                    kind = "tcp_socket"
                elif proto.startswith("udp"):
                    kind = "udp_socket"
                elif proto == "unix":
                    kind = "unix_socket"
                elif proto == "netlink":
                    kind = "netlink_socket"
                if info.laddr and info.raddr:
                    addr = f"{info.laddr} → {info.raddr}"
                elif info.laddr:
                    addr = info.laddr
                if info.state:
                    addr = f"{addr or ''} ({info.state})".strip()
        out.append(
            FdEntry(fd=fd_num, target=target, kind=kind, deleted=deleted, addr=addr)
        )
    out.sort(key=lambda e: e.fd)
    return out
