"""Per-process external-egress tracking.

A process holding a connection to the public internet is the single most
useful piece of network forensic evidence on a Linux host. This module
scans every live socket on the system periodically, attributes each to a
pid, classifies the remote IP as internal/external, and records first-
and last-seen times for `(pid, raddr, proto)` tuples.

Limitations honestly stated:
- Without root or CAP_NET_ADMIN, `psutil.net_connections(kind="all")`
  returns only sockets owned by the running user. The scan then misses
  egress from other users' processes. Use `--allow-root` deployment or
  systemd `CapabilityBoundingSet=CAP_NET_ADMIN` to get full visibility.
- We only catch connections that exist *at scan time*. Short-lived
  outbound calls (a `curl ... && exit` running in <5 s between ticks)
  may slip through. eBPF tracing would close that gap; deferred until
  someone needs it.
- "External" is anything not RFC1918, not loopback, not link-local. CGNAT
  ranges (100.64/10) and similar IS counted as external — they're routable
  on the bigger internet for tunnel users.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import asdict, dataclass, field
from threading import Lock

import psutil

log = logging.getLogger(__name__)


def is_external(ip_str: str | None) -> bool:
    """Routable internet address? Excludes loopback, RFC1918, link-local,
    multicast, broadcast, unspecified. CGNAT (100.64/10) counts as
    external (per stated policy in module doc).
    """
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except (ValueError, ipaddress.AddressValueError):
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return False
    if ip.is_private:
        return False
    return not (ip.is_unspecified or ip.is_reserved)


@dataclass
class Conn:
    pid: int
    comm: str
    proto: str          # tcp | tcp6 | udp | udp6
    laddr: str | None
    raddr: str
    state: str | None
    external: bool
    first_seen: float
    last_seen: float


@dataclass
class ConnectionLog:
    """`(pid, raddr_with_port, proto)` → Conn. Stale entries pruned by max_age."""
    max_age: float = 600.0    # 10 min — long enough to spot a "what was that?"
    seen: dict[tuple, Conn] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock, repr=False, compare=False)

    def update(self, conns: list[Conn]) -> None:
        now = time.time()
        with self._lock:
            for c in conns:
                key = (c.pid, c.raddr, c.proto)
                existing = self.seen.get(key)
                if existing is None:
                    c.first_seen = now
                    c.last_seen = now
                    self.seen[key] = c
                else:
                    existing.last_seen = now
                    # Drift in state field is interesting; pid/raddr/proto are
                    # the key so they can't drift.
                    existing.state = c.state

    def prune(self) -> None:
        now = time.time()
        with self._lock:
            for key in list(self.seen.keys()):
                if now - self.seen[key].last_seen > self.max_age:
                    del self.seen[key]

    def items(self, external_only: bool = True) -> list[dict]:
        with self._lock:
            rows = [asdict(c) for c in self.seen.values()]
        if external_only:
            rows = [r for r in rows if r["external"]]
        rows.sort(key=lambda r: r["last_seen"], reverse=True)
        return rows

    def count_external(self) -> int:
        with self._lock:
            return sum(1 for c in self.seen.values() if c.external)


# Single global instance shared with the scanner.
CONNECTIONS = ConnectionLog()


def _proto_str(family, type_) -> str:
    """Map psutil's enum-or-int family/type pair to one of tcp/tcp6/udp/udp6."""
    fam = getattr(family, "value", family)
    typ = getattr(type_, "value", type_)
    # AF_INET = 2, AF_INET6 = 10 on Linux; SOCK_STREAM = 1, SOCK_DGRAM = 2.
    if typ == 1:  # TCP
        return "tcp6" if fam == 10 else "tcp"
    if typ == 2:  # UDP
        return "udp6" if fam == 10 else "udp"
    return "other"


def scan(name_lookup: dict[int, str]) -> list[Conn]:
    """Return the current set of connections with a remote address.

    `name_lookup` maps pid → comm/name from the scanner snapshot so we
    don't have to re-stat /proc just for that.
    """
    try:
        raw = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        log.warning("net_connections denied — need root or CAP_NET_ADMIN")
        return []
    except OSError as e:
        log.warning("net_connections failed: %s", e)
        return []

    out: list[Conn] = []
    now = time.time()
    for c in raw:
        if c.raddr is None or c.pid is None:
            continue
        # psutil's addr is a namedtuple (ip, port) for inet sockets.
        try:
            ip = c.raddr.ip
            port = c.raddr.port
        except AttributeError:
            continue
        proto = _proto_str(c.family, c.type)
        laddr = (
            f"{c.laddr.ip}:{c.laddr.port}"
            if c.laddr and hasattr(c.laddr, "ip") else None
        )
        out.append(Conn(
            pid=c.pid,
            comm=name_lookup.get(c.pid, ""),
            proto=proto,
            laddr=laddr,
            raddr=f"{ip}:{port}",
            state=c.status if isinstance(c.status, str) else getattr(c.status, "name", None),
            external=is_external(ip),
            first_seen=now,
            last_seen=now,
        ))
    return out
