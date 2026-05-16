"""Per-process detail collection. Called lazily from the detail endpoint."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import psutil

from .fd import read_fds
from .maps import annotate_system, read_maps
from .sockets import load_socket_map

_REDACT_RE = re.compile(r"(?i)token|secret|key|pass|cred|auth")

# Value-shape regexes. If a value looks credential-like, redact it even when
# the KEY didn't match _REDACT_RE. Patterns chosen for high precision: false
# positives here only hide a value users could re-reveal by tweaking config.
_VALUE_REDACT_RES = [
    # URL-embedded credentials: scheme://user:pass@host
    re.compile(r"^[a-z][a-z0-9+.-]*://[^:/\s@]+:[^@/\s]+@", re.IGNORECASE),
    # JWT (three base64url segments separated by dots) — value is whole-string.
    re.compile(r"^[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}$"),
    # AWS access key id
    re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"),
    # PEM private key headers
    re.compile(r"-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY"),
    # GitHub / generic high-entropy long tokens (ghp_..., glpat-..., etc.)
    re.compile(r"\b(ghp|gho|ghu|ghs|ghr|glpat|xox[bp])[_-][A-Za-z0-9]{20,}\b"),
]


def set_redact_patterns(patterns: list[str]) -> None:
    """Replace the env-var key redaction regex. Called at startup from config."""
    global _REDACT_RE
    _REDACT_RE = re.compile("|".join(patterns))


def _value_looks_secret(v: str) -> bool:
    return any(r.search(v) for r in _VALUE_REDACT_RES)


def _sanitize_addr(s: str) -> str:
    """S7: strip control chars from socket addresses (UNIX socket paths can
    contain arbitrary bytes including newlines, ESC, etc.). Abstract sockets
    start with a NUL and are conventionally displayed with a leading @.
    """
    if not s:
        return s
    if s[0] == "\x00":
        s = "@" + s[1:]
    return "".join(c if (c.isprintable() and c not in "\r\n\t") else "?" for c in s)


@dataclass
class SocketInfo:
    fd: int | None
    family: str
    type: str
    laddr: str | None
    raddr: str | None
    status: str | None


def _safe(callable_, default=None):
    try:
        return callable_()
    except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError, PermissionError):
        return default


def collect(pid: int, security_cfg=None) -> dict[str, Any] | None:
    """Return full detail dict for pid, or None if the process is gone."""
    try:
        p = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return None

    with p.oneshot():
        meta = {
            "pid": pid,
            "ppid": _safe(p.ppid),
            "name": _safe(p.name, ""),
            "exe": _safe(p.exe, ""),
            "cwd": _safe(p.cwd, ""),
            "username": _safe(p.username, ""),
            "status": _safe(p.status, ""),
            "cmdline": _safe(p.cmdline, []),
            "create_time": _safe(p.create_time, 0.0),
            "num_threads": _safe(p.num_threads, 0),
            "num_fds": _safe(p.num_fds, 0),
            "cpu_percent": _safe(lambda: p.cpu_percent(interval=None), 0.0),
            "memory_rss": _safe(lambda: p.memory_info().rss, 0),
        }

    socket_map = load_socket_map()
    fds = [
        {
            "fd": e.fd,
            "target": e.target,
            "kind": e.kind,
            "deleted": e.deleted,
            "addr": e.addr,
        }
        for e in read_fds(pid, socket_map=socket_map)
    ]

    def _addr_str(a) -> str | None:
        # psutil returns a (ip, port) namedtuple for AF_INET/AF_INET6 and a
        # plain string (the socket path) for AF_UNIX. Empty string means
        # unbound. Treat all of those uniformly.
        if not a:
            return None
        if isinstance(a, str):
            return _sanitize_addr(a) or None
        ip = getattr(a, "ip", None)
        port = getattr(a, "port", None)
        if ip is None:
            return None
        return f"{ip}:{port}" if port is not None else ip

    sockets: list[dict[str, Any]] = []
    for c in _safe(lambda: p.net_connections(kind="all"), []) or []:
        sockets.append(
            {
                "fd": c.fd if c.fd != -1 else None,
                "family": getattr(c.family, "name", str(c.family)),
                "type": getattr(c.type, "name", str(c.type)),
                "laddr": _addr_str(c.laddr),
                "raddr": _addr_str(c.raddr),
                "status": c.status,
            }
        )

    map_entries = read_maps(pid)
    from .security import SecurityConfig
    cfg = security_cfg if security_cfg is not None else SecurityConfig()
    annotate_system(map_entries, cfg.system_lib_prefixes)
    maps = [
        {
            "path": m.path,
            "size": m.size,
            "executable": m.executable,
            "deleted": m.deleted,
            "is_system": m.is_system,
        }
        for m in map_entries
    ]

    return {**meta, "fds": fds, "sockets": sockets, "maps": maps}


def collect_env(pid: int, show: bool) -> dict | None:
    """Return {count, env} or None if pid is gone.

    When show=False, only the count is returned (keys/values both hidden) so
    env-var names don't leak. When show=True, values for keys matching the
    redaction regex are masked.
    """
    try:
        env = psutil.Process(pid).environ()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None
    if not show:
        return {"count": len(env), "env": {}}
    masked: dict[str, str] = {}
    for k, v in env.items():
        if _REDACT_RE.search(k):
            masked[k] = "<redacted: key>"
        elif _value_looks_secret(v):
            masked[k] = "<redacted: value>"
        else:
            masked[k] = v
    return {"count": len(masked), "env": masked}
