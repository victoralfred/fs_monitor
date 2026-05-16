"""Per-process security indicators ("Lite" tier).

Cheap unprivileged signals computed during the scanner tick. No eBPF,
no root, no syscalls beyond readlink/open on /proc. Tuning lives in the
TOML config's `[security]` table.

Indicators currently implemented:

- exe_suspicious_path  — /proc/<pid>/exe resolves under a flagged prefix
                         (default: /tmp, /dev/shm, /var/tmp, /run/user)
                         with an optional allowlist for known-safe shapes
                         (Flatpak under /run/user is excluded by default).
- exe_deleted_or_memfd — /proc/<pid>/exe ends with " (deleted)" or starts
                         with /memfd: — fileless / unlinked binary.
- kthread_impersonation — comm wrapped in [brackets] but ppid != 0/2 *or*
                         the exe link resolves to a real file. Real kernel
                         threads have no exe link and ppid in {0, 2}.

Each indicator returns a dict {id, severity, evidence}. The scanner stores
the list per pid; the API exposes it; the UI surfaces a red dot in the
tree and a Security tab in the detail panel.

Pure functions where possible — given an `exe_link` string and a `comm`
plus ppid, the classifiers are testable without /proc.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field

# Defaults — config can override.
DEFAULT_SUSPICIOUS_PREFIXES = ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/")
DEFAULT_ALLOWLIST_SUBSTRINGS = (
    "flatpak",        # /var/lib/flatpak/..., /run/user/<uid>/.flatpak-xxx/...
    "snap",           # /snap/<app>/current/...
    "appimage",       # /tmp/.mount_<App>.AppImage/...
)
# Multi-call binaries — argv[0] legitimately mismatches the exe basename.
DEFAULT_MULTICALL_BINS = ("busybox", "toybox", "coreutils")
# Interpreters whose argv[0] often names a script rather than the exe.
DEFAULT_INTERPRETER_BINS = (
    "python", "python3", "node", "perl", "ruby", "java",
    "bash", "sh", "dash", "zsh", "fish",
)
# Library paths considered "system" — anything outside these gets a B4 badge.
DEFAULT_SYSTEM_LIB_PREFIXES = (
    "/usr/", "/lib/", "/lib32/", "/lib64/", "/opt/",
    "/snap/", "/var/lib/flatpak/", "/nix/store/",
)
# Env-var KEY names that fire B3 (case-sensitive: these are exact Linux names).
DEFAULT_DANGEROUS_ENV_KEYS = ("LD_PRELOAD", "LD_AUDIT")


@dataclass
class SecurityConfig:
    suspicious_prefixes: tuple[str, ...] = DEFAULT_SUSPICIOUS_PREFIXES
    allowlist_substrings: tuple[str, ...] = DEFAULT_ALLOWLIST_SUBSTRINGS
    multicall_bins: tuple[str, ...] = DEFAULT_MULTICALL_BINS
    interpreter_bins: tuple[str, ...] = DEFAULT_INTERPRETER_BINS
    system_lib_prefixes: tuple[str, ...] = DEFAULT_SYSTEM_LIB_PREFIXES
    dangerous_env_keys: tuple[str, ...] = DEFAULT_DANGEROUS_ENV_KEYS
    # Paranoid mode (B7): off by default; opt-in via [security].paranoid.
    paranoid: bool = False
    # Internal caches keyed by (pid, start_time). Locked because the scanner
    # thread, detail-endpoint workers, and the ebpf reader all touch them.
    _env_cache: dict = field(default_factory=dict, repr=False, compare=False)
    _exe_cache: dict = field(default_factory=dict, repr=False, compare=False)
    _comm_cache: dict = field(default_factory=dict, repr=False, compare=False)
    _cache_lock: threading.Lock = field(
        default_factory=threading.Lock, repr=False, compare=False
    )


def classify_exe_path(exe_link: str | None, cfg: SecurityConfig) -> dict | None:
    """Return an indicator dict if exe_link looks suspicious, else None.

    `exe_link` is the raw readlink result for /proc/<pid>/exe, or None on
    permission denied / kernel thread.
    """
    if not exe_link:
        return None
    if exe_link.endswith(" (deleted)") or exe_link.startswith("/memfd:"):
        # Handled by classify_exe_deleted_or_memfd; don't double-fire here.
        return None
    lower = exe_link.lower()
    if any(sub in lower for sub in cfg.allowlist_substrings):
        return None
    for prefix in cfg.suspicious_prefixes:
        if exe_link.startswith(prefix):
            return {
                "id": "exe_suspicious_path",
                "severity": "high",
                "evidence": f"exe → {exe_link}",
            }
    return None


def classify_exe_deleted_or_memfd(exe_link: str | None) -> dict | None:
    if not exe_link:
        return None
    if exe_link.startswith("/memfd:"):
        return {
            "id": "exe_memfd",
            "severity": "high",
            "evidence": f"exe → {exe_link} (memory-resident binary)",
        }
    if exe_link.endswith(" (deleted)"):
        return {
            "id": "exe_deleted",
            "severity": "high",
            "evidence": f"exe → {exe_link} (backing file unlinked)",
        }
    return None


def classify_kthread_impersonation(comm: str, ppid: int, exe_link: str | None) -> dict | None:
    """A real kernel thread has `comm` like "[kworker/0:1]" AND no exe link
    AND ppid in {0, 2}. Anything that names itself like a kernel thread but
    has an exe is masquerading.
    """
    if not (comm.startswith("[") and comm.endswith("]")):
        return None
    if ppid in (0, 2) and not exe_link:
        return None
    return {
        "id": "kthread_impersonation",
        "severity": "high",
        "evidence": f"comm={comm!r} ppid={ppid} exe={exe_link or '<none>'}",
    }


def classify_argv_mismatch(
    cmdline: list[str] | str | None,
    exe_link: str | None,
    cfg: SecurityConfig,
    comm: str | None = None,
) -> dict | None:
    """B5: argv[0] vs basename(exe) divergence.

    Accept both a list (psutil) and a space-joined string (scanner snapshot
    convenience). Don't fire if:
    - exe link is missing (kernel thread or permission denied)
    - exe is already deleted/memfd (B2 handles it)
    - exe is in a suspicious path (B1 handles it; piling on adds noise)
    - the exe basename is a known multi-call or interpreter binary
    - argv[0] is empty (kernel threads, daemonized processes)
    - basename(exe) appears anywhere in argv[0], or vice versa
    """
    if not exe_link or exe_link.endswith(" (deleted)") or exe_link.startswith("/memfd:"):
        return None
    # Suppress when B1 would already fire to avoid duplicate noise.
    if any(exe_link.startswith(p) for p in cfg.suspicious_prefixes) and not any(
        sub in exe_link.lower() for sub in cfg.allowlist_substrings
    ):
        return None

    if isinstance(cmdline, list):
        argv0 = cmdline[0] if cmdline else ""
    else:
        argv0 = (cmdline or "").split(" ", 1)[0]
    if not argv0:
        return None
    # Chromium-style apps re-exec themselves via /proc/self/exe — a known
    # legitimate pattern. argv[0] won't match exe by definition.
    if argv0 == "/proc/self/exe" or argv0.startswith("/proc/") and argv0.endswith("/exe"):
        return None

    exe_base = os.path.basename(exe_link).lower()
    # Strip common suffixes for fuzzy compare: "python3.12" → "python3" → "python"
    exe_stem = exe_base
    while exe_stem and exe_stem[-1].isdigit() or (exe_stem.endswith(".") if exe_stem else False):
        exe_stem = exe_stem.rstrip("0123456789.")
        if exe_stem == exe_base:
            break

    if any(exe_stem.startswith(b) for b in cfg.multicall_bins):
        return None
    if any(exe_stem == b or exe_stem.startswith(b) for b in cfg.interpreter_bins):
        return None

    argv0_base = os.path.basename(argv0).lower().lstrip("-")  # "-bash" → "bash"
    # Permissive: any substring match in either direction is fine.
    if exe_stem and (exe_stem in argv0_base or argv0_base in exe_stem):
        return None
    if exe_base in argv0.lower() or argv0_base in exe_base:
        return None
    # Also accept a match against /proc/<pid>/comm — process name. This
    # covers apps whose exe is a versioned binary (e.g. claude →
    # ~/.local/share/claude/versions/2.1.143) but whose comm matches argv[0].
    if comm:
        c = comm.lower().strip("[]")
        if c and (c in argv0_base or argv0_base in c):
            return None

    return {
        "id": "argv_exe_mismatch",
        "severity": "medium",
        "evidence": f"argv[0]={argv0!r} but exe → {exe_link}",
    }


def _read_environ(pid: int) -> bytes | None:
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            return f.read()
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return None


def _scan_for_dangerous_env(pid: int, dangerous_keys: tuple[str, ...]) -> list[str]:
    data = _read_environ(pid)
    if data is None:
        return []
    found: list[str] = []
    key_bytes = [k.encode() for k in dangerous_keys]
    for kv in data.split(b"\x00"):
        if not kv:
            continue
        eq = kv.find(b"=")
        if eq < 0:
            continue
        k = kv[:eq]
        for kb, kname in zip(key_bytes, dangerous_keys, strict=True):
            if k == kb:
                found.append(kname)
                break
    return found


def check_dangerous_env(
    pid: int,
    start_time: float,
    cfg: SecurityConfig,
    exe_link: str | None = None,
) -> dict | None:
    """B3: LD_PRELOAD / LD_AUDIT in /proc/<pid>/environ.

    Cached by (pid, start_time). The cache is invalidated by the scanner
    when it sees the `execed` signal (cmdline change with unchanged start
    time) — exec replaces the env without changing start_time.

    Suppressed when `exe_link` is under a known sandbox path (snap,
    flatpak, etc.) — those launchers legitimately inject LD_PRELOAD.
    """
    if exe_link and any(sub in exe_link.lower() for sub in cfg.allowlist_substrings):
        return None
    key = (pid, start_time)
    with cfg._cache_lock:
        if key not in cfg._env_cache:
            # Release the lock for the actual /proc read.
            need_scan = True
        else:
            need_scan = False
            found = cfg._env_cache[key]
    if need_scan:
        found = _scan_for_dangerous_env(pid, cfg.dangerous_env_keys)
        with cfg._cache_lock:
            cfg._env_cache.setdefault(key, found)
            found = cfg._env_cache[key]
    if not found:
        return None
    return {
        "id": "dangerous_env",
        "severity": "high",
        "evidence": f"environ has {', '.join(found)}",
    }


def invalidate_env_cache(cfg: SecurityConfig, pid: int) -> None:
    """Drop ALL cache entries for `pid` (any start_time). Used on exec."""
    with cfg._cache_lock:
        for cache in (cfg._env_cache, cfg._exe_cache, cfg._comm_cache):
            for key in list(cache.keys()):
                if key[0] == pid:
                    del cache[key]


def prune_env_cache(cfg: SecurityConfig, live_pids: set[int]) -> None:
    """Drop entries for pids no longer alive. Called periodically."""
    with cfg._cache_lock:
        for cache in (cfg._env_cache, cfg._exe_cache, cfg._comm_cache):
            for key in list(cache.keys()):
                if key[0] not in live_pids:
                    del cache[key]


def _cached_exe(cfg: SecurityConfig, pid: int, start_time: float) -> str | None:
    """exe-link cache. Returns None if unreadable (kernel thread, perm)."""
    key = (pid, start_time)
    with cfg._cache_lock:
        if key in cfg._exe_cache:
            return cfg._exe_cache[key]
    val = _read_exe_link(pid)
    with cfg._cache_lock:
        cfg._exe_cache.setdefault(key, val)
        return cfg._exe_cache[key]


def _cached_comm(cfg: SecurityConfig, pid: int, start_time: float, fallback: str) -> str:
    key = (pid, start_time)
    with cfg._cache_lock:
        if key in cfg._comm_cache:
            return cfg._comm_cache[key]
    val = _read_comm(pid) or fallback
    with cfg._cache_lock:
        cfg._comm_cache.setdefault(key, val)
        return cfg._comm_cache[key]


def _read_exe_link(pid: int) -> str | None:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return None


def classify_external_egress_from_suspicious(
    exe_link: str | None,
    pid: int,
    cfg: SecurityConfig,
    connections,  # netwatch.ConnectionLog; passed explicitly to avoid a circular import
) -> dict | None:
    """Compound flag: process whose exe is in a suspicious path AND who
    holds at least one external connection. Cheap — one dict scan over
    the already-populated connections log.
    """
    if not exe_link:
        return None
    if not any(exe_link.startswith(p) for p in cfg.suspicious_prefixes):
        return None
    if any(sub in exe_link.lower() for sub in cfg.allowlist_substrings):
        return None

    remotes: list[str] = []
    with connections._lock:
        for (cpid, raddr, _proto), conn in connections.seen.items():
            if cpid == pid and conn.external:
                remotes.append(raddr)
                if len(remotes) >= 3:
                    break
    if not remotes:
        return None
    return {
        "id": "external_egress_from_suspicious",
        "severity": "high",
        "evidence": (
            f"exe → {exe_link}; external conn to {', '.join(remotes)}"
        ),
    }


def compute_flags(
    pid: int,
    name: str,
    ppid: int,
    cfg: SecurityConfig,
    cmdline: list[str] | str | None = None,
    start_time: float | None = None,
    connections=None,    # netwatch.ConnectionLog
    fs=None,             # fswatch.FsAggregator
) -> list[dict]:
    """Run all indicators against a single pid. Non-fatal on /proc races;
    missing data just suppresses the relevant check. `cmdline` and
    `start_time` are needed for B5 and B3; if not provided those checks
    are skipped.
    """
    flags: list[dict] = []
    if start_time is not None:
        exe = _cached_exe(cfg, pid, start_time)
        comm = _cached_comm(cfg, pid, start_time, name)
    else:
        exe = _read_exe_link(pid)
        comm = _read_comm(pid) or name

    for f in (
        classify_exe_deleted_or_memfd(exe),
        classify_exe_path(exe, cfg),
        classify_kthread_impersonation(comm, ppid, exe),
    ):
        if f:
            flags.append(f)

    if cmdline is not None:
        f = classify_argv_mismatch(cmdline, exe, cfg, comm=comm)
        if f:
            flags.append(f)

    if start_time is not None:
        f = check_dangerous_env(pid, start_time, cfg, exe_link=exe)
        if f:
            flags.append(f)

    # Compound: suspicious exe + external connection. Requires connections.
    if connections is not None:
        f = classify_external_egress_from_suspicious(exe, pid, cfg, connections)
        if f:
            flags.append(f)

    # Phase 10 A3: filesystem burst flags from the eBPF aggregator. No-op
    # when eBPF isn't running or fs isn't provided.
    if fs is not None:
        flags.extend(fs.flag(pid))

    return flags


def paranoid_scan(live_pids: set[int]) -> list[int]:
    """B7: probe pids in [1, upper_bound) with kill(0). Pids that respond
    (success or EPERM — both prove the pid exists) but aren't in
    `live_pids` are hidden-process candidates.

    upper_bound is min(pid_max, max(live_pids) + 1024). Probing past the
    highest live pid is wasted work; the +1024 catches near-future pids
    a rootkit might be hiding.
    """
    try:
        with open("/proc/sys/kernel/pid_max") as f:
            pid_max = int(f.read().strip())
    except (FileNotFoundError, ValueError):
        pid_max = 32768
    upper = min(pid_max, (max(live_pids) if live_pids else 0) + 1024)

    hidden: list[int] = []
    for p in range(1, upper):
        if p in live_pids:
            continue
        try:
            os.kill(p, 0)
            hidden.append(p)
        except ProcessLookupError:
            pass
        except PermissionError:
            hidden.append(p)
        except OSError:
            pass
    return hidden


def _read_comm(pid: int) -> str | None:
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return None


def config_from_toml(security_table: dict) -> SecurityConfig:
    """Build a SecurityConfig from the TOML [security] table. Unknown keys
    are ignored; missing keys keep defaults.
    """
    return SecurityConfig(
        suspicious_prefixes=tuple(
            security_table.get("suspicious_prefixes", DEFAULT_SUSPICIOUS_PREFIXES)
        ),
        allowlist_substrings=tuple(
            security_table.get("allowlist_substrings", DEFAULT_ALLOWLIST_SUBSTRINGS)
        ),
        multicall_bins=tuple(
            security_table.get("multicall_bins", DEFAULT_MULTICALL_BINS)
        ),
        interpreter_bins=tuple(
            security_table.get("interpreter_bins", DEFAULT_INTERPRETER_BINS)
        ),
        system_lib_prefixes=tuple(
            security_table.get("system_lib_prefixes", DEFAULT_SYSTEM_LIB_PREFIXES)
        ),
        dangerous_env_keys=tuple(
            security_table.get("dangerous_env_keys", DEFAULT_DANGEROUS_ENV_KEYS)
        ),
        paranoid=bool(security_table.get("paranoid", False)),
    )
