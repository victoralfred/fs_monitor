"""Background process scanner. Maintains a snapshot and emits diffs."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from typing import Any

import psutil

from .history import HISTORY, ExecEvent
from .metrics import SCAN_DURATION
from .netwatch import CONNECTIONS
from .netwatch import scan as netwatch_scan
from .security import (
    SecurityConfig,
    compute_flags,
    invalidate_env_cache,
    paranoid_scan,
    prune_env_cache,
)

log = logging.getLogger(__name__)

# Module-level so create_app can inject; defaulted for tests/CLI.
SECURITY_CFG = SecurityConfig()

ProcDict = dict[str, Any]


@dataclass
class Diff:
    added: list[ProcDict]
    removed: list[int]
    changed: list[ProcDict]
    execed: list[int]      # pids whose cmdline changed (exec without fork)


def _snapshot() -> dict[int, ProcDict]:
    out: dict[int, ProcDict] = {}
    attrs = [
        "pid",
        "ppid",
        "name",
        "username",
        "status",
        "cpu_percent",
        "memory_info",
        "create_time",
        "cmdline",
    ]
    for p in psutil.process_iter(attrs=attrs, ad_value=None):
        info = p.info
        try:
            mem = info["memory_info"]
            cmdline = info["cmdline"] or []
            pid = info["pid"]
            ppid = info["ppid"] or 0
            name = info["name"] or ""
            started = float(info["create_time"] or 0.0)
            flags = compute_flags(
                pid, name, ppid, SECURITY_CFG,
                cmdline=cmdline, start_time=started,
            )
            out[pid] = {
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "user": info["username"] or "",
                "status": info["status"] or "",
                "cpu": float(info["cpu_percent"] or 0.0),
                "rss": int(mem.rss) if mem else 0,
                "started": started,
                "cmd": " ".join(cmdline),
                "flags": [f["id"] for f in flags],
                "_flag_detail": flags,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return out


def _public(p: ProcDict) -> ProcDict:
    """Strip internal-only fields before sending over the wire."""
    return {k: v for k, v in p.items() if not k.startswith("_")}


def _scan_and_finalize(prev: dict[int, ProcDict]):
    """Worker-thread entrypoint: take a fresh snapshot, diff against `prev`,
    update history, recompute flags for execed pids. Returns the new
    snapshot plus pre-stripped public lists ready for broadcast.
    """
    new = _snapshot()
    diff = _diff(prev, new)
    live_pids = set(new.keys())

    # Sparkline samples + history pruning.
    for pid, row in new.items():
        HISTORY.record(pid, row["cpu"], row["rss"])
    if diff.removed:
        HISTORY.prune(live_pids)

    # Timeline exec log.
    for row in diff.added:
        HISTORY.add_exec(ExecEvent(
            at=row["started"] or time.time(),
            pid=row["pid"], ppid=row["ppid"],
            name=row["name"], exe=None, cmd=row["cmd"],
            source="scanner",
        ))
    for pid in diff.execed:
        row = new.get(pid)
        if row:
            HISTORY.add_exec(ExecEvent(
                at=time.time(), pid=pid, ppid=row["ppid"],
                name=row["name"], exe=None, cmd=row["cmd"],
                source="scanner",
            ))

    # B3: drop cached environ for execed/dead pids, then re-run flags
    # for execed pids with the fresh environ.
    for pid in diff.execed:
        invalidate_env_cache(SECURITY_CFG, pid)
    if diff.removed:
        prune_env_cache(SECURITY_CFG, live_pids)
    for pid in diff.execed:
        row = new.get(pid)
        if row is None:
            continue
        fresh = compute_flags(
            pid, row["name"], row["ppid"], SECURITY_CFG,
            cmdline=row["cmd"].split(" "), start_time=row["started"],
        )
        row["flags"] = [f["id"] for f in fresh]
        row["_flag_detail"] = fresh

    public_added = [_public(p) for p in diff.added]
    public_changed = [_public(p) for p in diff.changed]
    return new, diff, public_added, public_changed


def _diff(old: dict[int, ProcDict], new: dict[int, ProcDict]) -> Diff:
    old_pids = set(old)
    new_pids = set(new)
    added_pids = new_pids - old_pids
    removed_pids = old_pids - new_pids
    common = old_pids & new_pids

    added = [new[p] for p in added_pids]
    removed = sorted(removed_pids)
    changed: list[ProcDict] = []
    execed: list[int] = []
    for pid in common:
        a, b = old[pid], new[pid]
        # exec-without-fork: same pid + same start time, but cmdline mutated.
        if a.get("cmd") != b.get("cmd") and a.get("started") == b.get("started"):
            execed.append(pid)
        if (
            abs(a["cpu"] - b["cpu"]) > 0.5
            or a["rss"] != b["rss"]
            or a["status"] != b["status"]
            or a.get("cmd") != b.get("cmd")
            or a.get("flags") != b.get("flags")
        ):
            changed.append(b)
    return Diff(added=added, removed=removed, changed=changed, execed=execed)


class Scanner:
    def __init__(self, interval: float = 2.0, scan_timeout: float = 10.0) -> None:
        self.interval = interval
        self.scan_timeout = scan_timeout
        self.snapshot: dict[int, ProcDict] = {}
        self.last_scan_ms: float = 0.0
        self.hidden_pids: list[int] = []
        self.last_paranoid_at: float = 0.0
        self.paranoid_error_count: int = 0
        self.scan_timeout_count: int = 0
        self.last_netwatch_at: float = 0.0
        self.netwatch_error_count: int = 0
        self._subscribers: set[asyncio.Queue] = set()
        self._task: asyncio.Task | None = None
        self._paranoid_task: asyncio.Task | None = None
        self._netwatch_task: asyncio.Task | None = None

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=8)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def public_snapshot(self) -> list[ProcDict]:
        return [_public(p) for p in self.snapshot.values()]

    def flag_detail(self, pid: int) -> list[dict]:
        row = self.snapshot.get(pid)
        return list(row.get("_flag_detail", [])) if row else []

    def _broadcast(self, message: dict[str, Any]) -> None:
        # Pre-serialize once. Subscribers each get the same string instead
        # of each WebSocket re-encoding the dict.
        payload = json.dumps(message, separators=(",", ":"))
        dead: list[asyncio.Queue] = []
        for q in self._subscribers:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(q)
                log.warning("ws subscriber lagging — dropping")
        for q in dead:
            self._subscribers.discard(q)

    def broadcast_raw(self, message: dict[str, Any]) -> None:
        """Public hook for shutdown messages etc."""
        self._broadcast(message)

    async def _run(self) -> None:
        # Prime cpu_percent so subsequent reads are non-zero.
        psutil.cpu_percent(interval=None)
        for p in psutil.process_iter():
            try:
                p.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        while True:
            t0 = time.monotonic()
            try:
                # R8: bound scan duration; a hung /proc read should not stall forever.
                # T2: do all post-snapshot work in the worker, then assign atomically.
                prev = self.snapshot
                new, diff, public_added, public_changed = await asyncio.wait_for(
                    asyncio.to_thread(_scan_and_finalize, prev),
                    timeout=self.scan_timeout,
                )
                self.snapshot = new
                self.last_scan_ms = (time.monotonic() - t0) * 1000.0
                SCAN_DURATION.observe(self.last_scan_ms / 1000.0)
                if diff.added or diff.removed or diff.changed or diff.execed:
                    self._broadcast(
                        {
                            "type": "diff",
                            "added": public_added,
                            "removed": diff.removed,
                            "changed": public_changed,
                            "execed": diff.execed,
                        }
                    )
            except TimeoutError:
                self.scan_timeout_count += 1
                log.warning(
                    "scanner tick exceeded %.1fs (count=%d)",
                    self.scan_timeout, self.scan_timeout_count,
                )
            except Exception:
                log.exception("scanner tick failed")
            await asyncio.sleep(max(0.0, self.interval - (time.monotonic() - t0)))

    async def _run_netwatch(self) -> None:
        """Periodic egress scan — every 5 s. Cheaper than paranoid; we run
        it more often because external connections matter.
        """
        while True:
            await asyncio.sleep(5.0)
            try:
                name_lookup = {p: r["name"] for p, r in self.snapshot.items()}
                conns = await asyncio.to_thread(netwatch_scan, name_lookup)
                CONNECTIONS.update(conns)
                CONNECTIONS.prune()
                self.last_netwatch_at = time.time()
            except Exception:
                self.netwatch_error_count += 1
                log.exception("netwatch scan failed (count=%d)", self.netwatch_error_count)

    async def _run_paranoid(self) -> None:
        """B7 background sweep — only active when SECURITY_CFG.paranoid is True.
        Runs every 10 s so it doesn't compete with the main scan tick.
        """
        while True:
            await asyncio.sleep(10.0)
            if not SECURITY_CFG.paranoid:
                continue
            try:
                live = set(self.snapshot.keys())
                hidden = await asyncio.to_thread(paranoid_scan, live)
                self.hidden_pids = hidden
                self.last_paranoid_at = time.time()
            except Exception:
                self.paranoid_error_count += 1
                log.exception("paranoid scan failed (count=%d)", self.paranoid_error_count)

    async def start(self) -> None:
        if self._task is None:
            self.snapshot = await asyncio.to_thread(_snapshot)
            self._task = asyncio.create_task(self._run(), name="scanner")
            self._paranoid_task = asyncio.create_task(
                self._run_paranoid(), name="scanner-paranoid"
            )
            self._netwatch_task = asyncio.create_task(
                self._run_netwatch(), name="scanner-netwatch"
            )

    async def stop(self) -> None:
        for t in (self._task, self._paranoid_task, self._netwatch_task):
            if t:
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass
        self._task = None
        self._paranoid_task = None
        self._netwatch_task = None
