"""Optional eBPF integration via bpftrace subprocess.

We don't link libbpf or use BCC's clang-at-runtime path. Instead we spawn
`bpftrace` with a single-liner that emits JSON for every `execve`. That
keeps the dependency story dead simple — bpftrace is one apt package
(`bpftrace`) and produces self-describing output. Requires CAP_BPF and
CAP_PERFMON (or root); if the spawn fails we log and run without.

Feature is off by default. Enable with `[ebpf].enabled = true` in
monitor.toml. The integration writes events directly into the global
history timeline so the UI's exec log surfaces ebpf entries alongside
scanner-derived ones.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import time

from .fswatch import FS
from .history import HISTORY, ExecEvent
from .metrics import EBPF_EVENTS
from .netwatch import CONNECTIONS, Conn, is_external

log = logging.getLogger(__name__)

# bpftrace program: emit JSON for execve, openat-for-write, unlinkat, and
# outbound tcp connect. Type discriminator on each line so the reader can
# route. We hand-roll the JSON (rather than relying on bpftrace's
# --format json) to stay portable across bpftrace versions.
#
# openat filter: O_CREAT (0x40) | O_TRUNC (0x200). We fire on opens that
# *create or truncate*, which matches the overwrite-payload shape. Pure
# reads don't trip this.
#
# tcp_v{4,6}_connect probes fire on every outbound TCP connect() — that's
# the only way to catch sub-second connections, because by the time a
# 1-second netwatch poll runs the socket is closed and unattributed.
# We read daddr/dport off struct sock. dport is network-byte-order, so we
# byteswap to host order before printing.
BPFTRACE_PROG = r"""
tracepoint:syscalls:sys_enter_execve
{
    printf("{\"t\":\"exec\",\"pid\":%d,\"ppid\":%d,\"comm\":\"%s\",\"argv0\":\"%s\"}\n",
           pid, curtask->real_parent->tgid, comm, str(args->filename));
}

tracepoint:syscalls:sys_enter_openat
/ (args->flags & 0x40) || (args->flags & 0x200) /
{
    printf("{\"t\":\"open\",\"pid\":%d,\"comm\":\"%s\",\"path\":\"%s\"}\n",
           pid, comm, str(args->filename));
}

tracepoint:syscalls:sys_enter_unlinkat
{
    printf("{\"t\":\"unlink\",\"pid\":%d,\"comm\":\"%s\",\"path\":\"%s\"}\n",
           pid, comm, str(args->pathname));
}

kprobe:tcp_v4_connect
{
    $sk = (struct sock *)arg0;
    $dport = (uint16)$sk->__sk_common.skc_dport;
    $dport = ($dport >> 8) | (($dport & 0xff) << 8);
    printf("{\"t\":\"connect\",\"pid\":%d,\"comm\":\"%s\",\"family\":4,\"daddr\":\"%s\",\"dport\":%d}\n",
           pid, comm, ntop(2, $sk->__sk_common.skc_daddr), $dport);
}

kprobe:tcp_v6_connect
{
    $sk = (struct sock *)arg0;
    $dport = (uint16)$sk->__sk_common.skc_dport;
    $dport = ($dport >> 8) | (($dport & 0xff) << 8);
    printf("{\"t\":\"connect\",\"pid\":%d,\"comm\":\"%s\",\"family\":6,\"daddr\":\"%s\",\"dport\":%d}\n",
           pid, comm, ntop(10, $sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8), $dport);
}
"""


class EbpfTracer:
    def __init__(self) -> None:
        self._proc: asyncio.subprocess.Process | None = None
        self._task: asyncio.Task | None = None

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    async def start(self) -> bool:
        if not shutil.which("bpftrace"):
            log.info("bpftrace not on PATH; eBPF tracing disabled")
            return False
        try:
            self._proc = await asyncio.create_subprocess_exec(
                "bpftrace", "-q", "-e", BPFTRACE_PROG,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as e:
            log.warning("failed to spawn bpftrace: %s", e)
            return False
        # Give bpftrace a moment to fail (permission errors are loud).
        await asyncio.sleep(0.5)
        if self._proc.returncode is not None:
            stderr = (await self._proc.stderr.read()).decode("utf-8", "replace")
            log.warning(
                "bpftrace exited rc=%s; running without eBPF.\nstderr: %s",
                self._proc.returncode, stderr.strip()[:400],
            )
            self._proc = None
            return False
        self._task = asyncio.create_task(self._read_loop(), name="ebpf-reader")
        log.info("eBPF tracing active")
        return True

    async def _read_loop(self) -> None:
        assert self._proc and self._proc.stdout
        try:
            await self._read_lines()
        finally:
            # If we exit the read loop for any reason, the subprocess is
            # no longer producing useful data. Mark it dead so /api/timeline
            # reflects reality.
            if self._proc and self._proc.returncode is None:
                try:
                    self._proc.terminate()
                except ProcessLookupError:
                    pass
            log.warning("eBPF reader exited; tracer marked down")
            self._proc = None

    async def _read_lines(self) -> None:
        assert self._proc and self._proc.stdout
        async for raw in self._proc.stdout:
            line = raw.decode("utf-8", "replace").strip()
            if not line or line.startswith("Attaching") or line.startswith("Lost"):
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            try:
                t = rec.get("t", "exec")
                pid = int(rec.get("pid", 0))
                comm = str(rec.get("comm", ""))
                if t == "exec":
                    HISTORY.add_exec(ExecEvent(
                        at=time.time(),
                        pid=pid,
                        ppid=int(rec.get("ppid", 0)),
                        name=comm,
                        exe=str(rec.get("argv0") or "") or None,
                        cmd=str(rec.get("argv0", "")),
                        source="ebpf",
                    ))
                elif t == "open":
                    FS.record_write(pid, comm, str(rec.get("path", "")))
                elif t == "unlink":
                    FS.record_unlink(pid, comm, str(rec.get("path", "")))
                elif t == "connect":
                    self._handle_connect(pid, comm, rec)
                EBPF_EVENTS.inc()
            except (TypeError, ValueError):
                continue

    @staticmethod
    def _handle_connect(pid: int, comm: str, rec: dict) -> None:
        """A1: every outbound TCP connect() lands here within milliseconds
        of the SYN. Fills the gap where a polling-based netwatch (even at
        1 s) would miss a 50 ms curl that exits before the next tick.
        """
        try:
            daddr = str(rec.get("daddr", "")).strip()
            dport = int(rec.get("dport", 0))
            family = int(rec.get("family", 4))
        except (TypeError, ValueError):
            return
        if not daddr or dport <= 0:
            return
        # Format the raddr the same way netwatch does for consistency.
        raddr = f"[{daddr}]:{dport}" if family == 6 else f"{daddr}:{dport}"
        proto = "tcp6" if family == 6 else "tcp"
        now = time.time()
        CONNECTIONS.update([Conn(
            pid=pid, comm=comm, proto=proto,
            laddr=None, raddr=raddr,
            state="CONNECT",  # marks an ebpf-sourced intent record
            external=is_external(daddr),
            first_seen=now, last_seen=now,
        )])

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self._proc and self._proc.returncode is None:
            try:
                self._proc.terminate()
                try:
                    await asyncio.wait_for(self._proc.wait(), timeout=2.0)
                except TimeoutError:
                    self._proc.kill()
                    await self._proc.wait()
            except ProcessLookupError:
                pass
        self._proc = None
