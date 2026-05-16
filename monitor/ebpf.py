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

log = logging.getLogger(__name__)

# bpftrace program: emit JSON for execve, openat-for-write, and unlinkat.
# Type discriminator on each line so the reader can route. We hand-roll the
# JSON (rather than relying on bpftrace's --format json) to stay portable
# across bpftrace versions.
#
# openat filter: O_CREAT (0x40) | O_TRUNC (0x200) | O_WRONLY (0x1). We fire
# on opens that *create or truncate*, which matches the overwrite-payload
# shape. Pure reads don't trip this.
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
                EBPF_EVENTS.inc()
            except (TypeError, ValueError):
                continue

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
