#!/usr/bin/env python3
"""Benchmark psutil.net_connections vs raw /proc/net/* parsing.

Spawns N TCP listeners in this process, then times both approaches for
resolving "what sockets does this process own?". Answers the long-standing
plan.md open question.

Usage:
    python scripts/bench_sockets.py            # default N values
    python scripts/bench_sockets.py 100 500 2000
"""

from __future__ import annotations

import os
import socket
import statistics
import sys
import time

import psutil

from monitor.sockets import load_socket_map


def open_listeners(n: int) -> list[socket.socket]:
    socks: list[socket.socket] = []
    for _ in range(n):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        socks.append(s)
    return socks


def time_call(fn, *, repeats: int = 5) -> tuple[float, float]:
    samples: list[float] = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    return statistics.median(samples), max(samples)


def via_psutil() -> int:
    return len(psutil.Process(os.getpid()).net_connections(kind="all"))


def via_proc_net() -> int:
    # Build the inode map + filter to our own fds.
    m = load_socket_map()
    pid = os.getpid()
    base = f"/proc/{pid}/fd"
    count = 0
    for name in os.listdir(base):
        try:
            target = os.readlink(f"{base}/{name}")
        except OSError:
            continue
        if not target.startswith("socket:["):
            continue
        try:
            inode = int(target[len("socket:["):-1])
        except ValueError:
            continue
        if inode in m:
            count += 1
    return count


def bench(n: int) -> None:
    listeners = open_listeners(n)
    try:
        # Warm both paths once (psutil caches some metadata).
        via_psutil()
        via_proc_net()
        psu_med, psu_max = time_call(via_psutil)
        proc_med, proc_max = time_call(via_proc_net)
        print(
            f"N={n:>5}  psutil: {psu_med:6.2f} ms (max {psu_max:6.2f})   "
            f"/proc/net: {proc_med:6.2f} ms (max {proc_max:6.2f})"
        )
    finally:
        for s in listeners:
            s.close()


def main() -> None:
    sizes = [int(x) for x in sys.argv[1:]] or [100, 500, 2000]
    print("Per-process socket enumeration — lower is better, 5 samples each")
    for n in sizes:
        bench(n)


if __name__ == "__main__":
    main()
