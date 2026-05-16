"""Prometheus metrics. Exposed at GET /metrics.

Kept small on purpose — these are the gauges/histograms an operator
actually needs to alert on. Adding more should require justifying that
they answer a real question.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

SCAN_DURATION = Histogram(
    "monitor_scan_duration_seconds",
    "Time spent in a single scanner tick (after timeout enforcement).",
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0),
)
SCAN_TIMEOUTS = Counter(
    "monitor_scan_timeouts_total",
    "Scanner ticks that exceeded the configured scan timeout.",
)
PROCS_TRACKED = Gauge(
    "monitor_procs_tracked",
    "Number of processes in the current snapshot.",
)
WS_SUBSCRIBERS = Gauge(
    "monitor_ws_subscribers",
    "Currently connected websocket clients.",
)
FLAGS_FIRING = Gauge(
    "monitor_flags_firing",
    "Number of distinct security flags firing right now.",
    ["flag"],
)
PARANOID_HIDDEN = Gauge(
    "monitor_paranoid_hidden_pids",
    "Hidden-pid candidates from the most recent paranoid sweep.",
)
KILLS_SENT = Counter(
    "monitor_kills_sent_total",
    "Signals successfully delivered via the kill endpoint.",
    ["signal"],
)
RATE_LIMITED = Counter(
    "monitor_rate_limited_total",
    "Requests rejected by the rate limiter.",
    ["method", "prefix"],
)
EBPF_EVENTS = Counter(
    "monitor_ebpf_events_total",
    "Exec events received from the bpftrace subprocess.",
)
EXTERNAL_CONNECTIONS = Gauge(
    "monitor_external_connections",
    "Distinct (pid, remote, proto) tuples with a routable-internet remote.",
)
