# Changelog

Loosely follows [Keep a Changelog](https://keepachangelog.com/). Dates in
ISO 8601.

## 2026-05-16 — Phase 10 (supply-chain attack coverage)

### Added
- Netwatch cadence dropped 5 s → 1 s with adaptive back-off (interval
  doubles after a slow tick, halves after a fast one).
- `monitor/enrichment.py`: lazy reverse-DNS + optional MaxMind ASN
  lookup with 1-hour TTL cache, inflight dedup, 4-thread pool. Network
  panel rows now show "(Cloudflare, ptr.example.com)" next to each
  external remote.
- `monitor/fswatch.py`: per-pid rolling 5-second window of opens-for-
  write and unlinks, fed by two new bpftrace probes (openat with
  O_TRUNC|O_CREAT, unlinkat). New security flags `fs_write_burst`
  (>25 distinct files) and `fs_mass_delete` (>10 unlinks). Allowlists
  for noisy build/install tools and expected-noisy paths.
- 13 new tests (9 fswatch + 4 enrichment).

### Changed
- `Conn` dataclass gains `ptr`, `asn`, `asn_org` fields.
- bpftrace program now multi-probe; reader switches on a `t` (type)
  discriminator field.
- `compute_flags` calls into `fswatch.FS.flag()` so write-burst /
  mass-delete signals fire on the next scanner tick after the threshold
  trips.
- `/metrics` flag inventory adds `fs_write_burst` and `fs_mass_delete`.

## 2026-05-16 — Phase 9 (network egress tracking)

### Added
- `monitor/netwatch.py`: periodic scan (5 s cadence) attributing every
  open inet socket to a pid + comm, classifying remotes as external or
  internal, tracking first-/last-seen per `(pid, raddr, proto)`.
- `GET /api/connections?external_only=1` endpoint.
- New 🌐 toolbar button toggles a Network panel. External connections
  highlighted with a red pill. Click pid to select in tree.
- Compound security flag `external_egress_from_suspicious` — exe in a
  suspicious path + at least one external connection. Highest-signal
  heuristic so far.
- Prometheus gauge `monitor_external_connections`.
- 9 new tests for the classifier and connection log.

### Honest limitations
- Without root / CAP_NET_ADMIN, only sockets owned by the running user
  are visible. Documented in the module docstring.
- Sub-5-second connections may be missed; eBPF `tcp_connect` tracing
  would close this gap and is deferred.

## 2026-05-16 — Phase 8 (production-readiness review)

### Added
- Prometheus `/metrics` endpoint (`monitor/metrics.py`): scan duration
  histogram, procs/ws-subscribers/paranoid-hidden gauges, per-flag counts,
  kill/rate-limit/ebpf counters.
- Structured JSON logging via `python-json-logger`
  (`monitor/logging_config.py`).
- Security headers middleware (CSP, X-Frame-Options, Referrer-Policy,
  Permissions-Policy, X-Content-Type-Options).
- In-process rate limiter middleware. Defaults: 10 POST/min/host,
  60 timeline-GET/min/host.
- CSRF token endpoint `GET /api/csrf`; required on
  `POST /api/processes/{pid}/signal`.
- PID-recycling guard on the kill endpoint: validates
  `/proc/<pid>/stat` start_time before AND after the ACL check; accepts
  optional `expected_start` from the caller for fast fail.
- Env-var value scrubbing for URL creds, JWTs, AWS access keys, PEM
  private keys, GitHub-style tokens.
- Frontend `ErrorBoundary` so render-time exceptions don't blank the app.
- Socket address sanitization (control chars stripped; abstract sockets
  shown with `@` prefix).
- Scanner-tick watchdog via `asyncio.wait_for`; timeouts counted and
  logged.
- eBPF reader watchdog: subprocess EOF marks tracer down.
- Paranoid health fields: `stale_seconds`, `error_count`, `healthy`.

### Changed
- Scanner now caches exe-link and comm by `(pid, start_time)` under a
  `threading.Lock`. Roughly halves syscall load on stable workloads.
- Scanner finalizes the entire snapshot + diff + history + flag work in
  the worker thread; main loop assigns `self.snapshot = new` atomically.
- Paranoid scan upper bound changed to `max(live_pids) + 1024` instead of
  full pid_max.
- WS broadcast pre-serializes JSON once; subscribers receive the same
  string via `send_text`. Pre-shutdown clients get
  `{"type": "shutdown"}`.
- Frontend sparklines no longer poll `/history`; samples appended from the
  WS stream after one seed fetch.
- Frontend timeline uses `?since=` to fetch only new events.
- `load_socket_map` cached for 500 ms behind a lock.
- Timeline buffer raised from 500 → 2000 events.

## 2026-05-16 — Phase 6 (visibility & control)

### Added
- Per-pid cpu/rss sparklines in the detail header (`monitor/history.py`,
  `web/src/sparkline.jsx`, `GET /api/processes/{pid}/history`). 60-sample
  ring buffer per pid, pruned on death.
- Exec timeline panel: rolling 500-event in-memory log of new and execed
  pids, surfaced via `GET /api/timeline` and a toolbar `⏱` toggle that
  replaces the tree with a chronological event list.
- Optional eBPF exec tracing via a `bpftrace` subprocess
  (`monitor/ebpf.py`). Emits JSON `sys_enter_execve` events that merge
  into the timeline alongside scanner-derived events. Off by default;
  enable with `[ebpf].enabled = true`. Requires bpftrace on PATH and
  CAP_BPF/CAP_PERFMON.
- Process signalling: `POST /api/processes/{pid}/signal` with a six-signal
  allowlist (SIGTERM/INT/HUP/KILL/STOP/CONT). Off by default. ACL via
  `[security].kill_acl = "same_user"|"none"|"all"`. UI: signal picker +
  two-step confirm in the detail header.

### Changed
- `_addr_str` helper in collector normalizes psutil socket addresses (UNIX
  socket paths come through as plain strings, not namedtuples).
- Phase split: original "Phase 6 — Possible future directions" reorganized
  into Phase 6 (shipped: #2, #3, #4, #7) and Phase 7 (deferred: #1 export,
  #5 auth, #6 multi-host).

## 2026-05-16 — Phase 4 + 5 (security Standard + Paranoid)

### Added — security signals
- `argv_exe_mismatch` (B5): flags processes whose `argv[0]` and exe
  basename diverge, with allowlists for multi-call binaries and
  interpreters. Suppressed when B1 already fires.
- "non-system" badge on the libs detail tab (B4): library paths outside
  `/usr`, `/lib*`, `/opt`, `/snap`, `/var/lib/flatpak`, `/nix/store`
  get a yellow badge.
- `dangerous_env` (B3): flags processes with `LD_PRELOAD` or `LD_AUDIT`
  in environ. Cached by `(pid, start_time)`; invalidated on the existing
  exec signal; pruned when pids die.
- Paranoid mode (B7, opt-in): pid-range sweep via `kill(0)` finds pids
  that respond but aren't in `/proc`. Runs on a 10 s cadence in a second
  asyncio task. Surfaces as a top-of-app red banner. Enable with
  `[security].paranoid = true`.
- `GET /api/security/paranoid` endpoint reports `{enabled, hidden_pids,
  last_scan_at}`.

### Changed
- `compute_flags` signature extended with optional `cmdline` and
  `start_time` so callers can opt in to B3/B5 (scanner always provides).
- `monitor.example.toml` documents all six new `[security]` keys.

## 2026-05-16 — Phase 3

### Added — hygiene
- WebSocket origin check on `/ws`; cross-origin browser connections close
  with code 1008.
- Toolbar `scanner_lag_ms` indicator turns red when over the 500 ms budget.
- Frontend Vitest suite covering `buildTree` and the `applyDiff` reducer.
- Detail panel consumes the same WebSocket diff stream as the tree via a
  Preact context; no more `setInterval` polling per selection.
- CI workflow (`.github/workflows/ci.yml`): three jobs — backend
  (pytest + ruff), frontend (pnpm lint + test + build), docker build.
- Lint configs: `ruff` for Python, `eslint` + `prettier` for the frontend.
  `pnpm format` rewrites; `pnpm lint` checks.
- `scripts/bench_sockets.py` benchmarks psutil vs raw `/proc/net/*`
  parsing for per-process socket enumeration.
- CHANGELOG.md (this file).

### Added — security signals (Lite tier)
- Per-process indicators surface as a red dot in the tree (with tooltip
  listing the flags) and as an enumerated list in a new "Security" detail
  tab. Numeric score not shown — only the indicators that fired.
- `exe_suspicious_path` — exe path under `/tmp`, `/dev/shm`, `/var/tmp`,
  or `/run/user/`, with `flatpak` / `snap` / `appimage` allowlist.
- `exe_deleted` / `exe_memfd` — backing file unlinked or memory-resident.
- `kthread_impersonation` — bracketed `comm` without the kthread invariants
  (ppid in {0,2} + no exe link).
- Toolbar "flagged only" filter; ancestors of flagged pids are kept so the
  tree stays connected.
- `[security]` TOML table for `suspicious_prefixes` and
  `allowlist_substrings`. Defaults documented in `monitor.example.toml`.

### Changed
- Dockerfile run command requires explicit `--host 0.0.0.0 --allow-remote`
  when overriding CMD; README and unit-file comments updated.
- `packaging/monitor.service` documents the `User=` trade-off (root for
  full visibility vs a dedicated `--system` user with limited visibility).

## 2026-05-16 — Phase 2

### Added
- `/proc/<pid>/maps` parser → new "libs" tab in the detail panel with
  per-path size, executable flag, and deleted-file indicator
  (`monitor/maps.py`).
- `/proc/net/{tcp,tcp6,udp,udp6,unix,netlink}` parser; the Files tab now
  refines the generic `socket` fd kind into `tcp_socket` / `udp_socket` /
  `unix_socket` / `netlink_socket` and shows the address tuple
  (`monitor/sockets.py`).
- Cmdline-change ("exec without fork") detection: scanner snapshots include
  cmdline; diffs carry an `execed` pid list; UI flashes affected rows
  yellow for 2.5 s.
- TOML config support with CLI override (`monitor/config.py`,
  `monitor.example.toml`).
- Dark mode toggle in the toolbar; persisted in `localStorage`.
- Kernel-thread subtree hidden by default; toolbar checkbox reveals.
- Dockerfile (two-stage, pnpm → python:3.12-slim) and
  `packaging/monitor.service` systemd unit.

### Changed
- Removed pids fade out red for 1.5 s before being dropped (closes an MVP
  gap).
- Env-var endpoint hides names *and* values by default; reveal toggle still
  redacts secret-looking keys.

## 2026-05-16 — MVP

### Added
- Backend: FastAPI + psutil, 2 s scanner tick, snapshot+diff WebSocket
  fan-out, lazy per-process detail collector, fd classifier
  (`monitor/{app,scanner,collector,fd}.py`).
- REST: `GET /api/processes`, `GET /api/processes/{pid}`,
  `GET /api/processes/{pid}/env`, `GET /api/health`.
- Frontend: Preact + Vite + pnpm, virtualized tree, tabbed detail panel,
  client-side filter, new-pid highlight, WebSocket diff consumption.
- CLI: `python -m monitor` entrypoint, refuses non-loopback bind without
  `--allow-remote`.
- 14 passing tests covering fd classification, diff computation, and the
  `/api/processes` self-pid integration path.
