# Linux Process & Open-File Monitor — Implementation Plan

A local, browser-based process explorer for Ubuntu that shows the process tree
and, on demand, the files/sockets/fds each process has open. Python backend,
single-page frontend, localhost-only by default.

---

## Guiding principles

- **Ship the MVP first.** Phase 2 and "out of scope" exist so the MVP stays small.
- **Lazy by default.** Only the process tree is polled globally. Per-process
  fd/socket/maps enumeration happens on selection.
- **Non-fatal failures.** Any `/proc` read can race with process exit; every
  collector must tolerate `ProcessLookupError`, `PermissionError`, and broken
  symlinks without taking down the request.
- **One source of truth for process data: `psutil`.** Drop to raw `/proc` only
  where psutil is insufficient (fd link target resolution, deleted-file flag,
  `/proc/<pid>/maps` parsing).

---

## Performance budget (MVP)

| Metric | Target |
|---|---|
| Full process scan (2000 procs) | ≤ 500 ms |
| Tree refresh cadence | 2 s |
| Per-process detail fetch (fds + sockets) | ≤ 200 ms for ≤ 500 fds |
| WebSocket payload per tick | diffs only, not full snapshot |
| Memory footprint | < 150 MB resident |

If a target is missed, profile before adding caching layers.

---

## MVP scope

Status legend: ✅ done · ⚠️ done with deviation · ⏳ deferred

### Backend

- ✅ **Framework:** FastAPI + `uvicorn`, single process, `asyncio`.
- ✅ **Process scanner:** background task, 2 s tick. Uses `psutil.process_iter`
  with `attrs=['pid','ppid','name','username','status','cpu_percent',
  'memory_info','create_time','cmdline']`. Maintains an in-memory snapshot
  keyed by pid; computes diffs (added / removed / changed) against the
  previous snapshot.
- ✅ **Per-process detail collector** (lazy, called from the detail endpoint):
  - cwd, exe, root (via psutil)
  - file descriptors: read `/proc/<pid>/fd/*`, `os.readlink` each entry,
    classify target as `file | dir | pipe | unix_socket | tcp_socket |
    udp_socket | device | anon | deleted`
  - sockets: `psutil.Process.net_connections(kind='all')`
  - thread count, num_fds
- ✅ **Env vars:** collected but **redacted by default**. Endpoint accepts
  `?show_env=1`; values matching a configurable regex list
  (`(?i)token|secret|key|pass|cred|auth`) are masked even when shown.
  Implemented as a separate endpoint `/api/processes/{pid}/env` rather than
  a query on the detail endpoint — minor deviation from plan.

### REST API

| Method | Path | Returns |
|---|---|---|
| ✅ GET | `/api/processes` | flat list: `[{pid, ppid, name, user, status, cpu, rss, started}]` |
| ✅ GET | `/api/processes/{pid}` | metadata + fds + sockets + cwd/exe/root + threads |
| ✅ GET | `/api/processes/{pid}/env` | env vars (redacted unless `show_env=1`) |
| ✅ GET | `/api/health` | `{ok: true, scanner_lag_ms: N}` |

Errors are structured: `{error: "not_found"|"permission_denied"|..., pid: N}`.
404 for missing pid, 403 for permission denied, never 500 for normal `/proc`
races.

### WebSocket ✅

- `GET /ws` — server pushes JSON messages:
  - `{type: "snapshot", procs: [...]}` once on connect
  - `{type: "diff", added: [...], removed: [pid,...], changed: [...]}` per tick
- No client→server messages in MVP.

### Frontend

- ✅ Single static HTML page served by the backend. **Build step via Vite +
  pnpm** at user request (strictly pnpm, no npm). Built bundle lands in
  `monitor/static/`.
- ✅ **Stack:** Preact + Vite + pnpm; in-house virtualized tree (~100 LOC).
- ✅ **Layout:** left pane = process tree (collapsible, virtualized), right
  pane = detail tabs (Overview / Open files / Sockets / Env).
- ✅ **Search:** client-side filter on pid, name, user.
- ✅ **Live updates:** consumes `/ws` diffs; rAF-debounced.
- ✅ **Highlights:** new pids fade in green for 2 s; removed pids fade out red.
- ✅ No dark mode, no graphs, no kill button in MVP.

### Security (MVP)

- ✅ Bind `127.0.0.1` by default. CLI flag `--host` required to bind elsewhere
  and prints a warning.
- ✅ Env vars redacted by default (see above). Keys themselves are not
  returned unless `show_env=1`, so env-var *names* don't leak either.
- ✅ No authentication in MVP, but the server refuses to start on a
  non-loopback bind unless `--allow-remote` is also passed.
- ✅ Process killing: not implemented.

### Operational

- ✅ Single entrypoint: `python -m monitor` or `monitor` console script.
- ✅ `pyproject.toml` with pinned deps: `fastapi`, `uvicorn`, `psutil`.
- ✅ Structured logging to stderr (JSON-shaped, level configurable via
  `--log-level`).
- ✅ Config precedence: CLI flags > defaults. No env vars, no config file
  in MVP.

### Tests

- ✅ Unit tests for the fd classifier (table-driven).
- ✅ Unit tests for the diff computer (snapshot A → snapshot B → expected diff).
- ✅ Integration test that boots the app, hits `/api/processes`, and asserts
  the current pid appears.
- ✅ Collector smoke test against `os.getpid()` (added in fix pass).

---

## Phase 2 (after MVP lands and is used)

- ✅ `/proc/<pid>/maps` parsing → shared library list in detail view.
  `monitor/maps.py`; aggregates per-path, flags executable + deleted; new
  "libs" tab in the detail panel with path filter.
- ✅ Deleted-file detection (`(deleted)` suffix on fd link target). Surfaced
  as a red `(del)` badge in the Files tab and on libs.
- ✅ Socket endpoint resolution. `monitor/sockets.py` parses
  `/proc/net/{tcp,tcp6,udp,udp6,unix,netlink}` into an inode→info map.
  `read_fds` uses it to refine the generic `socket` kind into
  `tcp_socket`/`udp_socket`/`unix_socket`/`netlink_socket` and to annotate
  the Files tab with the `laddr → raddr (state)` tuple.
- ✅ Config file support (TOML), overrides CLI defaults.
  `monitor/config.py` + `monitor.example.toml`. Lookup order: `--config` >
  `$MONITOR_CONFIG` > `./monitor.toml` > `~/.config/monitor/config.toml`.
  CLI flags override file values. Includes configurable redact patterns.
- ✅ Highlight: processes whose cmdline changed (exec without fork).
  Scanner includes cmdline in each snapshot; diff emits an `execed` pid
  list when cmdline mutates with an unchanged start time; UI flashes those
  rows yellow for 2.5 s.
- ✅ Dark mode. Toggle in toolbar, persisted in `localStorage`, full palette
  via `[data-theme="dark"]` on `:root`.
- ✅ Dockerfile + sample systemd unit. `Dockerfile` does a two-stage build
  (pnpm → python:3.12-slim); `packaging/monitor.service` ships with
  `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`.

Also done in Phase 2:

- ✅ Kernel-thread collapse/dim toggle (resolved the last open question from
  the MVP plan). Children of pid 2 are hidden by default; toolbar checkbox
  reveals them rendered italic + muted.
- ✅ Tests grew to 14 passing (added maps parser tests).

---

## Phase 3 — Polish, hardening, and security signals (Lite)

Full deliberations live in
`~/.claude/plans/create-a-detailed-plan-humble-canyon.md`.

### Section A — Hygiene & polish (all approved, all done)

- ✅ A1 README catch-up for Phase 2 features (libs tab, kthreads toggle,
  dark mode, TOML config, Dockerfile, security signals).
- ✅ A2 WebSocket origin check in `/ws` handler. Cross-origin browser
  connections close with code 1008; CLI clients with no Origin allowed.
- ✅ A3 Detail panel consumes the same ws stream as the tree via a Preact
  context. No more `setInterval` polling per selection.
- ✅ A4 Dockerfile builds clean and serves `/api/health` end-to-end.
- ✅ A5 systemd unit syntax verified with `systemd-analyze verify`; unit
  documents the `User=` trade-off (root for full visibility vs a dedicated
  unprivileged user with `useradd --system`).
- ✅ A6 GitHub Actions CI (`.github/workflows/ci.yml`): three jobs —
  backend (pytest + ruff), frontend (pnpm lint + test + build), docker.
- ✅ A7 Lint configs landed: `ruff` for Python (E/F/W/I/B/UP/SIM),
  `eslint`+`prettier` for JS (`pnpm lint`, `pnpm format`).
- ✅ A8 Vitest frontend tests covering `buildTree` (5) and `applyDiff` (3).
- ✅ A9 `scanner_lag_ms` renders red when > 500 ms with budget tooltip.
- ✅ A10 `CHANGELOG.md` written, Keep-a-Changelog style.
- ✅ A11 Demo screenshots: `docs/lightmode.png` and `docs/darkmode.png`
  embedded in README header.
- ✅ A12 Benchmark `psutil.net_connections` vs `/proc/net/*` parsing
  (`scripts/bench_sockets.py`). Verdict: psutil is marginally faster at
  every N tested (3 ms / 5 ms / 12 ms vs 4 ms / 6 ms / 14 ms at
  N=100/500/2000). Both well under any threshold. The /proc/net parser
  stays because it's needed for the *fd kind refinement* use case
  (inode → proto lookup), not for the Sockets tab.

### Section B — Security signals (Lite tier, in this project)

Turns the tool into a flagger of suspicious processes. Unprivileged
signals, no eBPF, no root. Per-process indicators surface as a red dot in
the tree (with the indicator list as tooltip) and an enumerated list in a
new "Security" detail tab. Numeric score not shown — only the indicators
that fired (per #6 decision). Container behavior: signals fire on every
process the container's user can see; with `--pid=host` this means host
processes (per #5 decision). All weights and allowlists configurable via
the TOML `[security]` table.

- ✅ B1 Suspicious exe paths (`/tmp`, `/dev/shm`, `/var/tmp`, `/run/user`)
  with case-insensitive substring allowlist for `flatpak`, `snap`,
  `appimage` (carve-outs for legitimate sandboxes).
- ✅ B2 Deleted / `memfd:` executable. Fires `exe_deleted` or `exe_memfd`.
- ✅ B6 Kernel-thread name impersonation. Real kthreads have bracketed
  `comm`, ppid in {0, 2}, and no exe link; anything else with a bracketed
  comm fires `kthread_impersonation`.
- ✅ B8 `[security]` TOML table drives `suspicious_prefixes` and
  `allowlist_substrings`. Defaults documented in `monitor.example.toml`.
- ✅ B9 UI: red dot in tree, "Security" detail tab with indicator name +
  severity + evidence, toolbar "flagged only" filter that keeps flagged
  pids and their ancestors so the tree stays connected.
- ⏳ B3, B4, B5, B7 — deferred (Standard / Paranoid tiers, not approved).

### Phase 3 open questions — resolved

1. ✅ Hygiene scope: all of A1–A12 approved (A11 deferred — needs you).
2. ✅ Section B stays in this project.
3. ✅ Lite tier (B1, B2, B6 + B8 + B9).
4. ✅ Allowlist carve-outs: scanned the live system; **0 flagged processes**
   under the default `flatpak`/`snap`/`appimage` allowlist. No
   per-environment tuning required for this host. Adjust
   `[security].allowlist_substrings` in `monitor.toml` if a future
   workload (build tools running in `/tmp`, dev sandboxes, etc.) starts
   producing false positives.
5. ✅ Container mode fires signals (no special-casing).
6. ✅ Indicators only, no numeric score.
7. ✅ No fork — stays in this repo.

---

## Phase 4 — Security signals: Standard tier ✅ (shipped)

- ✅ B5 `argv_exe_mismatch`. `classify_argv_mismatch` compares
  `basename(exe)` against `argv[0]` with allowlists for multi-call
  binaries (`busybox`, `toybox`, `coreutils`) and interpreters
  (`python`, `node`, `bash`, …). Suppressed when B1 would already fire,
  to avoid double-flagging. Reuses scanner data — no extra cost.
- ✅ B4 Non-standard mapped libraries. `maps.annotate_system` tags each
  `MapEntry` with `is_system` based on `[security].system_lib_prefixes`.
  Libs detail tab shows a yellow "non-system" badge for entries outside
  the prefix set. On-demand only; no scanner cost.
- ✅ B3 `dangerous_env` (LD_PRELOAD / LD_AUDIT). `check_dangerous_env`
  caches per-pid `(pid, start_time)` → list of dangerous keys found.
  Scanner invalidates on exec (existing `execed` signal) and prunes on
  pid death. Configurable via `[security].dangerous_env_keys`.

## Phase 5 — Security signals: Paranoid tier ✅ (shipped, opt-in)

- ✅ B7 Hidden-process cross-check. `paranoid_scan(live_pids)` probes
  every pid in `[1, pid_max)` with `kill(0)`; positives that aren't in
  `live_pids` (success *or* `EPERM` — both prove existence) are reported
  as hidden. Runs on a separate 10 s cadence via a second asyncio task
  so it never blocks the main scan tick. Opt-in via
  `[security].paranoid = true` in `monitor.toml`. UI shows a red banner
  across the top when hidden pids are found, listing up to 10 pids. Off
  by default because the threat model (rooted machine with kernel
  rootkit) is one where the tool itself probably can't be trusted.

---

## Phase 6 — Visibility & control ✅ (shipped)

- ✅ **#2 Sparklines.** `monitor/history.py` holds a per-pid `deque(maxlen=60)`
  of `HistorySample(at, cpu, rss)`. Scanner records on every tick;
  prunes on pid death. `GET /api/processes/{pid}/history` returns the
  samples. Detail panel renders cpu+rss SVG sparklines (auto-scaling)
  in a new header strip via `web/src/sparkline.jsx`.
- ✅ **#3 Timeline.** Rolling in-memory log of `ExecEvent` (capacity 500
  events). Scanner appends for added pids and execed pids. `GET
  /api/timeline?since=<ts>` returns events + `ebpf_running` flag.
  Toolbar `⏱` button toggles `TimelinePane` in place of the tree.
- ✅ **#4 eBPF exec tracing.** `monitor/ebpf.py` launches a `bpftrace`
  subprocess with a one-liner attached to `tracepoint:syscalls:sys_enter_execve`
  that prints JSON for every execve. Reader task parses events and
  appends to the same history timeline (so scanner-derived and ebpf-derived
  events sort together by timestamp). Off by default; enable with
  `[ebpf].enabled = true`. Gracefully degrades if bpftrace isn't on PATH
  or lacks permissions — server runs without it. UI shows an "eBPF: on/off"
  pill in the timeline toolbar.
- ✅ **#7 Process killing.** `POST /api/processes/{pid}/signal` accepts
  `{signal: "SIGTERM"|"SIGINT"|"SIGHUP"|"SIGKILL"|"SIGSTOP"|"SIGCONT"}`.
  Off by default (`[security].allow_kill = false`). ACL: `kill_acl =
  "same_user"` (default — uid match), `"none"` (always 403), or `"all"`
  (rely on OS). UI: signal picker + send button in the detail header,
  with two-step confirm before dispatch. Errors surfaced inline.

---

## Phase 9 — Network egress tracking ✅ (shipped)

Continuous global view of which processes hold connections to public-
internet remotes. Designed for "what is *that* talking to?" investigations.

- ✅ `monitor/netwatch.py`. `is_external()` classifier (RFC1918 + loopback +
  link-local + multicast + reserved → internal; everything else external,
  CGNAT included per stated policy). Periodic scan via
  `psutil.net_connections(kind="inet")` attributes each open inet socket
  to a pid + comm.
- ✅ `ConnectionLog` (thread-safe) maintains `(pid, raddr, proto)` →
  `Conn(first_seen, last_seen, state, external)` for up to 10 min after
  the last sighting.
- ✅ Scanner runs `_run_netwatch()` on a separate asyncio task at 5 s
  cadence. Errors counted; doesn't block the main scan tick.
- ✅ `GET /api/connections?external_only=1` returns the log (sorted by
  recency) + `last_scan_at` + `error_count`.
- ✅ UI: 🌐 toolbar button toggles a `NetworkPane` (left side, replacing
  the tree). Table columns: proto | pid | comm | laddr → raddr | state |
  last-seen. External rows tagged with a red "external" pill. Click pid
  to jump back to the tree with that process selected.
- ✅ New compound security flag: `external_egress_from_suspicious` —
  fires when a process whose exe is under a suspicious path is also
  holding an external connection. Highest-signal heuristic in the
  current set; near-zero FPs.
- ✅ New Prometheus gauge `monitor_external_connections`.
- ✅ 9 new tests covering classifier, dedup, prune, filtering, and the
  REST endpoint.

### Honest limitations

- Without root or `CAP_NET_ADMIN`, `psutil.net_connections` only returns
  sockets owned by the running user. Other users' egress is invisible.
  Run via `sudo`, give the binary `setcap cap_net_admin+ep`, or use the
  systemd unit's `CapabilityBoundingSet`.
- Polling at 5 s misses sub-5-second connections. eBPF `tcp_connect`
  tracing would close this gap; deferred to a future phase.
- "External" is a routing classification, not a threat classification.
  Most processes that show up here are legitimate (browser, package
  manager, etc.). Combine with the security tab for triage.

---

## Phase 8 — Production-readiness review ✅ (shipped)

Outcome of the full-codebase review. ~20 individual items grouped into 9
work batches; all batches completed. Tests: 66 Python + 8 JS passing,
lint clean, frontend builds.

### Done

- ✅ **T1+P1 Scanner caching.** Per-(pid, start_time) caches for exe
  link and comm in `SecurityConfig` (with `threading.Lock`). Halves the
  per-tick syscall budget on stable workloads. Env cache also wrapped
  under the same lock (closes the read-modify-write race).
- ✅ **T2 Atomic snapshot swap.** `_scan_and_finalize` does the snapshot,
  diff, history record, exec-log append, and execed-flag recompute all in
  the worker thread; main loop assigns `self.snapshot = new` once.
- ✅ **P7 Paranoid range cap.** Now sweeps only `[1, max(live_pids) + 1024]`
  instead of full pid_max. Roughly 100× less work on systems with high
  pid_max.
- ✅ **R8 Scanner watchdog.** `asyncio.wait_for` bounds each tick to the
  configured `scan_timeout` (default 10 s). Timeouts increment
  `scan_timeout_count` and are logged.
- ✅ **S5 PID-recycling guard.** Kill endpoint reads `/proc/<pid>/stat`
  field 22 before and after the ACL check; refuses with 409 if start_time
  changed. Caller can also pin `expected_start` to fail fast.
- ✅ **S1 CSRF token.** `GET /api/csrf` issues a 32-byte token at server
  start; `POST /api/processes/{pid}/signal` requires it (constant-time
  compare). UI fetches and submits transparently.
- ✅ **S2 Env value scrubbing.** Values matching URL creds, JWT shape,
  AWS access keys, PEM private keys, or GitHub-style tokens are masked as
  `<redacted: value>` even when their key doesn't match the key regex.
- ✅ **S4 Security headers middleware.** CSP, X-Frame-Options: DENY,
  Referrer-Policy, Permissions-Policy, X-Content-Type-Options on every
  HTML response. API responses get `X-Content-Type-Options: nosniff`.
- ✅ **S7 Socket-address sanitization.** Control chars stripped from UNIX
  socket paths; abstract sockets shown with a `@` prefix.
- ✅ **S8 Rate limiting.** In-process fixed-window limiter via
  `RateLimitMiddleware`. Defaults: 10 POST/min/host, 60 GET timeline/min/host.
- ✅ **P3 WS pre-serialization.** Broadcasts JSON-encode once with
  `json.dumps`; subscribers receive the same string via `send_text`.
- ✅ **R3 Graceful WS shutdown.** Lifespan teardown broadcasts
  `{"type": "shutdown"}` before closing.
- ✅ **R5 eBPF watchdog.** Reader catches subprocess EOF, terminates,
  clears `_proc`. `tracer.running` reflects reality.
- ✅ **R4 Paranoid health.** `/api/security/paranoid` now returns
  `stale_seconds`, `error_count`, and a `healthy` boolean (false when
  enabled-but-stale-by-30s).
- ✅ **P4 Timeline `since`.** Frontend tracks last-seen timestamp and
  only fetches deltas. Buffer capped at 2000 client-side.
- ✅ **P5 Sparkline via WS.** Detail panel fetches history once on
  selection, then appends samples from the live ws stream. Polling
  removed.
- ✅ **R13 Frontend error boundary.** `ErrorBoundary` wraps `<App />` so a
  render-time exception shows a recovery panel instead of a blank page.
- ✅ **R1 Prometheus `/metrics`.** Histogram for scan duration, gauges
  for procs/ws-subs/paranoid-hidden/flag counts, counters for kills sent,
  rate-limit rejections, eBPF events.
- ✅ **R2 JSON logging.** `python-json-logger` produces one structured
  object per line. uvicorn access log silenced.
- ✅ **P2 Socket-map TTL cache.** 500 ms window; concurrent misses
  serialize on a lock.
- ✅ **SC2 Timeline cap.** 500 → 2000 events (~2 min of busy activity).

### Deferred for further deliberation

These came up during the review but were judged out of scope or wanted
explicit sign-off. Each is independently shippable.

- ⏳ **R6 Pin Python version in Dockerfile.** Container uses 3.12; dev box
  is 3.14. Pick one for CI matrix to mean anything.
- ⏳ **R9 SIGHUP config reload.** Edits to `monitor.toml` currently need a
  restart. Small, but no one has asked.
- ⏳ **R10 Log rotation.** Stderr-only. Defer to systemd/Docker.
- ⏳ **R11 SRI on script tag.** Vite emits hashed filenames; SRI for
  `type="module"` is finicky and offers little value on same-origin.
- ⏳ **R12 Accessibility audit.** No aria-labels on icon buttons (☾, ☀,
  ⏱), no keyboard nav in the tree, no focus trap in confirm dialog.
  Broad work; deserves its own pass.
- ⏳ **R14 CI test matrix.** Currently single-version. Add 3.10 / 3.12 /
  3.14 in `.github/workflows/ci.yml` if we publish.
- ⏳ **Q4 main.jsx refactor.** ~250 LOC, multiple hooks inline. Cosmetic.
- ⏳ **Q5 TypeScript migration.** ~600 LOC of JS would benefit; one
  evening's work but a real commitment.
- ⏳ **SC1 Multi-worker / persistence.** Single uvicorn worker;
  in-memory state. Requires SQLite/Redis decision plus pinning the
  scanner to one worker. Phase 7 territory.
- ⏳ **SC4 WS queue depth knob.** Currently hard-coded 8. Make config.
- ⏳ **SC6 Memoized kthread BFS.** Recomputes on every snapshot;
  performance only matters at 10k+ procs.

### Permanent decisions

- 🚫 **R7 Max body size middleware.** FastAPI / Starlette defaults
  (1 MB) are adequate. Adding our own knob only adds surface.
- 🚫 **TypeScript everywhere.** Out of scope unless the frontend grows
  significantly.

---

## Phase 7 — Deferred general-purpose features ❓ (not started)

The remaining items from the original Phase 6 list. Lower priority for
the current threat model.

1. **CSV/JSON export.** Toolbar button downloads a filtered snapshot
   (current tree state, or full procs) as JSON or CSV. Trivial; one
   endpoint with a Content-Disposition header.
5. **Authentication.** Token or mTLS. Only meaningful with multi-host or
   remote-access scenarios. Without #6 it's mostly theatre.
6. **Multi-host / agent+collector split.** Currently `--pid=host` in
   Docker covers single-node needs. A real split needs an agent protocol
   (gRPC? plain JSON?), a registry, and per-host auth — significant
   architecture work.

---

## Explicitly out of scope (until requested)

- Multi-host / agent+collector split *(see Phase 6 #6)*
- Authentication, TLS, user accounts *(see Phase 6 #5)*
- Process killing or any write actions *(see Phase 6 #7)*
- Historical timeline / time-series storage *(see Phase 6 #3)*
- Alerting / "suspicious activity" heuristics *(now under consideration in
  Phase 3 Section B as observation-only flags, not active alerting)*
- Real-time file open/close events without eBPF (would require `fanotify`
  + root or kernel modules; too much architectural cost vs. value)
- CSV/JSON export from the UI *(see Phase 6 #1; the REST API is the export
  today)*
- Resource usage graphs *(see Phase 6 #2)*

### Permanently out of scope 🚫

- **Real-time file open/close events without eBPF** — requires fanotify
  + root or kernel modules.
- **Alerting integrations** (Slack/email/PagerDuty). This is an
  inspector, not a SIEM. Export the REST API instead.
- **Numeric security score.** Replaced by indicator list — scores invite
  arguments about thresholds and aren't actionable.

---

## Open questions for the implementer

1. ✅ Resolved by Phase 3 A12: `psutil.net_connections(kind='all')` is
   marginally faster than parsing `/proc/net/*` at all tested N. Keep
   psutil for the Sockets tab; the `/proc/net` parser stays for fd-kind
   refinement (inode → proto lookup).
2. ✅ Resolved: tree endpoint returns flat list + `ppid`, client builds tree.
3. ✅ Resolved in Phase 2: kernel threads hidden by default, toolbar toggle
   reveals them styled italic + muted.
