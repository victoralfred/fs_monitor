# monitor — Roadmap (cross-phase plan)

This file tracks plans across phases. Per-phase implementation detail lives
in `plan.md`; this file is the higher-level ledger of what's shipped and
what's queued.

Status legend: ✅ shipped · 🟡 queued (approved) · ❓ awaiting decision ·
⏳ deferred · 🚫 out of scope

---

## Phase 1 — MVP ✅ (shipped)

FastAPI + psutil backend, Preact + Vite + pnpm frontend, WebSocket diff
stream, process tree + lazy detail panel, 14 tests. Full notes in
`plan.md` §MVP.

## Phase 2 — Capability deepening ✅ (shipped)

`/proc/<pid>/maps` shared-libs tab, `/proc/net/*` socket-fd kind
refinement, cmdline-change exec highlight, TOML config, dark mode,
kernel-thread toggle, Dockerfile, systemd unit. Details in `plan.md`
§Phase 2.

## Phase 3 — Polish, hardening, security signals (Lite) ✅ (shipped)

### Section A — hygiene (all 12 done)

README rewrite + screenshots, WS origin check, ws-driven detail panel,
Docker verification, systemd unit verified, GitHub Actions CI, ruff +
eslint + prettier, Vitest, lag-over-budget styling, CHANGELOG, socket
benchmark (psutil wins).

### Section B Lite — security signals (5 of 5 done)

- ✅ B1 `exe_suspicious_path` with flatpak/snap/appimage allowlist
- ✅ B2 `exe_deleted` / `exe_memfd`
- ✅ B6 `kthread_impersonation`
- ✅ B8 `[security]` TOML table
- ✅ B9 UI: red dot in tree, Security tab, "flagged only" filter

Live scan against the dev host: **0 false positives** on default config.

Resolved questions: all 7 (Phase 3 picks were ALL Section A, Lite tier,
in-project, indicators-only, container behavior unchanged, no fork).

---

## Phase 4 — Security signals: Standard tier 🟡 (queued, awaiting go-ahead)

These three items came from the original Section B but were not in the
Lite tier. They share the same UI surface (red dot in tree, Security tab,
"flagged only" filter) and the same `[security]` TOML config table — only
new indicators are added.

### B5 argv[0] ↔ basename(exe) mismatch ❓
Flag when `cmdline[0]` and the exe basename diverge meaningfully —
classic masquerade. Reuses data the scanner already collects. **Lowest
cost, no caching needed.** ~3% FP rate (re-execs, busybox multi-call
binaries).

**Implementation sketch.** Add `classify_argv_mismatch(cmdline, exe_link)`
to `monitor/security.py`. Comparator rule: basename(exe) must appear
somewhere in `cmdline[0]`, OR exe directory is the cwd at exec time, OR
the process is a known multi-call binary (allowlist: `busybox`,
`coreutils`). Test fixtures for each case.

### B4 Non-standard mapped libraries ❓
In the libs detail tab, badge `.so` files loaded from outside `/usr`,
`/lib*`, `/opt`, `/snap`, `/var/lib/flatpak`. **On-demand only** — runs
when the user opens the libs tab. ~6–8% FP rate (sanitizers, venvs with
compiled extensions).

**Implementation sketch.** Extend `monitor/maps.py` to compute an
`is_system` boolean per MapEntry against config-driven prefix list.
Detail endpoint passes it through; libs tab renders a yellow badge for
non-system entries. No new scanner work.

### B3 LD_PRELOAD / LD_AUDIT in environ ❓
Flag processes whose environ contains `LD_PRELOAD=` or `LD_AUDIT=` (MITRE
T1574.006 dynamic linker hijacking). **Most security-valuable, most
expensive.** ~6–8% FP rate.

**Implementation sketch.** Cache per-pid environ snapshot keyed by
`(pid, start_time)`. First sighting of a pid: read `/proc/<pid>/environ`
on the next tick (deferred so a flood of new pids doesn't stall scan).
Re-read only when cmdline changes (the existing `execed` signal). Two
queues: snapshot work queue, cache. Memory budget ~50 bytes/pid for the
relevant keys, well under any reasonable cap.

---

## Phase 5 — Security signals: Paranoid tier ⏳ (deferred unless requested)

### B7 Hidden-process cross-check ⏳
Probe pids 1..32768 with `kill(p, 0)`; pids that respond but aren't in
`/proc` are textbook LKM-rootkit signatures. Requires CAP_KILL or pid
ownership; without it the syscall returns EPERM and we can't distinguish
"doesn't exist" from "not yours".

**Why deferred.** Threat model is a rooted machine with kernel rootkit.
On such a machine the tool itself probably can't be trusted (a rootkit
that hides processes can also lie about what `/proc` returns to this
binary specifically). Value is mostly theatrical. Would surface as an
opt-in `--paranoid` flag with a top-level alert banner rather than a
per-process indicator.

---

## Phase 6 — Possible future directions ❓ (not committed)

Picked from `plan.md`'s "out of scope (until requested)" list, ordered by
how easily they'd fit the existing architecture:

1. **CSV/JSON export** of the current snapshot from the toolbar. Trivial
   (one button → `/api/processes` download with a filename header).
2. **Resource usage graphs** per process in the detail panel. Sparkline
   from a small ring buffer kept by the scanner.
3. **Process timeline / history.** Scanner persists a rolling N-minute
   history of (pid, exe, cmdline) so the UI can answer "what ran in the
   last hour." Storage decision: SQLite on disk, or in-memory only.
4. **eBPF-based behavioral detection** (Falco-style). Catches attacks
   that exit between polls. Requires CAP_PERFMON + a separate collector
   process. Architecturally bigger than Phases 1–5 combined.
5. **Authentication** (token or mTLS) — only meaningful with multi-host
   or remote-access scenarios.
6. **Multi-host / agent+collector split.** Currently `--pid=host` in
   Docker covers most "one node" needs.
7. **Process killing.** Deliberate non-feature so far; would need a
   confirmation flow and `[security]` ACL.

---

## Permanently out of scope 🚫

These were considered and ruled out:

- **Real-time file open/close events without eBPF.** Requires fanotify
  + root or kernel modules; too much architectural cost vs. value.
- **Alerting integrations** (Slack/email/PagerDuty). This is an
  inspector, not a SIEM. Export the REST API instead.
- **Numeric security score.** Replaced by indicator list — scores invite
  arguments about thresholds and aren't actionable.

---

## Notes on decision-making

The original plan was deliberately verbose with per-item deliberations.
Future plan revisions can follow the same shape: one paragraph of
context per item, an OPEN FOR DECISION section when the user needs to
weigh in, and an explicit "out of scope" with reasons. Detailed Phase 1–3
deliberations live in `plan.md`.
