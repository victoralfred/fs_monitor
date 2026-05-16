# monitor

Local browser-based Linux process & open-file explorer. Read-only, runs as
the invoking user, no root required. See [plan.md](plan.md) for the design
and [CHANGELOG.md](CHANGELOG.md) for what's shipped.

![light mode](docs/lightmode.png)
![dark mode](docs/darkmode.png)

## Features

- Live process tree with virtualized rendering and `/proc`-derived metadata
- Per-process detail panel with five tabs:
  - **files** — open file descriptors classified by kind (file/dir/pipe/
    socket/anon/device/deleted), with socket addresses resolved from
    `/proc/net/*`
  - **sockets** — full network/Unix socket table from psutil
  - **libs** — shared libraries and mapped files from `/proc/<pid>/maps`,
    with deleted-file flags
  - **env** — environment variables, hidden by default; reveal toggle masks
    secret-looking keys
  - **overview** — pointer to the tabs above
- Process tree extras:
  - Search filter on pid / name / user
  - Kernel-thread subtree hidden by default; toolbar checkbox reveals them
  - New pids fade in green, removed pids fade out red, exec-without-fork
    flashes yellow
  - Dark mode toggle (persisted in localStorage)
- WebSocket diff stream — no full-page reloads, no polling
- Security signals (see [plan.md](plan.md) §"Phase 3 Section B"): flags
  suspicious exe paths, memfd/deleted executables, and kernel-thread name
  impersonation. UI surfaces firing indicators per process, not a numeric
  score.

## Run (dev)

Backend:

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e .
python -m monitor                    # binds 127.0.0.1:8765
```

Frontend (separate terminal, **pnpm only** — `npm install` is blocked via
`engine-strict`):

```sh
cd web
pnpm install
pnpm dev                             # http://localhost:5173, proxies /api and /ws
```

## Run (production-ish)

Build the frontend into `monitor/static/` and let FastAPI serve it:

```sh
cd web && pnpm install && pnpm build
cd .. && python -m monitor
# open http://127.0.0.1:8765
```

> **Build before install.** `monitor/static/` is gitignored and not present
> in a fresh clone. If you `pip install .` (or build an sdist/wheel) without
> running `pnpm build` first, the package ships with no frontend and the
> server responds `503 frontend_not_built` on `/`. Always run `pnpm build`
> before packaging or installing.

## Docker

The Dockerfile does a two-stage build (pnpm → python:3.12-slim). Run with
`--pid=host` so `/proc` reflects the host:

```sh
docker build -t monitor .
docker run --rm --pid=host -p 8765:8765 monitor
```

## systemd

A sample unit lives at `packaging/monitor.service`. Edit `User=` based on
how much visibility you want (see the comment in the file), then:

```sh
sudo cp packaging/monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now monitor
```

## Configuration

CLI flags > TOML config > defaults. Config-file lookup order:

1. `--config <path>`
2. `$MONITOR_CONFIG`
3. `./monitor.toml`
4. `~/.config/monitor/config.toml`

See [`monitor.example.toml`](monitor.example.toml) for the full schema.
The `[security]` table controls env-var redaction patterns and security
signal weights / allowlists.

## CLI flags

```
monitor [--host HOST] [--port PORT] [--allow-remote]
        [--log-level {debug,info,warning,error}]
        [--config PATH]
```

- `--host`: bind address. Defaults to `127.0.0.1`. Non-loopback values
  require `--allow-remote`.
- `--allow-remote`: explicit opt-in for non-loopback binds.

## Tests

```sh
pip install pytest httpx
pytest                               # backend, 20+ tests
cd web && pnpm test                  # frontend, Vitest
```

## Security notes

- Localhost-only by default. Bind elsewhere with `--host 0.0.0.0
  --allow-remote`. There is no authentication — this is a tool for
  inspecting your own machine.
- WebSocket connections require a same-origin `Origin` header (or none, for
  CLI clients).
- Env-var values are hidden by default. Toggling "show values" still masks
  keys matching the configured redaction regex.
- Process killing is not implemented (deliberate — see plan.md).
- Security signals are *observation only*. Nothing is killed, blocked, or
  reported off-host.
