"""CLI entrypoint."""

from __future__ import annotations

import argparse
import sys

import uvicorn

from .app import create_app
from .config import load as load_config


def main() -> int:
    ap = argparse.ArgumentParser(prog="monitor")
    ap.add_argument("--config", help="path to TOML config file")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--allow-remote", action="store_true",
                    help="required to bind to a non-loopback address")
    ap.add_argument("--log-level",
                    choices=["debug", "info", "warning", "error"])
    args = ap.parse_args()

    cfg = load_config(args.config)
    # CLI flags override file values when supplied.
    if args.host is not None:
        cfg.host = args.host
    if args.port is not None:
        cfg.port = args.port
    if args.allow_remote:
        cfg.allow_remote = True
    if args.log_level is not None:
        cfg.log_level = args.log_level

    if cfg.host not in ("127.0.0.1", "localhost", "::1") and not cfg.allow_remote:
        print(
            f"refusing to bind {cfg.host}: pass --allow-remote to override",
            file=sys.stderr,
        )
        return 2

    from .logging_config import configure as configure_logging
    configure_logging(cfg.log_level)

    uvicorn.run(
        create_app(
            scan_interval=cfg.scan_interval,
            redact_patterns=cfg.redact_patterns,
            security_table=cfg.security,
            allow_kill=cfg.allow_kill,
            kill_acl=cfg.kill_acl,
            ebpf_enabled=cfg.ebpf_enabled,
        ),
        host=cfg.host,
        port=cfg.port,
        log_level=cfg.log_level,
        access_log=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
