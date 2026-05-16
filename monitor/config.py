"""Configuration loader. TOML file > CLI flags > defaults.

Lookup order for the config file:
  1. --config <path> on the CLI
  2. $MONITOR_CONFIG env var
  3. ./monitor.toml
  4. ~/.config/monitor/config.toml
First one that exists wins; otherwise defaults are used.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import tomllib


@dataclass
class Config:
    host: str = "127.0.0.1"
    port: int = 8765
    allow_remote: bool = False
    log_level: str = "info"
    scan_interval: float = 2.0
    redact_patterns: list[str] = field(
        default_factory=lambda: [r"(?i)token|secret|key|pass|cred|auth"]
    )
    # Raw [security] table; parsed into SecurityConfig at startup.
    security: dict = field(default_factory=dict)
    # Phase 6: process-killing ACL and eBPF tracing.
    allow_kill: bool = False
    kill_acl: str = "same_user"   # "same_user" | "none" | "all"
    ebpf_enabled: bool = False


def _candidate_paths(explicit: str | None) -> list[Path]:
    paths: list[Path] = []
    if explicit:
        paths.append(Path(explicit))
    env = os.environ.get("MONITOR_CONFIG")
    if env:
        paths.append(Path(env))
    paths.append(Path("monitor.toml"))
    paths.append(Path.home() / ".config" / "monitor" / "config.toml")
    return paths


def load(explicit: str | None = None) -> Config:
    cfg = Config()
    for path in _candidate_paths(explicit):
        if not path.is_file():
            continue
        with path.open("rb") as f:
            data = tomllib.load(f)
        srv = data.get("server", {})
        if "host" in srv:
            cfg.host = str(srv["host"])
        if "port" in srv:
            cfg.port = int(srv["port"])
        if "allow_remote" in srv:
            cfg.allow_remote = bool(srv["allow_remote"])
        if "log_level" in srv:
            cfg.log_level = str(srv["log_level"])
        scan = data.get("scanner", {})
        if "interval" in scan:
            cfg.scan_interval = float(scan["interval"])
        sec = data.get("security", {})
        if "redact_patterns" in sec:
            cfg.redact_patterns = list(sec["redact_patterns"])
        if "allow_kill" in sec:
            cfg.allow_kill = bool(sec["allow_kill"])
        if "kill_acl" in sec:
            cfg.kill_acl = str(sec["kill_acl"])
        cfg.security = sec
        ebpf = data.get("ebpf", {})
        if "enabled" in ebpf:
            cfg.ebpf_enabled = bool(ebpf["enabled"])
        break
    return cfg
