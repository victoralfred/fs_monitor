"""Structured JSON logging via python-json-logger.

Emits one JSON object per line to stderr — directly consumable by Loki,
Datadog, Cloud Logging, etc. Replaces the previous format-string approach
which produced near-JSON-but-not-quite output.
"""

from __future__ import annotations

import logging
import sys

try:
    from pythonjsonlogger.json import JsonFormatter
except ImportError:
    # python-json-logger < 3 ships the formatter at the package root.
    from pythonjsonlogger.jsonlogger import JsonFormatter  # type: ignore[no-redef]


def configure(level: str = "info") -> None:
    handler = logging.StreamHandler(sys.stderr)
    fmt = JsonFormatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s",
        rename_fields={"asctime": "ts", "levelname": "level", "name": "logger"},
    )
    handler.setFormatter(fmt)
    root = logging.getLogger()
    # Replace any previous handlers (uvicorn installs its own; we want JSON
    # everywhere).
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    # Quiet down uvicorn's access log; we use FastAPI middleware for that.
    logging.getLogger("uvicorn.access").setLevel("WARNING")
