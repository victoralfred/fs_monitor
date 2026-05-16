"""HTTP middleware: security headers + simple in-process rate limiting.

The rate limiter is intentionally minimal — a fixed-window token bucket
keyed by client host. Good enough to keep a buggy or malicious local
script from spinning POST /signal at thousands of req/s. For
multi-process production deployments, swap in slowapi+redis or similar.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

_HTML_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    # CSP: same-origin only. No inline scripts/styles allowed (vite outputs
    # external files). ws: for the websocket; data: for SVG.
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "  # vite ships hashed CSS, but JSX inline styles need 'unsafe-inline'
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'"
    ),
}


# FastAPI's auto-generated docs pages load Swagger UI / ReDoc bundles from
# cdn.jsdelivr.net. Applying our SPA CSP would block them. These paths are
# dev-only; the SPA's CSP is what we actually care about.
_DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response: Response = await call_next(request)
        path = request.url.path
        if path in _DOCS_PATHS or path.startswith("/docs/") or path.startswith("/redoc/"):
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
            return response
        ctype = response.headers.get("content-type", "")
        if "text/html" in ctype:
            for k, v in _HTML_HEADERS.items():
                response.headers.setdefault(k, v)
        else:
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-client fixed-window rate limiting on specific path prefixes.

    POSTs (signal endpoint) are limited tighter than expensive GETs
    (history, timeline). Reads of /api/processes/* paths intended to be
    polled (health, processes, timeline) are exempt.
    """

    def __init__(self, app: ASGIApp, *, rules: dict[tuple[str, str], tuple[int, float]]):
        super().__init__(app)
        # rules: {(method, path_prefix): (max_requests, window_seconds)}
        self._rules = rules
        self._buckets: dict[tuple, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def _match_rule(self, method: str, path: str):
        for (m, prefix), (limit, window) in self._rules.items():
            if m == method and path.startswith(prefix):
                return limit, window, prefix
        return None

    async def dispatch(self, request, call_next):
        rule = self._match_rule(request.method, request.url.path)
        if rule is None:
            return await call_next(request)
        limit, window, prefix = rule
        client = request.client.host if request.client else "unknown"
        key = (request.method, prefix, client)
        now = time.monotonic()
        with self._lock:
            q = self._buckets[key]
            cutoff = now - window
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= limit:
                retry = window - (now - q[0])
                return JSONResponse(
                    {"error": "rate_limited", "retry_after": round(retry, 2)},
                    status_code=429,
                    headers={"Retry-After": str(int(retry) + 1)},
                )
            q.append(now)
        return await call_next(request)


# Reasonable defaults: tight on writes, looser on reads we expect to poll.
DEFAULT_RULES = {
    ("POST", "/api/processes"): (10, 60.0),      # 10 signals per minute per host
    ("GET", "/api/timeline"): (60, 60.0),        # 1 / sec
}
