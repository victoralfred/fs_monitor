"""Remote-IP enrichment: reverse DNS + ASN org lookup.

The point isn't *automated* threat detection. The point is to turn
'node → 1.2.3.4' (uninterpretable) into 'node → 1.2.3.4
(ipgeolocation.io, DigitalOcean)' so a human triaging the network
panel can see in one glance whether that destination makes sense.

PTR records change rarely; ASN even less. We cache aggressively (1 h
default) so a tab open for a long time doesn't hammer DNS or the
maxmind reader.

ASN lookup is optional. If `maxminddb` isn't installed or the DB file
isn't where we expect it, we silently degrade to PTR-only. Document
the DB path in monitor.example.toml.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

# Where we look for the GeoLite2-ASN database, in order.
_ASN_DB_CANDIDATES = (
    os.environ.get("MONITOR_ASN_DB", ""),
    str(Path.home() / ".local/share/monitor/GeoLite2-ASN.mmdb"),
    "/var/lib/monitor/GeoLite2-ASN.mmdb",
    "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
)


@dataclass
class Enrichment:
    ptr: str | None = None      # reverse DNS, e.g. "edge-mqtt-ec2-1.fbcdn.net"
    asn: int | None = None      # autonomous system number, e.g. 13335
    asn_org: str | None = None  # AS organization, e.g. "Cloudflare, Inc."


class Enricher:
    """Lazy IP enrichment with async PTR + cached ASN.

    Thread-safe. Methods are non-blocking: enrich() returns whatever
    is cached and kicks off a background lookup if the IP is novel.
    Subsequent calls see the populated result.
    """

    def __init__(self, ttl_seconds: float = 3600.0, max_entries: int = 4096) -> None:
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._cache: dict[str, tuple[Enrichment, float]] = {}
        self._inflight: set[str] = set()
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="enrich")
        self._asn_reader = self._load_asn_db()
        if self._asn_reader is None:
            log.info("ASN database not found; enrichment will be PTR-only")

    def _load_asn_db(self):
        try:
            import maxminddb  # noqa: F401  optional dep
        except ImportError:
            return None
        for path in _ASN_DB_CANDIDATES:
            if not path:
                continue
            if not os.path.isfile(path):
                continue
            try:
                import maxminddb as mm
                return mm.open_database(path)
            except OSError as e:
                log.warning("failed to open ASN db at %s: %s", path, e)
        return None

    def enrich(self, ip: str) -> Enrichment:
        """Return whatever's cached for ip; schedule a lookup if novel.
        First call returns an empty Enrichment; later calls (a few hundred
        ms later) see the populated result.
        """
        now = time.monotonic()
        with self._lock:
            cached = self._cache.get(ip)
            if cached and now - cached[1] < self.ttl:
                return cached[0]
            if ip in self._inflight:
                return cached[0] if cached else Enrichment()
            self._inflight.add(ip)
        # Kick the lookup off in the background.
        self._executor.submit(self._lookup, ip)
        return cached[0] if cached else Enrichment()

    def _lookup(self, ip: str) -> None:
        result = Enrichment()
        # ASN first — it's a memory-mapped lookup, sub-millisecond.
        if self._asn_reader is not None:
            try:
                record = self._asn_reader.get(ip)
                if record:
                    result.asn = record.get("autonomous_system_number")
                    result.asn_org = record.get("autonomous_system_organization")
            except (ValueError, OSError):
                pass
        # PTR is the slow one. Bounded by socket's default 5-ish-second
        # resolver timeout, which is fine in a background thread.
        try:
            host, *_ = socket.gethostbyaddr(ip)
            result.ptr = host
        except (socket.herror, OSError):
            pass
        with self._lock:
            self._cache[ip] = (result, time.monotonic())
            self._inflight.discard(ip)
            # Cheap LRU-ish eviction: when we cross max_entries, drop the
            # oldest 25%. Avoids a real heap-based LRU for the modest
            # cardinality involved here.
            if len(self._cache) > self.max_entries:
                items = sorted(self._cache.items(), key=lambda kv: kv[1][1])
                for k, _ in items[: self.max_entries // 4]:
                    del self._cache[k]

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False)


# Module singleton; the scanner and the connections endpoint share this.
ENRICHER = Enricher()
