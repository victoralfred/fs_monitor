import time

from monitor.enrichment import Enricher, Enrichment


def test_enrich_returns_empty_on_first_call():
    e = Enricher()
    out = e.enrich("8.8.8.8")
    assert isinstance(out, Enrichment)
    # First call: no cached entry, lookup is in-flight.
    assert out.ptr is None
    assert out.asn is None
    e.shutdown()


def test_enrich_cache_populates_after_lookup(monkeypatch):
    e = Enricher()

    def fake_lookup(self, ip):
        result = Enrichment(ptr="dns.google", asn=15169, asn_org="Google LLC")
        with self._lock:
            self._cache[ip] = (result, time.monotonic())
            self._inflight.discard(ip)

    monkeypatch.setattr(Enricher, "_lookup", fake_lookup)
    e.enrich("8.8.8.8")
    # Give the executor a beat.
    time.sleep(0.05)
    out = e.enrich("8.8.8.8")
    assert out.ptr == "dns.google"
    assert out.asn == 15169
    assert out.asn_org == "Google LLC"
    e.shutdown()


def test_enrich_dedupes_inflight_lookups(monkeypatch):
    e = Enricher()
    calls = []

    def slow_lookup(self, ip):
        calls.append(ip)
        time.sleep(0.05)
        with self._lock:
            self._cache[ip] = (Enrichment(ptr="x"), time.monotonic())
            self._inflight.discard(ip)

    monkeypatch.setattr(Enricher, "_lookup", slow_lookup)
    for _ in range(5):
        e.enrich("1.1.1.1")
    time.sleep(0.15)
    assert calls == ["1.1.1.1"]
    e.shutdown()


def test_no_maxmind_db_still_works():
    """Construction must succeed even when maxminddb isn't installed or
    the DB file isn't present. The default install layout in CI has
    neither.
    """
    e = Enricher()
    # Just verify enrich doesn't blow up.
    e.enrich("1.2.3.4")
    e.shutdown()
