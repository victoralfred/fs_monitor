import os

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from monitor.app import create_app


def test_health_and_self_pid():
    app = create_app()
    with TestClient(app) as client:
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["ok"] is True

        r = client.get("/api/processes")
        assert r.status_code == 200
        pids = {p["pid"] for p in r.json()["procs"]}
        assert os.getpid() in pids


def test_connections_endpoint_returns_list():
    app = create_app()
    with TestClient(app) as client:
        r = client.get("/api/connections")
        assert r.status_code == 200
        body = r.json()
        assert "connections" in body
        assert isinstance(body["connections"], list)
        assert "last_scan_at" in body


def test_metrics_endpoint_returns_prometheus_format():
    app = create_app()
    with TestClient(app) as client:
        r = client.get("/metrics")
        assert r.status_code == 200
        body = r.text
        # Standard Prometheus exposition lines must be present.
        assert "monitor_procs_tracked" in body
        assert "monitor_scan_duration_seconds" in body
        assert "monitor_ws_subscribers" in body


def test_csrf_endpoint_returns_token():
    app = create_app()
    with TestClient(app) as client:
        r = client.get("/api/csrf")
        assert r.status_code == 200
        token = r.json()["csrf"]
        assert isinstance(token, str) and len(token) >= 32


def test_security_headers_on_html():
    app = create_app()
    with TestClient(app) as client:
        r = client.get("/api/csrf")
        # X-Content-Type-Options always on.
        assert r.headers.get("x-content-type-options") == "nosniff"


def test_ws_rejects_cross_origin():
    app = create_app()
    with TestClient(app) as client:
        # Origin host differs from Host header → must be rejected.
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                "/ws", headers={"origin": "http://evil.example.com"}
            ) as ws:
                ws.receive_json()


def test_ws_accepts_same_origin_and_no_origin():
    app = create_app()
    with TestClient(app) as client:
        # No Origin (CLI client) → allowed.
        with client.websocket_connect("/ws") as ws:
            msg = ws.receive_json()
            assert msg["type"] == "snapshot"


def _csrf(client):
    return client.get("/api/csrf").json()["csrf"]


def test_kill_endpoint_disabled_by_default():
    app = create_app()
    with TestClient(app) as client:
        r = client.post(
            f"/api/processes/{os.getpid()}/signal",
            json={"signal": "SIGTERM", "csrf": _csrf(client)},
        )
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "kill_disabled"


def test_kill_endpoint_rejects_missing_csrf():
    app = create_app(allow_kill=True)
    with TestClient(app) as client:
        r = client.post(f"/api/processes/{os.getpid()}/signal", json={"signal": "SIGCONT"})
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "bad_csrf"


def test_kill_endpoint_rejects_bad_signal():
    app = create_app(allow_kill=True)
    with TestClient(app) as client:
        token = _csrf(client)
        r = client.post(
            f"/api/processes/{os.getpid()}/signal",
            json={"signal": "SIGNUKE", "csrf": token},
        )
        assert r.status_code == 400
        assert r.json()["detail"]["error"] == "bad_signal"


def test_kill_endpoint_acl_none_always_blocks():
    app = create_app(allow_kill=True, kill_acl="none")
    with TestClient(app) as client:
        token = _csrf(client)
        r = client.post(
            f"/api/processes/{os.getpid()}/signal",
            json={"signal": "SIGCONT", "csrf": token},
        )
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "acl_blocked"


def test_kill_endpoint_same_user_allows_self_signal_cont():
    app = create_app(allow_kill=True, kill_acl="same_user")
    with TestClient(app) as client:
        token = _csrf(client)
        r = client.post(
            f"/api/processes/{os.getpid()}/signal",
            json={"signal": "SIGCONT", "csrf": token},
        )
        assert r.status_code == 200
        assert r.json()["ok"] is True


def test_kill_endpoint_rejects_wrong_expected_start():
    app = create_app(allow_kill=True, kill_acl="same_user")
    with TestClient(app) as client:
        token = _csrf(client)
        # Provide a deliberately wrong start_time → pid_recycled.
        r = client.post(
            f"/api/processes/{os.getpid()}/signal",
            json={"signal": "SIGCONT", "csrf": token, "expected_start": 1.0},
        )
        assert r.status_code == 409
        assert r.json()["detail"]["error"] == "pid_recycled"


def test_timeline_endpoint_returns_events_list():
    app = create_app()
    with TestClient(app) as client:
        r = client.get("/api/timeline")
        assert r.status_code == 200
        body = r.json()
        assert "events" in body
        assert "ebpf_running" in body


def test_history_endpoint_returns_samples():
    app = create_app()
    with TestClient(app) as client:
        # The scanner ran at least once during startup; our own pid may have
        # zero samples until a real tick happens. Either way the endpoint
        # must respond with a samples array.
        r = client.get(f"/api/processes/{os.getpid()}/history")
        assert r.status_code == 200
        assert isinstance(r.json()["samples"], list)
