from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def make_client(tmp_path: Path) -> TestClient:
    settings = Settings(
        environment="test",
        database_path=tmp_path / "api.db",
        api_key="test-secret",
        allowed_origins=("http://testserver",),
    )
    return TestClient(create_app(settings))


def test_health_endpoint(tmp_path):
    with make_client(tmp_path) as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_dashboard_assets_and_favicon(tmp_path):
    with make_client(tmp_path) as client:
        assert '/static/favicon.svg' in client.get('/').text
        for path in (
            '/static/styles.css', '/static/app.js', '/static/favicon.svg', '/favicon.ico'
        ):
            response = client.get(path)
            assert response.status_code == 200
            assert response.content
        assert client.get('/favicon.ico').headers['content-type'] == 'image/svg+xml'


def test_ingestion_requires_api_key(tmp_path):
    with make_client(tmp_path) as client:
        response = client.post(
            "/api/events",
            json={"event_type": "login_failed", "source_ip": "203.0.113.7"},
        )
    assert response.status_code == 401


def test_ingest_and_list_event(tmp_path):
    with make_client(tmp_path) as client:
        created = client.post(
            "/api/events",
            headers={"X-API-Key": "test-secret"},
            json={
                "event_type": "network_connection",
                "source_ip": "198.51.100.8",
                "destination_ip": "10.0.0.1",
                "destination_port": 443,
                "message": "TLS connection",
            },
        )
        listed = client.get("/api/events")
    assert created.status_code == 201
    assert listed.status_code == 200
    assert listed.json()[0]["source_ip"] == "198.51.100.8"


def test_batch_limit_is_enforced(tmp_path):
    with make_client(tmp_path) as client:
        response = client.post(
            "/api/events/batch",
            headers={"X-API-Key": "test-secret"},
            json=[],
        )
    assert response.status_code == 422


def test_alert_can_be_acknowledged(tmp_path):
    with make_client(tmp_path) as client:
        for _ in range(5):
            client.post(
                "/api/events",
                headers={"X-API-Key": "test-secret"},
                json={"event_type": "login_failed", "source_ip": "203.0.113.9"},
            )
        alerts = client.get("/api/alerts").json()
        response = client.patch(
            f"/api/alerts/{alerts[0]['id']}/acknowledge",
            headers={"X-API-Key": "test-secret"},
        )
    assert response.status_code == 200
    assert response.json()["status"] == "acknowledged"


def test_alert_investigation_can_be_updated(tmp_path):
    with make_client(tmp_path) as client:
        simulation = client.post("/api/demo/simulate/suspicious_process")
        alert = client.get("/api/alerts").json()[0]
        response = client.patch(
            f"/api/alerts/{alert['id']}",
            headers={"X-API-Key": "test-secret"},
            json={"status": "investigating", "analyst_note": "Escalated to endpoint team."},
        )
        summary = client.get("/api/dashboard/summary")
    assert simulation.status_code == 200
    assert response.status_code == 200
    assert response.json()["status"] == "investigating"
    assert response.json()["analyst_note"] == "Escalated to endpoint team."
    assert summary.json()["open_alerts"] == 1


def test_demo_simulations_generate_mitre_mapped_alerts(tmp_path):
    with make_client(tmp_path) as client:
        results = [
            client.post(f"/api/demo/simulate/{scenario}")
            for scenario in ("brute_force", "port_scan", "suspicious_process")
        ]
        alerts = client.get("/api/alerts").json()
    assert [result.status_code for result in results] == [200, 200, 200]
    assert [result.json()["generated_alerts"] for result in results] == [1, 1, 1]
    assert {alert["evidence"]["mitre_id"] for alert in alerts} == {
        "T1110",
        "T1046",
        "T1059.001",
    }


def test_demo_simulation_is_disabled_in_production(tmp_path):
    settings = Settings(
        environment="production",
        database_path=tmp_path / "production.db",
        api_key="production-secret",
        allowed_origins=("http://testserver",),
    )
    with TestClient(create_app(settings)) as client:
        response = client.post("/api/demo/simulate/brute_force")
    assert response.status_code == 403


def test_dashboard_summary(tmp_path):
    with make_client(tmp_path) as client:
        client.post(
            "/api/events",
            headers={"X-API-Key": "test-secret"},
            json={"event_type": "login_success", "source_ip": "10.0.0.10"},
        )
        response = client.get("/api/dashboard/summary")
    assert response.status_code == 200
    assert response.json()["total_events"] == 1
    assert response.json()["unique_sources"] == 1
