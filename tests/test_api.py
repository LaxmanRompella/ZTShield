import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import Base, app, get_db, settings


test_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestSessionLocal = sessionmaker(
    bind=test_engine,
    autoflush=False,
    expire_on_commit=False,
)


def override_get_db():
    with TestSessionLocal() as db:
        yield db


@pytest.fixture
def client():
    # Use a fresh, isolated database for each test.
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

    app.dependency_overrides[get_db] = override_get_db

    # Do not start the application's production-development lifespan.
    test_client = TestClient(
        app,
        headers={"X-ZTShield-Token": settings.ingest_token},
    )
    yield test_client

    app.dependency_overrides.clear()


def test_suricata_ingest_rejects_missing_token(client):
    client.headers.pop("X-ZTShield-Token")

    response = client.post(
        "/api/ingest/suricata",
        json={"event_type": "alert"},
    )

    assert response.status_code == 401


def test_suricata_ingest_rejects_invalid_token(client):
    client.headers["X-ZTShield-Token"] = "invalid-token"

    response = client.post(
        "/api/ingest/suricata",
        json={"event_type": "alert"},
    )

    assert response.status_code == 401


def sample_alert(**overrides):
    payload = {
        "title": "Port scan detected",
        "source_ip": "192.168.10.50",
        "destination": "192.168.20.10",
        "protocol": "TCP",
        "zone": "USER",
        "severity": "High",
        "status": "New",
    }
    payload.update(overrides)
    return payload


def test_health_endpoint(client):
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_create_and_retrieve_alert(client):
    response = client.post(
        "/api/alerts",
        json=sample_alert(),
    )

    assert response.status_code == 201
    created = response.json()
    assert created["title"] == "Port scan detected"
    assert created["source_type"] == "manual"

    response = client.get("/api/alerts")

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["event_id"] == created["event_id"]


def test_filter_alerts_by_severity(client):
    client.post(
        "/api/alerts",
        json=sample_alert(severity="High"),
    )
    client.post(
        "/api/alerts",
        json=sample_alert(
            title="Unusual DNS activity",
            protocol="DNS",
            severity="Low",
        ),
    )

    response = client.get("/api/alerts?severity=High")

    assert response.status_code == 200
    alerts = response.json()
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "High"


def test_search_alerts(client):
    client.post(
        "/api/alerts",
        json=sample_alert(),
    )
    client.post(
        "/api/alerts",
        json=sample_alert(
            title="Unusual DNS activity",
            protocol="DNS",
            severity="Low",
        ),
    )

    response = client.get("/api/alerts?q=port")

    assert response.status_code == 200
    alerts = response.json()
    assert len(alerts) == 1
    assert alerts[0]["title"] == "Port scan detected"



def test_ingest_suricata_alert(client):
    payload = {
        "timestamp": "2026-10-23T12:00:00Z",
        "event_type": "alert",
        "src_ip": "192.0.2.10",
        "src_port": 51515,
        "dest_ip": "192.0.2.20",
        "dest_port": 22,
        "proto": "TCP",
        "alert": {
            "signature": "ET SCAN Potential SSH Scan",
            "severity": 2,
            "category": "Attempted Information Leak",
        },
    }

    response = client.post("/api/ingest/suricata", json=payload)

    assert response.status_code == 201

    event = response.json()
    assert event["title"] == "ET SCAN Potential SSH Scan"
    assert event["severity"] == "High"
    assert event["source_type"] == "suricata"
    assert event["source_ip"] == "192.0.2.10"
    assert event["destination"] == "192.0.2.20:22"
    assert event["zone"] == "UNKNOWN"

    # Confirm that the ingested alert is retrievable.
    alerts_response = client.get("/api/alerts")

    assert alerts_response.status_code == 200
    assert any(
        alert["event_id"] == event["event_id"]
        for alert in alerts_response.json()
    )


def test_reject_non_alert_suricata_event(client):
    payload = {
        "event_type": "dns",
        "src_ip": "192.0.2.10",
        "dest_ip": "192.0.2.20",
        "proto": "UDP",
    }

    response = client.post("/api/ingest/suricata", json=payload)

    assert response.status_code == 422



def test_live_suricata_event_is_classified(client):
    payload = {
        "event_type": "alert",
        "src_ip": "192.0.2.10",
        "dest_ip": "192.0.2.20",
        "proto": "ICMP",
        "alert": {
            "signature": "ZTShield Live Classification Test",
            "severity": 3,
        },
    }

    response = client.post(
        "/api/ingest/suricata",
        json=payload,
        headers={"X-ZTShield-Capture-Mode": "live"},
    )

    assert response.status_code == 201
    assert response.json()["source_type"] == "suricata_live"


import pytest


@pytest.mark.parametrize(
    ("source_ip", "destination_ip", "expected_zone"),
    [
        ("192.168.10.25", "8.8.8.8", "USER"),
        ("192.168.20.100", "8.8.8.8", "SERVER"),
        ("192.168.30.15", "8.8.8.8", "DMZ"),
        ("192.168.40.100", "8.8.8.8", "MANAGEMENT"),
        ("192.168.56.10", "8.8.8.8", "TELEMETRY"),
        ("8.8.8.8", "192.168.20.100", "SERVER"),
        ("192.0.2.10", "192.0.2.20", "UNKNOWN"),
    ],
)
def test_suricata_network_zone_classification(
    client, source_ip, destination_ip, expected_zone
):
    payload = {
        "event_type": "alert",
        "src_ip": source_ip,
        "dest_ip": destination_ip,
        "proto": "ICMP",
        "alert": {
            "signature": "ZTShield Zone Classification Test",
            "severity": 3,
        },
    }

    response = client.post(
        "/api/ingest/suricata",
        json=payload,
        headers={"X-ZTShield-Capture-Mode": "live"},
    )

    assert response.status_code == 201
    assert response.json()["zone"] == expected_zone

def test_sensors_endpoint_lists_four_integrations(client):
    response = client.get("/api/sensors")

    assert response.status_code == 200

    body = response.json()
    assert body["activity_window_seconds"] == 300

    sensors = body["sensors"]
    assert len(sensors) == 4

    sensor_ids = {sensor["id"] for sensor in sensors}
    assert sensor_ids == {"suricata", "pfsense", "wireguard", "tpot"}

    assert all("status" in sensor for sensor in sensors)
    assert all("last_seen" in sensor for sensor in sensors)


def test_sensors_endpoint_detects_recent_suricata_activity(client):
    payload = {
        "event_type": "alert",
        "src_ip": "192.0.2.10",
        "dest_ip": "192.0.2.20",
        "proto": "ICMP",
        "alert": {
            "signature": "ZTShield Sensor API Test",
            "severity": 3,
        },
    }

    ingest_response = client.post(
        "/api/ingest/suricata",
        json=payload,
        headers={"X-ZTShield-Capture-Mode": "live"},
    )

    assert ingest_response.status_code == 201

    response = client.get("/api/sensors")
    assert response.status_code == 200

    sensors = response.json()["sensors"]
    suricata = next(
        sensor for sensor in sensors
        if sensor["id"] == "suricata"
    )

    assert suricata["status"] == "recently_active"
    assert suricata["last_seen"] is not None
    assert suricata["seconds_since_last_event"] is not None

def test_summary_counts_recently_active_sensors(client):
    payload = {
        "event_type": "alert",
        "src_ip": "192.0.2.10",
        "dest_ip": "192.0.2.20",
        "proto": "ICMP",
        "alert": {
            "signature": "ZTShield Summary Sensor Test",
            "severity": 3,
        },
    }

    ingest_response = client.post(
        "/api/ingest/suricata",
        json=payload,
        headers={"X-ZTShield-Capture-Mode": "live"},
    )

    assert ingest_response.status_code == 201

    response = client.get("/api/summary")

    assert response.status_code == 200

    summary = response.json()

    assert summary["connected_sensors"] == 1
    assert summary["recent_live_sources"] == 1
    assert summary["recent_activity_window_seconds"] == 300


def test_create_incident_with_alert_evidence(client):
    alert_response = client.post(
        "/api/alerts",
        json=sample_alert(),
    )
    assert alert_response.status_code == 201

    event_id = alert_response.json()["event_id"]

    incident_response = client.post(
        "/api/incidents",
        json={
            "title": "Suspicious port scanning activity",
            "description": "Multiple suspicious connection attempts.",
            "severity": "High",
            "risk_score": 75,
            "risk_level": "High",
            "assigned_to": "Security Team",
            "evidence_event_ids": [event_id],
        },
    )

    assert incident_response.status_code == 201

    incident = incident_response.json()

    assert incident["title"] == "Suspicious port scanning activity"
    assert incident["status"] == "Open"
    assert incident["risk_score"] == 75
    assert len(incident["evidence"]) == 1
    assert incident["evidence"][0]["event_id"] == event_id
    assert incident["timeline"][0]["action"] == "incident_created"


def test_incident_rejects_nonexistent_alert_evidence(client):
    response = client.post(
        "/api/incidents",
        json={
            "title": "Invalid evidence test",
            "description": "Testing evidence validation.",
            "severity": "High",
            "risk_score": 70,
            "risk_level": "High",
            "evidence_event_ids": ["NONEXISTENT-ALERT"],
        },
    )

    assert response.status_code == 404


def test_list_and_filter_incidents(client):
    client.post(
        "/api/incidents",
        json={
            "title": "High priority incident",
            "severity": "High",
            "risk_score": 80,
            "risk_level": "Critical",
        },
    )

    client.post(
        "/api/incidents",
        json={
            "title": "Low priority incident",
            "severity": "Low",
            "risk_score": 15,
            "risk_level": "Low",
        },
    )

    response = client.get("/api/incidents?severity=High")

    assert response.status_code == 200

    incidents = response.json()
    assert len(incidents) == 1
    assert incidents[0]["title"] == "High priority incident"


def test_get_incident_and_handle_missing_incident(client):
    create_response = client.post(
        "/api/incidents",
        json={
            "title": "Incident retrieval test",
            "severity": "Medium",
            "risk_score": 45,
            "risk_level": "Medium",
        },
    )

    assert create_response.status_code == 201

    incident_id = create_response.json()["incident_id"]

    response = client.get(f"/api/incidents/{incident_id}")

    assert response.status_code == 200
    assert response.json()["incident_id"] == incident_id

    missing_response = client.get(
        "/api/incidents/does-not-exist"
    )

    assert missing_response.status_code == 404



def test_incident_status_transitions_and_timeline(client):
    create_response = client.post(
        "/api/incidents",
        json={
            "title": "Lifecycle test incident",
            "severity": "High",
            "risk_score": 80,
            "risk_level": "Critical",
        },
    )
    assert create_response.status_code == 201

    incident_id = create_response.json()["incident_id"]

    transitions = [
        ("Investigating", "Open"),
        ("Resolved", "Investigating"),
        ("Closed", "Resolved"),
    ]

    for new_status, previous_status in transitions:
        response = client.patch(
            f"/api/incidents/{incident_id}/status",
            json={
                "status": new_status,
                "actor": "security-analyst",
                "details": "Lifecycle transition test.",
            },
        )

        assert response.status_code == 200
        assert response.json()["status"] == new_status

    final_response = client.get(f"/api/incidents/{incident_id}")
    incident = final_response.json()

    status_entries = [
        entry for entry in incident["timeline"]
        if entry["action"] == "status_changed"
    ]

    assert len(status_entries) == 3
    assert all(
        entry["actor"] == "security-analyst"
        for entry in status_entries
    )


def test_incident_rejects_invalid_status_transition(client):
    create_response = client.post(
        "/api/incidents",
        json={
            "title": "Invalid transition test",
            "severity": "Medium",
            "risk_score": 40,
            "risk_level": "Medium",
        },
    )
    incident_id = create_response.json()["incident_id"]

    response = client.patch(
        f"/api/incidents/{incident_id}/status",
        json={
            "status": "Closed",
            "actor": "security-analyst",
        },
    )

    assert response.status_code == 409

    unchanged = client.get(f"/api/incidents/{incident_id}")
    assert unchanged.json()["status"] == "Open"


def test_incident_status_update_rejects_missing_incident(client):
    response = client.patch(
        "/api/incidents/does-not-exist/status",
        json={
            "status": "Investigating",
        },
    )

    assert response.status_code == 404
