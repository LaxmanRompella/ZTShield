import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import Base, app, get_db


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
    test_client = TestClient(app)
    yield test_client

    app.dependency_overrides.clear()


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
