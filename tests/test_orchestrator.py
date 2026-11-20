import pytest
from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import (
    Base,
    Alert,
    Incident,
    IncidentDetection,
    IncidentEvidence,
    IncidentTimeline,
)
from backend.intelligence.orchestrator import process_alerts


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)

    TestSession = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )

    with TestSession() as session:
        yield session

    Base.metadata.drop_all(bind=engine)
    engine.dispose()


def add_alert(
    db,
    event_id,
    destination,
    *,
    source_ip="192.168.10.50",
    source_type="suricata_live",
    protocol="TCP",
    severity="High",
    timestamp="2026-11-07T10:00:00+00:00",
    title="Network activity detected",
):
    alert = Alert(
        event_id=event_id,
        timestamp=timestamp,
        title=title,
        source_ip=source_ip,
        destination=destination,
        protocol=protocol,
        zone="USER",
        severity=severity,
        status="New",
        source_type=source_type,
    )
    db.add(alert)
    db.flush()
    return alert


def run_orchestrator(db):
    return process_alerts(
        db,
        alert_model=Alert,
        incident_model=Incident,
        detection_model=IncidentDetection,
        evidence_model=IncidentEvidence,
        timeline_model=IncidentTimeline,
    )


def count_rows(db, model):
    return db.scalar(select(func.count()).select_from(model))


def test_port_scan_creates_incident_with_evidence(db):
    for port in range(80, 85):
        add_alert(
            db,
            f"scan-{port}",
            f"192.168.20.10:{port}",
        )

    result = run_orchestrator(db)

    assert result.processed_alerts == 5
    assert result.attack_detections >= 1
    assert result.incidents_created >= 1
    assert count_rows(db, Incident) >= 1
    assert count_rows(db, IncidentEvidence) >= 1
    assert count_rows(db, IncidentTimeline) >= 1


def test_cross_source_correlation_creates_incident(db):
    add_alert(
        db,
        "correlation-1",
        "192.168.20.10:443",
        source_type="suricata_live",
    )
    add_alert(
        db,
        "correlation-2",
        "192.168.20.10:443",
        source_type="pfsense",
        timestamp="2026-11-07T10:00:10+00:00",
    )

    result = run_orchestrator(db)

    assert result.cross_source_correlations >= 1
    assert result.incidents_created >= 1
    assert count_rows(db, Incident) >= 1


def test_reprocessing_does_not_duplicate_incidents_or_evidence(db):
    for port in range(80, 85):
        add_alert(
            db,
            f"dedup-{port}",
            f"192.168.20.10:{port}",
        )

    run_orchestrator(db)

    incidents_before = count_rows(db, Incident)
    evidence_before = count_rows(db, IncidentEvidence)

    run_orchestrator(db)

    assert count_rows(db, Incident) == incidents_before
    assert count_rows(db, IncidentEvidence) == evidence_before


def test_new_evidence_can_increase_existing_incident_risk(db):
    for port in range(80, 85):
        add_alert(
            db,
            f"risk-{port}",
            f"192.168.20.10:{port}",
        )

    run_orchestrator(db)

    incident_before = db.scalars(select(Incident)).first()
    assert incident_before is not None
    previous_score = incident_before.risk_score
    previous_evidence_count = count_rows(db, IncidentEvidence)

    add_alert(
        db,
        "risk-85",
        "192.168.20.10:85",
        timestamp="2026-11-07T10:00:30+00:00",
    )

    run_orchestrator(db)

    db.refresh(incident_before)

    assert incident_before.risk_score >= previous_score
    assert count_rows(db, IncidentEvidence) > previous_evidence_count


def test_database_changes_roll_back_when_commit_fails(db, monkeypatch):
    for port in range(80, 85):
        add_alert(
            db,
            f"rollback-{port}",
            f"192.168.20.10:{port}",
        )

    def fail_commit():
        raise RuntimeError("Simulated commit failure")

    monkeypatch.setattr(db, "commit", fail_commit)

    with pytest.raises(RuntimeError, match="Simulated commit failure"):
        run_orchestrator(db)

    assert count_rows(db, Incident) == 0
    assert count_rows(db, IncidentDetection) == 0
    assert count_rows(db, IncidentEvidence) == 0
    assert count_rows(db, IncidentTimeline) == 0

def test_new_evidence_creates_timeline_entry_with_exact_event_ids(db):
    import json

    for port in range(80, 85):
        add_alert(
            db,
            f"timeline-{port}",
            f"192.168.20.10:{port}",
        )

    run_orchestrator(db)

    incident = db.scalars(select(Incident)).first()
    assert incident is not None

    add_alert(
        db,
        "timeline-85",
        "192.168.20.10:85",
        timestamp="2026-11-07T10:00:30+00:00",
    )

    run_orchestrator(db)

    timeline_entries = db.scalars(
        select(IncidentTimeline).where(
            IncidentTimeline.incident_id == incident.incident_id,
            IncidentTimeline.action == "automated_evidence_added",
        )
    ).all()

    matching_entries = [
        entry
        for entry in timeline_entries
        if json.loads(entry.details).get("event_ids") == ["timeline-85"]
    ]

    assert len(matching_entries) == 1

    details = json.loads(matching_entries[0].details)
    assert details["new_evidence_count"] == 1
    assert details["event_ids"] == ["timeline-85"]

    timeline_count_before = count_rows(db, IncidentTimeline)

    run_orchestrator(db)

    assert count_rows(db, IncidentTimeline) == timeline_count_before
