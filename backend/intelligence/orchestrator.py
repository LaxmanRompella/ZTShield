
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .attack_detection import detect_attack_patterns
from .event_correlation import correlate_events
from .ip_context import classify_ip_pair
from .risk_scoring import assess_risk


SEVERITY_RANK = {
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}


@dataclass(frozen=True)
class OrchestrationResult:
    processed_alerts: int
    attack_detections: int
    cross_source_correlations: int
    incidents_created: int
    incidents_updated: int
    evidence_added: int
    detections_skipped: int

    def to_dict(self) -> dict:
        return asdict(self)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _severity(value: str) -> str:
    normalized = str(value or "").strip().casefold()

    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Low",
    }

    return mapping.get(normalized, "Low")


def _highest_severity(values: list[str]) -> str:
    normalized = [_severity(value) for value in values]

    return max(
        normalized or ["Low"],
        key=lambda item: SEVERITY_RANK[item],
    )


def _communication_scope(events: list[dict]) -> str:
    scopes = []

    for event in events:
        context = classify_ip_pair(
            event["source_ip"],
            event["destination"],
        )
        scopes.append(context["communication_scope"])

    if "external" in scopes:
        return "external"

    if "special" in scopes:
        return "special"

    return "internal"


def _detection_key(
    detection_type: str,
    source_ip: str,
    targets: list[str],
    first_seen: str,
    protocol: str = "",
) -> str:
    """
    Generate a stable fingerprint for a detection within its UTC hour.
    """

    try:
        timestamp = datetime.fromisoformat(
            first_seen.replace("Z", "+00:00")
        )
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        hour_bucket = timestamp.astimezone(timezone.utc).strftime(
            "%Y-%m-%dT%H"
        )
    except (ValueError, AttributeError):
        hour_bucket = first_seen[:13]

    fingerprint = "|".join([
        detection_type,
        source_ip,
        ",".join(sorted(set(targets))),
        protocol.upper(),
        hour_bucket,
    ])

    digest = hashlib.sha256(
        fingerprint.encode("utf-8")
    ).hexdigest()

    return f"DET-{digest}"


def _build_candidates(
    events: list[dict],
) -> tuple[list[dict], int, int]:
    candidates = []

    attack_detections = detect_attack_patterns(events)

    for detection in attack_detections:
        related_events = [
            event
            for event in events
            if event["event_id"] in detection.event_ids
        ]

        if not related_events:
            continue

        scope = _communication_scope(related_events)

        risk = assess_risk(
            severity=detection.severity,
            suspicious_characteristics=[
                detection.pattern,
            ],
            communication_scope=scope,
            repeated_events=max(0, detection.event_count - 1),
        )

        candidates.append({
            "detection_id": detection.detection_id,
            "detection_type": detection.pattern,
            "title": (
                "Possible "
                + detection.pattern.replace("_", " ").title()
            ),
            "description": detection.description,
            "source_ip": detection.source_ip,
            "targets": detection.target_ips,
            "event_ids": detection.event_ids,
            "first_seen": detection.first_seen,
            "severity": detection.severity,
            "risk": risk,
            "evidence": detection.evidence,
            "protocol": "",
        })

    correlations = correlate_events(events)

    cross_source_count = 0

    for group in correlations:
        # Repeated events from one source alone are not sufficient
        # for this correlation-based incident trigger.
        if not group.cross_source:
            continue

        cross_source_count += 1

        related_events = [
            event
            for event in events
            if event["event_id"] in group.event_ids
        ]

        if not related_events:
            continue

        severity = _highest_severity(group.severities)
        scope = _communication_scope(related_events)

        risk = assess_risk(
            severity=severity,
            suspicious_characteristics=[
                "cross_source_correlation",
            ],
            communication_scope=scope,
            repeated_events=max(0, group.event_count - 1),
        )

        candidates.append({
            "detection_id": group.correlation_id,
            "detection_type": "cross_source_correlation",
            "title": "Corroborated Network Activity",
            "description": (
                "Related network events were observed by multiple "
                "telemetry sources. Investigation is required; "
                "correlation alone does not prove malicious activity."
            ),
            "source_ip": group.source_ip,
            "targets": [group.destination_ip],
            "event_ids": group.event_ids,
            "first_seen": group.first_seen,
            "severity": severity,
            "risk": risk,
            "evidence": group.reasons,
            "protocol": group.protocol,
        })

    return candidates, len(attack_detections), cross_source_count


def process_alerts(
    db: Session,
    *,
    alert_model: Any,
    incident_model: Any,
    detection_model: Any,
    evidence_model: Any,
    timeline_model: Any,
    limit: int = 1000,
) -> OrchestrationResult:
    """
    Analyze persisted alerts and create or update evidence-backed incidents.

    This function does not ingest alerts and does not create its own
    database session. The caller owns the SQLAlchemy session.
    """

    if limit < 1 or limit > 10000:
        raise ValueError("limit must be between 1 and 10000.")



    alerts = list(
        db.scalars(
            select(alert_model)
            .order_by(alert_model.timestamp.desc(), alert_model.event_id.desc())
            .limit(limit)
        ).all()
    )

    # The engines expect chronological event input.
    alerts.reverse()

    events = [
        {
            "event_id": alert.event_id,
            "timestamp": alert.timestamp,
            "title": alert.title,
            "source_ip": alert.source_ip,
            "destination": alert.destination,
            "protocol": alert.protocol,
            "source_type": alert.source_type,
            "severity": _severity(alert.severity),
            "zone": alert.zone,
        }
        for alert in alerts
    ]

    candidates, attack_count, correlation_count = (
        _build_candidates(events)
    )

    incidents_created = 0
    incidents_updated = 0
    evidence_added = 0
    detections_skipped = 0

    # Avoid processing an identical fingerprint twice in one run.
    processed_keys = set()

    try:
        for candidate in candidates:
            detection_key = _detection_key(
                detection_type=candidate["detection_type"],
                source_ip=candidate["source_ip"],
                targets=candidate["targets"],
                first_seen=candidate["first_seen"],
                protocol=candidate["protocol"],
            )

            if detection_key in processed_keys:
                detections_skipped += 1
                continue

            processed_keys.add(detection_key)

            mapping = db.scalar(
                select(detection_model).where(
                    detection_model.detection_key == detection_key
                )
            )

            incident = (
                db.get(incident_model, mapping.incident_id)
                if mapping is not None
                else None
            )

            now = _now()

            risk = candidate["risk"]

            explanation = json.dumps(
                {
                    "detection_id": candidate["detection_id"],
                    "detection_type": candidate["detection_type"],
                    "description": candidate["description"],
                    "evidence": candidate["evidence"],
                    "risk_assessment": risk.to_dict(),
                },
                ensure_ascii=False,
            )

            if incident is None:
                incident = incident_model(
                    incident_id=__import__("uuid").uuid4().hex,
                    title=candidate["title"],
                    description=candidate["description"],
                    severity=candidate["severity"],
                    risk_score=risk.score,
                    risk_level=risk.level,
                    status="Open",
                    assigned_to=None,
                    created_at=now,
                    updated_at=now,
                )

                db.add(incident)
                db.flush()

                db.add(
                    detection_model(
                        id=__import__("uuid").uuid4().hex,
                        detection_key=detection_key,
                        detection_type=candidate["detection_type"],
                        incident_id=incident.incident_id,
                        created_at=now,
                        updated_at=now,
                    )
                )

                db.add(
                    timeline_model(
                        timeline_id=__import__("uuid").uuid4().hex,
                        incident_id=incident.incident_id,
                        action="automated_incident_created",
                        details=explanation,
                        actor="ZTShield Intelligence Engine",
                        created_at=now,
                    )
                )

                incidents_created += 1

            else:
                incidents_updated += 1

                incident_changed = False

                if risk.score > incident.risk_score:
                    incident.risk_score = risk.score
                    incident.risk_level = risk.level
                    incident_changed = True

                if (
                    SEVERITY_RANK[candidate["severity"]]
                    > SEVERITY_RANK[_severity(incident.severity)]
                ):
                    incident.severity = candidate["severity"]
                    incident_changed = True

                if incident_changed:
                    incident.updated_at = now

                    db.add(
                        timeline_model(
                            timeline_id=__import__("uuid").uuid4().hex,
                            incident_id=incident.incident_id,
                            action="automated_risk_updated",
                            details=explanation,
                            actor="ZTShield Intelligence Engine",
                            created_at=now,
                        )
                    )

            existing_evidence = set(
                db.scalars(
                    select(evidence_model.event_id).where(
                        evidence_model.incident_id == incident.incident_id
                    )
                ).all()
            )

            newly_added_event_ids = []

            for event_id in candidate["event_ids"]:
                if event_id in existing_evidence:
                    continue

                db.add(
                    evidence_model(
                        evidence_id=__import__("uuid").uuid4().hex,
                        incident_id=incident.incident_id,
                        event_id=event_id,
                        evidence_type=candidate["detection_type"],
                        explanation=explanation,
                        created_at=now,
                    )
                )

                evidence_added += 1
                newly_added_event_ids.append(event_id)
                existing_evidence.add(event_id)

            if newly_added_event_ids:
                incident.updated_at = now

                db.add(
                    timeline_model(
                        timeline_id=__import__("uuid").uuid4().hex,
                        incident_id=incident.incident_id,
                        action="automated_evidence_added",
                        details=json.dumps(
                            {
                                "detection_type": candidate["detection_type"],
                                "new_evidence_count": len(newly_added_event_ids),
                                "event_ids": newly_added_event_ids,
                            },
                            ensure_ascii=False,
                        ),
                        actor="ZTShield Intelligence Engine",
                        created_at=now,
                    )
                )

            if mapping is not None:
                mapping.updated_at = now

        db.commit()

    except Exception:
        db.rollback()
        raise

    return OrchestrationResult(
        processed_alerts=len(alerts),
        attack_detections=attack_count,
        cross_source_correlations=correlation_count,
        incidents_created=incidents_created,
        incidents_updated=incidents_updated,
        evidence_added=evidence_added,
        detections_skipped=detections_skipped,
    )
