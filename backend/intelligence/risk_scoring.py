
from dataclasses import asdict, dataclass
from typing import Literal

Severity = Literal["Critical", "High", "Medium", "Low"]

SEVERITY_POINTS = {
    "Critical": 40,
    "High": 30,
    "Medium": 20,
    "Low": 10,
}


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    level: str
    severity_points: int
    behavior_points: int
    context_points: int
    repetition_points: int
    reasons: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def assess_risk(
    severity: str,
    suspicious_characteristics: list[str] | None = None,
    communication_scope: str = "internal",
    repeated_events: int = 0,
) -> RiskAssessment:
    """
    Calculate an explainable risk score from 0 to 100.

    repeated_events represents the number of additional
    related events in the configured correlation window.
    """

    if severity not in SEVERITY_POINTS:
        raise ValueError(
            f"Unsupported severity: {severity}"
        )

    if repeated_events < 0:
        raise ValueError(
            "repeated_events cannot be negative."
        )

    characteristics = suspicious_characteristics or []

    severity_points = SEVERITY_POINTS[severity]

    # Maximum 25 points for suspicious characteristics.
    behavior_points = min(len(characteristics) * 5, 25)

    # External communication receives context points.
    context_points = {
        "internal": 0,
        "external": 15,
        "special": 0,
    }.get(communication_scope)

    if context_points is None:
        raise ValueError(
            "communication_scope must be internal, external, or special."
        )

    # Repeated related events increase risk.
    repetition_points = min(repeated_events * 5, 20)

    score = min(
        severity_points
        + behavior_points
        + context_points
        + repetition_points,
        100,
    )

    if score >= 80:
        calculated_level = "Critical"
    elif score >= 60:
        calculated_level = "High"
    elif score >= 35:
        calculated_level = "Medium"
    else:
        calculated_level = "Low"

    # Never downgrade the original alert severity.
    severity_rank = {
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4,
    }

    level = max(
    [calculated_level, severity],
    key=lambda item: severity_rank[item],
    )

    reasons = [
        f"Original severity: {severity} (+{severity_points})",
    ]

    if characteristics:
        reasons.append(
            f"Suspicious characteristics: "
            f"{len(characteristics)} (+{behavior_points})"
        )

    if communication_scope == "external":
        reasons.append(
            "External communication context (+15)"
        )
    elif communication_scope == "special":
        reasons.append(
            "Special-purpose network address; no reputation bonus"
        )

    if repeated_events:
        reasons.append(
            f"Repeated related events: "
            f"{repeated_events} (+{repetition_points})"
        )

    return RiskAssessment(
        score=score,
        level=level,
        severity_points=severity_points,
        behavior_points=behavior_points,
        context_points=context_points,
        repetition_points=repetition_points,
        reasons=reasons,
    )
