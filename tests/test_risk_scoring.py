
import pytest

from intelligence.risk_scoring import assess_risk


@pytest.mark.parametrize(
    ("severity", "expected_level", "expected_score"),
    [
        ("Low", "Low", 10),
        ("Medium", "Medium", 20),
        ("High", "High", 30),
        ("Critical", "Critical", 40),
    ],
)
def test_severity_floor(severity, expected_level, expected_score):
    result = assess_risk(
        severity=severity,
        communication_scope="internal",
    )

    assert result.level == expected_level
    assert result.score == expected_score


def test_suspicious_activity_escalates_risk():
    result = assess_risk(
        severity="High",
        suspicious_characteristics=["Suspicious connection"],
        communication_scope="external",
        repeated_events=5,
    )

    assert result.score == 70
    assert result.level == "High"
    assert result.behavior_points == 5
    assert result.context_points == 15
    assert result.repetition_points == 20


def test_risk_score_never_exceeds_100():
    result = assess_risk(
        severity="Critical",
        suspicious_characteristics=[
            "Pattern 1",
            "Pattern 2",
            "Pattern 3",
            "Pattern 4",
            "Pattern 5",
            "Pattern 6",
        ],
        communication_scope="external",
        repeated_events=100,
    )

    assert result.score == 100
    assert result.level == "Critical"


def test_invalid_severity_is_rejected():
    with pytest.raises(ValueError):
        assess_risk(severity="Unknown")


def test_negative_repeated_events_are_rejected():
    with pytest.raises(ValueError):
        assess_risk(
            severity="Low",
            repeated_events=-1,
        )


def test_invalid_communication_scope_is_rejected():
    with pytest.raises(ValueError):
        assess_risk(
            severity="Low",
            communication_scope="unknown",
        )


def test_internal_low_severity_has_no_context_bonus():
    result = assess_risk(
        severity="Low",
        communication_scope="internal",
    )

    assert result.context_points == 0
    assert result.score == 10
