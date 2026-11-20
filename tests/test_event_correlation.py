
import pytest

from intelligence.event_correlation import correlate_events


@pytest.fixture
def sample_events():
    return [
        {
            "event_id": "PF-001",
            "timestamp": "2026-11-07T10:00:00Z",
            "source_ip": "192.168.40.100",
            "destination": "192.168.20.100",
            "protocol": "ICMP",
            "source_type": "pfsense_live",
            "severity": "Medium",
        },
        {
            "event_id": "SUR-001",
            "timestamp": "2026-11-07T10:01:00Z",
            "source_ip": "192.168.40.100",
            "destination": "192.168.20.100",
            "protocol": "ICMP",
            "source_type": "suricata_live",
            "severity": "High",
        },
    ]


def test_correlates_matching_events_from_different_sources(sample_events):
    groups = correlate_events(sample_events)

    assert len(groups) == 1

    group = groups[0]
    assert group.event_count == 2
    assert group.cross_source is True
    assert set(group.source_types) == {
        "pfsense_live",
        "suricata_live",
    }
    assert len(group.event_ids) == 2


def test_deduplicates_identical_event_ids(sample_events):
    events = sample_events + [sample_events[0]]

    groups = correlate_events(events)

    assert len(groups) == 1
    assert groups[0].event_count == 2


def test_does_not_correlate_different_destinations(sample_events):
    sample_events[1]["destination"] = "192.168.30.100"

    groups = correlate_events(sample_events)

    assert groups == []


def test_does_not_correlate_different_protocols(sample_events):
    sample_events[1]["protocol"] = "TCP"

    groups = correlate_events(sample_events)

    assert groups == []


def test_does_not_correlate_events_outside_time_window(sample_events):
    sample_events[1]["timestamp"] = "2026-11-07T10:10:00Z"

    groups = correlate_events(
        sample_events,
        window_seconds=300,
    )

    assert groups == []


def test_correlates_events_within_custom_time_window(sample_events):
    sample_events[1]["timestamp"] = "2026-11-07T10:04:00Z"

    groups = correlate_events(
        sample_events,
        window_seconds=300,
    )

    assert len(groups) == 1


def test_minimum_event_count_is_respected(sample_events):
    groups = correlate_events(
        sample_events,
        min_events=3,
    )

    assert groups == []


def test_invalid_timestamp_is_rejected(sample_events):
    sample_events[0]["timestamp"] = "not-a-timestamp"

    with pytest.raises(ValueError):
        correlate_events(sample_events)


def test_invalid_ip_is_rejected(sample_events):
    sample_events[0]["source_ip"] = "invalid-ip"

    with pytest.raises(ValueError):
        correlate_events(sample_events)


def test_invalid_window_is_rejected(sample_events):
    with pytest.raises(ValueError):
        correlate_events(sample_events, window_seconds=0)


def test_invalid_minimum_event_count_is_rejected(sample_events):
    with pytest.raises(ValueError):
        correlate_events(sample_events, min_events=1)


def test_correlation_id_is_deterministic(sample_events):
    first = correlate_events(sample_events)[0]
    second = correlate_events(list(reversed(sample_events)))[0]

    assert first.correlation_id == second.correlation_id
