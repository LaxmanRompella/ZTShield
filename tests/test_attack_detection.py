
import pytest

from intelligence.attack_detection import detect_attack_patterns


BASE_TIME = "2026-11-07T10:{:02d}:00Z"


def make_event(
    event_id,
    minute,
    source="192.168.40.100",
    destination="192.168.20.100",
    protocol="TCP",
    title="Normal connection",
    action="pass",
):
    return {
        "event_id": event_id,
        "timestamp": BASE_TIME.format(minute),
        "source_ip": source,
        "destination": destination,
        "protocol": protocol,
        "title": title,
        "action": action,
        "source_type": "pfsense_live",
        "severity": "Medium",
    }


def test_detects_port_scan():
    events = [
        make_event(
            f"PORT-{port}",
            port,
            destination=f"192.168.20.100:{port + 1000}",
        )
        for port in range(5)
    ]

    results = detect_attack_patterns(events)

    assert any(item.pattern == "port_scan" for item in results)


def test_detects_host_scan():
    events = [
        make_event(
            f"HOST-{index}",
            index,
            destination=f"192.168.20.{index + 100}",
        )
        for index in range(5)
    ]

    results = detect_attack_patterns(events)

    assert any(item.pattern == "host_scan" for item in results)


def test_detects_repeated_blocked_connections():
    events = [
        make_event(
            f"BLOCK-{index}",
            index,
            action="block",
            title="pfSense BLOCK TCP",
        )
        for index in range(5)
    ]

    results = detect_attack_patterns(events)

    assert any(
        item.pattern == "repeated_blocked_connections"
        for item in results
    )


def test_detects_possible_brute_force():
    events = [
        make_event(
            f"AUTH-{index}",
            index,
            destination="192.168.20.100:22",
            title="SSH authentication failed",
        )
        for index in range(5)
    ]

    results = detect_attack_patterns(events)

    assert any(
        item.pattern == "possible_brute_force"
        for item in results
    )


def test_detects_lateral_movement_indicator():
    events = [
        make_event(
            f"LATERAL-{index}",
            index,
            destination=f"192.168.{20 + index}.100:445",
        )
        for index in range(3)
    ]

    results = detect_attack_patterns(events)

    assert any(
        item.pattern == "lateral_movement_indicator"
        for item in results
    )


def test_normal_traffic_does_not_trigger_detection():
    events = [
        make_event(
            f"NORMAL-{index}",
            index,
            destination="192.168.20.100:443",
            title="Normal HTTPS connection",
        )
        for index in range(3)
    ]

    results = detect_attack_patterns(events)

    assert results == []


def test_duplicate_event_ids_are_not_counted_twice():
    event = make_event(
        "DUPLICATE-1",
        1,
        action="block",
        title="Connection blocked",
    )

    events = [event] * 6

    results = detect_attack_patterns(events)

    assert not any(
        item.pattern == "repeated_blocked_connections"
        for item in results
    )


def test_detection_id_is_deterministic():
    events = [
        make_event(
            f"BLOCK-{index}",
            index,
            action="block",
        )
        for index in range(5)
    ]

    first = detect_attack_patterns(events)
    second = detect_attack_patterns(list(reversed(events)))

    first_ids = {
        item.detection_id for item in first
    }
    second_ids = {
        item.detection_id for item in second
    }

    assert first_ids == second_ids


def test_invalid_timestamp_is_rejected():
    events = [
        make_event("INVALID-1", 1),
        make_event("INVALID-2", 2),
    ]

    events[0]["timestamp"] = "invalid-time"

    with pytest.raises(ValueError):
        detect_attack_patterns(events)


def test_invalid_source_ip_is_rejected():
    events = [
        make_event("INVALID-IP-1", 1),
        make_event("INVALID-IP-2", 2),
    ]

    events[0]["source_ip"] = "not-an-ip"

    with pytest.raises(ValueError):
        detect_attack_patterns(events)


def test_invalid_window_is_rejected():
    with pytest.raises(ValueError):
        detect_attack_patterns([], window_seconds=0)


def test_invalid_threshold_is_rejected():
    with pytest.raises(ValueError):
        detect_attack_patterns([], min_port_scan=1)
