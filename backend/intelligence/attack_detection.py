
from __future__ import annotations

import hashlib
import ipaddress
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping


AUTH_FAILURE_KEYWORDS = (
    "authentication failed",
    "login failed",
    "failed login",
    "invalid password",
    "brute force",
    "authentication failure",
)

SERVICE_PORTS = {
    21, 22, 23, 25, 110, 143,
    445, 3306, 3389, 5432, 5900,
}

LATERAL_MOVEMENT_PORTS = {
    22,    # SSH
    135,   # RPC
    139,   # NetBIOS
    445,   # SMB
    3389,  # RDP
    5985,  # WinRM HTTP
    5986,  # WinRM HTTPS
}


@dataclass(frozen=True)
class AttackDetection:
    detection_id: str
    pattern: str
    source_ip: str
    target_ips: list[str]
    event_count: int
    severity: str
    confidence: str
    first_seen: str
    last_seen: str
    event_ids: list[str]
    evidence: list[str]
    description: str

    def to_dict(self) -> dict:
        return asdict(self)


def _get(event: Any, field: str) -> Any:
    if isinstance(event, Mapping):
        return event.get(field)
    return getattr(event, field, None)


def _parse_endpoint(value: Any) -> tuple[str, int | None]:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Missing or invalid destination endpoint.")

    value = value.strip()

    if value.startswith("[") and "]" in value:
        closing = value.index("]")
        host = value[1:closing]
        remainder = value[closing + 1:]
        port = None

        if remainder:
            if not remainder.startswith(":"):
                raise ValueError("Invalid IPv6 endpoint.")
            port = int(remainder[1:])

        address = ipaddress.ip_address(host)

    else:
        try:
            address = ipaddress.ip_address(value)
            port = None
        except ValueError:
            if value.count(":") != 1:
                raise ValueError(f"Invalid endpoint: {value}")

            host, port_text = value.rsplit(":", 1)

            if not port_text.isdigit():
                raise ValueError(f"Invalid destination port: {value}")

            address = ipaddress.ip_address(host)
            port = int(port_text)

    if port is not None and not 0 <= port <= 65535:
        raise ValueError("Destination port must be between 0 and 65535.")

    return str(address), port


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    else:
        raise ValueError("Invalid event timestamp.")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _is_blocked(event: Any) -> bool:
    action = str(_get(event, "action") or "").casefold()
    title = str(_get(event, "title") or "").casefold()

    return (
        action == "block"
        or "block" in title
        or "blocked" in title
    )


def _has_auth_failure(event: Any) -> bool:
    text = " ".join([
        str(_get(event, "title") or ""),
        str(_get(event, "category") or ""),
        str(_get(event, "signature") or ""),
    ]).casefold()

    return any(keyword in text for keyword in AUTH_FAILURE_KEYWORDS)


def _make_detection(
    pattern: str,
    source_ip: str,
    events: list[dict],
    severity: str,
    confidence: str,
    evidence: list[str],
    description: str,
) -> AttackDetection:

    event_ids = sorted({
        item["event_id"] for item in events
    })

    target_ips = sorted({
        item["destination_ip"] for item in events
    })

    first_seen = min(item["timestamp"] for item in events)
    last_seen = max(item["timestamp"] for item in events)

    fingerprint = "|".join([
        pattern,
        source_ip,
        *event_ids,
    ])

    detection_id = (
        "DETECT-"
        + hashlib.sha256(
            fingerprint.encode("utf-8")
        ).hexdigest()[:16].upper()
    )

    return AttackDetection(
        detection_id=detection_id,
        pattern=pattern,
        source_ip=source_ip,
        target_ips=target_ips,
        event_count=len(event_ids),
        severity=severity,
        confidence=confidence,
        first_seen=first_seen.isoformat(),
        last_seen=last_seen.isoformat(),
        event_ids=event_ids,
        evidence=evidence,
        description=description,
    )


def detect_attack_patterns(
    events: Iterable[Any],
    window_seconds: int = 300,
    min_port_scan: int = 5,
    min_host_scan: int = 5,
    min_blocked_events: int = 5,
    min_auth_failures: int = 5,
    min_lateral_events: int = 3,
) -> list[AttackDetection]:
    """
    Detect explainable attack indicators in network events.

    These detections indicate suspicious patterns, not proof
    of successful compromise.
    """

    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive.")

    thresholds = [
        min_port_scan,
        min_host_scan,
        min_blocked_events,
        min_auth_failures,
        min_lateral_events,
    ]

    if any(value < 2 for value in thresholds):
        raise ValueError("All detection thresholds must be at least 2.")

    prepared = []
    seen_ids = set()

    for event in events:
        event_id = str(_get(event, "event_id") or "").strip()

        if not event_id:
            raise ValueError("Every event must have an event_id.")

        if event_id in seen_ids:
            continue

        seen_ids.add(event_id)

        try:
            source_ip = str(
                ipaddress.ip_address(
                    str(_get(event, "source_ip") or "").strip()
                )
            )
        except ValueError as exc:
            raise ValueError(
                f"Invalid source IP in event {event_id}."
            ) from exc

        destination_value = (
            _get(event, "destination")
            or _get(event, "dest_ip")
        )

        destination_ip, destination_port = _parse_endpoint(
            destination_value
        )

        timestamp = _parse_timestamp(_get(event, "timestamp"))

        prepared.append({
            "event_id": event_id,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_port": (
                _get(event, "dest_port")
                if _get(event, "dest_port") is not None
                else destination_port
            ),
            "protocol": str(
                _get(event, "protocol") or "UNKNOWN"
            ).upper(),
            "timestamp": timestamp,
            "blocked": _is_blocked(event),
            "auth_failure": _has_auth_failure(event),
            "zone": str(_get(event, "zone") or "UNKNOWN").upper(),
        })

    prepared.sort(
        key=lambda item: (item["timestamp"], item["event_id"])
    )

    by_source = defaultdict(list)

    for event in prepared:
        by_source[event["source_ip"]].append(event)

    detections = {}
    window = timedelta(seconds=window_seconds)

    for source_ip, source_events in by_source.items():

        index = 0

        while index < len(source_events):
            anchor = source_events[index]["timestamp"]
            cutoff = anchor + window

            window_events = []

            while (
                index < len(source_events)
                and source_events[index]["timestamp"] <= cutoff
            ):
                window_events.append(source_events[index])
                index += 1

            if len(window_events) < 2:
                continue

            # 1. Port scan: one source probing many ports
            # on the same destination host.
            by_target = defaultdict(list)

            for event in window_events:
                by_target[event["destination_ip"]].append(event)

            for target_ip, target_events in by_target.items():
                ports = {
                    item["destination_port"]
                    for item in target_events
                    if item["destination_port"] is not None
                }

                if len(ports) >= min_port_scan:
                    detection = _make_detection(
                        pattern="port_scan",
                        source_ip=source_ip,
                        events=target_events,
                        severity="High",
                        confidence="High",
                        evidence=[
                            f"{len(ports)} distinct destination ports",
                            f"Target host: {target_ip}",
                            f"Observation window: {window_seconds} seconds",
                        ],
                        description=(
                            "One source contacted multiple ports "
                            "on the same destination host."
                        ),
                    )
                    detections[detection.detection_id] = detection

            # 2. Host scan: one source contacting many hosts.
            targets = {
                item["destination_ip"] for item in window_events
            }

            if len(targets) >= min_host_scan:
                detection = _make_detection(
                    pattern="host_scan",
                    source_ip=source_ip,
                    events=window_events,
                    severity="High",
                    confidence="High",
                    evidence=[
                        f"{len(targets)} distinct destination hosts",
                        f"Observation window: {window_seconds} seconds",
                    ],
                    description=(
                        "One source contacted multiple destination hosts."
                    ),
                )
                detections[detection.detection_id] = detection

            # 3. Repeated blocked connections.
            blocked_events = [
                item for item in window_events if item["blocked"]
            ]

            if len(blocked_events) >= min_blocked_events:
                detection = _make_detection(
                    pattern="repeated_blocked_connections",
                    source_ip=source_ip,
                    events=blocked_events,
                    severity="Medium",
                    confidence="High",
                    evidence=[
                        f"{len(blocked_events)} blocked events",
                        "Firewall block indicators found",
                    ],
                    description=(
                        "Repeated firewall-blocked activity "
                        "was observed from one source."
                    ),
                )
                detections[detection.detection_id] = detection

            # 4. Possible brute-force activity.
            # Require explicit authentication-failure evidence.
            auth_events = [
                item for item in window_events
                if item["auth_failure"]
            ]

            auth_ports = {
                item["destination_port"]
                for item in auth_events
                if item["destination_port"] in SERVICE_PORTS
            }

            if len(auth_events) >= min_auth_failures:
                detection = _make_detection(
                    pattern="possible_brute_force",
                    source_ip=source_ip,
                    events=auth_events,
                    severity="High",
                    confidence="Medium",
                    evidence=[
                        f"{len(auth_events)} authentication-failure indicators",
                        f"Recognized service ports: {sorted(auth_ports)}",
                    ],
                    description=(
                        "Repeated authentication-failure indicators "
                        "suggest possible brute-force activity."
                    ),
                )
                detections[detection.detection_id] = detection

            # 5. Lateral movement indicator.
    # Require private endpoints in different provisional subnets
    # AND a recognized administrative service port.
    lateral_events = []

    for event in window_events:
        source = ipaddress.ip_address(event["source_ip"])
        destination = ipaddress.ip_address(event["destination_ip"])

        if (
            source.is_private
            and destination.is_private
            and source.version == destination.version
            and event["destination_port"] in LATERAL_MOVEMENT_PORTS
        ):
            prefix = 24 if source.version == 4 else 64

            source_network = ipaddress.ip_network(
                f"{source}/{prefix}", strict=False
            )
            destination_network = ipaddress.ip_network(
                f"{destination}/{prefix}", strict=False
            )

            if source_network != destination_network:
                lateral_events.append(event)

    if len(lateral_events) >= min_lateral_events:
        detection = _make_detection(
            pattern="lateral_movement_indicator",
            source_ip=source_ip,
            events=lateral_events,
            severity="Medium",
            confidence="Low",
            evidence=[
                "Private source and destination addresses",
                "Communication crosses provisional subnet boundaries",
                "Administrative or remote-management service ports detected",
                f"{len(lateral_events)} qualifying events",
            ],
            description=(
                "Repeated cross-subnet communication over "
                "administrative service ports may indicate "
                "lateral movement and requires investigation."
            ),
        )
        detections[detection.detection_id] = detection

    return sorted(
        detections.values(),
        key=lambda item: item.first_seen,
        reverse=True,
    )
