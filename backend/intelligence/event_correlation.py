
from __future__ import annotations

import hashlib
import ipaddress
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping


@dataclass(frozen=True)
class CorrelationEvent:
    event_id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    source_type: str
    severity: str


@dataclass(frozen=True)
class CorrelationGroup:
    correlation_id: str
    source_ip: str
    destination_ip: str
    protocol: str
    event_count: int
    first_seen: str
    last_seen: str
    source_types: list[str]
    severities: list[str]
    event_ids: list[str]
    cross_source: bool
    reasons: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def _get(event: Any, field: str) -> Any:
    if isinstance(event, Mapping):
        return event.get(field)
    return getattr(event, field, None)


def _normalize_ip(value: str) -> str:
    """Normalize an IP, accepting an optional destination port."""

    value = value.strip()

    # Handle bracketed IPv6 addresses with optional ports.
    if value.startswith("[") and "]" in value:
        value = value[1:value.index("]")]

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass

    # Handle IPv4 addresses with destination ports.
    if value.count(":") == 1:
        host, _, port = value.rpartition(":")
        if port.isdigit():
            return str(ipaddress.ip_address(host))

    raise ValueError(f"Invalid IP endpoint: {value}")


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


def _prepare_event(event: Any) -> CorrelationEvent:
    event_id = str(_get(event, "event_id") or "").strip()
    if not event_id:
        raise ValueError("Every event must have an event_id.")

    timestamp = _parse_timestamp(_get(event, "timestamp"))

    source_ip = _normalize_ip(
        str(_get(event, "source_ip") or "")
    )

    destination_ip = _normalize_ip(
        str(_get(event, "destination") or "")
    )

    protocol = str(_get(event, "protocol") or "").strip().upper()
    source_type = str(_get(event, "source_type") or "unknown").strip()
    severity = str(_get(event, "severity") or "Unknown").strip()

    if not protocol:
        raise ValueError(f"Event {event_id} has no protocol.")

    return CorrelationEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        source_type=source_type,
        severity=severity,
    )


def correlate_events(
    events: Iterable[Any],
    window_seconds: int = 300,
    min_events: int = 2,
) -> list[CorrelationGroup]:
    """
    Group distinct events with matching source, destination and protocol.

    Each group uses a fixed time window anchored to its first event.
    This prevents continuous activity from extending a group indefinitely.
    """

    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than zero.")

    if min_events < 2:
        raise ValueError("min_events must be at least 2.")

    prepared: list[CorrelationEvent] = []
    seen_ids: set[str] = set()

    for raw_event in events:
        event = _prepare_event(raw_event)

        # Deduplicate globally by event ID.
        if event.event_id in seen_ids:
            continue

        seen_ids.add(event.event_id)
        prepared.append(event)

    # Group by exact, direction-aware network tuple.
    buckets: dict[tuple[str, str, str], list[CorrelationEvent]] = defaultdict(list)

    for event in prepared:
        key = (
            event.source_ip,
            event.destination_ip,
            event.protocol,
        )
        buckets[key].append(event)

    groups: list[CorrelationGroup] = []
    window = timedelta(seconds=window_seconds)

    for (source_ip, destination_ip, protocol), bucket in buckets.items():
        bucket.sort(key=lambda item: (item.timestamp, item.event_id))

        index = 0

        while index < len(bucket):
            first_event = bucket[index]
            cutoff = first_event.timestamp + window

            related = []

            while (
                index < len(bucket)
                and bucket[index].timestamp <= cutoff
            ):
                related.append(bucket[index])
                index += 1

            if len(related) < min_events:
                continue

            source_types = sorted({
                item.source_type for item in related
            })

            severities = sorted({
                item.severity for item in related
            })

            event_ids = [
                item.event_id for item in related
            ]

            cross_source = len(source_types) > 1

            reasons = [
                "Matching source IP",
                "Matching destination IP",
                "Matching network protocol",
                f"{len(related)} distinct events within "
                f"{window_seconds} seconds",
            ]

            if cross_source:
                reasons.append(
                    "Corroborating telemetry from multiple sources"
                )

            # Stable ID for the same group of events.
            fingerprint = "|".join([
                source_ip,
                destination_ip,
                protocol,
                *sorted(event_ids),
            ])

            correlation_id = (
                "CORR-"
                + hashlib.sha256(
                    fingerprint.encode("utf-8")
                ).hexdigest()[:16].upper()
            )

            groups.append(
                CorrelationGroup(
                    correlation_id=correlation_id,
                    source_ip=source_ip,
                    destination_ip=destination_ip,
                    protocol=protocol,
                    event_count=len(related),
                    first_seen=related[0].timestamp.isoformat(),
                    last_seen=related[-1].timestamp.isoformat(),
                    source_types=source_types,
                    severities=severities,
                    event_ids=event_ids,
                    cross_source=cross_source,
                    reasons=reasons,
                )
            )

    groups.sort(
        key=lambda group: group.first_seen,
        reverse=True,
    )

    return groups
