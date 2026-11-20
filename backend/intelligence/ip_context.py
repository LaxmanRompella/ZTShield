
from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from typing import Literal

IPCategory = Literal[
    "private",
    "public",
    "loopback",
    "link_local",
    "reserved",
    "multicast",
    "unspecified",
    "invalid",
]


@dataclass(frozen=True)
class IPContext:
    address: str
    version: int | None
    category: IPCategory
    is_global: bool
    is_private: bool
    is_reserved: bool
    reputation_lookup_eligible: bool
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)


def classify_ip(value: str) -> IPContext:
    """Validate, normalize and classify an IPv4 or IPv6 address."""

    try:
        address = ipaddress.ip_address(value.strip())
    except (ValueError, AttributeError):
        return IPContext(
            address=str(value),
            version=None,
            category="invalid",
            is_global=False,
            is_private=False,
            is_reserved=False,
            reputation_lookup_eligible=False,
            reason="Invalid IP address.",
        )

    if address.is_unspecified:
        category: IPCategory = "unspecified"
        reason = "Unspecified address; not a valid remote endpoint."
    elif address.is_loopback:
        category = "loopback"
        reason = "Loopback address; refers to the local host."
    elif address.is_multicast:
        category = "multicast"
        reason = "Multicast address; not an individual remote host."
    elif address.is_link_local:
        category = "link_local"
        reason = "Link-local address; limited to the local network segment."
    elif address.is_reserved or not address.is_global and not address.is_private:
        category = "reserved"
        reason = "Reserved or special-purpose address; reputation lookup is not applicable."
    elif address.is_private:
        category = "private"
        reason = "Private address; reputation lookup against public IP feeds is not applicable."
    else:
        category = "public"
        reason = "Globally routable address; eligible for external reputation enrichment."

    return IPContext(
        address=str(address),
        version=address.version,
        category=category,
        is_global=address.is_global,
        is_private=address.is_private,
        is_reserved=address.is_reserved,
        reputation_lookup_eligible=category == "public",
        reason=reason,
    )


def classify_ip_pair(source_ip: str, destination_ip: str) -> dict:
    """Classify both endpoints of a network event."""

    source = classify_ip(source_ip)
    destination = classify_ip(destination_ip)

    return {
        "source": source.to_dict(),
        "destination": destination.to_dict(),
        "communication_scope": (
            "internal"
            if source.is_private and destination.is_private
            else "external"
            if source.reputation_lookup_eligible
            or destination.reputation_lookup_eligible
            else "special"
        ),
    }
