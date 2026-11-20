import csv
import ipaddress
import json
import logging
import re
import socketserver
import hashlib
import os
from pathlib import Path
from dotenv import load_dotenv
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


# Windows host-only interface and pfSense telemetry address.
BIND_HOST = "192.168.56.1"
BIND_PORT = 5514
EXPECTED_SENDER = "192.168.56.2"

# Existing FastAPI backend.
API_URL = "http://127.0.0.1:8000/api/ingest/pfsense"

# Load the same secure token used by the FastAPI backend.
ENV_FILE = Path(__file__).with_name(".env")
load_dotenv(ENV_FILE)

INGEST_TOKEN = os.getenv("ZTSHIELD_INGEST_TOKEN")

if not INGEST_TOKEN or len(INGEST_TOKEN) != 64:
    raise RuntimeError(
        "Missing or invalid ZTSHIELD_INGEST_TOKEN in backend/.env"
    )

# Map pfSense physical interface names to configured logical names.
INTERFACE_LABELS = {
    "em0": "WAN",
    "em1": "LAN",
    "em2": "OPT1",
    "em3": "OPT2",
    "em4": "OPT3",
    "em5": "OPT4",
}

FILTERLOG_PATTERN = re.compile(
    r"\bfilterlog(?:\[\d+\])?:\s*(.*)$"
)

BSD_TIMESTAMP_PATTERN = re.compile(
    r"^(?:<\d+>)?([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


def parse_syslog_timestamp(message: str) -> str:
    """Parse a BSD syslog timestamp and normalize it to UTC."""

    match = BSD_TIMESTAMP_PATTERN.match(message)

    if not match:
        return datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        )

    current_local = datetime.now().astimezone()
    year = current_local.year

    parsed = datetime.strptime(
        f"{year} {match.group(1)}",
        "%Y %b %d %H:%M:%S",
    )

    parsed = parsed.replace(tzinfo=current_local.tzinfo)

    # Handle a December/January year boundary.
    if (parsed - current_local).days > 1:
        parsed = parsed.replace(year=year - 1)

    return parsed.astimezone(timezone.utc).isoformat(
        timespec="seconds"
    )


def parse_filterlog(message: str) -> dict | None:
    """Convert a pfSense BSD filterlog message into API input."""

    match = FILTERLOG_PATTERN.search(message)

    # Ignore non-firewall syslog messages.
    if not match:
        return None

    csv_data = match.group(1).strip()
    fields = next(csv.reader([csv_data]))

    # Common fields occupy positions 0 through 8.
    if len(fields) < 9:
        raise ValueError("Incomplete filterlog common fields")

    rule_number = fields[0]
    rule_tracker = fields[3] or None
    real_interface = fields[4]
    reason = fields[5]
    action = fields[6].lower()
    direction = fields[7].lower()

    ip_version = int(fields[8])

    if action not in {"pass", "block"}:
        logging.info("Skipping unsupported action: %s", action)
        return None

    if direction not in {"in", "out"}:
        raise ValueError(f"Unsupported direction: {direction}")

    # IPv4 and IPv6 have different protocol-specific offsets.
    if ip_version == 4:
        protocol_index = 16
        source_index = 18
        destination_index = 19
        port_index = 20

    elif ip_version == 6:
        protocol_index = 12
        source_index = 15
        destination_index = 16
        port_index = 17

    else:
        raise ValueError(f"Unsupported IP version: {ip_version}")

    required_length = destination_index + 1

    if len(fields) <= required_length:
        raise ValueError("Incomplete IP address fields")

    protocol = fields[protocol_index].strip().upper()

    source_ip = str(ipaddress.ip_address(fields[source_index]))
    destination_ip = str(
        ipaddress.ip_address(fields[destination_index])
    )

    source_address = ipaddress.ip_address(source_ip)
    destination_address = ipaddress.ip_address(destination_ip)

    if (
        source_address.version != ip_version
        or destination_address.version != ip_version
    ):
        raise ValueError("IP version does not match addresses")

    source_port = None
    destination_port = None

    if protocol in {"TCP", "UDP"}:
        if len(fields) <= port_index + 1:
            raise ValueError("Missing TCP/UDP port fields")

        source_port = int(fields[port_index])
        destination_port = int(fields[port_index + 1])

        if not (0 <= source_port <= 65535):
            raise ValueError("Invalid source port")

        if not (0 <= destination_port <= 65535):
            raise ValueError("Invalid destination port")

    interface = INTERFACE_LABELS.get(
        real_interface,
        real_interface.upper(),
    )

    return {
        "timestamp": parse_syslog_timestamp(message),
        "action": action,
        "interface": interface,
        "reason": reason or "match",
        "direction": direction,
        "ip_version": ip_version,
        "protocol": protocol,
        "src_ip": source_ip,
        "dest_ip": destination_ip,
        "src_port": source_port,
        "dest_port": destination_port,
        "rule_number": rule_number,
        "rule_tracker": rule_tracker,
        "severity": "medium" if action == "block" else "info",
    }



def forward_to_api(payload: dict) -> None:
    """Submit a normalized event securely to the FastAPI endpoint."""

    # Generate a deterministic fingerprint for duplicate protection.
    canonical_payload = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    fingerprint = hashlib.sha256(canonical_payload).hexdigest().upper()

    body = json.dumps(payload).encode("utf-8")

    request = Request(
        API_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-ZTShield-Token": INGEST_TOKEN,
            "X-Event-Fingerprint": fingerprint,
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=5) as response:
            logging.info(
                "Event submitted: HTTP %s | %s -> %s | %s | fingerprint=%s",
                response.status,
                payload["src_ip"],
                payload["dest_ip"],
                payload["action"],
                fingerprint[:12],
            )

    except HTTPError as exc:
        logging.error(
            "FastAPI rejected event: HTTP %s | %s",
            exc.code,
            exc.read().decode("utf-8", errors="replace"),
        )

    except URLError as exc:
        logging.error("FastAPI connection failed: %s", exc.reason)

    except TimeoutError:
        logging.error("FastAPI request timed out")



class SyslogUDPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        raw_data = self.request[0].decode(
            "utf-8",
            errors="replace",
        )

        sender_ip = self.client_address[0]

        # Defense in depth: only accept our pfSense telemetry IP.
        if sender_ip != EXPECTED_SENDER:
            logging.warning(
                "Rejected syslog sender: %s",
                sender_ip,
            )
            return

        for line in raw_data.splitlines() or [raw_data]:
            try:
                payload = parse_filterlog(line)

                if payload is None:
                    continue

                forward_to_api(payload)

            except (ValueError, IndexError, csv.Error) as exc:
                logging.warning(
                    "Could not parse filterlog message: %s",
                    exc,
                )


class SyslogUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    server_address = (BIND_HOST, BIND_PORT)

    try:
        with SyslogUDPServer(
            server_address,
            SyslogUDPHandler,
        ) as server:

            logging.info(
                "ZTShield pfSense syslog receiver listening on "
                "%s:%s/UDP",
                BIND_HOST,
                BIND_PORT,
            )

            logging.info(
                "Accepted sender: %s",
                EXPECTED_SENDER,
            )

            logging.info("FastAPI target: %s", API_URL)

            server.serve_forever()

    except OSError as exc:
        logging.error("Could not start UDP listener: %s", exc)
        raise


if __name__ == "__main__":
    main()
