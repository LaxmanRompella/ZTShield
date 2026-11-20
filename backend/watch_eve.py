import argparse
import json
import time
import hashlib
import os

from dotenv import load_dotenv
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


DEFAULT_API_URL = "http://127.0.0.1:8000/api/ingest/suricata"


ENV_FILE = Path(__file__).with_name(".env")
load_dotenv(ENV_FILE)

INGEST_TOKEN = os.getenv("ZTSHIELD_INGEST_TOKEN")

if not INGEST_TOKEN or len(INGEST_TOKEN) != 64:
    raise RuntimeError(
        "Missing or invalid ZTSHIELD_INGEST_TOKEN in backend/.env"
    )

def event_fingerprint(event: dict) -> str:
    """Create a stable SHA-256 fingerprint for an EVE event."""
    canonical = json.dumps(
        event,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(canonical).hexdigest()


def load_seen_fingerprints(path: Path) -> set[str]:
    """Load fingerprints recorded after successful ingestion."""
    if not path.exists():
        return set()

    return {
        line.strip()
        for line in path.read_text(encoding="ascii").splitlines()
        if line.strip()
    }


def remember_fingerprint(path: Path, fingerprint: str) -> None:
    """Persist a fingerprint only after successful API ingestion."""
    with path.open("a", encoding="ascii") as ledger:
        ledger.write(fingerprint + "\n")
        ledger.flush()



def get_file_identity(path: Path) -> str:
    stat = path.stat()
    return f"{stat.st_dev}:{stat.st_ino}"


def save_state(path: Path, identity: str, offset: int) -> None:
    state_path = Path(str(path) + ".watch-state.json")

    data = {
        "file_identity": identity,
        "offset": offset,
    }

    temporary_path = None

    for attempt in range(5):
        temporary_path = state_path.with_name(
            f"{state_path.name}.{time.time_ns()}.{attempt}.tmp"
        )

        try:
            temporary_path.write_text(
                json.dumps(data),
                encoding="utf-8",
            )
            temporary_path.replace(state_path)
            return

        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(0.2 * (attempt + 1))

        finally:
            if temporary_path.exists():
                try:
                    temporary_path.unlink()
                except OSError:
                    pass

def post_alert(
    event: dict,
    api_url: str,
    capture_mode: str,
) -> tuple[bool, bool]:
    """Return (success, permanent_rejection)."""
    request = Request(
        api_url,
        data=json.dumps(event).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-ZTShield-Capture-Mode": capture_mode,
            "X-ZTShield-Token": INGEST_TOKEN,
        },
        method="POST",
    )

    try:
        with urlopen(request, timeout=10) as response:
            if response.status == 201:
                body = json.loads(
                    response.read().decode("utf-8")
                )
                print(
                    f"INGESTED {body['event_id']} - {body['title']}",
                    flush=True,
                )
                return True, False

            print(f"Unexpected HTTP status: {response.status}", flush=True)
            return False, False

    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        print(f"API HTTP {exc.code}: {detail}", flush=True)

        # A permanently invalid record should not block later events.
        if 400 <= exc.code < 500 and exc.code not in (401, 403, 429):
            return False, True

        return False, False

    except (URLError, TimeoutError, OSError, ValueError) as exc:
        print(f"API request failed: {exc}", flush=True)
        return False, False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Monitor a Suricata EVE JSON file for new alerts."
    )
    parser.add_argument("eve_file", type=Path)
    parser.add_argument(
        "--api-url",
        default=DEFAULT_API_URL,
        help="ZTShield Suricata ingestion endpoint",
    )
    parser.add_argument(
    "--capture-mode",
    choices=["live", "pcap", "unknown"],
    default="unknown",
    help="Label the origin of ingested Suricata events",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=1.0,
        help="Seconds between checks (default: 1)",
    )
    parser.add_argument(
        "--from-start",
        action="store_true",
        help="Read existing records from the beginning on first run",
    )
    args = parser.parse_args()

    source = args.eve_file.resolve()

    if args.poll_interval <= 0:
        parser.error("--poll-interval must be greater than zero")

    state_path = Path(str(source) + ".watch-state.json")
    saved_state = None
    
    seen_path = Path(str(source) + ".watch-seen.sha256")

    if state_path.exists():
        try:
            saved_state = json.loads(
                state_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            print(f"Cannot read watcher state: {exc}")
            return 1
    seen = load_seen_fingerprints(seen_path)
    
    identity = None
    offset = 0 if args.from_start else None

    if saved_state:
        identity = saved_state.get("file_identity")
        offset = saved_state.get("offset", 0)

    initialized = False
    waiting_reported = False

    print(f"Watching: {source}", flush=True)
    print(f"API: {args.api_url}", flush=True)
    print("Press Ctrl+C to stop.", flush=True)

    try:
        while True:
            if not source.is_file():
                if not waiting_reported:
                    print("Waiting for the EVE file to appear...", flush=True)
                    waiting_reported = True
                time.sleep(args.poll_interval)
                continue

            waiting_reported = False

            try:
                current_identity = get_file_identity(source)
                current_size = source.stat().st_size
            except OSError as exc:
                print(f"Cannot inspect EVE file: {exc}", flush=True)
                time.sleep(args.poll_interval)
                continue

            if identity is None:
                identity = current_identity
                offset = (
                    current_size
                    if offset is None
                    else offset
                )
                save_state(source, identity, offset)
                initialized = True
                print(f"Starting at byte offset {offset}.", flush=True)

            elif identity != current_identity or current_size < offset:
                # The file was replaced, rotated, or truncated.
                identity = current_identity
                offset = 0
                save_state(source, identity, offset)
                print("File rotation/truncation detected; restarting at byte 0.", flush=True)

            try:
                with source.open("rb") as log:
                    log.seek(offset)

                    while True:
                        line_start = log.tell()
                        raw_line = log.readline()

                        if not raw_line:
                            break

                        # Wait for a complete JSONL record.
                        if not raw_line.endswith(b"\n"):
                            break

                        next_offset = log.tell()

                        try:
                            event = json.loads(raw_line.decode("utf-8-sig"))
                        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                            print(
                                f"Skipping invalid JSON at byte {line_start}: {exc}",
                                flush=True,
                            )
                            offset = next_offset
                            save_state(source, identity, offset)
                            continue

                        if not isinstance(event, dict):
                            offset = next_offset
                            save_state(source, identity, offset)
                            continue

                        if event.get("event_type") != "alert":
                            offset = next_offset
                            save_state(source, identity, offset)
                            continue

                        if not isinstance(event.get("alert"), dict):
                            print("Skipping alert without alert details.", flush=True)
                            offset = next_offset
                            save_state(source, identity, offset)
                            continue

                        
                        event_hash = event_fingerprint(event)

                        if event_hash in seen:
                            offset = next_offset
                            save_state(source, identity, offset)
                            print(
                                f"Skipping previously processed event at byte {line_start}.",
                                flush=True,
                            )
                            continue

                        success, permanent_rejection = post_alert(
                            event,
                            args.api_url,
                            args.capture_mode,
                        )
                        
                        
                        if success:
                            remember_fingerprint(seen_path, event_hash)
                            seen.add(event_hash)
                            
                            offset = next_offset
                            save_state(source, identity, offset)
                            continue
                        
                        if permanent_rejection:
                            offset = next_offset
                            save_state(source, identity, offset)
                            continue

                        # Keep the failed record unconsumed so it can retry.
                        offset = line_start
                        save_state(source, identity, offset)
                        break

            except OSError as exc:
                print(f"Error reading EVE file: {exc}", flush=True)

            time.sleep(args.poll_interval)

    except KeyboardInterrupt:
        print("\nEVE watcher stopped.", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
