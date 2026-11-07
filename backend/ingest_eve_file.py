import argparse
import hashlib
import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


API_URL = "http://127.0.0.1:8000/api/ingest/suricata"


def fingerprint(event: dict) -> str:
    canonical = json.dumps(
        event, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replay Suricata EVE JSON alert records into ZTShield."
    )
    parser.add_argument("eve_file", help="Path to newline-delimited EVE JSON")
    args = parser.parse_args()

    source = Path(args.eve_file)
    if not source.is_file():
        print(f"ERROR: EVE file not found: {source}")
        return 1

    # Remember successfully ingested lines to avoid replaying them.
    state_file = source.with_name(source.name + ".ingested.sha256")
    seen = set()

    if state_file.exists():
        seen = {
            line.strip()
            for line in state_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }

    sent = skipped = duplicates = failed = 0

    with source.open("r", encoding="utf-8") as log, \
            state_file.open("a", encoding="utf-8") as state:
        for line_number, line in enumerate(log, start=1):
            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"Line {line_number}: invalid JSON: {exc}")
                failed += 1
                continue

            if not isinstance(event, dict):
                print(f"Line {line_number}: skipped non-object JSON")
                skipped += 1
                continue

            # Ignore DNS, flow and other non-alert EVE event types.
            if event.get("event_type") != "alert":
                skipped += 1
                continue

            if not isinstance(event.get("alert"), dict):
                print(f"Line {line_number}: alert details missing")
                failed += 1
                continue

            event_hash = fingerprint(event)

            if event_hash in seen:
                duplicates += 1
                continue

            request = Request(
                API_URL,
                data=json.dumps(event).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            try:
                with urlopen(request, timeout=10) as response:
                    body = json.loads(response.read().decode("utf-8"))

                    if response.status != 201:
                        print(
                            f"Line {line_number}: unexpected HTTP "
                            f"{response.status}"
                        )
                        failed += 1
                        continue

                # Save the fingerprint only after successful ingestion.
                state.write(event_hash + "\n")
                state.flush()
                seen.add(event_hash)
                sent += 1
                print(
                    f"Line {line_number}: ingested "
                    f"{body['event_id']} — {body['title']}"
                )

            except HTTPError as exc:
                details = exc.read().decode("utf-8", errors="replace")
                print(f"Line {line_number}: HTTP {exc.code}: {details}")
                failed += 1
            except (URLError, TimeoutError, OSError, ValueError) as exc:
                print(f"Line {line_number}: ingestion failed: {exc}")
                failed += 1

    print(
        f"\nFinished: {sent} ingested, {skipped} skipped, "
        f"{duplicates} already processed, {failed} failed."
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
