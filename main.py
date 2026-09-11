"""CLI entry point for the local Automated SOC Incident Response milestone."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import uuid

from detector import detect_repeated_failed_logins
from parser import parse_auth_log
from risk import assess_risk


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_LOG = PROJECT_ROOT / "data" / "auth.log"
DEFAULT_INCIDENTS = PROJECT_ROOT / "incidents"


def build_incident(detection, assessment) -> dict:
    """Create one self-contained, JSON-serializable incident record."""
    incident_id = f"INC-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:8].upper()}"
    return {
        "incident_id": incident_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "open",
        "detection": "repeated_failed_ssh_logins",
        "source_ip": detection.source_ip,
        "host": detection.events[0].host,
        "time_window": {
            "start": detection.window_start.isoformat(),
            "end": detection.window_end.isoformat(),
        },
        "risk": assessment.to_dict(),
        "evidence": [event.to_dict() for event in detection.events],
        "recommended_next_step": (
            "Review the source and account activity in the authorized lab or SIEM. "
            "No automated containment action was taken."
        ),
    }


def write_incident(incident: dict, output_dir: Path) -> Path:
    """Write an incident record locally without modifying any external system."""
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{incident['incident_id']}.json"
    with output_path.open("w", encoding="utf-8") as incident_file:
        json.dump(incident, incident_file, indent=2)
        incident_file.write("\n")
    return output_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze SSH authentication logs and write local incident JSON records."
    )
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG, help="Path to auth.log")
    parser.add_argument(
        "--incidents-dir",
        type=Path,
        default=DEFAULT_INCIDENTS,
        help="Directory for generated incident JSON files",
    )
    parser.add_argument("--threshold", type=int, default=3, help="Failed-login count to alert on")
    parser.add_argument("--window-minutes", type=int, default=10, help="Rolling detection window")
    parser.add_argument(
        "--year",
        type=int,
        default=datetime.now().year,
        help="Year to apply to syslog timestamps that omit a year",
    )
    args = parser.parse_args()

    events = parse_auth_log(args.log, year=args.year)
    detections = detect_repeated_failed_logins(
        events, threshold=args.threshold, window_minutes=args.window_minutes
    )

    print(f"Parsed {len(events)} SSH authentication event(s) from {args.log}")
    if not detections:
        print("No repeated failed-login detections met the configured threshold.")
        return 0

    print(f"Found {len(detections)} repeated failed-login detection(s):")
    for detection in detections:
        assessment = assess_risk(detection)
        incident = build_incident(detection, assessment)
        output_path = write_incident(incident, args.incidents_dir)
        print(
            f"  {incident['incident_id']} | {detection.source_ip} | "
            f"{assessment.severity.upper()} ({assessment.score}/100) | {output_path}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
