"""Parsing helpers for common Linux SSH authentication log entries."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
import re
from typing import Iterable


AUTH_EVENT_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<action>Failed password|Accepted \S+)\s+for\s+"
    r"(?:(?P<invalid>invalid user)\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<source_ip>\S+)\s+port\s+(?P<port>\d+)"
)


@dataclass(frozen=True)
class AuthEvent:
    """A normalized SSH authentication event extracted from one log line."""

    timestamp: datetime
    host: str
    source_ip: str
    username: str
    port: int
    outcome: str
    invalid_user: bool
    raw_line: str
    line_number: int

    def to_dict(self) -> dict:
        """Return a JSON-friendly representation."""
        payload = asdict(self)
        payload["timestamp"] = self.timestamp.isoformat()
        return payload


def parse_auth_line(line: str, line_number: int, year: int) -> AuthEvent | None:
    """Parse one SSH auth.log line; return None for unsupported or comment lines."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    match = AUTH_EVENT_RE.match(stripped)
    if not match:
        return None

    timestamp = datetime.strptime(
        f"{year} {match.group('timestamp')}", "%Y %b %d %H:%M:%S"
    )
    action = match.group("action")
    return AuthEvent(
        timestamp=timestamp,
        host=match.group("host"),
        source_ip=match.group("source_ip"),
        username=match.group("user"),
        port=int(match.group("port")),
        outcome="failure" if action == "Failed password" else "success",
        invalid_user=bool(match.group("invalid")),
        raw_line=stripped,
        line_number=line_number,
    )


def parse_auth_log(path: str | Path, year: int | None = None) -> list[AuthEvent]:
    """Read a local auth.log file and normalize recognized SSH events.

    Linux syslog timestamps omit the year; the current year is used unless one is
    provided explicitly. Unrecognized lines are safely skipped.
    """
    log_path = Path(path)
    event_year = year if year is not None else datetime.now().year
    events: list[AuthEvent] = []

    with log_path.open("r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            event = parse_auth_line(line, line_number, event_year)
            if event is not None:
                events.append(event)
    return events


def failed_events(events: Iterable[AuthEvent]) -> list[AuthEvent]:
    """Return only failed authentication events."""
    return [event for event in events if event.outcome == "failure"]
