"""Detection logic for repeated failed SSH authentication attempts."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable

from parser import AuthEvent


@dataclass(frozen=True)
class FailedLoginDetection:
    """A group of failures from one source IP inside the configured time window."""

    source_ip: str
    events: tuple[AuthEvent, ...]
    window_start: object
    window_end: object

    @property
    def failure_count(self) -> int:
        return len(self.events)

    @property
    def invalid_user_attempts(self) -> int:
        return sum(event.invalid_user for event in self.events)


def detect_repeated_failed_logins(
    events: Iterable[AuthEvent], threshold: int = 3, window_minutes: int = 10
) -> list[FailedLoginDetection]:
    """Find source IPs with ``threshold`` failures in a rolling time window.

    Detections are local analytical findings only. This module does not block an
    address, modify accounts, or contact external systems.
    """
    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    if window_minutes <= 0:
        raise ValueError("window_minutes must be positive")

    failures_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.outcome == "failure":
            failures_by_ip[event.source_ip].append(event)

    detections: list[FailedLoginDetection] = []
    window = timedelta(minutes=window_minutes)
    for source_ip, failures in failures_by_ip.items():
        ordered = sorted(failures, key=lambda event: event.timestamp)
        start_index = 0
        for end_index, event in enumerate(ordered):
            while event.timestamp - ordered[start_index].timestamp > window:
                start_index += 1
            candidate = ordered[start_index : end_index + 1]
            if len(candidate) >= threshold:
                # One incident per source IP is enough for this milestone; use
                # the widest qualifying local window so the report is concise.
                detections.append(
                    FailedLoginDetection(
                        source_ip=source_ip,
                        events=tuple(candidate),
                        window_start=candidate[0].timestamp,
                        window_end=candidate[-1].timestamp,
                    )
                )
                break
    return detections
