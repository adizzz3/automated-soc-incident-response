"""Transparent, local-only risk scoring for failed-login detections."""

from __future__ import annotations

from dataclasses import dataclass

from detector import FailedLoginDetection


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    severity: str
    reasons: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "severity": self.severity,
            "reasons": list(self.reasons),
        }


def assess_risk(detection: FailedLoginDetection) -> RiskAssessment:
    """Score a detection using simple, explainable defensive rules.

    Scores are capped at 100. They are triage guidance, not a verdict that an IP
    is malicious.
    """
    reasons: list[str] = []
    score = min(detection.failure_count * 15, 60)
    reasons.append(f"{detection.failure_count} failed logins from one source IP")

    if detection.failure_count >= 3:
        score += 20
        reasons.append("repeated-login threshold met within the analysis window")
    if detection.invalid_user_attempts:
        score += 20
        reasons.append(
            f"{detection.invalid_user_attempts} attempt(s) targeted invalid account names"
        )

    score = min(score, 100)
    if score >= 80:
        severity = "high"
    elif score >= 50:
        severity = "medium"
    else:
        severity = "low"
    return RiskAssessment(score=score, severity=severity, reasons=tuple(reasons))
