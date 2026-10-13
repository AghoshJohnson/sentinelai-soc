"""
scorer.py - Severity Scoring Engine

Assigns a severity score (LOW / MEDIUM / HIGH / CRITICAL) to a set of
detections based on frequency, rule confidence, threat category weights,
and MITRE tactic risk levels.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

SeverityLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass
class ScoringResult:
    """Final severity assessment for a log analysis session."""
    score: int                   # raw numeric score (0–100)
    severity: SeverityLevel
    breakdown: dict              # per-factor scores for transparency
    summary: str

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "severity": self.severity,
            "breakdown": self.breakdown,
            "summary": self.summary,
        }


# ---------------------------------------------------------------------------
# Scoring weights
# ---------------------------------------------------------------------------

# Per alert-type base score
_TYPE_BASE_SCORES: dict[str, int] = {
    "SSH Brute Force": 30,
    "Brute Force Success": 60,
    "SQL Injection": 45,
    "Cross-Site Scripting (XSS)": 35,
    "Path Traversal": 40,
    "Sensitive File Enumeration": 25,
    "Automated Scanner Detected": 20,
    "Command Injection": 50,
}

# Confidence multipliers
_CONFIDENCE_MULTIPLIERS: dict[str, float] = {
    "low": 0.5,
    "medium": 0.75,
    "high": 1.0,
}

# MITRE tactic risk weights
_TACTIC_RISK_WEIGHTS: dict[str, int] = {
    "Initial Access": 15,
    "Credential Access": 12,
    "Execution": 18,
    "Persistence": 15,
    "Privilege Escalation": 20,
    "Defense Evasion": 10,
    "Lateral Movement": 18,
    "Collection": 12,
    "Command and Control": 15,
    "Exfiltration": 20,
    "Impact": 20,
    "Reconnaissance": 5,
    "Discovery": 8,
}

# Thresholds for final severity bands
_SEVERITY_THRESHOLDS = [
    (80, "CRITICAL"),
    (55, "HIGH"),
    (30, "MEDIUM"),
    (0,  "LOW"),
]


# ---------------------------------------------------------------------------
# Scoring functions
# ---------------------------------------------------------------------------

def _score_from_alerts(alerts: list[dict]) -> tuple[int, dict]:
    """
    Compute a score contribution from rule alerts.

    Returns (score, breakdown_dict).
    """
    if not alerts:
        return 0, {}

    breakdown: dict[str, int] = {}
    total = 0

    for alert in alerts:
        alert_type = alert.get("type", "unknown")
        confidence = alert.get("confidence", "low").lower()
        base = _TYPE_BASE_SCORES.get(alert_type, 15)
        multiplier = _CONFIDENCE_MULTIPLIERS.get(confidence, 0.5)
        contribution = int(base * multiplier)
        breakdown[alert_type] = breakdown.get(alert_type, 0) + contribution
        total += contribution

    # Diminishing returns: cap per-category at base*2, cap total at 70
    capped_breakdown = {k: min(v, _TYPE_BASE_SCORES.get(k, 15) * 2) for k, v in breakdown.items()}
    capped_total = min(total, 70)

    return capped_total, capped_breakdown


def _score_from_mitre(mitre_techniques: list[dict]) -> tuple[int, list[str]]:
    """
    Add risk score based on MITRE tactics observed.

    Returns (score, list_of_high_risk_tactics).
    """
    if not mitre_techniques:
        return 0, []

    tactics_seen: set[str] = {t.get("tactic", "") for t in mitre_techniques}
    high_risk: list[str] = []
    total = 0

    for tactic in tactics_seen:
        weight = _TACTIC_RISK_WEIGHTS.get(tactic, 5)
        total += weight
        if weight >= 15:
            high_risk.append(tactic)

    # Cap MITRE contribution at 30
    return min(total, 30), high_risk


def _score_from_volume(events: list[dict], alerts: list[dict]) -> int:
    """
    Add a small bonus for high-volume attacks.
    """
    n_events = len(events)
    n_alerts = len(alerts)

    if n_alerts >= 5 or n_events >= 200:
        return 10
    if n_alerts >= 3 or n_events >= 50:
        return 5
    return 0


def _score_to_severity(score: int) -> SeverityLevel:
    for threshold, level in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return level  # type: ignore[return-value]
    return "LOW"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compute_severity(
    events: list[dict],
    alerts: list[dict],
    mitre_techniques: list[dict],
) -> ScoringResult:
    """
    Compute a holistic severity score for a log analysis session.

    Parameters
    ----------
    events:
        Parsed log events from parser.py.
    alerts:
        Rule alerts from rules.py (as dicts via .to_dict()).
    mitre_techniques:
        MITRE technique list from mitre.py build_mitre_summary().

    Returns
    -------
    ScoringResult
        Full scoring result including numeric score, severity label, and breakdown.
    """
    alert_score, alert_breakdown = _score_from_alerts(alerts)
    mitre_score, high_risk_tactics = _score_from_mitre(mitre_techniques)
    volume_score = _score_from_volume(events, alerts)

    total_score = min(alert_score + mitre_score + volume_score, 100)
    severity = _score_to_severity(total_score)

    # Build human-readable summary
    alert_types = list({a.get("type", "unknown") for a in alerts})
    if severity == "CRITICAL":
        summary = (
            f"CRITICAL threat detected. Multiple high-confidence indicators including "
            f"{', '.join(alert_types[:3])} across {len(events)} events. "
            f"Immediate incident response recommended."
        )
    elif severity == "HIGH":
        summary = (
            f"High-severity activity detected: {', '.join(alert_types[:3])}. "
            f"Prompt investigation and containment required."
        )
    elif severity == "MEDIUM":
        summary = (
            f"Moderate suspicious activity detected: {', '.join(alert_types[:3])}. "
            f"Review and monitor closely."
        )
    else:
        summary = (
            f"Low-severity indicators observed. Minimal risk, but continued monitoring advised."
        )

    if high_risk_tactics:
        summary += f" High-risk MITRE tactics: {', '.join(high_risk_tactics)}."

    breakdown = {
        "alert_score": alert_score,
        "mitre_score": mitre_score,
        "volume_score": volume_score,
        "total_score": total_score,
        "per_alert_type": alert_breakdown,
        "high_risk_mitre_tactics": high_risk_tactics,
    }

    logger.info(
        "Severity computed: %s (score=%d) | alerts=%d, mitre_tactics=%d",
        severity, total_score, len(alerts), len(mitre_techniques),
    )

    return ScoringResult(
        score=total_score,
        severity=severity,
        breakdown=breakdown,
        summary=summary,
    )
