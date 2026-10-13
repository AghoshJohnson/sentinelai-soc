"""
rules.py - Rule-Based Threat Detection Engine

Implements signature/threshold-based detection for common attack patterns.
Each rule returns a standardised RuleAlert dict.
"""

from __future__ import annotations

import re
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Alert data structure
# ---------------------------------------------------------------------------

@dataclass
class RuleAlert:
    """Represents a single rule-triggered alert."""
    alert: bool
    rule_id: str
    type: str
    confidence: str          # "low" | "medium" | "high"
    description: str
    source_ip: str
    affected_events: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "alert": self.alert,
            "rule_id": self.rule_id,
            "type": self.type,
            "confidence": self.confidence,
            "description": self.description,
            "source_ip": self.source_ip,
            "affected_event_count": len(self.affected_events),
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Thresholds & constants
# ---------------------------------------------------------------------------

SSH_BRUTEFORCE_THRESHOLD = 5          # failed logins per IP to trigger alert
SSH_RAPID_THRESHOLD_SECONDS = 60      # window in seconds for rapid fire check
WEB_SCAN_THRESHOLD = 10               # distinct paths triggering scanner alert

# SQL injection patterns
_SQLI_PATTERNS: list[re.Pattern] = [
    re.compile(r"('|\%27)\s*(OR|AND)\s*('|\%27)?\d+\s*(=|LIKE)\s*('|\%27)?\d+", re.IGNORECASE),
    re.compile(r"UNION\s+(ALL\s+)?SELECT", re.IGNORECASE),
    re.compile(r";\s*(DROP|ALTER|CREATE|INSERT|UPDATE|DELETE)\s+", re.IGNORECASE),
    re.compile(r"--\s*$|#\s*$|/\*.*?\*/", re.IGNORECASE),
    re.compile(r"SLEEP\s*\(\s*\d+\s*\)", re.IGNORECASE),
    re.compile(r"BENCHMARK\s*\(", re.IGNORECASE),
    re.compile(r"(?i)(information_schema|sys\.tables|pg_tables)"),
    re.compile(r"(?i)(xp_cmdshell|exec\s+master\.\.)"),
]

# XSS patterns
_XSS_PATTERNS: list[re.Pattern] = [
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on\w+\s*=\s*[\"']?.*?[\"']?", re.IGNORECASE),
    re.compile(r"<iframe[^>]*>", re.IGNORECASE),
    re.compile(r"eval\s*\(", re.IGNORECASE),
]

# Path traversal patterns
_PATH_TRAVERSAL_PATTERNS: list[re.Pattern] = [
    re.compile(r"\.\./|\.\.\\", re.IGNORECASE),
    re.compile(r"%2e%2e%2f|%252e%252e%252f", re.IGNORECASE),
    re.compile(r"etc/passwd|etc/shadow|proc/self", re.IGNORECASE),
    re.compile(r"windows/system32|boot\.ini", re.IGNORECASE),
]

# Sensitive file probes
_SENSITIVE_FILE_PATTERNS: list[re.Pattern] = [
    re.compile(r"\.(env|bak|old|backup|sql|git|svn|htaccess|htpasswd)($|\?)", re.IGNORECASE),
    re.compile(r"/(config|wp-config|database|credentials|secret)", re.IGNORECASE),
    re.compile(r"phpinfo\.php|test\.php|info\.php", re.IGNORECASE),
]

# Known scanner user-agents
_SCANNER_UA_PATTERNS: list[re.Pattern] = [
    re.compile(r"sqlmap", re.IGNORECASE),
    re.compile(r"nikto", re.IGNORECASE),
    re.compile(r"nmap", re.IGNORECASE),
    re.compile(r"masscan", re.IGNORECASE),
    re.compile(r"wpscan", re.IGNORECASE),
    re.compile(r"dirbuster", re.IGNORECASE),
    re.compile(r"gobuster", re.IGNORECASE),
    re.compile(r"nuclei", re.IGNORECASE),
    re.compile(r"zgrab", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Individual rule implementations
# ---------------------------------------------------------------------------

def detect_ssh_brute_force(events: list[dict]) -> list[RuleAlert]:
    """
    Rule R001: SSH Brute Force Detection

    Triggers when a single source IP generates >= SSH_BRUTEFORCE_THRESHOLD
    failed SSH login attempts.
    """
    alerts: list[RuleAlert] = []
    failed_by_ip: dict[str, list[dict]] = defaultdict(list)

    for evt in events:
        if evt.get("event_type") == "SSH_FAILED_LOGIN":
            failed_by_ip[evt["source_ip"]].append(evt)

    for ip, failed_events in failed_by_ip.items():
        count = len(failed_events)
        if count >= SSH_BRUTEFORCE_THRESHOLD:
            # Determine confidence based on volume
            if count >= 20:
                confidence = "high"
            elif count >= 10:
                confidence = "medium"
            else:
                confidence = "medium"

            usernames = list({e.get("username", "unknown") for e in failed_events})
            alerts.append(RuleAlert(
                alert=True,
                rule_id="R001",
                type="SSH Brute Force",
                confidence=confidence,
                description=(
                    f"IP {ip} generated {count} SSH failed login attempts "
                    f"targeting usernames: {', '.join(usernames[:5])}"
                    + (f" and {len(usernames) - 5} more" if len(usernames) > 5 else "")
                ),
                source_ip=ip,
                affected_events=failed_events,
                metadata={
                    "failed_count": count,
                    "targeted_usernames": usernames,
                },
            ))
            logger.info("R001 triggered: SSH brute force from %s (%d attempts)", ip, count)

    return alerts


def detect_sql_injection(events: list[dict]) -> list[RuleAlert]:
    """
    Rule R002: SQL Injection Detection

    Inspects the request_path of web events for known SQLi signatures.
    """
    alerts: list[RuleAlert] = []
    sqli_by_ip: dict[str, list[dict]] = defaultdict(list)

    for evt in events:
        if evt.get("event_type") != "WEB_REQUEST":
            continue
        path = evt.get("request_path", "") + evt.get("raw", "")
        for pattern in _SQLI_PATTERNS:
            if pattern.search(path):
                sqli_by_ip[evt["source_ip"]].append(evt)
                break  # one match per event is sufficient

    for ip, matched_events in sqli_by_ip.items():
        count = len(matched_events)
        confidence = "high" if count >= 3 else "medium"
        alerts.append(RuleAlert(
            alert=True,
            rule_id="R002",
            type="SQL Injection",
            confidence=confidence,
            description=(
                f"IP {ip} sent {count} requests containing SQL injection signatures."
            ),
            source_ip=ip,
            affected_events=matched_events,
            metadata={"sqli_request_count": count},
        ))
        logger.info("R002 triggered: SQL injection from %s (%d requests)", ip, count)

    return alerts


def detect_xss(events: list[dict]) -> list[RuleAlert]:
    """
    Rule R003: Cross-Site Scripting (XSS) Detection
    """
    alerts: list[RuleAlert] = []
    xss_by_ip: dict[str, list[dict]] = defaultdict(list)

    for evt in events:
        if evt.get("event_type") != "WEB_REQUEST":
            continue
        path = evt.get("request_path", "") + evt.get("raw", "")
        for pattern in _XSS_PATTERNS:
            if pattern.search(path):
                xss_by_ip[evt["source_ip"]].append(evt)
                break

    for ip, matched_events in xss_by_ip.items():
        count = len(matched_events)
        alerts.append(RuleAlert(
            alert=True,
            rule_id="R003",
            type="Cross-Site Scripting (XSS)",
            confidence="medium",
            description=f"IP {ip} sent {count} requests with XSS payloads.",
            source_ip=ip,
            affected_events=matched_events,
            metadata={"xss_request_count": count},
        ))
        logger.info("R003 triggered: XSS from %s", ip)

    return alerts


def detect_path_traversal(events: list[dict]) -> list[RuleAlert]:
    """
    Rule R004: Path / Directory Traversal Detection
    """
    alerts: list[RuleAlert] = []
    pt_by_ip: dict[str, list[dict]] = defaultdict(list)

    for evt in events:
        if evt.get("event_type") != "WEB_REQUEST":
            continue
        path = evt.get("request_path", "") + evt.get("raw", "")
        for pattern in _PATH_TRAVERSAL_PATTERNS:
            if pattern.search(path):
                pt_by_ip[evt["source_ip"]].append(evt)
                break

    for ip, matched_events in pt_by_ip.items():
        count = len(matched_events)
        alerts.append(RuleAlert(
            alert=True,
            rule_id="R004",
            type="Path Traversal",
            confidence="high",
            description=(
                f"IP {ip} sent {count} requests attempting directory traversal."
            ),
            source_ip=ip,
            affected_events=matched_events,
            metadata={"traversal_request_count": count},
        ))
        logger.info("R004 triggered: Path traversal from %s", ip)

    return alerts


def detect_sensitive_file_probe(events: list[dict]) -> list[RuleAlert]:
    """
    Rule R005: Sensitive File Enumeration / Probe Detection
    """
    alerts: list[RuleAlert] = []
    probe_by_ip: dict[str, list[dict]] = defaultdict(list)

    for evt in events:
        if evt.get("event_type") != "WEB_REQUEST":
            continue
        path = evt.get("request_path", "")
        for pattern in _SENSITIVE_FILE_PATTERNS:
            if pattern.search(path):
                probe_by_ip[evt["source_ip"]].append(evt)
                break

    for ip, matched_events in probe_by_ip.items():
        count = len(matched_events)
        if count >= 2:
            alerts.append(RuleAlert(
                alert=True,
                rule_id="R005",
                type="Sensitive File Enumeration",
                confidence="medium",
                description=(
                    f"IP {ip} probed {count} sensitive file paths "
                    f"(.env, config files, backup files, etc.)."
                ),
                source_ip=ip,
                affected_events=matched_events,
                metadata={"probe_count": count},
            ))
            logger.info("R005 triggered: Sensitive file probe from %s", ip)

    return alerts


def detect_scanner_activity(events: list[dict]) -> list[RuleAlert]:
    """
    Rule R006: Automated Scanner / Tool Detection via User-Agent.
    """
    alerts: list[RuleAlert] = []
    scanner_by_ip: dict[str, list[dict]] = defaultdict(list)

    for evt in events:
        if evt.get("event_type") != "WEB_REQUEST":
            continue
        ua = evt.get("user_agent", "")
        for pattern in _SCANNER_UA_PATTERNS:
            if pattern.search(ua):
                scanner_by_ip[evt["source_ip"]].append(evt)
                break

    for ip, matched_events in scanner_by_ip.items():
        uas = list({e.get("user_agent", "") for e in matched_events})
        alerts.append(RuleAlert(
            alert=True,
            rule_id="R006",
            type="Automated Scanner Detected",
            confidence="high",
            description=(
                f"IP {ip} used known security scanner user-agents: {', '.join(uas[:3])}."
            ),
            source_ip=ip,
            affected_events=matched_events,
            metadata={"scanner_user_agents": uas},
        ))
        logger.info("R006 triggered: Scanner activity from %s", ip)

    return alerts


def detect_ssh_successful_after_failures(events: list[dict]) -> list[RuleAlert]:
    """
    Rule R007: Successful SSH login after multiple failures (possible credential stuffing success).
    """
    alerts: list[RuleAlert] = []
    failed_ips: set[str] = set()
    successful_events_by_ip: dict[str, list[dict]] = defaultdict(list)

    for evt in events:
        if evt.get("event_type") == "SSH_FAILED_LOGIN":
            failed_ips.add(evt["source_ip"])
        elif evt.get("event_type") == "SSH_ACCEPTED_LOGIN":
            successful_events_by_ip[evt["source_ip"]].append(evt)

    for ip in failed_ips & set(successful_events_by_ip.keys()):
        success_evts = successful_events_by_ip[ip]
        alerts.append(RuleAlert(
            alert=True,
            rule_id="R007",
            type="Brute Force Success",
            confidence="high",
            description=(
                f"IP {ip} had failed SSH attempts followed by a successful login — "
                f"possible credential brute force success."
            ),
            source_ip=ip,
            affected_events=success_evts,
            metadata={"successful_logins": len(success_evts)},
        ))
        logger.warning("R007 triggered: Brute force success from %s", ip)

    return alerts


# ---------------------------------------------------------------------------
# Rule registry & orchestrator
# ---------------------------------------------------------------------------

_RULE_REGISTRY = [
    detect_ssh_brute_force,
    detect_sql_injection,
    detect_xss,
    detect_path_traversal,
    detect_sensitive_file_probe,
    detect_scanner_activity,
    detect_ssh_successful_after_failures,
]


def run_all_rules(events: list[dict]) -> list[RuleAlert]:
    """
    Execute all registered detection rules against the provided event list.

    Returns a consolidated list of RuleAlert objects for all triggered rules.
    """
    all_alerts: list[RuleAlert] = []
    for rule_fn in _RULE_REGISTRY:
        try:
            rule_alerts = rule_fn(events)
            all_alerts.extend(rule_alerts)
        except Exception as exc:
            logger.error("Rule %s raised an exception: %s", rule_fn.__name__, exc)
    logger.info("Rule engine finished. Total alerts: %d", len(all_alerts))
    return all_alerts
