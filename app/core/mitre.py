"""
mitre.py - MITRE ATT&CK Framework Mapping Module

Maps detected threat types to MITRE ATT&CK techniques and tactics.
Uses an embedded, offline technique database — no external calls required.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MitreTechnique:
    """Represents a MITRE ATT&CK technique with full metadata."""
    technique_id: str
    sub_technique_id: Optional[str]
    name: str
    tactic: str
    tactic_id: str
    description: str
    url: str
    data_sources: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    detection_notes: str = ""

    def to_dict(self) -> dict:
        return {
            "technique_id": self.full_id,
            "name": self.name,
            "tactic": self.tactic,
            "tactic_id": self.tactic_id,
            "description": self.description,
            "url": self.url,
            "data_sources": list(self.data_sources),
            "mitigations": list(self.mitigations),
            "detection_notes": self.detection_notes,
        }

    @property
    def full_id(self) -> str:
        if self.sub_technique_id:
            return f"{self.technique_id}.{self.sub_technique_id}"
        return self.technique_id


# ---------------------------------------------------------------------------
# Embedded MITRE ATT&CK technique database
# ---------------------------------------------------------------------------

_TECHNIQUES: dict[str, MitreTechnique] = {
    "T1110": MitreTechnique(
        technique_id="T1110",
        sub_technique_id=None,
        name="Brute Force",
        tactic="Credential Access",
        tactic_id="TA0006",
        description=(
            "Adversaries may use brute force techniques to gain access to accounts "
            "when passwords are unknown or when password hashes are obtained. "
            "Brute force attacks may be conducted by cycling through many possible "
            "passwords with the hope of eventually guessing correctly."
        ),
        url="https://attack.mitre.org/techniques/T1110/",
        data_sources=["Authentication logs", "Process monitoring"],
        mitigations=[
            "Account Lockout (M1036)",
            "Multi-factor Authentication (M1032)",
            "Password Policies (M1027)",
        ],
        detection_notes=(
            "Monitor for large numbers of authentication failures; "
            "alert on repeated failed logins from the same source IP."
        ),
    ),
    "T1110.001": MitreTechnique(
        technique_id="T1110",
        sub_technique_id="001",
        name="Password Guessing",
        tactic="Credential Access",
        tactic_id="TA0006",
        description=(
            "Adversaries with no prior knowledge of legitimate credentials may guess "
            "passwords to attempt access to accounts. Without knowledge of the "
            "password for an account, an adversary may opt to systematically guess "
            "the password using a repetitive or iterative mechanism."
        ),
        url="https://attack.mitre.org/techniques/T1110/001/",
        data_sources=["Authentication logs"],
        mitigations=["Account Lockout (M1036)", "Multi-factor Authentication (M1032)"],
        detection_notes="Detect repeated failed login attempts for a single username.",
    ),
    "T1110.003": MitreTechnique(
        technique_id="T1110",
        sub_technique_id="003",
        name="Password Spraying",
        tactic="Credential Access",
        tactic_id="TA0006",
        description=(
            "Adversaries may use a single or small list of commonly used passwords "
            "against many different accounts to attempt to acquire valid account "
            "credentials. Password spraying uses one password (or a small list) "
            "in an attempt to authenticate against many accounts."
        ),
        url="https://attack.mitre.org/techniques/T1110/003/",
        data_sources=["Authentication logs"],
        mitigations=["Multi-factor Authentication (M1032)", "Password Policies (M1027)"],
        detection_notes="Detect failed logins spread across many usernames from one IP.",
    ),
    "T1190": MitreTechnique(
        technique_id="T1190",
        sub_technique_id=None,
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        tactic_id="TA0001",
        description=(
            "Adversaries may attempt to exploit a weakness in an Internet-facing host "
            "or system to initially access a network. The weakness in the system can "
            "be a software bug, a temporary glitch, or a misconfiguration. "
            "SQL Injection is a common technique used here."
        ),
        url="https://attack.mitre.org/techniques/T1190/",
        data_sources=["Application logs", "Network traffic", "Web application firewall logs"],
        mitigations=[
            "Application Isolation and Sandboxing (M1048)",
            "Exploit Protection (M1050)",
            "Update Software (M1051)",
            "Web Application Firewall (M1042)",
        ],
        detection_notes=(
            "Monitor web application logs for SQL injection strings, unusual "
            "query parameters, and error codes indicating exploitation attempts."
        ),
    ),
    "T1059": MitreTechnique(
        technique_id="T1059",
        sub_technique_id=None,
        name="Command and Scripting Interpreter",
        tactic="Execution",
        tactic_id="TA0002",
        description=(
            "Adversaries may abuse command and script interpreters to execute "
            "commands, scripts, or binaries. These interfaces and languages provide "
            "ways of interacting with computer systems and are a common feature "
            "across many different platforms."
        ),
        url="https://attack.mitre.org/techniques/T1059/",
        data_sources=["Process monitoring", "Command execution"],
        mitigations=["Code Signing (M1045)", "Execution Prevention (M1038)"],
        detection_notes="Monitor for suspicious command execution via web shells or RCE.",
    ),
    "T1083": MitreTechnique(
        technique_id="T1083",
        sub_technique_id=None,
        name="File and Directory Discovery",
        tactic="Discovery",
        tactic_id="TA0007",
        description=(
            "Adversaries may enumerate files and directories or may search in "
            "specific locations of a host or network share for certain information "
            "within a file system."
        ),
        url="https://attack.mitre.org/techniques/T1083/",
        data_sources=["File monitoring", "Process monitoring"],
        mitigations=["Audit (M1047)"],
        detection_notes="Look for access to sensitive files like .env, config files, backups.",
    ),
    "T1595": MitreTechnique(
        technique_id="T1595",
        sub_technique_id=None,
        name="Active Scanning",
        tactic="Reconnaissance",
        tactic_id="TA0043",
        description=(
            "Adversaries may execute active reconnaissance scans to gather information "
            "that can be used during targeting. Active scans are those where the "
            "adversary probes victim infrastructure via network traffic."
        ),
        url="https://attack.mitre.org/techniques/T1595/",
        data_sources=["Network traffic", "Web application logs"],
        mitigations=["Pre-compromise Mitigation (M1056)"],
        detection_notes="Detect automated scanning tools via user-agent strings and request patterns.",
    ),
    "T1055": MitreTechnique(
        technique_id="T1055",
        sub_technique_id=None,
        name="Process Injection",
        tactic="Defense Evasion",
        tactic_id="TA0005",
        description=(
            "Adversaries may inject code into processes in order to evade "
            "process-based defenses as well as possibly elevate privileges."
        ),
        url="https://attack.mitre.org/techniques/T1055/",
        data_sources=["Process monitoring", "API monitoring"],
        mitigations=["Privileged Account Management (M1026)", "Behavior Prevention on Endpoint (M1040)"],
        detection_notes="Monitor for unusual process injection via XSS/code injection vectors.",
    ),
    "T1078": MitreTechnique(
        technique_id="T1078",
        sub_technique_id=None,
        name="Valid Accounts",
        tactic="Defense Evasion",
        tactic_id="TA0005",
        description=(
            "Adversaries may obtain and abuse credentials of existing accounts as a "
            "means of gaining Initial Access, Persistence, Privilege Escalation, or "
            "Defense Evasion."
        ),
        url="https://attack.mitre.org/techniques/T1078/",
        data_sources=["Authentication logs", "User account management"],
        mitigations=["Multi-factor Authentication (M1032)", "Privileged Account Management (M1026)"],
        detection_notes="Alert on logins after multiple failures — possible credential compromise.",
    ),
}


# ---------------------------------------------------------------------------
# Rule-type → MITRE technique mapping
# ---------------------------------------------------------------------------

_RULE_TYPE_TO_TECHNIQUES: dict[str, list[str]] = {
    "SSH Brute Force": ["T1110", "T1110.001"],
    "Brute Force Success": ["T1078", "T1110"],
    "SQL Injection": ["T1190"],
    "Cross-Site Scripting (XSS)": ["T1055", "T1190"],
    "Path Traversal": ["T1083", "T1190"],
    "Sensitive File Enumeration": ["T1083"],
    "Automated Scanner Detected": ["T1595"],
    # Generic fallbacks
    "Command Injection": ["T1059", "T1190"],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def map_alert_to_mitre(alert_type: str) -> list[dict]:
    """
    Map a rule alert type string to a list of MITRE ATT&CK technique dicts.

    Parameters
    ----------
    alert_type:
        The 'type' field from a RuleAlert (e.g. "SSH Brute Force").

    Returns
    -------
    list[dict]
        List of technique dicts, or empty list if no mapping found.
    """
    technique_ids = _RULE_TYPE_TO_TECHNIQUES.get(alert_type, [])
    results: list[dict] = []

    for tid in technique_ids:
        technique = _TECHNIQUES.get(tid)
        if technique:
            results.append(technique.to_dict())
        else:
            logger.warning("MITRE technique %s not found in local database", tid)

    if not results:
        logger.debug("No MITRE mapping found for alert type: %s", alert_type)

    return results


def get_technique_by_id(technique_id: str) -> Optional[dict]:
    """
    Retrieve a single MITRE technique by its ID.

    Parameters
    ----------
    technique_id:
        Full technique ID, e.g. 'T1110' or 'T1110.001'.

    Returns
    -------
    dict | None
    """
    technique = _TECHNIQUES.get(technique_id)
    return technique.to_dict() if technique else None


def list_all_tactics() -> list[str]:
    """Return a de-duplicated list of all tactics in the embedded database."""
    return sorted({t.tactic for t in _TECHNIQUES.values()})


def build_mitre_summary(alerts: list[dict]) -> list[dict]:
    """
    Given a list of alert dicts (from rules engine), return a consolidated
    list of unique MITRE techniques observed across all alerts.

    Parameters
    ----------
    alerts:
        List of alert.to_dict() results from the rule engine.

    Returns
    -------
    list[dict]
        Unique MITRE techniques with technique_id, name, tactic, url.
    """
    seen: set[str] = set()
    summary: list[dict] = []

    for alert in alerts:
        alert_type = alert.get("type", "")
        techniques = map_alert_to_mitre(alert_type)
        for tech in techniques:
            tid = tech["technique_id"]
            if tid not in seen:
                seen.add(tid)
                summary.append({
                    "technique_id": tid,
                    "name": tech["name"],
                    "tactic": tech["tactic"],
                    "tactic_id": tech["tactic_id"],
                    "url": tech["url"],
                    "mitigations": tech.get("mitigations", []),
                })

    return summary
