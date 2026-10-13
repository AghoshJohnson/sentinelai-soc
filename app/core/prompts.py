"""
prompts.py - LLM Prompt Engineering for SOC Analysis

Contains carefully crafted prompt templates for driving AI-based
log analysis, threat summarisation, and remediation recommendations.
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

SYSTEM_PROMPT_SOC_ANALYST = """You are an expert SOC (Security Operations Center) analyst with 10+ years of experience 
in threat detection, incident response, and log forensics. You are analytical, concise, and precise.

Your job is to:
1. Analyse security log data and structured detection findings
2. Identify attack patterns, threat actor behaviour, and kill-chain stages
3. Provide clear, actionable remediation recommendations
4. Communicate findings in a professional, structured manner suitable for incident reports

Always base your conclusions on evidence from the provided data. 
Do not speculate beyond what the data supports.
Format your response in clear sections with headers."""


# ---------------------------------------------------------------------------
# User prompt builders
# ---------------------------------------------------------------------------

def build_log_analysis_prompt(
    log_summary: str,
    alerts: list[dict],
    mitre_techniques: list[dict],
    top_events: list[dict],
) -> str:
    """
    Build a prompt asking the LLM to analyse detected threats and produce
    a structured incident summary.

    Parameters
    ----------
    log_summary:
        Brief text summary of parsed log statistics (event counts, IPs, etc.).
    alerts:
        List of alert dicts from the rule engine.
    mitre_techniques:
        List of mapped MITRE technique dicts.
    top_events:
        A sample of the most relevant raw log events (max 10).

    Returns
    -------
    str
        Fully assembled prompt string.
    """
    alert_block = _format_alerts(alerts)
    mitre_block = _format_mitre(mitre_techniques)
    events_block = _format_events(top_events)

    return f"""## Security Log Analysis Request

### Log Overview
{log_summary}

### Rule-Based Detections ({len(alerts)} alerts)
{alert_block}

### MITRE ATT&CK Techniques Identified
{mitre_block}

### Sample Log Events (up to 10)
{events_block}

---

Please provide a structured security analysis with the following sections:

**1. THREAT SUMMARY**
Provide a concise 2-3 sentence executive summary of the threat activity observed.

**2. ATTACK PATTERN ANALYSIS**
Describe the attack methodology, likely kill-chain stage, and what the attacker was attempting to accomplish.

**3. RISK ASSESSMENT**
What data, systems, or services are at risk? What is the potential impact?

**4. INDICATORS OF COMPROMISE (IOCs)**
List all suspicious source IPs, usernames, or URL patterns observed.

**5. REMEDIATION RECOMMENDATIONS**
Provide 3-5 specific, prioritised remediation steps an analyst should take immediately.

**6. DETECTION GAPS**
Are there any blind spots in the current detection coverage that should be addressed?

Be precise and actionable. Avoid generic security advice not grounded in the evidence above."""


def build_ip_context_prompt(
    ip_address: str,
    events: list[dict],
    reputation_data: dict | None = None,
) -> str:
    """
    Build a prompt for contextual IP threat analysis.

    Parameters
    ----------
    ip_address:
        The IP address under analysis.
    events:
        All log events from this IP.
    reputation_data:
        Optional AbuseIPDB or similar reputation data dict.

    Returns
    -------
    str
    """
    events_block = _format_events(events[:15])
    rep_block = _format_reputation(reputation_data) if reputation_data else "No reputation data available."

    return f"""## IP Threat Context Analysis

### Target IP: {ip_address}

### IP Reputation Data
{rep_block}

### Activity Observed ({len(events)} events)
{events_block}

---

Please analyse this IP address and answer:

**1. Threat Actor Profile**
Based on the activity pattern, what type of actor is this? (automated scanner, manual attacker, botnet, etc.)

**2. Objective Assessment**
What was this IP attempting to accomplish based on the observed events?

**3. Confidence Level**
How confident are you in this assessment, and what additional data would help?

**4. Recommended Response**
Should this IP be blocked immediately? What other response actions are warranted?

Keep your analysis tight and evidence-based."""


def build_quick_triage_prompt(events: list[dict], alert_count: int) -> str:
    """
    Build a prompt for rapid triage of a small set of events.
    Used for lightweight, fast analysis when a full deep-dive isn't needed.
    """
    events_block = _format_events(events[:8])

    return f"""## Rapid SOC Triage Request

{alert_count} automated alerts were triggered. Quickly assess the following log events:

{events_block}

In 3-4 sentences, answer:
1. Is this malicious activity or a false positive?
2. What is the most likely attack type?
3. What is the immediate recommended action?

Be direct and concise."""


# ---------------------------------------------------------------------------
# Private formatting helpers
# ---------------------------------------------------------------------------

def _format_alerts(alerts: list[dict]) -> str:
    if not alerts:
        return "No rule-based alerts triggered."
    lines = []
    for i, alert in enumerate(alerts, 1):
        lines.append(
            f"{i}. [{alert.get('rule_id', 'R?')}] {alert.get('type', 'Unknown')} "
            f"| Confidence: {alert.get('confidence', 'unknown').upper()} "
            f"| Source IP: {alert.get('source_ip', 'N/A')} "
            f"| Events: {alert.get('affected_event_count', 0)}\n"
            f"   {alert.get('description', '')}"
        )
    return "\n".join(lines)


def _format_mitre(techniques: list[dict]) -> str:
    if not techniques:
        return "No MITRE techniques mapped."
    lines = []
    for t in techniques:
        lines.append(
            f"- {t.get('technique_id')} | {t.get('name')} | Tactic: {t.get('tactic')}"
            f" | Ref: {t.get('url', '')}"
        )
    return "\n".join(lines)


def _format_events(events: list[dict]) -> str:
    if not events:
        return "No events available."
    lines = []
    for evt in events:
        ts = evt.get("timestamp", "N/A")
        ip = evt.get("source_ip", "N/A")
        etype = evt.get("event_type", "N/A")
        raw = evt.get("raw", "")[:200]
        lines.append(f"[{ts}] {ip} | {etype} | {raw}")
    return "\n".join(lines)


def _format_reputation(rep: dict) -> str:
    lines = [
        f"Abuse Confidence Score: {rep.get('abuseConfidenceScore', 'N/A')}",
        f"Country: {rep.get('countryCode', 'N/A')}",
        f"Total Reports: {rep.get('totalReports', 'N/A')}",
        f"Last Reported: {rep.get('lastReportedAt', 'N/A')}",
        f"Domain: {rep.get('domain', 'N/A')}",
        f"ISP: {rep.get('isp', 'N/A')}",
    ]
    return "\n".join(lines)
