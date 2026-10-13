"""
correlator.py - Advanced Attack Correlation Engine (Final Clean Version)

Features:
- Dynamic attack-aware summaries (SSH / SQLi / XSS / etc.)
- Behavior classification (aggressive / probing / low-volume)
- Threat prioritization (top attacker)
- Urgency scoring (multi-vector aware)
- Context-aware wording (SSH vs web attacks)
- Analyst-style narrative + intent reasoning
- Actionable mitigation recommendations
"""

from dataclasses import dataclass
from collections import defaultdict


# ================= DATA STRUCTURES =================

@dataclass
class CorrelatedAttack:
    ip: str
    attack_types: list[str]
    confidence: str
    event_count: int
    behavior: str

    def to_dict(self):
        return self.__dict__


@dataclass
class ImpactAnalysis:
    potential_impact: str
    recommended_action: str

    def to_dict(self):
        return self.__dict__


@dataclass
class CorrelationResult:
    correlated_attacks: list
    attack_chain_summary: str
    impact_analysis: ImpactAnalysis
    multi_stage_ips: list
    top_attacker: str | None


# ================= CORE LOGIC =================

def correlate_alerts(alerts, events, mitre_techniques):

    ip_map = defaultdict(list)
    event_map = defaultdict(list)

    for alert in alerts:
        ip_map[alert["source_ip"]].append(alert)

    for event in events:
        event_map[event.get("source_ip")].append(event)

    correlated_attacks = []
    aggressive_ips = []
    probing_ips = []
    multi_stage_ips = []

    top_attacker = None
    max_events = 0

    # ================= PER-IP ANALYSIS =================

    for ip in ip_map:
        alerts_list = ip_map[ip]
        event_count = len(event_map[ip])

        attack_types = list({a["type"] for a in alerts_list})
        confidence_levels = [a["confidence"] for a in alerts_list]

        # Behavior classification
        if event_count >= 10:
            behavior = "aggressive attack activity"
            aggressive_ips.append(ip)
        elif event_count >= 5:
            behavior = "credential probing activity"
            probing_ips.append(ip)
        else:
            behavior = "low-volume scanning"

        # Top attacker
        if event_count > max_events:
            max_events = event_count
            top_attacker = ip

        # Multi-stage detection
        if len(attack_types) >= 2:
            multi_stage_ips.append(ip)

        confidence = "high" if "high" in confidence_levels else "medium"

        correlated_attacks.append(
            CorrelatedAttack(ip, attack_types, confidence, event_count, behavior)
        )

    unique_types = list({a["type"] for a in alerts})

    # ================= URGENCY =================

    if aggressive_ips:
        urgency = "HIGH"
    elif len(unique_types) >= 2:
        # multi-vector attack → high severity
        urgency = "HIGH"
    elif probing_ips:
        urgency = "MEDIUM"
    else:
        urgency = "LOW"

    # ================= CONTEXT-AWARE WORDING =================

    if "SQL Injection" in unique_types:
        probing_phrase = "lower-volume web exploitation attempts targeting application inputs"
    elif "SSH Brute Force" in unique_types:
        probing_phrase = "lower-volume credential probing attempts"
    else:
        probing_phrase = "lower-volume exploitation attempts"

    # ================= SUMMARY =================

    if not alerts:
        summary = "No suspicious activity detected in the analysed logs."
    else:
        # Base description
        if "SSH Brute Force" in unique_types:
            summary = "Multiple IP addresses are attempting SSH brute-force attacks using common credential patterns. "
        elif "SQL Injection" in unique_types:
            summary = "Multiple IP addresses are attempting SQL injection attacks targeting web application inputs. "
        elif "Cross-Site Scripting (XSS)" in unique_types:
            summary = "Cross-site scripting (XSS) attempts detected, indicating potential client-side exploitation. "
        else:
            summary = "Multiple suspicious attack patterns detected across the analysed logs. "

        # Behavior
        if aggressive_ips:
            count = len(aggressive_ips)
            if count == 1:
                summary += "One source IP demonstrates high-frequency attack behavior, suggesting automated exploitation attempts. "
            else:
                summary += f"{count} source IPs demonstrate high-frequency attack behavior, suggesting automated exploitation attempts. "

        if probing_ips:
            summary += f"Additional {len(probing_ips)} IPs are engaged in {probing_phrase}. "

        # Prioritization
        if top_attacker:
            summary += f"The most active threat source identified is {top_attacker}. "

        # Multi-stage
        if multi_stage_ips:
            summary += "Multi-stage attack patterns indicate coordinated or scripted attack execution. "

        # Urgency + confidence
        summary += (
            f"Overall threat level is assessed as {urgency}. "
            "Confidence level of detections is moderate, but observed behavior and frequency indicate high risk. "
        )

        # Intent layer
        if "SQL Injection" in unique_types:
            summary += (
                "The attack pattern suggests attempts to exploit backend database queries, "
                "potentially leading to data extraction or unauthorized manipulation."
            )
        elif "SSH Brute Force" in unique_types:
            summary += (
                "The attack pattern suggests credential harvesting attempts targeting weak or reused passwords."
            )
        elif "Cross-Site Scripting (XSS)" in unique_types:
            summary += (
                "The attack pattern suggests attempts to inject malicious scripts into web pages for client-side exploitation."
            )
        else:
            summary += "The attack pattern suggests opportunistic scanning for exploitable vulnerabilities."

    # ================= IMPACT =================

    if not alerts:
        impact = ImpactAnalysis(
            potential_impact="No security impact detected.",
            recommended_action="No action required."
        )
    elif "SSH Brute Force" in unique_types:
        impact = ImpactAnalysis(
            potential_impact=(
                "Repeated failed authentication attempts indicate active brute-force attacks. "
                "Successful exploitation could grant attackers unauthorized system access, "
                "leading to lateral movement, persistence, and potential data compromise."
            ),
            recommended_action=(
                "Immediately block identified source IPs at the firewall level. "
                "Enforce multi-factor authentication (MFA), disable password-based login where possible, "
                "and implement rate limiting or fail2ban protections. Monitor for continued attack attempts."
            )
        )
    elif "SQL Injection" in unique_types:
        impact = ImpactAnalysis(
            potential_impact=(
                "SQL injection attempts may lead to unauthorized database access, data leakage, "
                "or manipulation of application data."
            ),
            recommended_action=(
                "Implement input validation, use parameterized queries, deploy a Web Application Firewall (WAF), "
                "and review database access controls."
            )
        )
    else:
        impact = ImpactAnalysis(
            potential_impact=(
                "Detected activity indicates potential attack attempts that could result in unauthorized access, "
                "data exposure, or service disruption."
            ),
            recommended_action=(
                "Investigate affected systems, block malicious sources, and strengthen monitoring controls."
            )
        )

    # ================= RETURN =================

    return CorrelationResult(
        correlated_attacks=correlated_attacks,
        attack_chain_summary=summary,
        impact_analysis=impact,
        multi_stage_ips=multi_stage_ips,
        top_attacker=top_attacker,
    )