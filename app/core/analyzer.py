"""
analyzer.py - SOC Analysis Pipeline Orchestrator

Coordinates the full SOC analysis pipeline:

    Parse → Rule Detection → MITRE Mapping → Attack Correlation → Severity Scoring → AI Analysis → Output
"""

from __future__ import annotations

import json
import logging
import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .mitre import build_mitre_summary
from .ollama_client import get_ai_analysis
from .parser import parse_log_file
from .prompts import SYSTEM_PROMPT_SOC_ANALYST
from .rules import run_all_rules
from .scorer import compute_severity

from .correlator import correlate_alerts

logger = logging.getLogger(__name__)


# ================= DATA STRUCTURE =================

@dataclass
class AnalysisResult:
    file_path: str
    log_type: str
    analysed_at: str
    event_count: int
    alert_count: int

    alerts: list[dict]
    mitre_techniques: list[dict]
    severity: any
    ai_analysis: str
    ai_available: bool

    top_source_ips: list[dict]
    event_timeline: list[dict]
    ip_enrichments: dict[str, dict]

    correlated_attacks: list[dict]
    attack_chain_summary: str
    impact_analysis: dict

    def to_dict(self):
        return {
        "meta": {
            "file_path": self.file_path,
            "log_type": self.log_type,
            "analysed_at": self.analysed_at,
            "event_count": self.event_count,
            "alert_count": self.alert_count,
            "ai_available": self.ai_available,
        },
        "severity": self.severity.to_dict() if hasattr(self.severity, "to_dict") else str(self.severity),
        "alerts": self.alerts,
        "mitre_techniques": self.mitre_techniques,
        "ai_analysis": self.ai_analysis,
        "top_source_ips": self.top_source_ips,
        "event_timeline": self.event_timeline,
        "ip_enrichments": self.ip_enrichments,
        "correlated_attacks": self.correlated_attacks,
        "attack_chain_summary": self.attack_chain_summary,
        "impact_analysis": self.impact_analysis,
    }


# ================= HELPERS =================

def _compute_top_ips(events):
    counter = Counter(e.get("source_ip", "unknown") for e in events)
    return [{"ip": ip, "event_count": c} for ip, c in counter.most_common(10)]


def _build_event_timeline(events):
    bucket = defaultdict(Counter)
    for e in events:
        minute = e.get("timestamp", "")[:16]
        bucket[minute][e.get("event_type", "UNKNOWN")] += 1

    return [
        {"timestamp": k, "total": sum(v.values()), "event_types": dict(v)}
        for k, v in sorted(bucket.items())
    ]


# ================= MAIN PIPELINE =================

def analyse_log_file(
    file_path: str,
    log_type: str = "auto",
    enable_ai: bool = True,
    ollama_model: str | None = None,
    ip_enricher=None,
):

    analysed_at = datetime.now(timezone.utc).isoformat()

    # 1. Parse
    events = parse_log_file(file_path, log_type=log_type)

    # 2. Rules
    rule_alerts = run_all_rules(events)
    alerts_dicts = [a.to_dict() for a in rule_alerts]

    # 3. MITRE
    mitre_techniques = build_mitre_summary(alerts_dicts)

    # 4. CORRELATION 🔥
    correlation = correlate_alerts(alerts_dicts, events, mitre_techniques)

    # 5. Severity
    severity = compute_severity(events, alerts_dicts, mitre_techniques)

    if correlation.multi_stage_ips:
        severity.severity = "CRITICAL"
        severity.summary += " Multi-stage attack detected."

    # 6. AI
    ai_text = ""
    ai_available = False

    if enable_ai:
        ai_text, ai_available = get_ai_analysis(
            user_prompt="Summarize SOC findings",
            system_prompt=SYSTEM_PROMPT_SOC_ANALYST,
            model=ollama_model or "mistral",
            fallback_on_error=True,
        )

    # 7. Enrichment
    ip_enrichments = {}
    if ip_enricher:
        for ip in set(e.get("source_ip") for e in events):
            try:
                ip_enrichments[ip] = ip_enricher(ip)
            except:
                pass

    # 8. Stats
    top_ips = _compute_top_ips(events)
    timeline = _build_event_timeline(events)

    return AnalysisResult(
        file_path=file_path,
        log_type=log_type,
        analysed_at=analysed_at,
        event_count=len(events),
        alert_count=len(rule_alerts),
        alerts=alerts_dicts,
        mitre_techniques=mitre_techniques,
        severity=severity,
        ai_analysis=ai_text,
        ai_available=ai_available,
        top_source_ips=top_ips,
        event_timeline=timeline,
        ip_enrichments=ip_enrichments,
        correlated_attacks=[a.to_dict() for a in correlation.correlated_attacks],
        attack_chain_summary=correlation.attack_chain_summary,
        impact_analysis=correlation.impact_analysis.to_dict(),
    )


# ================= CLI SUPPORT =================

def analyse_multiple_files(file_paths, **kwargs):
    return [analyse_log_file(p, **kwargs) for p in file_paths]


def save_report(result, output_dir="outputs/reports"):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = Path(result.file_path).stem

    path = Path(output_dir) / f"report_{name}_{ts}.json"

    with open(path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)

    print(f"Report saved: {path}")
    return path


# ================= TEXT REPORT =================

def generate_text_report(result):

    sep = "=" * 60
    lines = [sep, "SOC ANALYSIS REPORT", sep]

    lines.append(f"\nFile: {result.file_path}")
    lines.append(f"Severity: {result.severity.severity}")

    # 🔥 NEW SECTION
    lines.append("\n--- ATTACK CHAIN SUMMARY ---")
    lines.append(result.attack_chain_summary)

    # 🔥 NEW SECTION
    lines.append("\n--- IMPACT ANALYSIS ---")
    lines.append(result.impact_analysis.get("potential_impact", ""))

    lines.append("\n--- ALERTS ---")
    for a in result.alerts:
        lines.append(f"{a['type']} from {a['source_ip']}")

    return "\n".join(lines)