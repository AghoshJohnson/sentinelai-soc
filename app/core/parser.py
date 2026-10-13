"""
parser.py - Log Parsing Module for AI SOC Assistant

Supports SSH auth logs and Apache/Nginx web server access logs.
Outputs structured JSON events for downstream analysis.
"""

from __future__ import annotations

import re
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------
LogEvent = dict  # {"timestamp", "source_ip", "event_type", "raw", ...}


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# sshd log patterns
_SSH_FAILED = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for(?: invalid user)?\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)"
)
_SSH_ACCEPTED = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted \w+ for\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)"
)
_SSH_DISCONNECT = re.compile(
    # FIXED: user group made non-greedy and guarded so it won't consume an IP.
    # Pattern handles both:
    #   "Connection closed by 1.2.3.4 port 54321 [preauth]"
    #   "Disconnected from invalid user admin 1.2.3.4 port 54321 [preauth]"
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?:Disconnected from|Connection closed by)"
    r"(?:(?: invalid user)?\s+(?P<user>(?!\d+\.\d+\.\d+\.\d+)\S+))?"
    r"\s*(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)"
)

# Web log pattern (Combined Log Format)
_WEB_CLF = re.compile(
    r'(?P<ip>[\d.]+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>[^"]+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

_MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_syslog_ts(month: str, day: str, time_str: str, year: int = 2023) -> str:
    """Convert syslog-style timestamp components to ISO-8601 string."""
    try:
        mo = _MONTH_MAP.get(month, 1)
        dt = datetime(year, mo, int(day),
                      *[int(x) for x in time_str.split(":")])
        return dt.isoformat()
    except Exception:
        return f"{year}-{month}-{day}T{time_str}"


def _parse_clf_ts(raw: str) -> str:
    """Convert Common Log Format timestamp to ISO-8601 string."""
    try:
        dt = datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
        return dt.isoformat()
    except Exception:
        return raw


# ---------------------------------------------------------------------------
# SSH Parser
# ---------------------------------------------------------------------------

def parse_ssh_log(line: str) -> Optional[LogEvent]:
    """
    Parse a single SSH log line.

    Returns a structured LogEvent dict or None if the line is unrecognised.
    """
    line = line.strip()
    if not line:
        return None

    # Failed attempt
    m = _SSH_FAILED.search(line)
    if m:
        return {
            "timestamp": _parse_syslog_ts(m["month"], m["day"], m["time"]),
            "source_ip": m["ip"],
            "destination_port": int(m["port"]),
            "username": m["user"],
            "event_type": "SSH_FAILED_LOGIN",
            "raw": line,
        }

    # Successful auth
    m = _SSH_ACCEPTED.search(line)
    if m:
        return {
            "timestamp": _parse_syslog_ts(m["month"], m["day"], m["time"]),
            "source_ip": m["ip"],
            "destination_port": int(m["port"]),
            "username": m["user"],
            "event_type": "SSH_ACCEPTED_LOGIN",
            "raw": line,
        }

    # Disconnects / pre-auth closes
    m = _SSH_DISCONNECT.search(line)
    if m:
        return {
            "timestamp": _parse_syslog_ts(m["month"], m["day"], m["time"]),
            "source_ip": m["ip"],
            "destination_port": int(m["port"]) if m["port"] else 22,
            "username": m["user"] or "unknown",
            "event_type": "SSH_DISCONNECT",
            "raw": line,
        }

    return None


# ---------------------------------------------------------------------------
# Web Access Log Parser
# ---------------------------------------------------------------------------

def parse_web_log(line: str) -> Optional[LogEvent]:
    """
    Parse a single Apache/Nginx Combined Log Format line.

    Returns a structured LogEvent dict or None if unrecognised.
    """
    line = line.strip()
    if not line:
        return None

    m = _WEB_CLF.match(line)
    if not m:
        return None

    path = m["path"].strip()
    method = m["method"].upper()
    status = int(m["status"])
    ua = m["ua"] or ""

    return {
        "timestamp": _parse_clf_ts(m["timestamp"]),
        "source_ip": m["ip"],
        "http_method": method,
        "request_path": path,
        "status_code": status,
        "response_size": int(m["size"]) if m["size"] != "-" else 0,
        "user_agent": ua,
        "event_type": "WEB_REQUEST",
        "raw": line,
    }


# ---------------------------------------------------------------------------
# Log-type auto-detection
# ---------------------------------------------------------------------------

def detect_log_type(file_path: Path) -> str:
    """
    Heuristically detect whether a log file contains SSH or web entries.

    Returns 'ssh', 'web', or 'unknown'.
    """
    try:
        sample = file_path.read_text(encoding="utf-8", errors="replace")
        head = sample[:4096]
        ssh_score = len(re.findall(r"sshd\[", head))
        web_score = len(re.findall(r'HTTP/\d\.\d"', head))
        if ssh_score >= web_score and ssh_score > 0:
            return "ssh"
        if web_score > 0:
            return "web"
    except Exception as exc:
        logger.warning("Log type detection failed: %s", exc)
    return "unknown"


# ---------------------------------------------------------------------------
# Public entry-point
# ---------------------------------------------------------------------------

def parse_log_file(file_path: str | Path, log_type: str = "auto") -> list[LogEvent]:
    """
    Parse an entire log file and return a list of structured LogEvent dicts.

    Parameters
    ----------
    file_path:
        Absolute or relative path to the log file.
    log_type:
        'ssh', 'web', or 'auto' (default). When 'auto', the type is inferred
        from file contents.

    Returns
    -------
    list[LogEvent]
        Parsed, non-null events.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    resolved_type = log_type
    if log_type == "auto":
        resolved_type = detect_log_type(path)
        logger.info("Auto-detected log type: %s", resolved_type)

    parser_fn = {
        "ssh": parse_ssh_log,
        "web": parse_web_log,
    }.get(resolved_type)

    if parser_fn is None:
        logger.warning("Unknown log type '%s'. Attempting both parsers.", resolved_type)
        # Fallback: try both parsers per line
        events: list[LogEvent] = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            evt = parse_ssh_log(line) or parse_web_log(line)
            if evt:
                events.append(evt)
        return events

    events = []
    raw_text = path.read_text(encoding="utf-8", errors="replace")
    for line in raw_text.splitlines():
        try:
            evt = parser_fn(line)
            if evt:
                events.append(evt)
        except Exception as exc:
            logger.debug("Parser skipped line due to error: %s | line: %s", exc, line[:120])

    logger.info("Parsed %d events from %s", len(events), path.name)
    return events
