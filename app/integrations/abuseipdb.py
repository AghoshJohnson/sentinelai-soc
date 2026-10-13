"""
abuseipdb.py - Enhanced IP Reputation + Smart Classification

Adds:
- Internal IP detection
- Test IP detection
- Meaningful fallback (no more None → UNKNOWN issue)
"""

from __future__ import annotations

import logging
import os
import time
from typing import Optional

import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

# ================= CONFIG =================

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
ABUSEIPDB_MAX_AGE_DAYS = int(os.getenv("ABUSEIPDB_MAX_AGE_DAYS", "90"))

_REQUEST_TIMEOUT = 10
_RATE_LIMIT_DELAY = 1.1

_cache: dict[str, dict] = {}

# ================= LOCAL CLASSIFICATION =================

def classify_ip(ip: str) -> Optional[dict]:
    """Classify IP locally (before API call)"""

    # Internal/private IP ranges
    if ip.startswith(("10.", "192.168.", "172.")):
        return {
            "ipAddress": ip,
            "abuseConfidenceScore": "N/A",
            "countryCode": "LOCAL",
            "totalReports": 0,
            "threat_label": "INTERNAL NETWORK"
        }

    # Test / reserved IP ranges
    if ip.startswith(("203.0.113.", "198.51.100.", "192.0.2.")):
        return {
            "ipAddress": ip,
            "abuseConfidenceScore": "N/A",
            "countryCode": "TEST-NET",
            "totalReports": 0,
            "threat_label": "SIMULATED ATTACK"
        }

    return None


# ================= MAIN FUNCTION =================

def check_ip(ip_address: str, max_age_days: int = ABUSEIPDB_MAX_AGE_DAYS) -> dict:
    """
    Always returns meaningful enrichment data (never None)
    """

    # Cache check
    if ip_address in _cache:
        return _cache[ip_address]

    # 🔥 STEP 1: Local classification FIRST
    local = classify_ip(ip_address)
    if local:
        _cache[ip_address] = local
        return local

    # 🔥 STEP 2: No API key → fallback
    if not ABUSEIPDB_API_KEY:
        result = {
            "ipAddress": ip_address,
            "abuseConfidenceScore": "N/A",
            "countryCode": "UNKNOWN",
            "totalReports": 0,
            "threat_label": "EXTERNAL (UNVERIFIED)"
        }
        _cache[ip_address] = result
        return result

    # 🔥 STEP 3: API call
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": max_age_days,
        "verbose": "",
    }

    try:
        time.sleep(_RATE_LIMIT_DELAY)

        response = requests.get(
            f"{ABUSEIPDB_BASE_URL}/check",
            headers=headers,
            params=params,
            timeout=_REQUEST_TIMEOUT,
        )

        if response.status_code != 200:
            raise Exception(f"API returned {response.status_code}")

        data = response.json().get("data", {})

        score = data.get("abuseConfidenceScore", 0)

        if score >= 80:
            label = "HIGH RISK"
        elif score >= 40:
            label = "SUSPICIOUS"
        else:
            label = "LOW RISK"

        result = {
            "ipAddress": ip_address,
            "abuseConfidenceScore": score,
            "countryCode": data.get("countryCode", "N/A"),
            "totalReports": data.get("totalReports", 0),
            "threat_label": label,
        }

        _cache[ip_address] = result
        return result

    except RequestException as e:
        logger.warning(f"Request failed for {ip_address}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error for {ip_address}: {e}")

    # 🔥 FINAL FALLBACK
    result = {
        "ipAddress": ip_address,
        "abuseConfidenceScore": "ERROR",
        "countryCode": "UNKNOWN",
        "totalReports": 0,
        "threat_label": "LOOKUP FAILED",
    }

    _cache[ip_address] = result
    return result


# ================= BULK =================

def enrich_ips_bulk(ip_list: list[str]) -> dict[str, dict]:
    return {ip: check_ip(ip) for ip in ip_list}


# ================= STATUS =================

def is_api_configured() -> bool:
    return bool(ABUSEIPDB_API_KEY)