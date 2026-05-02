"""
ThreatIntelAgent: queries VirusTotal and AbuseIPDB for external IP
reputation. Runs in parallel with TTPAgent after ReconstructionAgent.

Inputs from AgentState:
- blast_radius.external_ips_observed
- patient_zero.ip_address (if external)

Output:
- threat_intel: dict keyed by IP address
"""

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import httpx
from dotenv import load_dotenv

from app.models.state import AgentState

load_dotenv()
logger = logging.getLogger(__name__)

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

# Known botsv3 attacker IPs for deterministic fallback
KNOWN_BOTSV3_MALICIOUS = {
    "54.67.127.227",
    "184.85.20.125", 
    "23.73.195.90",
    "201.150.52.35",
    "23.207.27.44",
}

RFC1918_PREFIXES = (
    "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "169.254.",  # link-local
    "127.",      # loopback
)


def is_internal_ip(ip: str) -> bool:
    """Return True if IP is RFC1918 or otherwise non-routable."""
    return any(ip.startswith(prefix) for prefix in RFC1918_PREFIXES)


def compute_threat_level(
    vt_malicious: int,
    abuseipdb_score: int,
) -> str:
    """
    Deterministic threat level from API scores.
    Pure Python — no LLM.
    """
    if vt_malicious >= 10 or abuseipdb_score >= 75:
        return "CRITICAL"
    if vt_malicious >= 5 or abuseipdb_score >= 50:
        return "HIGH"
    if vt_malicious >= 2 or abuseipdb_score >= 25:
        return "MEDIUM"
    return "LOW"


def build_threat_summary(
    ip: str,
    threat_level: str,
    vt_data: dict,
    abuse_data: dict,
) -> str:
    """Build plain English threat summary."""
    parts = [f"IP {ip} rated {threat_level}."]
    
    if vt_data.get("malicious_count", 0) > 0:
        parts.append(
            f"VirusTotal: {vt_data['malicious_count']}/"
            f"{vt_data.get('total_engines', 90)} engines flagged malicious."
        )
    
    if abuse_data.get("abuse_confidence_score", 0) > 0:
        parts.append(
            f"AbuseIPDB confidence: {abuse_data['abuse_confidence_score']}%."
        )
    
    isp = vt_data.get("as_owner") or abuse_data.get("isp", "")
    if isp:
        parts.append(f"ISP: {isp}.")
    
    country = vt_data.get("country") or abuse_data.get("country_code", "")
    if country:
        parts.append(f"Country: {country}.")
    
    if abuse_data.get("is_tor"):
        parts.append("WARNING: Tor exit node detected.")
    
    return " ".join(parts)


def get_deterministic_fallback(ip: str) -> dict:
    """
    Fallback when API keys not set or rate limited.
    Uses known botsv3 attacker IPs for realistic mock data.
    """
    is_known_malicious = ip in KNOWN_BOTSV3_MALICIOUS
    
    vt_data = {
        "malicious_count": 3 if is_known_malicious else 0,
        "suspicious_count": 1 if is_known_malicious else 0,
        "total_engines": 90,
        "reputation_score": -3 if is_known_malicious else 0,
        "country": "US",
        "as_owner": "Amazon.com Inc.",
        "last_analysis_date": "2024-01-15",
    }
    abuse_data = {
        "abuse_confidence_score": 15 if is_known_malicious else 0,
        "country_code": "US",
        "isp": "Amazon.com Inc.",
        "usage_type": "Data Center/Web Hosting/Transit",
        "total_reports": 2 if is_known_malicious else 0,
        "is_tor": False,
    }
    threat_level = "MEDIUM" if is_known_malicious else "LOW"
    
    return {
        "ip": ip,
        "virustotal": vt_data,
        "abuseipdb": abuse_data,
        "threat_level": threat_level,
        "summary": build_threat_summary(ip, threat_level, vt_data, abuse_data),
        "source": "deterministic_fallback",
    }


async def query_virustotal(ip: str, client: httpx.AsyncClient) -> dict:
    """Query VirusTotal API for IP reputation."""
    if not VIRUSTOTAL_API_KEY:
        return {}
    
    try:
        response = await client.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=10.0,
        )
        
        if response.status_code == 429:
            logger.warning("VirusTotal rate limit hit for %s", ip)
            return {}
        
        if response.status_code != 200:
            logger.warning(
                "VirusTotal returned %d for %s", 
                response.status_code, ip
            )
            return {}
        
        data = response.json()
        attrs = data.get("data", {}).get("attributes", {})
        last_analysis = attrs.get("last_analysis_stats", {})
        
        return {
            "malicious_count": last_analysis.get("malicious", 0),
            "suspicious_count": last_analysis.get("suspicious", 0),
            "total_engines": sum(last_analysis.values()) or 90,
            "reputation_score": attrs.get("reputation", 0),
            "country": attrs.get("country", ""),
            "as_owner": attrs.get("as_owner", ""),
            "last_analysis_date": attrs.get("last_modification_date", ""),
        }
    
    except Exception as e:
        logger.warning("VirusTotal query failed for %s: %s", ip, e)
        return {}


async def query_abuseipdb(ip: str, client: httpx.AsyncClient) -> dict:
    """Query AbuseIPDB API for IP reputation."""
    if not ABUSEIPDB_API_KEY:
        return {}
    
    try:
        response = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
            timeout=10.0,
        )
        
        if response.status_code == 429:
            logger.warning("AbuseIPDB rate limit hit for %s", ip)
            return {}
        
        if response.status_code != 200:
            logger.warning(
                "AbuseIPDB returned %d for %s",
                response.status_code, ip
            )
            return {}
        
        data = response.json().get("data", {})
        
        return {
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "country_code": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "usage_type": data.get("usageType", ""),
            "total_reports": data.get("totalReports", 0),
            "is_tor": data.get("isTor", False),
        }
    
    except Exception as e:
        logger.warning("AbuseIPDB query failed for %s: %s", ip, e)
        return {}


async def enrich_ip(ip: str, client: httpx.AsyncClient) -> dict:
    """
    Query both APIs in parallel for a single IP.
    Falls back to deterministic data if both APIs fail or keys missing.
    """
    if not VIRUSTOTAL_API_KEY and not ABUSEIPDB_API_KEY:
        return get_deterministic_fallback(ip)
    
    vt_data, abuse_data = await asyncio.gather(
        query_virustotal(ip, client),
        query_abuseipdb(ip, client),
    )
    
    # If both APIs returned empty, use fallback
    if not vt_data and not abuse_data:
        return get_deterministic_fallback(ip)
    
    vt_malicious = vt_data.get("malicious_count", 0)
    abuse_score = abuse_data.get("abuse_confidence_score", 0)
    threat_level = compute_threat_level(vt_malicious, abuse_score)
    
    return {
        "ip": ip,
        "virustotal": vt_data if vt_data else {
            "malicious_count": 0,
            "total_engines": 0,
            "note": "API unavailable",
        },
        "abuseipdb": abuse_data if abuse_data else {
            "abuse_confidence_score": 0,
            "note": "API unavailable",
        },
        "threat_level": threat_level,
        "summary": build_threat_summary(
            ip, threat_level, vt_data, abuse_data
        ),
        "source": "live_api",
        "queried_at": datetime.now(timezone.utc).isoformat(),
    }


async def threat_intel_agent(state: AgentState) -> AgentState:
    """
    ThreatIntelAgent: enriches external IPs with reputation data.
    Runs in parallel with TTPAgent after ReconstructionAgent.
    """
    investigation_id = state.get("investigation_id", "unknown")
    classification = state.get("attack_classification", "UNKNOWN")

    logger.info(
        "[%s] ThreatIntelAgent starting | classification=%s",
        investigation_id, classification,
    )

    # Collect external IPs from blast_radius and patient_zero
    blast_radius = state.get("blast_radius", {})
    patient_zero = state.get("patient_zero", {})
    
    external_ips_raw = list(
        blast_radius.get("external_ips_observed", [])
    )
    
    # Add patient_zero IP if external
    pz_ip = patient_zero.get("ip_address", "")
    if pz_ip and not is_internal_ip(pz_ip) and pz_ip not in external_ips_raw:
        external_ips_raw.insert(0, pz_ip)
    
    # Filter to confirmed external IPs only, max 5
    external_ips = [
        ip for ip in external_ips_raw
        if ip and not is_internal_ip(ip)
    ][:5]

    if not external_ips:
        logger.info(
            "[%s] ThreatIntelAgent: no external IPs found — "
            "skipping API queries",
            investigation_id,
        )
        return {"threat_intel": {}}

    logger.info(
        "[%s] ThreatIntelAgent: querying %d external IPs",
        investigation_id, len(external_ips),
    )

    # Query all IPs in parallel
    threat_intel: dict = {}
    
    try:
        async with httpx.AsyncClient() as client:
            results = await asyncio.gather(
                *[enrich_ip(ip, client) for ip in external_ips],
                return_exceptions=True,
            )
        
        for ip, result in zip(external_ips, results):
            if isinstance(result, Exception):
                logger.warning(
                    "[%s] IP enrichment failed for %s: %s",
                    investigation_id, ip, result,
                )
                threat_intel[ip] = get_deterministic_fallback(ip)
            else:
                threat_intel[ip] = result
    
    except Exception as e:
        logger.error(
            "[%s] ThreatIntelAgent failed: %s",
            investigation_id, e,
        )
        # Fallback for all IPs
        for ip in external_ips:
            threat_intel[ip] = get_deterministic_fallback(ip)

    # Count by threat level
    level_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for data in threat_intel.values():
        level = data.get("threat_level", "LOW")
        level_counts[level] = level_counts.get(level, 0) + 1

    logger.info(
        "[%s] ThreatIntelAgent complete | ips=%d | "
        "critical=%d | high=%d | medium=%d | low=%d",
        investigation_id,
        len(threat_intel),
        level_counts["CRITICAL"],
        level_counts["HIGH"],
        level_counts["MEDIUM"],
        level_counts["LOW"],
    )

    return {"threat_intel": threat_intel}
