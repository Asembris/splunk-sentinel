"""
Detection Gap Analyzer — Splunk Sentinel

Analyzes MITRE ATT&CK technique coverage against
existing Splunk saved searches. Identifies gaps and
generates recommended detection SPL for uncovered
techniques.

Runs post-investigation on analyst request.
Never modifies AgentState or investigation pipeline.

5 production risks handled:
1. Slow saved_searches query: 5-min in-memory cache
2. False positive coverage: match_confidence field
3. SPL generation failure: deterministic template fallback
4. Duplicate deploy: name check before create
5. Guardrail blocking: validate before return, fallback
"""

import asyncio
import logging
import re
import time
from typing import Optional

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage

from app.guardrails.spl_guardrail import validate_spl

logger = logging.getLogger(__name__)

PLACEHOLDER_SPL_TERMS = (
    "your_sourcetype",
    "<sourcetype>",
    "todo",
    "replace_me",
    "your_index",
    "<index>",
    "your_field",
    "<field>",
    "field_name",
    "fake_field",
    "placeholder",
)

RAW_SOURCETYPE_TOKENS = (
    "stream:http",
    "stream:dns",
    "stream:tcp",
    "stream:udp",
    "WinEventLog:Security",
)

# In-memory cache for saved searches
# Risk 1 mitigation: 5-minute TTL
_saved_searches_cache: dict = {
    "data": None,
    "fetched_at": 0,
    "ttl_seconds": 300,
}

# Coverage score labels
COVERAGE_LABELS = {
    (0.0, 0.25): "CRITICAL GAPS",
    (0.25, 0.50): "SIGNIFICANT GAPS",
    (0.50, 0.75): "PARTIAL COVERAGE",
    (0.75, 1.01): "GOOD COVERAGE",
}

# MITRE technique keyword map
# Maps technique ID to keywords that should appear
# in saved search SPL to consider it covered
# Risk 2 mitigation: explicit keywords per technique
# with match_confidence based on specificity
TECHNIQUE_KEYWORDS = {
    "T1190": {
        "keywords": [
            "stream:http", "uri_path", "web_attack",
            "exploit", "public.facing", "4688",
            "forumdisplay", "php",
        ],
        "description": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "high_confidence_keywords": [
            "stream:http", "uri_path", "forumdisplay",
        ],
    },
    "T1552": {
        "keywords": [
            "169.254.169.254", "metadata", "imds",
            "stream:http", "ec2", "aws",
        ],
        "description": "Unsecured Credentials",
        "tactic": "Credential Access",
        "high_confidence_keywords": [
            "169.254.169.254", "metadata", "imds",
        ],
    },
    "T1552.005": {
        "keywords": [
            "169.254.169.254", "metadata", "imds",
            "stream:http", "dest_ip",
        ],
        "description": "Cloud Instance Metadata API",
        "tactic": "Credential Access",
        "high_confidence_keywords": [
            "169.254.169.254", "metadata",
        ],
    },
    "T1078": {
        "keywords": [
            "4624", "4625", "4648", "logon",
            "privileged", "account", "valid.account",
        ],
        "description": "Valid Accounts",
        "tactic": "Defense Evasion",
        "tactics": [
            "Defense Evasion", "Persistence",
            "Privilege Escalation", "Initial Access",
        ],
        "high_confidence_keywords": [
            "4624", "4625", "privileged",
        ],
    },
    "T1562": {
        "keywords": [
            "4688", "netsh", "firewall", "sc stop",
            "auditpol", "disable", "impair",
        ],
        "description": "Impair Defenses",
        "tactic": "Defense Evasion",
        "high_confidence_keywords": [
            "netsh", "auditpol", "firewall",
        ],
    },
    "T1562.004": {
        "keywords": [
            "4688", "netsh", "firewall", "sc stop",
            "auditpol",
        ],
        "description": "Disable or Modify System Firewall",
        "tactic": "Defense Evasion",
        "high_confidence_keywords": [
            "netsh", "firewall",
        ],
    },
    "T1059": {
        "keywords": [
            "4688", "powershell", "cmd", "wscript",
            "cscript", "process", "CommandLine",
        ],
        "description": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "high_confidence_keywords": [
            "powershell", "CommandLine",
        ],
    },
    "T1059.003": {
        "keywords": [
            "4688", "cmd.exe", "CommandLine",
            "process", "shell",
        ],
        "description": "Windows Command Shell",
        "tactic": "Execution",
        "high_confidence_keywords": [
            "cmd.exe", "CommandLine",
        ],
    },
    "T1003": {
        "keywords": [
            "4688", "mimikatz", "lsass", "credential",
            "dump", "procdump", "sekurlsa",
        ],
        "description": "OS Credential Dumping",
        "tactic": "Credential Access",
        "high_confidence_keywords": [
            "lsass", "mimikatz", "sekurlsa",
        ],
    },
    "T1055": {
        "keywords": [
            "4688", "injection", "process", "hollowing",
            "CreateRemoteThread", "VirtualAlloc",
        ],
        "description": "Process Injection",
        "tactic": "Defense Evasion",
        "tactics": ["Defense Evasion", "Privilege Escalation"],
        "high_confidence_keywords": [
            "CreateRemoteThread", "hollowing",
        ],
    },
    "T1528": {
        "keywords": [
            "token", "steal", "oauth", "access_token",
            "credential", "application",
        ],
        "description": "Steal Application Access Token",
        "tactic": "Credential Access",
        "high_confidence_keywords": [
            "access_token", "oauth", "steal",
        ],
    },
    "T1486": {
        "keywords": [
            "4663", "shadow", "vssadmin", "wmic",
            "encrypt", "ransom", "bcdedit",
        ],
        "description": "Data Encrypted for Impact",
        "tactic": "Impact",
        "high_confidence_keywords": [
            "vssadmin", "shadow", "bcdedit",
        ],
    },
    "T1021": {
        "keywords": [
            "4624", "lateral", "remote", "rdp",
            "smb", "psexec", "wmi",
        ],
        "description": "Remote Services",
        "tactic": "Lateral Movement",
        "high_confidence_keywords": [
            "rdp", "psexec", "lateral",
        ],
    },
    "T1071": {
        "keywords": [
            "stream:http", "stream:dns", "c2",
            "beacon", "command.control", "dns",
        ],
        "description": "Application Layer Protocol",
        "tactic": "Command and Control",
        "high_confidence_keywords": [
            "beacon", "c2", "stream:dns",
        ],
    },
}

# Deterministic template SPL per technique
# Risk 3 mitigation: fallback when LLM fails
TEMPLATE_SPL = {
    "T1190": (
        "index=botsv3 earliest=0 sourcetype=stream:http"
        " | where match(uri_path, \"(?i)(php|asp|jsp)\")"
        " AND status>=400"
        " | stats count by src_ip, uri_path, status"
        " | where count > 10"
        " | sort -count"
    ),
    "T1552.005": (
        "index=botsv3 earliest=0 sourcetype=stream:http"
        " dest_ip=169.254.169.254"
        " | stats count by src_ip, uri_path"
        " | where count > 5"
        " | sort -count"
    ),
    "T1552": (
        "index=botsv3 earliest=0 sourcetype=stream:http"
        " dest_ip=169.254.169.254"
        " | stats count by src_ip"
        " | where count > 1"
    ),
    "T1078": (
        "index=botsv3 earliest=0"
        " sourcetype=WinEventLog:Security"
        " (EventCode=4624 OR EventCode=4672 OR EventCode=4673)"
        " | eval account=coalesce(Account_Name, user)"
        " | stats count dc(host) as host_count"
        " by account, src_ip, EventCode"
        " | where count > 3 OR host_count > 1"
        " | sort -count"
    ),
    "T1562.004": (
        "index=botsv3 earliest=0"
        " sourcetype=WinEventLog:Security"
        " EventCode=4688"
        " | where match(New_Process_Name, \"(?i)netsh\")"
        " OR match(Process_Command_Line,"
        " \"(?i)firewall|advfirewall|disable\")"
        " | table _time, host, Account_Name,"
        " New_Process_Name, Process_Command_Line"
    ),
    "T1562": (
        "index=botsv3 earliest=0"
        " sourcetype=WinEventLog:Security"
        " EventCode=4688"
        " | where match(Process_Command_Line,"
        " \"(?i)netsh|firewall|sc stop|auditpol\")"
        " | table _time, host, Account_Name,"
        " Process_Command_Line"
    ),
    "T1059.003": (
        "index=botsv3 earliest=0"
        " sourcetype=WinEventLog:Security"
        " EventCode=4688"
        " New_Process_Name=\"*cmd.exe*\""
        " | stats count by host, Account_Name,"
        " Process_Command_Line"
        " | where count > 3"
        " | sort -count"
    ),
    "T1059": (
        "index=botsv3 earliest=0"
        " sourcetype=WinEventLog:Security"
        " EventCode=4688"
        " | where match(New_Process_Name,"
        " \"(?i)powershell|cmd|wscript|cscript\")"
        " | stats count by host, New_Process_Name"
        " | sort -count"
    ),
    "T1528": (
        "index=botsv3 earliest=0 sourcetype=stream:http"
        " | where match(uri_path, \"(?i)token|oauth\")"
        " | stats count by src_ip, uri_path"
        " | sort -count"
    ),
    "T1486": (
        "index=botsv3 earliest=0"
        " sourcetype=WinEventLog:Security"
        " EventCode=4688"
        " | where match(Process_Command_Line,"
        " \"(?i)vssadmin|shadow|bcdedit|wmic\")"
        " | table _time, host, Account_Name,"
        " Process_Command_Line"
    ),
    "T1021": (
        "index=botsv3 earliest=0"
        " sourcetype=WinEventLog:Security"
        " EventCode=4624 Logon_Type=10"
        " | stats count by src_ip, Account_Name,"
        " Workstation_Name"
        " | where count > 3"
        " | sort -count"
    ),
    "T1071": (
        "index=botsv3 earliest=0"
        " sourcetype=stream:dns"
        " | where len(query) > 50"
        " | stats count by src_ip, query"
        " | where count > 10"
        " | sort -count"
    ),
    "T1003": (
        "index=botsv3 earliest=0"
        " sourcetype=WinEventLog:Security"
        " EventCode=4688"
        " | where match(New_Process_Name,"
        " \"(?i)mimikatz|procdump\")"
        " OR match(Process_Command_Line,"
        " \"(?i)sekurlsa|lsass\")"
        " | table _time, host, Account_Name,"
        " Process_Command_Line"
    ),
    "T1055": (
        "index=botsv3 earliest=0"
        " sourcetype=WinEventLog:Security"
        " EventCode=4688"
        " | where match(Process_Command_Line,"
        " \"(?i)inject|hollow|VirtualAlloc\")"
        " | table _time, host, Account_Name,"
        " Process_Command_Line"
    ),
}


def _contains_placeholder_spl(spl: str) -> bool:
    """Reject generated SPL that still contains analyst-facing placeholders."""
    spl_lower = spl.lower()
    if any(term in spl_lower for term in PLACEHOLDER_SPL_TERMS):
        return True
    return bool(
        re.search(r"<[^|>\s]+>", spl_lower)
        or re.search(r"\byour_[a-z0-9_]+\b", spl_lower)
        or re.search(r"\breplace_[a-z0-9_]+\b", spl_lower)
    )


def _contains_unfielded_sourcetype(spl: str) -> bool:
    """Require concrete sourcetypes to be expressed as sourcetype=<value>."""
    spl_lower = spl.lower()
    for token in RAW_SOURCETYPE_TOKENS:
        token_lower = token.lower()
        for match in re.finditer(re.escape(token_lower), spl_lower):
            prefix = spl_lower[:match.start()]
            compact_prefix = re.sub(r"\s+", "", prefix[-30:])
            if not compact_prefix.endswith("sourcetype="):
                return True
    return False


def _is_detection_spl_safe(spl: str) -> bool:
    guard_result = validate_spl(spl)
    return (
        not _contains_placeholder_spl(spl)
        and not _contains_unfielded_sourcetype(spl)
        and not guard_result.is_blocked
        and spl.lower().startswith("index=botsv3 earliest=0")
    )


def _canonical_technique_name(tech_id: str, reported_name: str = "") -> str:
    config = TECHNIQUE_KEYWORDS.get(tech_id)
    if not config and "." in tech_id:
        config = TECHNIQUE_KEYWORDS.get(tech_id.split(".")[0])
    if config and config.get("description"):
        return config["description"]
    return reported_name or tech_id


def _display_tactic(tech_id: str, reported_tactic: str = "") -> str:
    tactic = (reported_tactic or "").strip()
    if tactic and tactic.lower() != "unknown":
        return tactic
    config = TECHNIQUE_KEYWORDS.get(tech_id)
    if not config and "." in tech_id:
        config = TECHNIQUE_KEYWORDS.get(tech_id.split(".")[0])
    if config and len(config.get("tactics", [])) > 1:
        return " / ".join(config["tactics"])
    return config.get("tactic", "Unknown") if config else "Unknown"

def _get_saved_searches(splunk_service) -> list[dict]:
    """
    Fetch all saved searches from Splunk with caching.
    Risk 1: 5-minute TTL cache prevents slow repeated calls.
    Returns list of {name, search, description} dicts.
    """
    now = time.time()
    cache = _saved_searches_cache

    if (
        cache["data"] is not None
        and now - cache["fetched_at"] < cache["ttl_seconds"]
    ):
        logger.debug(
            "[GAPS] Saved searches cache hit "
            "(age=%.0fs)",
            now - cache["fetched_at"],
        )
        return cache["data"]

    try:
        logger.info(
            "[GAPS] Connecting to Splunk service: %s",
            type(splunk_service).__name__,
        )
        searches = []
        for s in splunk_service.saved_searches:
            # s.get("description") triggers a REST call that
            # can 404 on some Splunk versions — guard it
            try:
                desc = s.get("description", "")
            except Exception:
                desc = ""
            searches.append({
                "name": s.name,
                "search": s["search"],
                "description": desc,
            })
            logger.info(
                "[GAPS] Found saved search: %s",
                s.name,
            )
        cache["data"] = searches
        cache["fetched_at"] = now
        logger.info(
            "[GAPS] Total saved searches found: %d",
            len(searches),
        )
        return searches
    except Exception as e:
        logger.error(
            "[GAPS] Failed to fetch saved searches: %s",
            str(e),
        )
        return []


def _compute_match_confidence(
    spl: str,
    technique_id: str,
) -> str:
    """
    Compute match confidence based on keyword specificity.
    Risk 2: HIGH/MEDIUM/LOW tells analyst how reliable
    the coverage assessment is.
    HIGH: high_confidence_keywords matched
    MEDIUM: regular keywords matched
    LOW: only generic keywords matched
    """
    config = TECHNIQUE_KEYWORDS.get(technique_id, {})
    spl_lower = spl.lower()

    high_kws = config.get("high_confidence_keywords", [])
    if any(kw.lower() in spl_lower for kw in high_kws):
        return "HIGH"

    regular_kws = config.get("keywords", [])
    matched = sum(
        1 for kw in regular_kws
        if kw.lower() in spl_lower
    )
    if matched >= 2:
        return "MEDIUM"
    if matched >= 1:
        return "LOW"

    return "NONE"


def _check_technique_coverage(
    technique_id: str,
    saved_searches: list[dict],
) -> tuple[bool, list[str], str]:
    """
    Check if any saved search covers a technique.
    Returns (is_covered, matching_search_names, confidence)
    """
    config = TECHNIQUE_KEYWORDS.get(technique_id)
    if not config:
        # Unknown technique — check parent if subtechnique
        parent = technique_id.split(".")[0]
        config = TECHNIQUE_KEYWORDS.get(parent)
        if not config:
            return False, [], "NONE"

    keywords = config.get("keywords", [])
    matching = []
    best_confidence = "NONE"

    for search in saved_searches:
        spl = search.get("search", "").lower()
        if any(kw.lower() in spl for kw in keywords):
            matching.append(search["name"])
            conf = _compute_match_confidence(
                search.get("search", ""),
                technique_id,
            )
            if conf == "HIGH":
                best_confidence = "HIGH"
            elif conf == "MEDIUM" and best_confidence != "HIGH":
                best_confidence = "MEDIUM"
            elif conf == "LOW" and best_confidence == "NONE":
                best_confidence = "LOW"

    return bool(matching), matching, best_confidence


def _coverage_label(score: float) -> str:
    for (low, high), label in COVERAGE_LABELS.items():
        if low <= score < high:
            return label
    return "UNKNOWN"


async def _generate_recommended_spl(
    technique_id: str,
    technique_name: str,
    tactic: str,
    investigation_evidence: dict,
    investigation_id: str,
) -> tuple[str, str]:
    """
    Generate recommended detection SPL for uncovered technique.
    Risk 3: Falls back to deterministic template if LLM fails.
    Risk 5: Validates through guardrail before returning.
    Returns (spl, generation_method) where method is
    "llm" or "template".
    """
    # Build evidence context for LLM
    evidence_parts = []
    if investigation_evidence.get("external_ips"):
        evidence_parts.append(
            f"External IPs: "
            f"{', '.join(investigation_evidence['external_ips'][:3])}"
        )
    if investigation_evidence.get("event_codes"):
        evidence_parts.append(
            f"EventCodes: "
            f"{', '.join(str(e) for e in investigation_evidence['event_codes'][:5])}"
        )
    if investigation_evidence.get("sourcetypes"):
        evidence_parts.append(
            f"Sourcetypes: "
            f"{', '.join(investigation_evidence['sourcetypes'][:3])}"
        )
    if investigation_evidence.get("internal_hosts"):
        evidence_parts.append(
            f"Internal hosts: "
            f"{', '.join(investigation_evidence['internal_hosts'][:3])}"
        )

    evidence_str = "\n".join(evidence_parts) or "No specific evidence available"

    prompt = f"""You are a Splunk detection engineer.
Generate a production-ready Splunk SPL detection query
for this MITRE ATT&CK technique:

Technique: {technique_id} — {technique_name}
Tactic: {tactic}

Investigation evidence from botsv3 dataset:
{evidence_str}

Requirements:
- Query must start with: index=botsv3 earliest=0
- Use concrete sourcetypes only, such as stream:http,
  stream:dns, or WinEventLog:Security
- Sourcetypes must always use explicit fielded filters,
  for example sourcetype=stream:http. Never write raw
  sourcetype terms like stream:http OR stream:dns.
- Do not invent placeholders, fake fields, TODO values,
  your_sourcetype, <sourcetype>, or replace_me tokens
- For T1078 Valid Accounts, use account/authentication
  fields and Windows auth events such as EventCode=4624,
  EventCode=4672, or EventCode=4673. Do not produce
  generic src_ip-only counting.
- Include meaningful filtering (stats, where, eval)
- Should detect the specific technique not just log it
- Keep it concise — under 200 characters preferred
- Do not use | delete, | truncate, | rest, | inputlookup
- Only target index=botsv3

Return ONLY the SPL query, no explanation, no markdown."""

    try:
        llm = ChatOpenAI(
            model="gpt-4o-mini",
            temperature=0.1,
        )
        response = await asyncio.wait_for(
            llm.ainvoke([HumanMessage(content=prompt)]),
            timeout=15.0,
        )
        generated_spl = response.content.strip()

        # Strip markdown fences if present
        if generated_spl.startswith("```"):
            lines = generated_spl.split("\n")
            generated_spl = "\n".join(
                l for l in lines
                if not l.startswith("```")
            ).strip()

        if _contains_placeholder_spl(generated_spl):
            logger.warning(
                "[GAPS] Generated SPL contained placeholder "
                "tokens for %s. Using template.",
                technique_id,
            )
            return _get_guarded_template_spl(technique_id), "template"

        if _contains_unfielded_sourcetype(generated_spl):
            logger.warning(
                "[GAPS] Generated SPL contained raw sourcetype "
                "tokens for %s. Using template.",
                technique_id,
            )
            return _get_guarded_template_spl(technique_id), "template"

        # Risk 5: Validate through guardrail
        guard_result = validate_spl(generated_spl)
        if guard_result.is_blocked:
            logger.warning(
                "[GAPS] Generated SPL blocked by guardrail "
                "for %s: %s. Using template.",
                technique_id,
                guard_result.reason,
            )
            return _get_guarded_template_spl(technique_id), "template"

        # Ensure it targets botsv3
        if "botsv3" not in generated_spl.lower():
            logger.warning(
                "[GAPS] Generated SPL does not target "
                "botsv3 for %s. Using template.",
                technique_id,
            )
            return _get_guarded_template_spl(technique_id), "template"

        logger.info(
            "[GAPS] LLM generated SPL for %s",
            technique_id,
        )
        return generated_spl, "llm"

    except asyncio.TimeoutError:
        logger.warning(
            "[GAPS] LLM timeout for %s. Using template.",
            technique_id,
        )
        return _get_guarded_template_spl(technique_id), "template"
    except Exception as e:
        logger.error(
            "[GAPS] LLM error for %s: %s. Using template.",
            technique_id,
            str(e),
        )
        return _get_guarded_template_spl(technique_id), "template"


def _get_template_spl(technique_id: str) -> str:
    """
    Get deterministic template SPL for a technique.
    Risk 3: Always returns valid SPL even if LLM fails.
    """
    # Try exact match first
    if technique_id in TEMPLATE_SPL:
        return TEMPLATE_SPL[technique_id]
    # Try parent technique
    parent = technique_id.split(".")[0]
    if parent in TEMPLATE_SPL:
        return TEMPLATE_SPL[parent]
    # Generic fallback
    return (
        f"index=botsv3 earliest=0"
        f" sourcetype=WinEventLog:Security"
        f" | stats count by sourcetype, host"
        f" | sort -count"
        f" | head 100"
        f" | eval technique=\"{technique_id}\""
    )


def _get_guarded_template_spl(technique_id: str) -> str:
    """
    Return template SPL only after the same placeholder and guardrail
    checks used for generated SPL.
    """
    spl = _get_template_spl(technique_id)
    guard_result = validate_spl(spl)
    if _is_detection_spl_safe(spl):
        return spl

    logger.warning(
        "[GAPS] Template SPL failed safety checks for %s: %s. "
        "Using generic fallback.",
        technique_id,
        guard_result.reason if guard_result.is_blocked else "syntax",
    )
    return (
        f"index=botsv3 earliest=0"
        f" sourcetype=WinEventLog:Security"
        f" | stats count by sourcetype, host"
        f" | sort -count"
        f" | head 100"
        f" | eval technique=\"{technique_id}\""
    )


async def analyze_detection_gaps(
    investigation_id: str,
    ttp_mappings: list[dict],
    kill_chain: list[dict],
    threat_intel: dict,
    blast_radius: dict,
    splunk_service,
) -> dict:
    """
    Main detection gap analysis function.
    Called by the API endpoint on analyst request.

    Args:
        investigation_id: The investigation ID
        ttp_mappings: List of TTP mappings from TTPAgent
        kill_chain: Kill chain stages from ReconstructionAgent
        threat_intel: Threat intel from ThreatIntelAgent
        blast_radius: Blast radius from ReconstructionAgent
        splunk_service: Authenticated Splunk SDK service

    Returns:
        Full coverage report dict
    """
    logger.info(
        "[GAPS] Starting detection gap analysis | "
        "investigation_id=%s | techniques=%d",
        investigation_id,
        len(ttp_mappings),
    )

    if not ttp_mappings:
        logger.warning(
            "[GAPS] No TTP mappings found for %s",
            investigation_id,
        )
        return {
            "investigation_id": investigation_id,
            "techniques_analyzed": 0,
            "covered": 0,
            "not_covered": 0,
            "coverage_score": 0.0,
            "coverage_label": "NO DATA",
            "gaps": [],
            "weak_matches": [],
            "covered_techniques": [],
            "error": "No MITRE techniques identified "
                     "in this investigation",
        }

    # Build evidence context for SPL generation
    external_ips = list(threat_intel.keys()) if threat_intel else []
    internal_hosts = blast_radius.get(
        "compromised_hosts", []
    ) if blast_radius else []
    event_codes = []
    sourcetypes = []

    for stage in kill_chain:
        evidence = stage.get("evidence", "")
        # Extract EventCodes from evidence strings
        import re
        codes = re.findall(r"EventCode[=:]\s*(\d+)", evidence)
        event_codes.extend(codes)
        # Extract sourcetypes
        src_matches = re.findall(
            r"sourcetype[=:]\s*(\S+)", evidence
        )
        sourcetypes.extend(src_matches)

    investigation_evidence = {
        "external_ips": external_ips[:5],
        "internal_hosts": internal_hosts[:5],
        "event_codes": list(set(event_codes))[:10],
        "sourcetypes": list(set(sourcetypes))[:5],
    }

    # Get saved searches with cache
    saved_searches = _get_saved_searches(splunk_service)

    # Extract unique technique IDs from TTP mappings
    technique_ids = []
    technique_details = {}

    for ttp in ttp_mappings:
        tech_id = ttp.get("technique_id", "")
        if not tech_id or tech_id in technique_ids:
            continue
        technique_ids.append(tech_id)
        reported_name = ttp.get("technique_name", "")
        reported_tactic = ttp.get("tactic", "")
        technique_details[tech_id] = {
            "name": _canonical_technique_name(tech_id, reported_name),
            "tactic": _display_tactic(tech_id, reported_tactic),
            "confidence": ttp.get("confidence", 0.0),
        }

    gaps = []
    weak_matches = []
    covered_techniques = []

    # Check coverage for each technique
    for tech_id in technique_ids:
        is_covered, matching_searches, confidence = (
            _check_technique_coverage(
                tech_id, saved_searches
            )
        )
        details = technique_details.get(tech_id, {})

        if is_covered and confidence in ("HIGH", "MEDIUM"):
            covered_techniques.append({
                "technique_id": tech_id,
                "technique_name": details.get("name", tech_id),
                "tactic": details.get("tactic", "Unknown"),
                "covered": True,
                "existing_searches": matching_searches,
                "match_confidence": confidence,
            })
        elif is_covered:
            weak_matches.append({
                "technique_id": tech_id,
                "technique_name": details.get("name", tech_id),
                "tactic": details.get("tactic", "Unknown"),
                "covered": False,
                "status": "weak_match",
                "existing_searches": matching_searches,
                "match_confidence": confidence,
            })
        else:
            gaps.append({
                "technique_id": tech_id,
                "technique_name": details.get("name", tech_id),
                "tactic": details.get("tactic", "Unknown"),
                "covered": False,
                "existing_searches": [],
                "recommended_spl": None,
                "recommended_name": (
                    f"Sentinel — {tech_id} Detection"
                ),
                "generation_method": None,
                "evidence_used": investigation_evidence,
                "deployed": False,
            })

    # Generate recommended SPL for gaps in parallel
    # Risk 3: each generates independently with fallback
    if gaps:
        spl_tasks = [
            _generate_recommended_spl(
                gap["technique_id"],
                gap["technique_name"],
                gap["tactic"],
                investigation_evidence,
                investigation_id,
            )
            for gap in gaps
        ]
        spl_results = await asyncio.gather(
            *spl_tasks, return_exceptions=True
        )

        for i, result in enumerate(spl_results):
            if isinstance(result, Exception):
                gaps[i]["recommended_spl"] = (
                    _get_guarded_template_spl(gaps[i]["technique_id"])
                )
                gaps[i]["generation_method"] = "template"
            else:
                spl, method = result
                gaps[i]["recommended_spl"] = spl
                gaps[i]["generation_method"] = method
            gaps[i]["spl_guardrail_passed"] = True

    # Compute coverage score
    total = len(technique_ids)
    covered_count = len(covered_techniques)
    score = covered_count / total if total > 0 else 0.0

    result = {
        "investigation_id": investigation_id,
        "techniques_analyzed": total,
        "covered": covered_count,
        "weak_matches_count": len(weak_matches),
        "not_covered": len(gaps),
        "coverage_score": round(score, 2),
        "coverage_label": _coverage_label(score),
        "gaps": gaps,
        "weak_matches": weak_matches,
        "covered_techniques": covered_techniques,
        "saved_searches_checked": len(saved_searches),
        "cache_used": (
            time.time() - _saved_searches_cache["fetched_at"]
            < _saved_searches_cache["ttl_seconds"]
            and _saved_searches_cache["data"] is not None
        ),
    }

    logger.info(
        "[GAPS] Analysis complete | "
        "investigation_id=%s | "
        "total=%d | covered=%d | score=%.2f | "
        "label=%s",
        investigation_id,
        total,
        covered_count,
        score,
        result["coverage_label"],
    )

    return result


async def deploy_detection(
    technique_id: str,
    spl: str,
    name: str,
    investigation_id: str,
    splunk_service,
) -> dict:
    """
    Deploy a recommended detection as a Splunk saved search.
    Risk 4: Checks for duplicate by name before creating.
    Risk 5: Validates SPL through guardrail before deploying.

    Returns deployment result dict.
    """
    if _contains_placeholder_spl(spl):
        return {
            "success": False,
            "error": "SPL blocked by guardrail: placeholder token detected",
            "technique_id": technique_id,
        }

    if _contains_unfielded_sourcetype(spl):
        return {
            "success": False,
            "error": "SPL blocked by guardrail: raw sourcetype token detected",
            "technique_id": technique_id,
        }

    # Risk 5: Validate SPL before deploy
    guard_result = validate_spl(spl)
    if guard_result.is_blocked:
        return {
            "success": False,
            "error": (
                f"SPL blocked by guardrail: "
                f"{guard_result.reason}"
            ),
            "technique_id": technique_id,
        }

    # Risk 4: Check for duplicate
    try:
        existing_names = [
            s.name for s in splunk_service.saved_searches
        ]
        if name in existing_names:
            logger.info(
                "[GAPS] Saved search '%s' already exists",
                name,
            )
            return {
                "success": True,
                "already_deployed": True,
                "name": name,
                "technique_id": technique_id,
                "message": (
                    f"'{name}' already exists in Splunk"
                ),
            }
    except Exception as e:
        logger.warning(
            "[GAPS] Could not check existing searches: %s",
            str(e),
        )

    # Deploy
    try:
        description = (
            f"Auto-generated by Splunk Sentinel "
            f"from investigation {investigation_id}. "
            f"Technique: {technique_id}. "
            f"Deploy date: "
            f"{__import__('datetime').datetime.utcnow().isoformat()}Z"
        )

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: splunk_service.saved_searches.create(
                name,
                spl,
                **{"description": description},
            ),
        )

        logger.info(
            "[GAPS] Deployed saved search '%s' for %s",
            name,
            technique_id,
        )

        return {
            "success": True,
            "already_deployed": False,
            "name": name,
            "technique_id": technique_id,
            "message": (
                f"Successfully deployed '{name}' to Splunk"
            ),
        }

    except Exception as e:
        logger.error(
            "[GAPS] Deploy failed for '%s': %s",
            name,
            str(e),
        )
        return {
            "success": False,
            "error": str(e),
            "technique_id": technique_id,
        }
