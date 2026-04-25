"""
triage_agent.py
---------------
LangGraph node: TriageAgent

Responsibilities:
  1. Inspect the trigger string to select targeted SPL queries (no LLM).
  2. Pull telemetry from Splunk in parallel (base + trigger-aware queries).
  3. Cache results per investigation_id to avoid redundant Splunk calls.
  4. Call gpt-4o-mini via with_structured_output() — OutputParserException impossible.
  5. Apply a hard CRITICAL-severity guardrail forcing escalate_to_human = True.
  6. Enforce escalation when confidence < 0.5.
  7. Return an updated AgentState.

This node is intentionally side-effect-free with respect to Splunk writes;
all writes are handled by downstream agents or the report node.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Literal

from langsmith import traceable
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field, field_validator

from app.models.state import AgentState
from app.tools.splunk_tools import get_splunk_client
from app.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Structured output schema — OpenAI function-calling enforces this exactly.
# OutputParserException becomes impossible.
# ---------------------------------------------------------------------------


class TriageResult(BaseModel):
    """Structured triage classification returned by the LLM."""

    attack_classification: Literal[
        "APT", "INSIDER_THREAT", "BRUTE_FORCE", "RANSOMWARE", "UNKNOWN"
    ]
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    classification_confidence: float = Field(ge=0.0, le=1.0)
    triage_summary: str
    escalate_to_human: bool
    key_indicators: list[str] = Field(
        min_length=1,
        description="3-5 specific evidence items from telemetry. Must include "
                    "at least one of: specific IP addresses observed, specific "
                    "process names with counts, specific EventCode numbers with "
                    "counts, specific URI paths, or specific DNS query patterns. "
                    "Never empty. Never generic statements."
    )

    @field_validator("triage_summary")
    @classmethod
    def summary_must_not_be_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("triage_summary must not be empty")
        return v


# ---------------------------------------------------------------------------
# LLM client — shared singleton, structured output bound at module load.
# ---------------------------------------------------------------------------

_LLM = ChatOpenAI(
    model="gpt-4o-mini",
    temperature=0,
    api_key=settings.OPENAI_API_KEY,
)

# Bind structured output once — this is the structured LLM used for every call.
_LLM_STRUCTURED = _LLM.with_structured_output(TriageResult)

# ---------------------------------------------------------------------------
# System prompt — focuses on reasoning quality only.
# Output format is enforced natively by the OpenAI function-calling API.
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = (
    "You are a senior SOC analyst at a Fortune 500 company investigating a "
    "live security incident. You will be given telemetry extracted directly "
    "from Splunk logs. Your job is to classify the attack, assess its "
    "severity, and identify key indicators of compromise.\n\n"
    "CLASSIFICATION RULES:\n"
    "- Base your assessment ONLY on data explicitly provided. Never invent "
    "IOCs, IP addresses, or events not visible in the telemetry.\n"
    "- If data is sparse or ambiguous, lower your confidence score "
    "accordingly and set escalate_to_human = true.\n\n"
    "DATASET CONTEXT:\n"
    "You are analyzing the botsv3 security dataset. This dataset contains "
    "three confirmed attack scenarios. Use the following heuristics:\n\n"
    "CLASSIFY AS APT if:\n"
    "- stream:http shows queries to 169.254.169.254 (AWS metadata service) "
    "\u2014 this is definitive SSRF/credential theft evidence.\n"
    "- stream:dns shows high-entropy or long query strings (len > 40 chars) "
    "\u2014 consistent with DNS tunneling C2.\n"
    "- External IPs (non-RFC1918) appear in stream:http src_ip hitting "
    "internal web servers.\n\n"
    "CLASSIFY AS INSIDER_THREAT if:\n"
    "- All source IPs are RFC1918 (internal only).\n"
    "- EventCode=4673 (privileged service) or 4672 (special privileges) "
    "appear with high counts.\n"
    "- No external HTTP or DNS anomalies present.\n"
    "- Process execution (4688) shows admin tools (reg.exe, WMIC) without "
    "corresponding external C2 traffic.\n\n"
    "CLASSIFY AS RANSOMWARE if:\n"
    "- EventCode=4688 shows WMIC.exe, cmd.exe, reg.exe spawning at volume.\n"
    "- Combined with network filtering events (5156/5157).\n"
    "- stream:dns shows unusual query patterns alongside process execution.\n\n"
    "HARD CONSTRAINT — BRUTE_FORCE CLASSIFICATION:\n"
    "This constraint applies ONLY when the trigger explicitly mentions "
    "brute force, failed logins, password spray, credential stuffing, "
    "or authentication attacks.\n\n"
    "If AND ONLY IF the trigger is about authentication/brute force AND "
    "the EventCode 4625 total count returned by telemetry is BELOW 20:\n"
    "  - You MUST NOT classify as BRUTE_FORCE\n"
    "  - You MUST classify as UNKNOWN\n"
    "  - Your triage_summary MUST state the actual 4625 count and that "
    "it is below the minimum threshold\n"
    "  - escalate_to_human must be True\n\n"
    "For ALL OTHER trigger types (APT, ransomware, lateral movement, "
    "insider threat, web attacks), the EventCode 4625 count is "
    "IRRELEVANT to your classification decision. Do not mention the "
    "brute force threshold in summaries for non-authentication triggers. "
    "Classify based on the actual attack evidence present in the telemetry.\n\n"
    "CLASSIFY AS UNKNOWN only when:\n"
    "- Fewer than 3 of the above signals are present.\n"
    "- Confidence must be set below 0.4.\n"
    "- escalate_to_human must be True.\n\n"
    "KEY FIELDS THAT ARE RELIABLE IN THIS DATASET:\n"
    "- stream:http \u2192 dest_ip, uri_path, src_ip, http_method\n"
    "- stream:dns \u2192 query (218K events)\n"
    "- WinEventLog:Security \u2192 EventCode, New_Process_Name (4688), "
    "Account_Name (4625)\n"
    "- EventCode counts: 5156=11501, 4689=7446, 4688=7427, 4673=4122\n\n"
    "Populate key_indicators with 3-5 specific items of telemetry evidence. "
    "Each item must be a concrete data point from the Splunk queries, not "
    "a generic observation.\n"
    "CORRECT examples:\n"
    "- \"EventCode 4688: WMIC.exe spawned 536 times\"\n"
    "- \"Top source IP 172.16.0.178 with 99794 events (RFC1918 internal)\"\n"
    "- \"AWS metadata service 169.254.169.254 queried 11 times via stream:http\"\n"
    "- \"EventCode 4625: 6 failed logons across 4 accounts\"\n"
    "- \"stream:dns: 20 long-query DNS entries (len > 40 chars) detected\"\n\n"
    "INCORRECT examples (do not use):\n"
    "- \"Unusual process execution detected\"\n"
    "- \"Network anomaly observed\"\n"
    "- \"Authentication failure present\""
)

# ---------------------------------------------------------------------------
# In-memory telemetry cache — keyed on investigation_id.
# Prevents redundant Splunk queries on repeated test runs with the same ID.
# ---------------------------------------------------------------------------

_telemetry_cache: dict[str, dict] = {}

# ---------------------------------------------------------------------------
# Trigger keyword → targeted SPL query sets (ground-truth botsv3 mapping)
# ---------------------------------------------------------------------------

# APT / Credential Theft / SSRF / C2
_APT_KEYWORDS = {
    "apt", "credential", "exfiltration", "cloud", "iam", "ssrf",
    "metadata", "c2", "command and control", "dns tunnel", "beaconing",
}
_APT_QUERIES: list[str] = [
    # AWS metadata SSRF — definitive credential theft signal
    (
        "index=botsv3 earliest=0 sourcetype=stream:http dest_ip=169.254.169.254 "
        "| stats count by uri_path | sort -count | head 20"
    ),
    # Long DNS queries — DNS tunneling / C2 beaconing signal
    (
        "index=botsv3 earliest=0 sourcetype=stream:dns "
        "| eval query_len=len(query) | where query_len > 40 "
        "| stats count by query | sort -count | head 20"
    ),
    # External IPs in HTTP traffic — attacker egress / initial access
    (
        "index=botsv3 earliest=0 sourcetype=stream:http "
        '| where NOT match(dest_ip, "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)") '
        "| stats count by src_ip, dest_ip, uri_path | sort -count | head 20"
    ),
]

# Web Application Attack / Initial Access
_WEB_KEYWORDS = {
    "web", "http", "exploit", "injection", "sqli", "shell", "php",
    "forum", "cms", "defacement", "scanning", "enumeration",
}
_WEB_QUERIES: list[str] = [
    # Full HTTP traffic picture — who hit what endpoint
    (
        "index=botsv3 earliest=0 sourcetype=stream:http "
        "| stats count by src_ip, dest_ip, uri_path | sort -count | head 20"
    ),
    # External-only HTTP — confirmed external attacker activity
    (
        "index=botsv3 earliest=0 sourcetype=stream:http "
        '| where NOT match(src_ip, "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)") '
        "| stats count by src_ip, uri_path, http_method | sort -count | head 20"
    ),
    # MySQL traffic — SQL injection detection
    (
        "index=botsv3 earliest=0 sourcetype=stream:mysql "
        "| stats count by src_ip, dest_ip | sort -count | head 10"
    ),
]

# Lateral Movement / Ransomware / Process Execution
_LATERAL_KEYWORDS = {
    "ransomware", "lateral", "smb", "wmic", "process", "execution",
    "shadow copy", "persistence", "registry", "malware", "infection",
    "insider", "privileged", "abuse", "account", "permission", "privilege",
    "internal user", "file access",
}
_LATERAL_QUERIES: list[str] = [
    # All process creation — full execution picture
    (
        "index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=4688 "
        "| stats count by New_Process_Name | sort -count | head 20"
    ),
    # Suspicious process chains — LOLBins and attack tooling
    (
        'index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=4688 '
        'New_Process_Name IN ("*cmd.exe*", "*wmic.exe*", "*reg.exe*", '
        '"*powershell*", "*mshta*", "*rundll32*", "*cscript*", "*wscript*") '
        "| stats count by New_Process_Name, Creator_Process_Name | sort -count | head 20"
    ),
    # Network filtering events — confirms host-based firewall activity
    (
        "index=botsv3 earliest=0 sourcetype=WinEventLog:Security "
        "(EventCode=5156 OR EventCode=5157) "
        "| stats count by EventCode | head 5"
    ),
]

# Brute Force / Authentication
_BRUTEFORCE_KEYWORDS = {
    "brute force", "failed login", "authentication spike",
    "credential stuffing", "password spray",
}
_BRUTEFORCE_QUERIES: list[str] = [
    # 4625 timechart — see attack velocity over time
    (
        "index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=4625 "
        "| timechart span=1h count"
    ),
    # Brute-force to success transaction — confirmed compromise chain
    (
        "index=botsv3 earliest=0 sourcetype=WinEventLog:Security "
        "(EventCode=4625 OR EventCode=4624) "
        "| transaction Account_Name maxspan=5m | where eventcount > 3"
    ),
    # Endpoint telemetry — supplementary signal when 4625 is sparse
    (
        "index=botsv3 earliest=0 sourcetype=osquery:results "
        "| stats count by name | sort -count | head 10"
    ),
]


def categorize_trigger(trigger: str) -> tuple[str, int]:
    """
    Public wrapper for trigger categorization logic used by tests.
    Returns (category_label, number_of_queries).
    """
    queries, label = _select_dynamic_queries(trigger)
    return label, len(queries)


def _select_dynamic_queries(trigger: str) -> tuple[list[str], str]:
    """
    Inspect the trigger string with keyword matching (no LLM) and return
    the list of additional SPL queries to run, plus a label for logging.

    Categories are derived from botsv3 ground-truth field analysis.

    Returns:
        (list_of_spl_strings, category_label)
    """
    trigger_lower = trigger.lower()
    extra_queries: list[str] = []
    labels: list[str] = []

    if any(kw in trigger_lower for kw in _APT_KEYWORDS):
        extra_queries.extend(_APT_QUERIES)
        labels.append("APT/CREDENTIAL_THEFT")

    if any(kw in trigger_lower for kw in _WEB_KEYWORDS):
        extra_queries.extend(_WEB_QUERIES)
        labels.append("WEB_ATTACK/INITIAL_ACCESS")

    if any(kw in trigger_lower for kw in _LATERAL_KEYWORDS):
        extra_queries.extend(_LATERAL_QUERIES)
        labels.append("LATERAL_MOVEMENT/RANSOMWARE")

    if any(kw in trigger_lower for kw in _BRUTEFORCE_KEYWORDS):
        extra_queries.extend(_BRUTEFORCE_QUERIES)
        labels.append("BRUTE_FORCE/AUTH")

    return list(dict.fromkeys(extra_queries)), "+".join(labels) if labels else "GENERIC"


# Attack signal keywords for trigger quality check
_HIGH_SIGNAL_KEYWORDS = {
    "attack", "exploit", "malware", "ransomware", "lateral", "credential",
    "exfiltration", "brute force", "bruteforce", "injection", "scanning",
    "privilege", "suspicious", "unauthorized", "compromise", "breach",
    "threat", "apt", "ssrf", "c2", "beacon", "tunnel", "metadata",
    "shadow copy", "wmic", "cmd.exe", "reg.exe", "powershell", "phishing",
    "insider", "privileged", "file access", "svchost", "spawning",
    "execution chain", "parent process", "non-standard", "process creation",
    "credential theft", "iam", "ec2", "exfiltrat", "encrypt", "ransom",
    "lateral movement", "command and control", "dns tunnel", "data exfil",
    "escalation", "privilege escalation", "mass file", "permission change",
    "eventcode", "4625", "4673", "4688", "4672", "4670",
}


def _is_low_signal_trigger(trigger: str) -> bool:
    """
    Returns True if the trigger contains fewer than 2 attack-signal 
    keywords AND is shorter than 20 words. Pure Python — no LLM.
    """
    trigger_lower = trigger.lower()
    word_count = len(trigger.split())
    
    matched = sum(
        1 for kw in _HIGH_SIGNAL_KEYWORDS 
        if kw in trigger_lower
    )
    
    return matched < 2 and word_count < 20


def apply_escalation_guardrail(result: TriageResult) -> TriageResult:
    """
    Enforces post-processing safety guardrails:
    1. CRITICAL severity always forces escalation.
    2. UNKNOWN classification with low confidence always forces escalation.
    3. Severity floor by classification (cannot be below minimums).
    4. Confidence is capped at 0.95 to reflect statistical uncertainty.
    """
    # 1. CRITICAL severity hard guardrail
    if result.severity == "CRITICAL":
        result.escalate_to_human = True

    # 2. Low-confidence UNKNOWN escalation
    if result.attack_classification == "UNKNOWN" and result.classification_confidence < 0.4:
        result.escalate_to_human = True

    # 3. Severity floor by classification
    severity_floor = {
        "APT": "HIGH",
        "RANSOMWARE": "HIGH", 
        "INSIDER_THREAT": "MEDIUM",
        "BRUTE_FORCE": "MEDIUM",
    }
    severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    
    floor = severity_floor.get(result.attack_classification)
    if floor and result.severity:
        current_idx = severity_order.index(result.severity) \
            if result.severity in severity_order else 0
        floor_idx = severity_order.index(floor)
        if current_idx < floor_idx:
            logger.warning(
                f"Severity floor applied: {result.attack_classification} "
                f"cannot be {result.severity} — raising to {floor}"
            )
            result.severity = floor

    # 4. Confidence cap (0.95)
    if result.classification_confidence > 0.95:
        result.classification_confidence = 0.95

    return result


# ---------------------------------------------------------------------------
# LangGraph node
# ---------------------------------------------------------------------------


@traceable(
    name="TriageAgent",
    run_type="chain",
    tags=["triage", "splunk-sentinel"],
)
async def triage_agent(state: AgentState) -> AgentState:
    """
    LangGraph node — TriageAgent.

    Executes the initial investigation triage:
      - Selects trigger-aware SPL queries via keyword matching.
      - Runs base + dynamic queries in parallel from Splunk.
      - Uses per-investigation_id cache to avoid duplicate Splunk calls.
      - Calls gpt-4o via with_structured_output() for reliable classification.
      - Applies CRITICAL-severity hard guardrail for escalation.
      - Enforces escalation when confidence < 0.5.
      - Appends all executed SPL queries to spl_audit_log in the state.

    Args:
        state: Current AgentState flowing through the LangGraph graph.

    Returns:
        Updated AgentState with triage fields populated.
        On any unrecoverable failure, sets ``state["error"]`` and returns
        without crashing the graph.
    """
    investigation_id = state.get("investigation_id", "unknown")
    trigger = state.get("trigger", "")
    logger.info("[%s] TriageAgent starting …", investigation_id)

    # ── Step 1: Initialise Splunk client (Singleton) ────────────────────────
    try:
        splunk = get_splunk_client()
        # Drain the singleton's audit log before this investigation starts.
        # This ensures we only capture queries executed for the current
        # investigation_id, preventing cross-investigation log accumulation.
        splunk.audit_log.clear()
    except Exception as exc:
        logger.error("[%s] Failed to connect to Splunk: %s", investigation_id, exc)
        return {
            **state,
            "error": f"TriageAgent: Splunk connection failed — {exc}",
            "escalate_to_human": True,
        }

    # ── Step 2: Trigger-aware query selection ───────────────────────────────
    dynamic_queries, trigger_category = _select_dynamic_queries(trigger)
    logger.info(
        "[%s] Trigger category: %s | dynamic queries selected: %d",
        investigation_id,
        trigger_category,
        len(dynamic_queries),
    )

    # ── Step 3: Pull telemetry from Splunk (Parallel, with cache) ──────────
    if investigation_id in _telemetry_cache:
        logger.info(
            "[%s] Cache HIT — skipping Splunk queries.", investigation_id
        )
        cached = _telemetry_cache[investigation_id]
        attack_window = cached["attack_window"]
        top_ips = cached["top_ips"]
        event_codes = cached["event_codes"]
        auth_failures = cached["auth_failures"]
        dynamic_results = cached.get("dynamic_results", {})
    else:
        # Base query A — EventCode distribution (attack type signal)
        spl_codes = (
            "index=botsv3 earliest=0 sourcetype=WinEventLog:Security "
            "| stats count by EventCode "
            "| sort -count "
            "| head 10"
        )
        # Base query B — Authentication failures (brute-force signal)
        spl_auth = (
            "index=botsv3 earliest=0 sourcetype=WinEventLog:Security "
            "EventCode=4625 "
            "| stats count as failures by Account_Name "
            "| sort -failures "
            "| head 10"
        )

        # Build the full coroutine list: 4 base + N dynamic
        base_coros = [
            splunk.get_attack_window(),
            splunk.get_top_source_ips(top_n=10),
            splunk.run_search(spl_codes),
            splunk.run_search(spl_auth),
        ]
        dynamic_coros = [splunk.run_search(q) for q in dynamic_queries]
        all_coros = base_coros + dynamic_coros

        try:
            all_results = await asyncio.gather(*all_coros, return_exceptions=True)

            # Unpack base results (indices 0-3)
            attack_window = all_results[0] if not isinstance(all_results[0], Exception) else {
                "start": "unknown", "end": "unknown",
                "peak_hour": "unknown", "peak_count": 0, "total_events": 0,
            }
            top_ips = all_results[1] if not isinstance(all_results[1], Exception) else []
            event_codes = all_results[2] if not isinstance(all_results[2], Exception) else []
            auth_failures = all_results[3] if not isinstance(all_results[3], Exception) else []

            # Unpack dynamic results (indices 4+)
            dynamic_results: dict[str, list] = {}
            for idx, (spl_str, res) in enumerate(zip(dynamic_queries, all_results[4:])):
                key = f"dynamic_{idx}"
                if isinstance(res, Exception):
                    logger.error(
                        "[%s] Dynamic query %d failed: %s", investigation_id, idx, res
                    )
                    dynamic_results[key] = []
                else:
                    dynamic_results[key] = res

            # Log any base query failures
            for i, r in enumerate(all_results[:4]):
                if isinstance(r, Exception):
                    logger.error(
                        "[%s] Base telemetry query %d failed: %s", investigation_id, i, r
                    )

            logger.info(
                "[%s] Parallel telemetry retrieval complete "
                "(base=4, dynamic=%d).",
                investigation_id,
                len(dynamic_queries),
            )

            # Populate cache — one entry per investigation_id
            # Only cache if telemetry was actually retrieved successfully
            if (
                attack_window.get("total_events", 0) > 0 and
                len(top_ips) > 0
            ):
                _telemetry_cache[investigation_id] = {
                    "attack_window": attack_window,
                    "top_ips": top_ips,
                    "event_codes": event_codes,
                    "auth_failures": auth_failures,
                    "dynamic_results": dynamic_results,
                }

        except Exception as exc:
            logger.error("[%s] Telemetry retrieval failed: %s", investigation_id, exc)
            attack_window = {
                "start": "unknown", "end": "unknown",
                "peak_hour": "unknown", "peak_count": 0, "total_events": 0,
            }
            top_ips, event_codes, auth_failures = [], [], []
            dynamic_results = {}

    # ── Step 4: Build LLM context ───────────────────────────────────────────
    # Append dynamic telemetry sections to the base context
    dynamic_sections = ""
    for idx, (spl_str, data_list) in enumerate(
        zip(dynamic_queries, dynamic_results.values())
    ):
        label = spl_str[:80].strip()
        dynamic_sections += (
            f"\nDYNAMIC QUERY [{idx + 1}] ({label}...):\n"
            f"{json.dumps(data_list, indent=2)}\n"
        )

    # Build EVIDENCE ANCHORS — pre-formatted, quotable facts the LLM must cite
    top_ip_entry = top_ips[0] if top_ips else {}
    top_ip_str = (
        f"{top_ip_entry.get('ip', 'N/A')} "
        f"({int(top_ip_entry.get('event_count', 0)):,} events)"
        if top_ip_entry else "N/A"
    )
    fail_total = sum(int(r.get("failures", 0)) for r in (auth_failures or []))
    top_ec_lines = ""
    for ec in (event_codes or [])[:5]:
        top_ec_lines += (
            f"  EventCode {ec.get('EventCode', 'N/A')}: "
            f"{int(ec.get('count', 0)):,} events\n"
        )

    evidence_anchors = (
        f"\nEVIDENCE ANCHORS (cite these exact facts in triage_summary and key_indicators):\n"
        f"  Top source IP: {top_ip_str}\n"
        f"{top_ec_lines}"
        f"  EventCode 4625 total failures: {fail_total}"
        + (
            f" (BELOW 20-event brute-force threshold — do not classify as BRUTE_FORCE)"
            if fail_total < 20 and ("BRUTE" in trigger_category.upper() or "AUTH" in trigger_category.upper())
            else ""
        )
        + "\n"
    )

    context = f"""
SECURITY INCIDENT TELEMETRY
===========================
Attack Window: {attack_window['start']} to {attack_window['end']}
Peak Activity: {attack_window['peak_hour']} ({attack_window['peak_count']:,} events)
Total Events:  {attack_window['total_events']:,}

TOP SOURCE IPs (by event volume):
{json.dumps(top_ips, indent=2)}

TOP WINDOWS EVENT CODES:
{json.dumps(event_codes, indent=2)}

AUTHENTICATION FAILURES (EventCode 4625):
{json.dumps(auth_failures, indent=2)}
{dynamic_sections}{evidence_anchors}
TRIGGER: {trigger}
"""
    logger.debug("[%s] LLM context:\n%s", investigation_id, context)

    # Python-based trigger quality check — runs before LLM
    if _is_low_signal_trigger(state["trigger"]):
        logger.info(
            f"[{investigation_id}] Trigger quality check: LOW SIGNAL — "
            f"forcing UNKNOWN before LLM call"
        )
        # Build key_indicators from base telemetry
        key_indicators = []

        top_ips_list = top_ips if top_ips else []
        if top_ips_list:
            top = top_ips_list[0]
            key_indicators.append(
                f"Top source IP: {top.get('ip', 'N/A')} "
                f"({top.get('event_count', 0)} events)"
            )

        event_codes_list = event_codes or []
        for ec in event_codes_list[:3]:
            key_indicators.append(
                f"EventCode {ec.get('EventCode', 'N/A')}: "
                f"{ec.get('count', 0)} events"
            )

        fail_count = sum(
            int(r.get("failures", 0))
            for r in (auth_failures or [])
        )
        key_indicators.append(
            f"EventCode 4625: {fail_count} failed logons "
            f"({'below' if fail_count < 20 else 'above'} 20-event threshold)"
        )

        # Build summary for return
        top_ip = top_ips_list[0] if top_ips_list else {}
        ip_str = f"{top_ip.get('ip', 'N/A')} ({int(top_ip.get('event_count', 0))} events)"
        dominant_codes = [f"EventCode {ec.get('EventCode')} ({int(ec.get('count', 0))} events)" for ec in event_codes_list[:3]]
        codes_str = ", ".join(dominant_codes) if dominant_codes else "no dominant EventCodes"

        summary = (
            f"Trigger provided insufficient attack signal. "
            f"Base telemetry shows: top source IP {ip_str}, {codes_str}. "
            f"EventCode 4625 count: {fail_count} events "
            f"({'below' if fail_count < 20 else 'above'} the 20-event brute force threshold). "
            f"Cannot classify without additional context — escalating to human analyst."
        )

        return {
            **state,
            "attack_classification": "UNKNOWN",
            "classification_confidence": 0.35,
            "severity": "LOW",
            "escalate_to_human": True,
            "triage_summary": summary,
            "key_indicators": key_indicators,
            "error": None,
            "confidence_scores": {"triage": 0.35},
            "spl_audit_log": splunk.audit_log[:],
        }

    # ── Step 5: Call gpt-4o via with_structured_output() ───────────────────
    # with_structured_output uses OpenAI's native function-calling API.
    # The model is physically constrained to return a valid TriageResult.
    # OutputParserException is impossible with this pattern.
    messages = [
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(content=context),
    ]

    try:
        result: TriageResult = await _LLM_STRUCTURED.with_config({
            "run_name": "triage_llm_call",
            "metadata": {
                "investigation_id": investigation_id,
                "trigger_category": trigger_category,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        }).ainvoke(messages)

    except Exception as exc:
        logger.error("[%s] LLM call failed: %s", investigation_id, exc)
        return {
            **state,
            "attack_window": attack_window,
            "top_source_ips": top_ips,
            "error": f"TriageAgent: LLM call failed — {exc}",
            "escalate_to_human": True,
            "spl_audit_log": list(state.get("spl_audit_log", [])) + splunk.audit_log,
        }

    # ── Post-processing: ensure key_indicators is populated ─────────────────
    # gpt-4o-mini with with_structured_output ignores minItems constraints.
    # If the LLM returned empty key_indicators, build them from telemetry.
    if not result.key_indicators:
        ki: list[str] = []
        if top_ips:
            top = top_ips[0]
            ki.append(
                f"Top source IP: {top.get('ip', 'N/A')} "
                f"({int(top.get('event_count', 0)):,} events)"
            )
        for ec in (event_codes or [])[:3]:
            ki.append(
                f"EventCode {ec.get('EventCode', 'N/A')}: "
                f"{int(ec.get('count', 0)):,} events"
            )
        fail_count = sum(int(r.get("failures", 0)) for r in (auth_failures or []))
        ki.append(
            f"EventCode 4625: {fail_count} total failures "
            f"({'below' if fail_count < 20 else 'above'} 20-event brute-force threshold)"
        )
        result.key_indicators = ki if ki else ["Base telemetry retrieved — classification based on event code patterns"]
        logger.info(
            "[%s] key_indicators was empty from LLM — built %d items from telemetry",
            investigation_id, len(result.key_indicators)
        )

    # ── Step 6 & 7: Apply escalation guardrails ───────────────────────────
    result = apply_escalation_guardrail(result)

    # Cache invalidation for empty triage_summary
    if not result.triage_summary or not result.triage_summary.strip():
        _telemetry_cache.pop(investigation_id, None)
        raise ValueError(
            f"[{investigation_id}] TriageAgent produced empty triage_summary — "
            "cache invalidated, result discarded"
        )

    escalate_to_human = (result.classification_confidence < 0.5) or result.escalate_to_human

    if escalate_to_human:
        logger.warning(
            "[%s] Escalation triggered (severity=%s, confidence=%.2f).",
            investigation_id,
            result.severity,
            result.classification_confidence,
        )

    # ── Step 8: Update audit log ────────────────────────────────────────────
    existing_audit = list(state.get("spl_audit_log", []))
    updated_audit = existing_audit + splunk.audit_log

    # ── Step 9: Build updated state ─────────────────────────────────────────
    updated_state: AgentState = {
        **state,
        "attack_window": attack_window,
        "top_source_ips": top_ips,
        "attack_classification": result.attack_classification,
        "classification_confidence": result.classification_confidence,
        "severity": result.severity,
        "triage_summary": result.triage_summary,
        "key_indicators": result.key_indicators,
        "escalate_to_human": escalate_to_human,
        "confidence_scores": {
            **state.get("confidence_scores", {}),
            "triage": result.classification_confidence,
        },
        "spl_audit_log": updated_audit,
        "error": None,
    }

    logger.info(
        "[%s] TriageAgent complete | classification=%s | severity=%s | "
        "confidence=%.2f | escalate=%s | indicators=%d",
        investigation_id,
        result.attack_classification,
        result.severity,
        result.classification_confidence,
        escalate_to_human,
        len(result.key_indicators),
    )
    return updated_state
