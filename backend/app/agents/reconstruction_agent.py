"""
reconstruction_agent.py
-----------------------
LangGraph node — ReconstructionAgent.

Receives TriageAgent output and reconstructs the full attack narrative:
  - Kill chain stages with MITRE ATT&CK mapping and timestamps
  - Patient zero identification by earliest timestamp
  - Blast radius assessment (internal/external IPs, containment priority)

Design constraints:
  - Reuses the existing SplunkClient singleton (get_splunk_client)
  - Runs all Splunk queries in parallel via asyncio.gather()
  - One structured LLM call using with_structured_output(ReconstructionResult)
  - Target latency: under 25 seconds for Splunk + LLM combined
  - Does NOT duplicate base telemetry queries already run by TriageAgent
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Literal

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field
from typing import Optional, Literal

from app.models.state import AgentState
from app.tools.splunk_tools import get_splunk_client

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------


class KillChainStage(BaseModel):
    stage_number: int
    stage_name: str          # e.g. "Initial Access", "Execution", "Lateral Movement"
    mitre_tactic: str        # e.g. "TA0001"
    mitre_technique: str     # e.g. "T1190 - Exploit Public-Facing Application"
    timestamp: str           # earliest observed timestamp for this stage
    evidence: str            # specific telemetry citation: IP, EventCode, count, URI
    confidence: Literal["CONFIRMED", "INFERRED"]
    affected_assets: list[str]  # IPs or hostnames involved in this stage


class PatientZero(BaseModel):
    ip_address: str
    first_seen: str          # earliest timestamp this IP appeared
    role: str                # "External Attacker", "Compromised Internal Host", etc.
    evidence: str            # the specific query result that identifies patient zero
    confidence: Literal["CONFIRMED", "INFERRED"]


class BlastRadius(BaseModel):
    total_affected_ips: int
    internal_ips_affected: list[str]
    external_ips_observed: list[str]
    affected_sourcetypes: list[str]
    data_at_risk: str        # plain English assessment of what data/systems are at risk
    containment_priority: Literal["IMMEDIATE", "HIGH", "MEDIUM", "LOW"]


class ReconstructionResult(BaseModel):
    kill_chain: list[KillChainStage] = Field(min_length=1)
    patient_zero: PatientZero
    blast_radius: BlastRadius
    attack_narrative: str    # 2-3 sentence plain English summary of the full attack
    reconstruction_confidence: float = Field(ge=0.0, le=1.0)


class ReconstructionResultRaw(BaseModel):
    """Relaxed version — all fields optional to catch partial LLM output."""
    kill_chain: list[KillChainStage] = Field(default_factory=list)
    patient_zero: Optional[PatientZero] = None
    blast_radius: Optional[BlastRadius] = None
    attack_narrative: Optional[str] = None
    reconstruction_confidence: Optional[float] = None


# ---------------------------------------------------------------------------
# Forensic reconstruction queries (keyed by TriageAgent classification)
# These are timeline/attribution queries — NOT duplicates of TriageAgent
# classification queries which focus on counts and patterns.
# ---------------------------------------------------------------------------

RECONSTRUCTION_QUERIES: dict[str, list[str]] = {
    "APT": [
        # Temporal sequence of external HTTP access — establishes initial access timeline
        (
            "index=botsv3 earliest=0 sourcetype=stream:http "
            "| where NOT match(src_ip, \"^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)\")"
            "| eval time=strftime(_time, \"%Y-%m-%d %H:%M:%S\")"
            "| table time, src_ip, dest_ip, uri_path, http_method"
            "| sort time | head 20"
        ),
        # AWS metadata service access timeline — credential theft staging
        (
            "index=botsv3 earliest=0 sourcetype=stream:http dest_ip=169.254.169.254 "
            "| eval time=strftime(_time, \"%Y-%m-%d %H:%M:%S\")"
            "| table time, src_ip, uri_path "
            "| sort time | head 20"
        ),
        # DNS tunneling timeline — C2 communication sequence
        (
            "index=botsv3 earliest=0 sourcetype=stream:dns "
            "| eval query_len=len(query) | where query_len > 40 "
            "| eval time=strftime(_time, \"%Y-%m-%d %H:%M:%S\")"
            "| table time, src_ip, query "
            "| sort time | head 20"
        ),
        # Process execution timeline — post-exploitation activity
        (
            "index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=4688 "
            "| eval time=strftime(_time, \"%Y-%m-%d %H:%M:%S\")"
            "| table time, New_Process_Name, Creator_Process_Name, ComputerName "
            "| sort time | head 20"
        ),
        # Privilege escalation timeline — access elevation events
        (
            "index=botsv3 earliest=0 sourcetype=WinEventLog:Security "
            "(EventCode=4672 OR EventCode=4673) "
            "| eval time=strftime(_time, \"%Y-%m-%d %H:%M:%S\")"
            "| table time, EventCode, Account_Name, ComputerName "
            "| sort time | head 20"
        ),
    ],

    "RANSOMWARE": [
        # Process execution chain timeline — malware deployment sequence
        (
            "index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=4688 "
            "| eval time=strftime(_time, \"%Y-%m-%d %H:%M:%S\")"
            "| table time, New_Process_Name, Creator_Process_Name, ComputerName "
            "| sort time | head 30"
        ),
        # Network connections during execution — lateral movement / C2 traffic
        (
            "index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=5156 "
            "| eval time=strftime(_time, \"%Y-%m-%d %H:%M:%S\")"
            "| table time, src_ip, dest_ip, dest_port "
            "| sort time | head 20"
        ),
        # File and object access — encryption targets and permission changes
        (
            "index=botsv3 earliest=0 sourcetype=WinEventLog:Security "
            "(EventCode=4663 OR EventCode=4659 OR EventCode=4670) "
            "| eval time=strftime(_time, \"%Y-%m-%d %H:%M:%S\")"
            "| table time, EventCode, Object_Name, Account_Name "
            "| sort time | head 20"
        ),
        # Privilege usage during ransomware — service/token abuse
        (
            "index=botsv3 earliest=0 sourcetype=WinEventLog:Security "
            "(EventCode=4672 OR EventCode=4673) "
            "| eval time=strftime(_time, \"%Y-%m-%d %H:%M:%S\")"
            "| table time, EventCode, Account_Name, ComputerName "
            "| sort time | head 20"
        ),
    ],

    "INSIDER_THREAT": [
        # Account activity timeline — logon and privilege events
        (
            "index=botsv3 earliest=0 sourcetype=WinEventLog:Security "
            "(EventCode=4624 OR EventCode=4672 OR EventCode=4673) "
            "| eval time=strftime(_time, \"%Y-%m-%d %H:%M:%S\")"
            "| table time, EventCode, Account_Name, ComputerName "
            "| sort time | head 30"
        ),
        # Object access and permission changes — data exfil or sabotage
        (
            "index=botsv3 earliest=0 sourcetype=WinEventLog:Security "
            "(EventCode=4670 OR EventCode=4663) "
            "| eval time=strftime(_time, \"%Y-%m-%d %H:%M:%S\")"
            "| table time, EventCode, Object_Name, Account_Name "
            "| sort time | head 20"
        ),
        # Process execution by internal accounts — tool usage timeline
        (
            "index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=4688 "
            "| eval time=strftime(_time, \"%Y-%m-%d %H:%M:%S\")"
            "| table time, New_Process_Name, Creator_Process_Name, Account_Name "
            "| sort time | head 20"
        ),
    ],
}

# Fallback for UNKNOWN or any unmatched classification
FALLBACK_QUERIES = RECONSTRUCTION_QUERIES["APT"]


# ---------------------------------------------------------------------------
# LLM setup
# ---------------------------------------------------------------------------

_LLM = ChatOpenAI(model="gpt-4o-mini", temperature=0)
_LLM_STRUCTURED_RAW = _LLM.with_structured_output(ReconstructionResultRaw)

_SYSTEM_PROMPT = (
    "You are a senior threat intelligence analyst performing forensic attack "
    "reconstruction. You have received pre-classified telemetry from a triage "
    "agent and must reconstruct the full attack timeline.\n\n"
    "Your job:\n"
    "1. Build a chronological kill chain from the telemetry evidence\n"
    "2. Identify patient zero — the EARLIEST external IP or compromised internal "
    "host where the attack originated. Patient zero is determined by TIMESTAMP "
    "not by event count.\n"
    "3. Assess blast radius — all assets touched by the attack\n\n"
    "KILL CHAIN RULES:\n"
    "- Map each stage to a MITRE ATT&CK tactic (TA00XX) and technique (TXXX)\n"
    "- Every stage must cite specific evidence: IP addresses, EventCodes with "
    "counts, timestamps, process names, or URI paths\n"
    "- If you cannot find direct evidence for a stage, set confidence=INFERRED "
    "and explain why it is inferred\n"
    "- Stages must be in chronological order by timestamp\n"
    "- Use only evidence present in the telemetry — do not hallucinate stages\n\n"
    "PATIENT ZERO RULES:\n"
    "- Patient zero is the FIRST external IP seen in stream:http or stream:dns "
    "contacting an internal host, by earliest timestamp\n"
    "- If all IPs are RFC1918, patient zero is the internal host with the "
    "earliest anomalous activity timestamp\n"
    "- Never assign patient zero based on event count alone\n\n"
    "BLAST RADIUS RULES:\n"
    "- List every unique internal IP that appears in any telemetry result\n"
    "- List every unique external IP observed\n"
    "- containment_priority must be IMMEDIATE for APT or RANSOMWARE with "
    "CONFIRMED kill chain stages\n"
    "- data_at_risk must be specific: name the systems, credentials, or "
    "data types at risk based on the evidence\n\n"
    "MITRE ATT&CK REFERENCE (use these for botsv3 attack patterns):\n"
    "- TA0001 Initial Access: T1190 Exploit Public-Facing Application\n"
    "- TA0002 Execution: T1059.003 Windows Command Shell, T1047 WMI\n"
    "- TA0003 Persistence: T1547 Boot/Logon Autostart\n"
    "- TA0004 Privilege Escalation: T1078 Valid Accounts\n"
    "- TA0005 Defense Evasion: T1070 Indicator Removal\n"
    "- TA0006 Credential Access: T1552.005 Cloud Instance Metadata API\n"
    "- TA0007 Discovery: T1082 System Information Discovery\n"
    "- TA0008 Lateral Movement: T1021 Remote Services\n"
    "- TA0009 Collection: T1005 Data from Local System\n"
    "- TA0010 Exfiltration: T1048 Exfiltration Over Alternative Protocol\n"
    "- TA0040 Impact: T1486 Data Encrypted for Impact\n"
)


# ---------------------------------------------------------------------------
# LangGraph node
# ---------------------------------------------------------------------------


async def reconstruction_agent(state: AgentState) -> AgentState:
    """
    ReconstructionAgent — LangGraph node.

    Receives TriageAgent output and reconstructs the full attack narrative:
      - Kill chain stages mapped to MITRE ATT&CK tactics/techniques
      - Patient zero identified by earliest timestamp in telemetry
      - Blast radius: all affected IPs and containment priority

    Only runs when classification != UNKNOWN and confidence >= 0.5
    (routing enforced by investigation_graph.py).

    Args:
        state: AgentState populated by TriageAgent.

    Returns:
        Updated AgentState with kill_chain, patient_zero, blast_radius,
        attack_narrative, and reconstruction_confidence populated.
    """
    investigation_id = state.get("investigation_id", "unknown")
    classification = state.get("attack_classification", "UNKNOWN")
    trigger = state.get("trigger", "")
    triage_summary = state.get("triage_summary", "")
    key_indicators = state.get("key_indicators", [])
    top_source_ips = state.get("top_source_ips", [])
    attack_window = state.get("attack_window", {})

    logger.info(
        "[%s] ReconstructionAgent starting | classification=%s",
        investigation_id,
        classification,
    )

    # ── Step 1: Select queries based on classification ───────────────────────
    queries = RECONSTRUCTION_QUERIES.get(classification, FALLBACK_QUERIES)

    # ── Step 2: Run queries in parallel ──────────────────────────────────────
    splunk = get_splunk_client()
    splunk.audit_log.clear()

    async def run_query(spl: str) -> list:
        try:
            return await splunk.run_search(spl) or []
        except Exception as exc:
            logger.warning(
                "[%s] Reconstruction query failed: %.60s | error: %s",
                investigation_id,
                spl,
                exc,
            )
            return []

    logger.info(
        "[%s] Running %d reconstruction queries in parallel",
        investigation_id,
        len(queries),
    )

    query_results: list[list] = await asyncio.gather(
        *[run_query(q) for q in queries]
    )

    logger.info(
        "[%s] Reconstruction telemetry complete | queries=%d",
        investigation_id,
        len(queries),
    )

    # ── Step 3: Build LLM context ─────────────────────────────────────────────
    reconstruction_sections = ""
    for i, (query, result) in enumerate(zip(queries, query_results)):
        reconstruction_sections += (
            f"\nRECONSTRUCTION QUERY [{i + 1}] "
            f"({query[:80].strip()}...):\n"
            f"{json.dumps(result[:20], indent=2)}\n"
        )

    context = f"""
TRIAGE CONTEXT
==============
Investigation ID: {investigation_id}
Trigger: {trigger}
Classification: {classification}
Triage Summary: {triage_summary}
Key Indicators: {json.dumps(key_indicators, indent=2)}
Attack Window: {attack_window.get('start')} to {attack_window.get('end')}
Peak Hour: {attack_window.get('peak_hour')} ({attack_window.get('peak_count', 0):,} events)

TOP SOURCE IPs FROM TRIAGE:
{json.dumps(top_source_ips, indent=2)}

RECONSTRUCTION TELEMETRY (chronological forensic queries):
{reconstruction_sections}

Based on all evidence above, reconstruct the full attack kill chain,
identify patient zero by earliest timestamp, and assess blast radius.
"""

    messages = [
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(content=context),
    ]

    # ── Step 4: LLM call ──────────────────────────────────────────────────────
    try:
        raw: ReconstructionResultRaw = await _LLM_STRUCTURED_RAW.with_config(
            {
                "run_name": "reconstruction_llm_call",
                "metadata": {
                    "investigation_id": investigation_id,
                    "classification": classification,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            }
        ).ainvoke(messages)

        # ── Step 5: Python post-processing & field injection ──────────────────
        
        # Inject missing attack_narrative from kill chain stages if LLM omitted it
        if not raw.attack_narrative or not raw.attack_narrative.strip():
            if raw.kill_chain:
                stages_summary = ", ".join(
                    f"{s.stage_name} ({s.confidence})" 
                    for s in raw.kill_chain[:3]
                )
                raw.attack_narrative = (
                    f"{classification} attack reconstructed with "
                    f"{len(raw.kill_chain)} kill chain stages: {stages_summary}. "
                    f"Patient zero identified as {raw.patient_zero.ip_address if raw.patient_zero else 'unknown'}. "
                    f"Containment priority: {raw.blast_radius.containment_priority if raw.blast_radius else 'HIGH'}."
                )
            else:
                raw.attack_narrative = (
                    f"{classification} attack detected. "
                    f"Insufficient telemetry to reconstruct full kill chain. "
                    f"Manual forensic investigation recommended."
                )
            logger.info(
                "[%s] attack_narrative was missing from LLM output — built from kill chain",
                investigation_id
            )

        # Inject missing reconstruction_confidence
        if raw.reconstruction_confidence is None:
            confirmed_stages = sum(
                1 for s in raw.kill_chain if s.confidence == "CONFIRMED"
            )
            total_stages = len(raw.kill_chain)
            if total_stages > 0:
                raw.reconstruction_confidence = min(
                    0.95,
                    0.5 + (confirmed_stages / total_stages) * 0.45
                )
            else:
                raw.reconstruction_confidence = 0.3
            logger.info(
                "[%s] reconstruction_confidence was missing — computed %.2f from %d/%d confirmed stages",
                investigation_id, raw.reconstruction_confidence, 
                confirmed_stages, total_stages
            )

        # Inject missing patient_zero
        if raw.patient_zero is None:
            # Use the first non-RFC1918 IP from top_source_ips if available
            external_ips = [
                ip for ip in top_source_ips
                if not any(
                    ip.get("ip", "").startswith(prefix)
                    for prefix in ("10.", "192.168.", "172.16.", "172.31.")
                )
            ]
            if external_ips:
                raw.patient_zero = PatientZero(
                    ip_address=external_ips[0]["ip"],
                    first_seen=attack_window.get("start", "unknown"),
                    role="External Attacker",
                    evidence=f"Highest event count external IP from triage telemetry: {external_ips[0]['event_count']} events",
                    confidence="INFERRED",
                )
            else:
                top_ip = top_source_ips[0] if top_source_ips else {}
                raw.patient_zero = PatientZero(
                    ip_address=top_ip.get("ip", "unknown"),
                    first_seen=attack_window.get("start", "unknown"),
                    role="Compromised Internal Host",
                    evidence=f"Highest activity internal IP: {top_ip.get('event_count', 0)} events",
                    confidence="INFERRED",
                )
            logger.info("[%s] patient_zero was missing — injected from triage telemetry", investigation_id)

        # Inject missing blast_radius
        if raw.blast_radius is None:
            all_ips = [ip.get("ip", "") for ip in top_source_ips]
            internal = [
                ip for ip in all_ips
                if any(ip.startswith(p) for p in ("10.", "192.168.", "172."))
            ]
            external = [ip for ip in all_ips if ip not in internal]
            raw.blast_radius = BlastRadius(
                total_affected_ips=len(all_ips),
                internal_ips_affected=internal,
                external_ips_observed=external,
                affected_sourcetypes=["WinEventLog:Security", "stream:http", "stream:dns"],
                data_at_risk="Assessment incomplete — manual review required",
                containment_priority="HIGH",
            )
            logger.info("[%s] blast_radius was missing — injected from triage telemetry", investigation_id)

        # Now validate into strict model
        result = ReconstructionResult(
            kill_chain=raw.kill_chain if raw.kill_chain else [],
            patient_zero=raw.patient_zero,
            blast_radius=raw.blast_radius,
            attack_narrative=raw.attack_narrative,
            reconstruction_confidence=raw.reconstruction_confidence,
        )

        # ── Step 6: Handle empty kill_chain gracefully ────────────────────────
        if not result.kill_chain:
            result.kill_chain = [
                KillChainStage(
                    stage_number=1,
                    stage_name="Unknown Initial Stage",
                    mitre_tactic="TA0001",
                    mitre_technique="T1190 - Exploit Public-Facing Application",
                    timestamp=attack_window.get("start", "unknown"),
                    evidence=(
                        f"Classification: {classification}. "
                        f"Triage summary: {triage_summary[:200]}. "
                        f"Full forensic reconstruction requires manual analysis."
                    ),
                    confidence="INFERRED",
                    affected_assets=[ip.get("ip", "") for ip in top_source_ips[:3]],
                )
            ]
            logger.warning(
                "[%s] kill_chain was empty after LLM call — inserted synthetic INFERRED stage",
                investigation_id,
            )

    except Exception as exc:
        logger.error(
            "[%s] ReconstructionAgent LLM call failed: %s",
            investigation_id,
            exc,
        )
        return {
            **state,
            "error": f"ReconstructionAgent: LLM call failed — {exc}",
            "escalate_to_human": True,
            "spl_audit_log": list(state.get("spl_audit_log", [])) + splunk.audit_log,
        }

    # ── Step 7: Post-processing guardrails ────────────────────────────────────
    # Cap reconstruction confidence at 0.95
    if result.reconstruction_confidence > 0.95:
        result.reconstruction_confidence = 0.95

    # Force IMMEDIATE containment for confirmed CRITICAL attacks
    severity = state.get("severity", "")
    if severity == "CRITICAL" and any(
        s.confidence == "CONFIRMED" for s in result.kill_chain
    ):
        result.blast_radius.containment_priority = "IMMEDIATE"
        logger.info(
            "[%s] CRITICAL severity with CONFIRMED stages — "
            "forcing containment_priority=IMMEDIATE",
            investigation_id,
        )

    logger.info(
        "[%s] ReconstructionAgent complete | stages=%d | patient_zero=%s | "
        "containment=%s | confidence=%.2f",
        investigation_id,
        len(result.kill_chain),
        result.patient_zero.ip_address,
        result.blast_radius.containment_priority,
        result.reconstruction_confidence,
    )

    # ── Step 6: Update audit log and state ────────────────────────────────────
    updated_audit = list(state.get("spl_audit_log", [])) + splunk.audit_log

    return {
        **state,
        "kill_chain": [stage.model_dump() for stage in result.kill_chain],
        "patient_zero": result.patient_zero.model_dump(),
        "blast_radius": result.blast_radius.model_dump(),
        "attack_narrative": result.attack_narrative,
        "reconstruction_confidence": result.reconstruction_confidence,
        "spl_audit_log": updated_audit,
        "error": None,
    }
