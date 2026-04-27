"""
reconstruction_agent.py
-----------------------
LangGraph node — ReconstructionAgent (ReAct Mode).

This agent implements a Reasoning + Acting (ReAct) loop to iteratively
reconstruct the attack timeline. It generates follow-up SPL queries
based on previous findings, self-corrects broken queries, and
produces a synthesized final report.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Literal, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from app.models.state import AgentState
from app.tools.splunk_tools import get_splunk_client, SplunkClient
from app.guardrails.spl_guardrail import SPLGuardrail

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class KillChainStage(BaseModel):
    stage_number: int
    stage_name: str
    mitre_tactic: str   # e.g. "TA0001"
    mitre_technique: str  # e.g. "T1190 - Exploit Public-Facing Application"
    timestamp: str
    evidence: str  # MUST cite specific IP, EventCode+count, process name, or URI
    confidence: Literal["CONFIRMED", "INFERRED"]
    affected_assets: list[str]

class PatientZero(BaseModel):
    ip_address: str
    first_seen: str
    role: str  # "External Attacker" or "Compromised Internal Host"
    evidence: str
    confidence: Literal["CONFIRMED", "INFERRED"]

class BlastRadius(BaseModel):
    total_affected_ips: int
    internal_ips_affected: list[str]
    external_ips_observed: list[str]
    affected_sourcetypes: list[str]
    data_at_risk: str  # specific systems/data named, not generic
    containment_priority: Literal["IMMEDIATE", "HIGH", "MEDIUM", "LOW"]

class ReconstructionResultRaw(BaseModel):
    """Relaxed model — all fields optional to handle gpt-4o-mini dropping fields."""
    kill_chain: list[KillChainStage] = Field(default_factory=list)
    patient_zero: Optional[PatientZero] = None
    blast_radius: Optional[BlastRadius] = None
    attack_narrative: Optional[str] = None
    reconstruction_confidence: Optional[float] = None

class ReconstructionResult(BaseModel):
    kill_chain: list[KillChainStage] = Field(min_length=1)
    patient_zero: PatientZero
    blast_radius: BlastRadius
    attack_narrative: str
    reconstruction_confidence: float = Field(ge=0.0, le=1.0)

class ReActObservation(BaseModel):
    """What the agent learned from executing queries in one iteration."""
    iteration: int
    findings: str  # plain English: what do the results show?
    new_stages_identified: list[str]  # stage names found this iteration
    gaps_remaining: list[str]  # what is still unknown
    recommended_next_queries: list[str]  # raw SPL for next iteration (1-3)
    current_confidence: float = Field(ge=0.0, le=1.0)
    should_terminate: bool

# ---------------------------------------------------------------------------
# Seed Queries
# ---------------------------------------------------------------------------

SEED_QUERIES: dict[str, list[str]] = {
    "APT": [
        # External HTTP access — who hit what first and when
        (
            'index=botsv3 earliest=0 sourcetype=stream:http '
            '| where NOT match(src_ip, "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)")'
            '| eval time=strftime(_time, "%Y-%m-%d %H:%M:%S")'
            '| table time, src_ip, dest_ip, uri_path, http_method'
            '| sort time | head 20'
        ),
        # AWS metadata service access timeline
        (
            'index=botsv3 earliest=0 sourcetype=stream:http dest_ip=169.254.169.254 '
            '| eval time=strftime(_time, "%Y-%m-%d %H:%M:%S")'
            '| table time, src_ip, uri_path '
            '| sort time | head 20'
        ),
        # Process execution timeline
        (
            'index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=4688 '
            '| eval time=strftime(_time, "%Y-%m-%d %H:%M:%S")'
            '| table time, New_Process_Name, Creator_Process_Name, ComputerName'
            '| sort time | head 20'
        ),
    ],
    "RANSOMWARE": [
        # Process execution chain
        (
            'index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=4688 '
            '| eval time=strftime(_time, "%Y-%m-%d %H:%M:%S")'
            '| table time, New_Process_Name, Creator_Process_Name, ComputerName'
            '| sort time | head 30'
        ),
        # Network connections during execution
        (
            'index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=5156 '
            '| eval time=strftime(_time, "%Y-%m-%d %H:%M:%S")'
            '| table time, src_ip, dest_ip '
            '| sort time | head 20'
        ),
        # File and object access
        (
            'index=botsv3 earliest=0 sourcetype=WinEventLog:Security '
            '(EventCode=4663 OR EventCode=4659 OR EventCode=4670) '
            '| eval time=strftime(_time, "%Y-%m-%d %H:%M:%S")'
            '| table time, EventCode, Object_Name, Account_Name'
            '| sort time | head 20'
        ),
    ],
    "INSIDER_THREAT": [
        # Account activity timeline
        (
            'index=botsv3 earliest=0 sourcetype=WinEventLog:Security '
            '(EventCode=4624 OR EventCode=4672 OR EventCode=4673) '
            '| eval time=strftime(_time, "%Y-%m-%d %H:%M:%S")'
            '| table time, EventCode, Account_Name, ComputerName'
            '| sort time | head 30'
        ),
        # Object access and permission changes
        (
            'index=botsv3 earliest=0 sourcetype=WinEventLog:Security '
            '(EventCode=4670 OR EventCode=4663) '
            '| eval time=strftime(_time, "%Y-%m-%d %H:%M:%S")'
            '| table time, EventCode, Object_Name, Account_Name'
            '| sort time | head 20'
        ),
        # Process execution by internal accounts
        (
            'index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=4688 '
            '| eval time=strftime(_time, "%Y-%m-%d %H:%M:%S")'
            '| table time, New_Process_Name, Creator_Process_Name, Account_Name'
            '| sort time | head 20'
        ),
    ],
    "BRUTE_FORCE": [
        (
            'index=botsv3 earliest=0 sourcetype=WinEventLog:Security '
            '(EventCode=4625 OR EventCode=4624) '
            '| eval time=strftime(_time, "%Y-%m-%d %H:%M:%S")'
            '| table time, EventCode, Account_Name, src_ip, ComputerName'
            '| sort time | head 30'
        ),
    ],
}
SEED_QUERIES["UNKNOWN"] = SEED_QUERIES["APT"]

# ---------------------------------------------------------------------------
# LLM Setup
# ---------------------------------------------------------------------------

_REASONING_LLM = ChatOpenAI(model="gpt-4o-mini", temperature=0.2, max_tokens=600)
_REASONING_STRUCTURED = _REASONING_LLM.with_structured_output(ReActObservation)

_SYNTHESIS_LLM = ChatOpenAI(model="gpt-4o-mini", temperature=0)
_SYNTHESIS_STRUCTURED = _SYNTHESIS_LLM.with_structured_output(ReconstructionResultRaw)

# ---------------------------------------------------------------------------
# System Prompts
# ---------------------------------------------------------------------------

_REASONING_SYSTEM_PROMPT = """You are a senior threat intelligence 
analyst performing iterative forensic reconstruction of a cyber attack.

Each iteration you receive:
1. The attack classification and trigger from the triage agent
2. Kill chain stages already identified in previous iterations
3. Telemetry results from queries executed this iteration
4. What gaps remain

Your job each iteration:
1. REASON: What do the results show? What attack stages are confirmed?
   What causal relationships can you establish between events?
2. IDENTIFY: List any new kill chain stages found this iteration by name
3. ACT: Generate 1-3 precise SPL queries to fill the most critical 
   remaining gaps. Do not repeat already-executed queries.
4. ASSESS: Update confidence based on evidence strength
5. DECIDE: Should you terminate?

SPL QUERY GENERATION RULES (STRICT):
- Every query MUST start with: index=botsv3 earliest=0
- Every query MUST include timestamp: 
  | eval time=strftime(_time, "%Y-%m-%d %H:%M:%S")
- Every query MUST end with: | sort time | head 20
- Use specific IPs, EventCodes, and hostnames from previous results
- Never repeat a query already executed
- If a query returned 0 rows, query something different
- Focus on establishing CAUSAL RELATIONSHIPS and TIMESTAMPS

KILL CHAIN STAGE RULES:
- CONFIRMED: direct telemetry evidence — specific timestamp, IP, 
  EventCode, URI, or process name
- INFERRED: logically deduced but no direct evidence
- New stage names must map to MITRE ATT&CK tactics

TERMINATION — set should_terminate=True if ANY:
- current_confidence >= 0.85
- No new stages found AND iteration >= 3
- gaps_remaining is empty
- Patient zero identified AND blast radius clear AND >= 4 confirmed stages

MITRE ATT&CK REFERENCE:
TA0001 Initial Access | TA0002 Execution | TA0003 Persistence
TA0004 Privilege Escalation | TA0005 Defense Evasion
TA0006 Credential Access | TA0007 Discovery | TA0008 Lateral Movement  
TA0009 Collection | TA0010 Exfiltration | TA0040 Impact
"""

_SYNTHESIS_SYSTEM_PROMPT = """You are producing the final forensic 
reconstruction report from a completed ReAct investigation loop.

Produce a ReconstructionResult with:

kill_chain: Chronological list of confirmed and inferred attack stages.
Each stage evidence field MUST cite at minimum ONE specific data point:
- A specific IP address with timestamp
- An EventCode with count (e.g. "EventCode 4688: WMIC.exe 536 times")
- A specific process name spawning sequence
- A specific URI path accessed
Generic statements like "suspicious activity detected" are REJECTED.

patient_zero: The EARLIEST external IP or compromised host by TIMESTAMP.
- External IP (non-RFC1918) seen in stream:http or stream:dns = 
  role "External Attacker"
- All RFC1918 IPs = role "Compromised Internal Host" — use earliest 
  anomalous activity timestamp
- Never assign patient zero by event count alone — use timestamp

blast_radius: Every unique IP from all telemetry.
- containment_priority MUST be IMMEDIATE for APT or RANSOMWARE
- data_at_risk must name specific systems and data types:
  GOOD: "IAM credentials via AWS metadata service 169.254.169.254, 
         EC2 instance role EC2InstanceRole exfiltrated"
  BAD:  "data may be at risk"

attack_narrative: 2-3 sentences. Must include: attack type, initial 
vector with specific evidence, what was compromised, immediate action.

reconstruction_confidence: Set to 0.75 as placeholder — Python will 
overwrite this with the deterministic formula.

CRITICAL: Only use evidence present in the telemetry provided.
Do not hallucinate events, IPs, or timestamps not in the data.
"""

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def compute_reconstruction_confidence(
    confirmed_stages: int,
    total_stages: int,
    sourcetypes_covered: set[str],
    has_patient_zero: bool,
    has_blast_radius: bool,
    has_external_ip: bool,
) -> float:
    score = 0.0
    # Evidence breadth: sourcetype diversity (max 0.30)
    score += min(len(sourcetypes_covered) * 0.075, 0.30)
    # Kill chain completeness (max 0.35)
    if total_stages > 0:
        score += (confirmed_stages / total_stages) * 0.35
    # Attribution (max 0.20)
    if has_patient_zero:
        score += 0.10
    if has_external_ip:
        score += 0.10
    # Blast radius assessed (max 0.15)
    if has_blast_radius:
        score += 0.15
    return round(min(score, 0.95), 3)


def correct_patient_zero_role(patient_zero: PatientZero) -> PatientZero:
    """
    Ensures RFC1918 IP addresses are never classified as External Attacker.
    Returns corrected PatientZero object.
    """
    RFC1918_PREFIXES = (
        "10.", "192.168.",
        "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
        "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    )
    is_internal = any(
        patient_zero.ip_address.startswith(p) for p in RFC1918_PREFIXES
    )
    if is_internal and patient_zero.role == "External Attacker":
        patient_zero.role = "Compromised Internal Host"
    return patient_zero


def apply_containment_guardrail(
    blast_radius: BlastRadius,
    kill_chain: list[KillChainStage],
    severity: str,
) -> BlastRadius:
    """
    Forces IMMEDIATE containment for CRITICAL severity attacks 
    with at least one CONFIRMED kill chain stage.
    """
    if (
        severity == "CRITICAL"
        and any(s.confidence == "CONFIRMED" for s in kill_chain)
    ):
        blast_radius.containment_priority = "IMMEDIATE"
    return blast_radius


def _infer_sourcetypes_from_spl(spl: str) -> set[str]:
    """
    Extract sourcetype names from SPL query string.
    Used to populate sourcetypes_seen when result rows 
    don't include a sourcetype field.
    """
    import re
    sourcetypes = set()

    # Match sourcetype=value patterns
    matches = re.findall(
        r'sourcetype\s*=\s*([^\s|)\]]+)', spl, re.IGNORECASE
    )
    for match in matches:
        # Clean quotes if present
        sourcetypes.add(match.strip('"\''))

    # Also infer from known patterns
    if 'stream:http' in spl:
        sourcetypes.add('stream:http')
    if 'stream:dns' in spl:
        sourcetypes.add('stream:dns')
    if 'WinEventLog:Security' in spl:
        sourcetypes.add('WinEventLog:Security')
    if 'stream:tcp' in spl:
        sourcetypes.add('stream:tcp')
    if 'osquery' in spl:
        sourcetypes.add('osquery:results')

    return sourcetypes

_MAX_CONSECUTIVE_ERRORS = 3
_MAX_SPL_RETRIES = 2

async def _execute_query_with_retry(
    splunk: SplunkClient,
    guardrail: SPLGuardrail,
    spl: str,
    investigation_id: str,
) -> tuple[list, str]:
    """
    Execute SPL query with guardrail validation and self-correction.
    Returns (results, final_spl_executed).
    On failure: LLM rewrites the broken query (max 2 retries).
    """
    current_spl = spl.strip()
    if not current_spl.lower().startswith("search ") and \
       not current_spl.lower().startswith("index="):
        current_spl = f"search {current_spl}"

    for attempt in range(_MAX_SPL_RETRIES + 1):
        validation = guardrail.validate(current_spl)
        if validation.is_blocked:
            logger.warning(
                "[%s] SPL blocked (attempt %d): %s | reason: %s",
                investigation_id, attempt + 1,
                current_spl[:60], validation.reason
            )
            return [], current_spl

        guardrail.audit(current_spl)
        splunk.audit_log.append(
            f"[{datetime.now(timezone.utc).isoformat()}] {current_spl}"
        )

        try:
            results = await splunk.run_search(current_spl)
            if results is not None:
                logger.info(
                    "[%s] Query returned %d rows | spl=%s",
                    investigation_id, len(results), current_spl[:60]
                )
                return results, current_spl
        except Exception as e:
            logger.warning(
                "[%s] SPL execution failed (attempt %d): %s | error: %s",
                investigation_id, attempt + 1, current_spl[:60], e
            )
            if attempt < _MAX_SPL_RETRIES:
                try:
                    fix_prompt = (
                        f"This SPL query failed with error: {e}\n\n"
                        f"Broken query:\n{current_spl}\n\n"
                        f"Rewrite it to fix the error. Rules:\n"
                        f"- Must start with: index=botsv3 earliest=0\n"
                        f"- Must be valid Splunk SPL syntax\n"
                        f"- Must include: "
                        f"| eval time=strftime(_time, \"%Y-%m-%d %H:%M:%S\")\n"
                        f"- Must end with: | sort time | head 20\n"
                        f"Return ONLY the corrected SPL, nothing else."
                    )
                    correction = await _REASONING_LLM.ainvoke([
                        HumanMessage(content=fix_prompt)
                    ])
                    current_spl = correction.content.strip()
                    logger.info(
                        "[%s] SPL self-corrected (attempt %d): %s",
                        investigation_id, attempt + 1, current_spl[:60]
                    )
                except Exception as ce:
                    logger.error(
                        "[%s] SPL self-correction failed: %s",
                        investigation_id, ce
                    )
                    break

    return [], current_spl

# ---------------------------------------------------------------------------
# Main ReAct Agent Function
# ---------------------------------------------------------------------------

async def reconstruction_agent(
    state: AgentState, 
    progress_callback=None
) -> AgentState:
    investigation_id = state.get("investigation_id", "unknown")
    classification = state.get("attack_classification", "UNKNOWN")
    trigger = state.get("trigger", "")
    triage_summary = state.get("triage_summary", "")
    key_indicators = state.get("key_indicators", [])
    top_source_ips = state.get("top_source_ips", [])
    attack_window = state.get("attack_window", {})

    logger.info(
        "[%s] ReconstructionAgent starting | classification=%s | "
        "mode=ReAct | max_iterations=8",
        investigation_id, classification
    )

    splunk = get_splunk_client()
    splunk.audit_log.clear()
    guardrail = SPLGuardrail()

    # ── ReAct loop state ─────────────────────────────────────────────────
    all_telemetry: dict[str, list] = {}
    accumulated_stage_names: list[str] = []
    react_history: list[dict] = []
    executed_queries: set[str] = set()
    consecutive_errors: int = 0
    current_confidence: float = 0.0
    sourcetypes_seen: set[str] = set()
    iteration: int = 0

    # ── ReAct Loop ────────────────────────────────────────────────────────
    while iteration < 8:
        iteration += 1
        logger.info(
            "[%s] ReAct iteration %d/8 | confidence=%.2f | stages=%d",
            investigation_id, iteration,
            current_confidence, len(accumulated_stage_names)
        )

        # Select queries for this iteration
        if iteration == 1:
            queries_this_iter = [
                q for q in SEED_QUERIES.get(
                    classification, SEED_QUERIES["UNKNOWN"]
                )
                if q not in executed_queries
            ]
        else:
            if react_history:
                last_obs = react_history[-1].get("observation", {})
                queries_this_iter = [
                    q for q in last_obs.get(
                        "recommended_next_queries", []
                    )
                    if q not in executed_queries
                ][:3]
            else:
                queries_this_iter = []

        if not queries_this_iter:
            logger.info(
                "[%s] No new queries for iteration %d — terminating",
                investigation_id, iteration
            )
            break

        # Execute queries in parallel
        query_tasks = [
            _execute_query_with_retry(
                splunk, guardrail, q, investigation_id
            )
            for q in queries_this_iter
        ]
        query_outputs = await asyncio.gather(
            *query_tasks, return_exceptions=True
        )

        iteration_results: dict[str, list] = {}
        iteration_errors = 0

        for q, output in zip(queries_this_iter, query_outputs):
            executed_queries.add(q)
            if isinstance(output, Exception):
                logger.warning(
                    "[%s] Query failed: %s | error: %s",
                    investigation_id, q[:60], output
                )
                iteration_errors += 1
                iteration_results[q] = []
            else:
                results, final_spl = output
                iteration_results[final_spl] = results
                all_telemetry[final_spl] = results

                # Infer sourcetypes from SPL string (primary method)
                sourcetypes_seen.update(_infer_sourcetypes_from_spl(final_spl))

                # Also check result rows (secondary method)
                for row in results:
                    if "sourcetype" in row:
                        sourcetypes_seen.add(row["sourcetype"])

        if iteration_errors == len(queries_this_iter):
            consecutive_errors += 1
        else:
            consecutive_errors = 0

        if consecutive_errors >= _MAX_CONSECUTIVE_ERRORS:
            logger.error(
                "[%s] %d consecutive error iterations — aborting loop",
                investigation_id, consecutive_errors
            )
            break

        # Build telemetry summary for reasoning step
        telemetry_summary = ""
        for spl_str, results in iteration_results.items():
            telemetry_summary += (
                f"\nQUERY: {spl_str[:100]}...\n"
                f"ROWS RETURNED: {len(results)}\n"
                f"SAMPLE (first 5 rows):\n"
                f"{json.dumps(results[:5], indent=2)}\n"
            )

        reasoning_context = f"""
INVESTIGATION CONTEXT
=====================
Investigation ID: {investigation_id}
Classification: {classification}
Trigger: {trigger}
Triage Summary: {triage_summary}
Attack Window: {attack_window.get('start')} to {attack_window.get('end')}

TRIAGE KEY INDICATORS:
{json.dumps(key_indicators, indent=2)}

TOP SOURCE IPs:
{json.dumps(top_source_ips[:5], indent=2)}

CURRENT ITERATION: {iteration}/8
CURRENT CONFIDENCE: {current_confidence:.2f}
STAGES FOUND SO FAR: {json.dumps(accumulated_stage_names, indent=2)}

QUERIES ALREADY EXECUTED (DO NOT REPEAT):
{json.dumps(list(executed_queries - set(queries_this_iter)), indent=2)}

TELEMETRY FROM THIS ITERATION:
{telemetry_summary}
"""

        try:
            observation: ReActObservation = await \
                _REASONING_STRUCTURED.with_config({
                    "run_name": f"react_reasoning_iter_{iteration}",
                    "metadata": {
                        "investigation_id": investigation_id,
                        "iteration": iteration,
                    }
                }).ainvoke([
                    SystemMessage(content=_REASONING_SYSTEM_PROMPT),
                    HumanMessage(content=reasoning_context),
                ])

            # Add newly identified stages
            for stage_name in observation.new_stages_identified:
                if stage_name not in accumulated_stage_names:
                    accumulated_stage_names.append(stage_name)

            react_history.append({
                "iteration": iteration,
                "queries": queries_this_iter,
                "telemetry_rows": {
                    q: len(r) for q, r in iteration_results.items()
                },
                "observation": observation.model_dump(),
            })

            # Update confidence using deterministic formula
            confirmed_count = len(accumulated_stage_names)
            current_confidence = compute_reconstruction_confidence(
                confirmed_stages=confirmed_count,
                total_stages=max(confirmed_count, 1),
                sourcetypes_covered=sourcetypes_seen,
                has_patient_zero=any(
                    "Initial Access" in s or "patient" in s.lower()
                    for s in accumulated_stage_names
                ),
                has_blast_radius=len(all_telemetry) > 2,
                has_external_ip=any(
                    not any(
                        ip.get("ip", "").startswith(p)
                        for p in ("10.", "192.168.", "172.")
                    )
                    for ip in top_source_ips
                ),
            )

            # Always emit progress — show activity even when no new stages found
            if progress_callback:
                await progress_callback({
                    "event": "reconstruction_progress",
                    "iteration": iteration,
                    "new_stages": observation.new_stages_identified,
                    "confidence": round(current_confidence, 2),
                    "gaps_remaining": len(observation.gaps_remaining),
                    "total_stages_found": len(accumulated_stage_names),
                })

            logger.info(
                "[%s] Iteration %d | new_stages=%d | "
                "confidence=%.2f | terminate=%s | gaps=%d",
                investigation_id, iteration,
                len(observation.new_stages_identified),
                current_confidence,
                observation.should_terminate,
                len(observation.gaps_remaining),
            )

            # Check termination conditions
            if observation.should_terminate:
                logger.info(
                    "[%s] ReAct terminating — LLM requested termination",
                    investigation_id
                )
                break

            if current_confidence >= 0.85:
                logger.info(
                    "[%s] ReAct terminating — confidence %.2f >= 0.85",
                    investigation_id, current_confidence
                )
                break

            if len(accumulated_stage_names) >= 5:
                logger.info(
                    "[%s] ReAct terminating — %d stages identified",
                    investigation_id, len(accumulated_stage_names)
                )
                break

        except Exception as reasoning_exc:
            logger.error(
                "[%s] Reasoning step failed at iteration %d: %s",
                investigation_id, iteration, reasoning_exc
            )
            consecutive_errors += 1
            if consecutive_errors >= _MAX_CONSECUTIVE_ERRORS:
                break

    logger.info(
        "[%s] ReAct loop complete | iterations=%d | confidence=%.2f | "
        "total_queries=%d | stages_found=%d",
        investigation_id, iteration, current_confidence,
        len(executed_queries), len(accumulated_stage_names),
    )

    # ── Synthesis: single LLM call to produce final structured output ─────
    full_telemetry_summary = ""
    for spl_str, results in all_telemetry.items():
        full_telemetry_summary += (
            f"\nQUERY: {spl_str[:100]}...\n"
            f"ROWS: {len(results)}\n"
            f"{json.dumps(results[:10], indent=2)}\n"
        )

    react_summary = json.dumps([
        {
            "iteration": h["iteration"],
            "queries_run": len(h["queries"]),
            "findings": h["observation"].get("findings", ""),
            "new_stages": h["observation"].get(
                "new_stages_identified", []
            ),
            "confidence": h["observation"].get("current_confidence", 0),
        }
        for h in react_history
    ], indent=2)

    synthesis_context = f"""
INVESTIGATION COMPLETE — PRODUCE FINAL REPORT
==============================================
Investigation ID: {investigation_id}
Classification: {classification}
Trigger: {trigger}
Attack Window: {attack_window.get('start')} to {attack_window.get('end')}
ReAct Iterations Completed: {iteration}
Final Confidence: {current_confidence:.2f}

TRIAGE KEY INDICATORS:
{json.dumps(key_indicators, indent=2)}

TOP SOURCE IPs FROM TRIAGE:
{json.dumps(top_source_ips, indent=2)}

REACT INVESTIGATION HISTORY:
{react_summary}

COMPLETE TELEMETRY EVIDENCE 
({len(all_telemetry)} queries, 
{sum(len(r) for r in all_telemetry.values())} total rows):
{full_telemetry_summary}

Produce the final ReconstructionResult using ONLY evidence from 
the telemetry above. Do not hallucinate events not in the data.
"""

    try:
        raw: ReconstructionResultRaw = await \
            _SYNTHESIS_STRUCTURED.with_config({
                "run_name": "reconstruction_synthesis",
                "metadata": {
                    "investigation_id": investigation_id,
                    "iterations_completed": iteration,
                    "final_confidence": current_confidence,
                }
            }).ainvoke([
                SystemMessage(content=_SYNTHESIS_SYSTEM_PROMPT),
                HumanMessage(content=synthesis_context),
            ])

    except Exception as synthesis_exc:
        logger.error(
            "[%s] Synthesis LLM call failed: %s",
            investigation_id, synthesis_exc
        )
        return {
            **state,
            "error": f"ReconstructionAgent synthesis failed: {synthesis_exc}",
            "escalate_to_human": True,
            "spl_audit_log": list(
                state.get("spl_audit_log", [])
            ) + splunk.audit_log,
        }

    # ── Field injection — gpt-4o-mini drops fields on complex schemas ──────
    if not raw.attack_narrative or not raw.attack_narrative.strip():
        stages_summary = ", ".join(
            f"{s.stage_name} ({s.confidence})"
            for s in (raw.kill_chain or [])[:3]
        )
        pz_ip = raw.patient_zero.ip_address \
            if raw.patient_zero else "unknown"
        cp = raw.blast_radius.containment_priority \
            if raw.blast_radius else "IMMEDIATE"
        raw.attack_narrative = (
            f"{classification} attack reconstructed over {iteration} "
            f"ReAct iterations with {len(raw.kill_chain or [])} kill "
            f"chain stages: {stages_summary}. "
            f"Patient zero: {pz_ip}. "
            f"Containment priority: {cp}."
        )
        logger.info(
            "[%s] attack_narrative injected from kill chain",
            investigation_id
        )

    # Always override confidence with deterministic formula
    confirmed_final = sum(
        1 for s in (raw.kill_chain or [])
        if s.confidence == "CONFIRMED"
    )
    raw.reconstruction_confidence = compute_reconstruction_confidence(
        confirmed_stages=confirmed_final,
        total_stages=len(raw.kill_chain or []),
        sourcetypes_covered=sourcetypes_seen,
        has_patient_zero=raw.patient_zero is not None,
        has_blast_radius=raw.blast_radius is not None,
        has_external_ip=any(
            not any(
                ip.get("ip", "").startswith(p)
                for p in ("10.", "192.168.", "172.")
            )
            for ip in top_source_ips
        ),
    )

    if raw.patient_zero is None:
        external = [
            ip for ip in top_source_ips
            if not any(
                ip.get("ip", "").startswith(p)
                for p in ("10.", "192.168.", "172.")
            )
        ]
        if external:
            raw.patient_zero = PatientZero(
                ip_address=external[0]["ip"],
                first_seen=attack_window.get("start", "unknown"),
                role="External Attacker",
                evidence=(
                    f"External IP from triage telemetry: "
                    f"{external[0].get('event_count', 0)} events"
                ),
                confidence="INFERRED"
            )
        else:
            top = top_source_ips[0] if top_source_ips else {}
            raw.patient_zero = PatientZero(
                ip_address=top.get("ip", "unknown"),
                first_seen=attack_window.get("start", "unknown"),
                role="Compromised Internal Host",
                evidence=(
                    f"Highest activity internal host: "
                    f"{top.get('event_count', 0)} events"
                ),
                confidence="INFERRED"
            )

    if raw.blast_radius is None:
        all_ips = [ip.get("ip", "") for ip in top_source_ips]
        internal = [
            ip for ip in all_ips
            if any(ip.startswith(p) for p in ("10.", "192.168.", "172."))
        ]
        external_ips = [ip for ip in all_ips if ip not in internal]
        raw.blast_radius = BlastRadius(
            total_affected_ips=len(all_ips),
            internal_ips_affected=internal,
            external_ips_observed=external_ips,
            affected_sourcetypes=list(sourcetypes_seen) or [
                "WinEventLog:Security", "stream:http", "stream:dns"
            ],
            data_at_risk="Assessment incomplete — manual review required",
            containment_priority="HIGH"
        )

    if not raw.kill_chain:
        raw.kill_chain = [
            KillChainStage(
                stage_number=1,
                stage_name="Unknown Initial Stage",
                mitre_tactic="TA0001",
                mitre_technique="T1190 - Exploit Public-Facing Application",
                timestamp=attack_window.get("start", "unknown"),
                evidence=(
                    f"Classification: {classification}. "
                    f"Triage: {triage_summary[:200]}. "
                    f"Manual analysis required."
                ),
                confidence="INFERRED",
                affected_assets=[
                    ip.get("ip", "") for ip in top_source_ips[:3]
                ]
            )
        ]

    if raw.patient_zero:
        raw.patient_zero = correct_patient_zero_role(raw.patient_zero)

    raw.blast_radius = apply_containment_guardrail(
        raw.blast_radius, raw.kill_chain, state.get("severity", "")
    )

    # Build final validated result
    result = ReconstructionResult(
        kill_chain=raw.kill_chain,
        patient_zero=raw.patient_zero,
        blast_radius=raw.blast_radius,
        attack_narrative=raw.attack_narrative,
        reconstruction_confidence=raw.reconstruction_confidence,
    )

    logger.info(
        "[%s] ReconstructionAgent complete | stages=%d | confirmed=%d | "
        "patient_zero=%s (%s) | containment=%s | confidence=%.2f | "
        "iterations=%d | queries=%d",
        investigation_id,
        len(result.kill_chain),
        sum(1 for s in result.kill_chain if s.confidence == "CONFIRMED"),
        result.patient_zero.ip_address,
        result.patient_zero.role,
        result.blast_radius.containment_priority,
        result.reconstruction_confidence,
        iteration,
        len(executed_queries),
    )

    updated_audit = list(
        state.get("spl_audit_log", [])
    ) + splunk.audit_log

    return {
        **state,
        "kill_chain": [s.model_dump() for s in result.kill_chain],
        "patient_zero": result.patient_zero.model_dump(),
        "blast_radius": result.blast_radius.model_dump(),
        "attack_narrative": result.attack_narrative,
        "reconstruction_confidence": result.reconstruction_confidence,
        "react_iterations": iteration,
        "spl_audit_log": updated_audit,
        "error": None,
    }
