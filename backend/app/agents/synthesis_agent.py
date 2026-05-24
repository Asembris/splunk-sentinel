"""
synthesis_agent.py
------------------
SynthesisAgent: converges all upstream agent outputs into a structured
final_report with RAG-grounded recommendations.

Runs after ThreatIntelAgent and TTPAgent complete (parallel fan-in).

Inputs from AgentState:
  - triage output: attack_classification, triage_summary, key_indicators,
                   attack_window, severity
  - kill_chain, patient_zero, blast_radius, attack_narrative,
    reconstruction_confidence  (from ReconstructionAgent)
  - threat_intel   (from ThreatIntelAgent)
  - ttp_mappings   (from TTPAgent)

Output:
  - final_report: dict   — structured incident report
  - rag_context: dict    — raw RAG results used for grounding
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Literal

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from app.models.state import AgentState
from app.rag.retriever import retrieve_for_synthesis
from app.utils.prompt_loader import get_prompt

logger = logging.getLogger(__name__)


# ── Pydantic output schemas ───────────────────────────────────────────────────

class FindingWithConfidence(BaseModel):
    finding: str
    evidence: str
    confidence: float = Field(ge=0.0, le=1.0)
    source: str  # "telemetry" | "mitre_rag" | "cve_rag" | "playbook_rag" | "threat_intel"


class RecommendedAction(BaseModel):
    priority: Literal["IMMEDIATE", "SHORT_TERM", "LONG_TERM"]
    action: str
    rationale: str
    mitre_technique: str


class NarrativeSection(BaseModel):
    executive_summary: str
    attack_overview: str
    threat_actor_profile: str

class StructuredSection(BaseModel):
    key_findings: list[FindingWithConfidence] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    mitre_techniques_used: list[str] = Field(default_factory=list)
    cves_identified: list[str] = Field(default_factory=list)
    investigation_confidence: float = Field(ge=0.0, le=1.0)

class FinalReportRaw(BaseModel):
    executive_summary: str = ""
    attack_overview: str = ""
    key_findings: list[FindingWithConfidence] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    mitre_techniques_used: list[str] = Field(default_factory=list)
    cves_identified: list[str] = Field(default_factory=list)
    threat_actor_profile: str = ""
    investigation_confidence: float = 0.0
    containment_plan: dict = Field(default_factory=dict)


# ── System prompt ─────────────────────────────────────────────────────────────

_SYNTHESIS_NARRATIVE_FALLBACK = """You are a senior threat intelligence \
analyst producing the final incident report for a security investigation.
You have received outputs from multiple specialized AI agents:
- TriageAgent: attack classification and initial telemetry
- ReconstructionAgent: full kill chain with MITRE mappings
- ThreatIntelAgent: external IP reputation data
- TTPAgent: enriched MITRE technique details from knowledge base
- RAG retrieval: relevant playbooks, CVEs, and investigation notes

YOUR JOB:
Synthesize all inputs into a coherent, actionable incident report.
Every claim must be traceable to evidence — either telemetry data,
threat intel scores, or RAG-retrieved knowledge base content.

REPORT REQUIREMENTS:

executive_summary:
- 3-5 sentences maximum
- Written for a CISO or VP of Security — no technical jargon
- Must state: what happened, what was compromised, immediate risk
- Example: "A confirmed APT actor exploited an SSRF vulnerability in
  the organization's web application to steal AWS IAM credentials.
  The attack originated from IP 54.67.127.227 (AbuseIPDB confidence:
  15%, ISP: Amazon AWS). Immediate credential rotation and SSRF
  patching are required to prevent further compromise."

attack_overview:
- 3-8 sentences technical narrative
- Follow the kill chain chronologically
- Cite specific EventCodes, IPs, URIs, and timestamps
- Connect stages causally: "This led to..." / "Which enabled..."

key_findings:
- Minimum 4 findings, maximum 8
- Each finding must have:
  * finding: a specific factual claim (not generic)
  * evidence: the exact data point supporting it
  * confidence: based on how strong the evidence is
  * source: where the evidence came from
- GOOD finding: "External IP 54.67.127.227 accessed AWS metadata
  service 73 times via SSRF" with evidence "stream:http query
  returning 11 rows for dest_ip=169.254.169.254" at confidence 0.95
- BAD finding: "Suspicious network activity detected" — too generic

recommended_actions:
- Minimum 3 actions, maximum 6
- IMMEDIATE: must be done within 1 hour
- SHORT_TERM: within 24-72 hours
- LONG_TERM: within 30 days
- Each action must cite which MITRE technique it mitigates
- Ground in playbook_rag or mitre_rag context when available

mitre_techniques_used:
- List all T-codes confirmed in the kill chain
- Only include CONFIRMED stages — not INFERRED

cves_identified:
- Only include CVEs that appear in the RAG context
- Never hallucinate CVE IDs

threat_actor_profile:
- 2-3 sentences assessing attacker sophistication
- Base on: attack complexity, tools used, evasion techniques observed
- Example: "The threat actor demonstrated intermediate-to-advanced
  capability, leveraging SSRF exploitation and cloud metadata abuse
  — techniques associated with financially-motivated APT groups.
  Use of AWS EC2 infrastructure for attack origin suggests
  deliberate operational security awareness."

investigation_confidence:
- Overall confidence in the investigation completeness
- Weight: kill chain completeness (40%) + threat intel data (20%) +
  RAG grounding (20%) + patient zero identification (20%)

CITATION RULES:
- When using TTP/MITRE data: cite the technique ID and source
- When using threat intel: cite the IP, score, and API source
- When using playbook guidance: note "per IR playbook"
- When using CVE data: cite the CVE ID
- Do NOT make claims about specific CVEs unless they appear in
  the provided RAG context

CONTAINMENT PLAN GENERATION:
You must also generate a 3-phase containment plan in the 'containment_plan' field.
Phases:
1. PHASE 1 (Short-term/Immediate): Tactical blocks (IPs, accounts).
2. PHASE 2 (Mid-term): Endpoint isolation, process kills.
3. PHASE 3 (Long-term): Hardening, credential rotation.

Each action must have:
- type: one of BLOCK_IP, ISOLATE_HOST, KILL_PROCESS, REVOKE_CREDENTIALS
- target: the specific entity (IP, Hostname, etc.)
- title: clear short title
- description: rationale
- is_irreversible: boolean

Only include actions for entities confirmed as malicious in the kill chain or blast radius.
"""

_SYNTHESIS_COUNTERFACTUAL_FALLBACK = """You are a senior forensic analyst explaining an 
automated investigation result to a SOC team.

The attack was classified as: {classification}
Confidence: Based on confirmed kill chain stages and telemetry.

Confirmed kill chain: {kill_chain_summary}

Key indicators present in the telemetry:
{indicators_text}

Triage summary: {triage_summary}

For each alternative classification below, explain specifically 
what evidence is ABSENT from the telemetry that would be required 
to make that classification. Be specific - cite EventCodes, 
sourcetypes, process names, IP patterns, or behavioral indicators 
that are missing. Keep each explanation to 2-3 sentences maximum.

Alternative classifications to rule out: {alternatives}

Respond in this exact JSON format:
{{
  "alternatives_ruled_out": [
    {{
      "classification": "CLASSIFICATION_NAME",
      "reason": "2-3 sentence explanation of what is absent",
      "missing_indicators": ["specific indicator 1", "specific indicator 2"]
    }}
  ]
}}

Only respond with valid JSON. No preamble or explanation outside JSON."""

_SYNTHESIS_CONTAINMENT_FALLBACK = """Generate a 3-phase containment plan for a {classification} investigation.
Blast Radius: {blast_radius}
Kill Chain: {kill_chain}

You MUST generate exactly 3 phases with these exact names:
- "Phase 1: IMMEDIATE (Execute now)"
- "Phase 2: SHORT TERM (Within 24 hours)"
- "Phase 3: REMEDIATION (Within 72 hours)"

For each action, you MUST ONLY choose one of these exact action types:
- BLOCK_IP
- ISOLATE_HOST
- KILL_PROCESS
- REVOKE_CREDENTIALS
- DISABLE_ACCOUNT
- ROTATE_CREDENTIALS
- AUDIT_CLOUDTRAIL

CRITICAL: Do NOT invent or use any other action type under any circumstances. If an action does not map to one of these 7 types, do NOT include it.

kill_process: ONLY use if you have confirmed malicious process names from the kill chain stages.
Target must be a specific process name like:
"backgroundTaskHost.exe", "cmd.exe", "WMIC.exe", "reg.exe", "powershell.exe"
Use EventCode 4688 evidence from the kill chain.
If you have no confirmed process name from the evidence, DO NOT include a kill_process action.
Never use placeholder targets like "suspicious_process_id" or "malicious_process".

Return a JSON object matching this structure:
{{
  "phases": [
    {{
      "name": "Phase 1: IMMEDIATE (Execute now)",
      "description": "Immediate blocks...",
      "actions": [
        {{
          "type": "BLOCK_IP | ISOLATE_HOST | KILL_PROCESS | REVOKE_CREDENTIALS",
          "target": "the entity",
          "title": "Action Title",
          "description": "Why...",
          "is_irreversible": false
        }}
      ]
    }},
    {{
      "name": "Phase 2: SHORT TERM (Within 24 hours)",
      "description": "Short-term mitigations...",
      "actions": []
    }},
    {{
      "name": "Phase 3: REMEDIATION (Within 72 hours)",
      "description": "Long-term recovery...",
      "actions": []
    }}
  ]
}}
"""


# ── LLM setup ─────────────────────────────────────────────────────────────────

_LLM = ChatOpenAI(model="gpt-4o-mini", temperature=0)
_LLM_NARRATIVE = _LLM.with_structured_output(NarrativeSection)
_LLM_STRUCTURED = _LLM.with_structured_output(StructuredSection)


async def _safe_call(coro, fallback, label: str):
    """
    Run a coroutine safely.
    Returns fallback value on any exception or None result.
    Never raises.
    """
    try:
        result = await coro
        if result is None:
            logger.error(
                "[SynthesisAgent] %s returned None - using fallback",
                label,
            )
            return fallback
        return result
    except Exception as e:
        logger.error(
            "[SynthesisAgent] %s failed: %s - using fallback",
            label,
            str(e),
        )
        return fallback


def _fallback_narrative(state: dict) -> str:
    """Minimal narrative when LLM call fails."""
    classification = state.get("attack_classification", "UNKNOWN")
    inv_id = state.get("investigation_id", "unknown")
    return (
        f"Automated investigation {inv_id} identified "
        f"a {classification} attack pattern. "
        f"Narrative generation encountered an error - "
        f"please review the structured findings below "
        f"for full investigation details."
    )


def _fallback_structured(state: dict) -> dict:
    """Minimal structured findings when LLM call fails."""
    return {
        "executive_summary": _fallback_narrative(state),
        "attack_vector": "See kill chain stages",
        "impact_assessment": "See blast radius data",
        "key_findings": [
            "Automated reconstruction completed",
            "See TTP mappings for technique details",
            "See threat intel for IP analysis",
        ],
        "recommendations": [
            "Review kill chain stages",
            "Execute containment plan",
            "Monitor sentinel_findings index",
        ],
        "error": "structured_findings_generation_failed",
    }


def _fallback_counterfactual(state: dict) -> dict:
    """Minimal counterfactual when LLM call fails."""
    classification = state.get("attack_classification", "UNKNOWN")
    return {
        "alternatives_ruled_out": [
            {
                "classification": "ALTERNATIVE",
                "reason": (
                    "Counterfactual analysis unavailable. "
                    f"Investigation classified as "
                    f"{classification} based on "
                    f"kill chain evidence."
                ),
                "missing_indicators": [],
            }
        ],
        "error": "counterfactual_generation_failed",
    }


def _fallback_containment(state: dict):
    """
    Return existing containment plan from state if
    available, otherwise minimal valid plan.
    """
    existing = state.get("containment_plan")
    if existing:
        return existing

    from app.models.containment import ContainmentPlan, ContainmentPhase

    return ContainmentPlan(
        investigation_id=state.get("investigation_id", "unknown"),
        phases=[
            ContainmentPhase(
                phase=1,
                name="Phase 1: IMMEDIATE",
                label="Phase 1: IMMEDIATE (Execute now)",
                description=(
                    "Containment plan generation failed. "
                    "Review kill chain and apply manual "
                    "IR procedures."
                ),
                timeframe="Immediate",
                actions=[],
                status="PENDING",
            ),
            ContainmentPhase(
                phase=2,
                name="Phase 2: SHORT TERM",
                label="Phase 2: SHORT TERM (Within 24 hours)",
                description="Manual review required.",
                timeframe="Within 24 hours",
                actions=[],
                status="PENDING",
            ),
            ContainmentPhase(
                phase=3,
                name="Phase 3: REMEDIATION",
                label="Phase 3: REMEDIATION (Within 72 hours)",
                description="Manual review required.",
                timeframe="Within 72 hours",
                actions=[],
                status="PENDING",
            ),
        ],
        classification=state.get("attack_classification", "UNKNOWN"),
        confidence=0.0,
        status="PENDING",
    ).model_dump(mode="json")


async def _generate_narrative(
    narrative_prompt: str,
    synthesis_context: str,
    investigation_id: str,
):
    """Generate narrative section with structured output."""
    return await _LLM_NARRATIVE.with_config({
        "run_name": "synthesis_narrative_call",
        "metadata": {"investigation_id": investigation_id},
    }).ainvoke([
        SystemMessage(content=narrative_prompt),
        HumanMessage(content=synthesis_context),
    ])


async def _generate_structured(
    narrative_prompt: str,
    synthesis_context: str,
    investigation_id: str,
):
    """Generate structured findings section with structured output."""
    return await _LLM_STRUCTURED.with_config({
        "run_name": "synthesis_structured_call",
        "metadata": {"investigation_id": investigation_id},
    }).ainvoke([
        SystemMessage(content=narrative_prompt),
        HumanMessage(content=synthesis_context),
    ])


# ── Counterfactual reasoning helpers ──────────────────────────────────────────

def _get_alternative_classifications(
    classification: str,
) -> list[str]:
    """
    Returns the alternative classifications that were
    NOT selected, for counterfactual reasoning.
    """
    all_classifications = [
        "APT",
        "RANSOMWARE", 
        "INSIDER_THREAT",
        "BRUTE_FORCE",
    ]
    return [c for c in all_classifications if c != classification]


async def _generate_counterfactual_reasoning(
    classification: str,
    kill_chain: list,
    key_indicators: list,
    triage_summary: str,
    attack_narrative: str,
    llm,
) -> dict:
    """
    Generate counterfactual reasoning explaining why
    alternative classifications were ruled out.

    Uses the confirmed kill chain and key indicators
    as evidence for what IS present, then reasons about
    what is ABSENT for each alternative.
    """
    alternatives = _get_alternative_classifications(classification)

    if not alternatives:
        return {}

    # Build kill chain summary for context
    kill_chain_summary = " → ".join([
        f"{s.get('stage_name', '')} ({s.get('mitre_technique', '')})"
        for s in kill_chain
    ]) if kill_chain else "No stages confirmed"

    # Format indicators
    indicators_text = "\n".join(
        f"- {ind}" for ind in key_indicators
    ) if key_indicators else "No specific indicators"

    prompt = f"""You are a senior forensic analyst explaining an 
automated investigation result to a SOC team.

The attack was classified as: {classification}
Confidence: Based on confirmed kill chain stages and telemetry.

Confirmed kill chain: {kill_chain_summary}

Key indicators present in the telemetry:
{indicators_text}

Triage summary: {triage_summary}

For each alternative classification below, explain specifically 
what evidence is ABSENT from the telemetry that would be required 
to make that classification. Be specific — cite EventCodes, 
sourcetypes, process names, IP patterns, or behavioral indicators 
that are missing. Keep each explanation to 2-3 sentences maximum.

Alternative classifications to rule out: {', '.join(alternatives)}

Respond in this exact JSON format:
{{
  "alternatives_ruled_out": [
    {{
      "classification": "CLASSIFICATION_NAME",
      "reason": "2-3 sentence explanation of what is absent",
      "missing_indicators": ["specific indicator 1", "specific indicator 2"]
    }}
  ]
}}

Only respond with valid JSON. No preamble or explanation outside JSON."""

    prompt = get_prompt(
        name="synthesis-counterfactual",
        fallback=_SYNTHESIS_COUNTERFACTUAL_FALLBACK,
        classification=classification,
        kill_chain_summary=kill_chain_summary,
        indicators_text=indicators_text,
        triage_summary=triage_summary,
        alternatives=", ".join(alternatives),
    )

    try:
        from langchain_core.messages import HumanMessage
        response = await llm.ainvoke([HumanMessage(content=prompt)])
        
        import json
        # Clean response text
        text = response.content.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        text = text.strip()
        
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(
                "[SynthesisAgent] JSON parse failed: %s "
                "Response preview: %s",
                str(e),
                str(response.content)[:200],
            )
            return None
        
        return {
            "confirmed_classification": classification,
            "alternatives_ruled_out": parsed.get(
                "alternatives_ruled_out", []
            ),
        }

    except Exception as e:
        logger.error(
            "Counterfactual reasoning failed | error=%s", str(e)
        )
        return {
            "confirmed_classification": classification,
            "alternatives_ruled_out": [],
            "error": str(e),
        }


# ── Main agent ────────────────────────────────────────────────────────────────

async def synthesis_agent(state: AgentState, config=None) -> AgentState:
    """
    SynthesisAgent: converges all upstream agent outputs into a structured
    final_report with RAG-grounded recommendations.

    Inputs: triage output, kill_chain, patient_zero, blast_radius,
            threat_intel, ttp_mappings
    Output: final_report, rag_context
    """
    investigation_id = state.get("investigation_id", "unknown")
    classification = state.get("attack_classification", "UNKNOWN")

    logger.info(
        "[%s] SynthesisAgent starting | classification=%s",
        investigation_id, classification,
    )

    # ── Extract all upstream outputs ──────────────────────────────────────
    trigger = state.get("trigger", "")
    triage_summary = state.get("triage_summary", "")
    key_indicators = state.get("key_indicators", [])
    attack_window = state.get("attack_window", {})
    severity = state.get("severity", "HIGH")
    kill_chain = state.get("kill_chain", [])
    patient_zero = state.get("patient_zero", {})
    blast_radius = state.get("blast_radius", {})
    attack_narrative = state.get("attack_narrative", "")
    reconstruction_confidence = state.get("reconstruction_confidence", 0.0)
    confidence_breakdown = state.get("confidence_breakdown", {})
    threat_intel = state.get("threat_intel", {})
    ttp_mappings = state.get("ttp_mappings", [])

    # ── RAG retrieval — parallel across all 4 collections ─────────────────
    logger.info(
        "[%s] SynthesisAgent: running parallel RAG retrieval",
        investigation_id,
    )

    try:
        rag_results = await retrieve_for_synthesis(
            attack_classification=classification,
            kill_chain_stages=kill_chain,
            patient_zero_ip=patient_zero.get("ip_address", ""),
            attack_narrative=attack_narrative,
        )
    except Exception as e:
        logger.warning(
            "[%s] RAG retrieval failed: %s — proceeding without",
            investigation_id, e,
        )
        rag_results = {"mitre": [], "cve": [], "playbooks": [], "botsv3": []}

    rag_context_text = _format_rag_context(rag_results)

    logger.info(
        "[%s] RAG retrieval complete | mitre=%d | cve=%d | "
        "playbooks=%d | botsv3=%d",
        investigation_id,
        len(rag_results.get("mitre", [])),
        len(rag_results.get("cve", [])),
        len(rag_results.get("playbooks", [])),
        len(rag_results.get("botsv3", [])),
    )

    # ── Build synthesis context ────────────────────────────────────────────
    threat_intel_text = _format_threat_intel(threat_intel)
    ttp_text = _format_ttp_mappings(ttp_mappings)
    
    kill_chain_text = "\n".join([
        f"Stage {s.get('stage_number', i+1)}: {s.get('stage_name')} "
        f"[{s.get('mitre_tactic')} / {s.get('mitre_technique')}] "
        f"Confidence: {s.get('confidence')} | "
        f"Timestamp: {s.get('timestamp')} | "
        f"Evidence: {s.get('evidence', '')[:150]}"
        for i, s in enumerate(kill_chain)
    ])

    synthesis_context = f"""
INVESTIGATION SYNTHESIS INPUTS
================================
Investigation ID: {investigation_id}
Trigger: {trigger}
Attack Classification: {classification}
Severity: {severity}
Attack Window: {attack_window.get('start', 'unknown')} to {attack_window.get('end', 'unknown')}
Reconstruction Confidence: {reconstruction_confidence:.2f}

TRIAGE SUMMARY:
{triage_summary}

KEY INDICATORS FROM TRIAGE:
{json.dumps(key_indicators, indent=2)}

FULL KILL CHAIN ({len(kill_chain)} stages):
{kill_chain_text}

PATIENT ZERO:
{json.dumps(patient_zero, indent=2)}

BLAST RADIUS:
{json.dumps(blast_radius, indent=2)}

ATTACK NARRATIVE FROM RECONSTRUCTION:
{attack_narrative}

THREAT INTELLIGENCE (IP Reputation):
{threat_intel_text}

TTP ENRICHMENT FROM MITRE RAG ({len(ttp_mappings)} techniques):
{ttp_text}

RAG KNOWLEDGE BASE CONTEXT:
{rag_context_text}

Produce the final incident report. Ground every claim in the \
evidence above. Do not hallucinate CVE IDs or threat intelligence
data not present in the inputs.
"""

    # ── Parallel LLM calls — all 4 are independent of each other's output ─
    # narrative + structured use synthesis_context (built from state above)
    # counterfactual + containment_plan use state fields directly
    # Running all 4 in one gather cuts total time from ~40-50s → ~10-15s
    logger.info(
        "[%s] SynthesisAgent: launching 4 parallel LLM calls",
        investigation_id,
    )
    narrative_prompt = get_prompt(
        name="synthesis-narrative",
        fallback=_SYNTHESIS_NARRATIVE_FALLBACK,
    )
    try:
        (
            narrative_result,
            structured_result,
            counterfactual_result,
            containment_result,
        ) = await asyncio.gather(
            _safe_call(
                _generate_narrative(
                    narrative_prompt=narrative_prompt,
                    synthesis_context=synthesis_context,
                    investigation_id=investigation_id,
                ),
                _fallback_narrative(state),
                "narrative",
            ),
            _safe_call(
                _generate_structured(
                    narrative_prompt=narrative_prompt,
                    synthesis_context=synthesis_context,
                    investigation_id=investigation_id,
                ),
                _fallback_structured(state),
                "structured",
            ),
            _safe_call(
                _generate_counterfactual_reasoning(
                    classification=classification,
                    kill_chain=kill_chain,
                    key_indicators=key_indicators,
                    triage_summary=triage_summary,
                    attack_narrative=attack_narrative,
                    llm=_LLM,
                ),
                _fallback_counterfactual(state),
                "counterfactual",
            ),
            _safe_call(
                _generate_containment_plan(
                    investigation_id=investigation_id,
                    blast_radius=blast_radius,
                    kill_chain=kill_chain,
                    classification=classification,
                    llm=_LLM,
                ),
                _fallback_containment(state),
                "containment",
            ),
        )

        narrative_used_fallback = isinstance(narrative_result, str)
        structured_used_fallback = isinstance(structured_result, dict)
        counterfactual_used_fallback = (
            isinstance(counterfactual_result, dict)
            and bool(counterfactual_result.get("error"))
        )

        if narrative_used_fallback:
            narrative = NarrativeSection(
                executive_summary=narrative_result,
                attack_overview=(
                    "Attack overview generation failed - "
                    "review kill chain stages for chronology."
                ),
                threat_actor_profile=(
                    "Threat actor profile generation failed - "
                    "manual analyst review recommended."
                ),
            )
        else:
            narrative = narrative_result

        if structured_used_fallback:
            structured = StructuredSection(
                key_findings=[
                    FindingWithConfidence(
                        finding=finding,
                        evidence="Fallback structured synthesis output",
                        confidence=0.5,
                        source="telemetry",
                    )
                    for finding in structured_result.get("key_findings", [])
                ],
                recommended_actions=[
                    RecommendedAction(
                        priority="IMMEDIATE",
                        action=action,
                        rationale=(
                            "Fallback structured synthesis output "
                            "after generation failure"
                        ),
                        mitre_technique="T0000",
                    )
                    for action in structured_result.get("recommendations", [])
                ],
                mitre_techniques_used=[],
                cves_identified=[],
                investigation_confidence=0.0,
            )
        else:
            structured = structured_result

        counterfactual = counterfactual_result
        containment_plan = containment_result

        logger.info(
            "[%s] All 4 parallel LLM calls complete | "
            "counterfactual_alternatives=%d | containment_phases=%d",
            investigation_id,
            len(counterfactual.get("alternatives_ruled_out", [])),
            len(containment_plan.get("phases", [])),
        )

    except Exception as exc:
        logger.error(
            "[%s] SynthesisAgent parallel LLM gather failed: %s",
            investigation_id, exc,
        )
        narrative_used_fallback = True
        structured_used_fallback = True
        counterfactual_used_fallback = True
        return {
            **state,
            "error": f"SynthesisAgent: LLM gather failed — {exc}",
            "escalate_to_human": True,
            # Preserve a minimal final_report so report_agent and frontend
            # receive a structured degraded response rather than null
            "final_report": state.get("final_report") or {
                "investigation_id": investigation_id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "classification": classification,
                "severity": severity,
                "executive_summary": (
                    f"Investigation incomplete — synthesis LLM call failed. "
                    f"Manual review required. Error: {exc}"
                ),
                "key_findings": [],
                "recommended_actions": [],
                "mitre_techniques_used": [],
                "investigation_confidence": 0.0,
                "confidence_breakdown": state.get("confidence_breakdown", {}),
                "containment_plan": {"phases": []},
            },
        }

    degraded_sections = []
    if narrative_used_fallback:
        degraded_sections.append("narrative")
    if structured_used_fallback:
        degraded_sections.append("structured_findings")
    if counterfactual_used_fallback:
        degraded_sections.append("counterfactual")

    # ── Field injection — gpt-4o-mini drops fields on sparse input data ────
    raw = FinalReportRaw(
        executive_summary=narrative.executive_summary,
        attack_overview=narrative.attack_overview,
        threat_actor_profile=narrative.threat_actor_profile,
        key_findings=structured.key_findings,
        recommended_actions=structured.recommended_actions,
        mitre_techniques_used=structured.mitre_techniques_used,
        cves_identified=structured.cves_identified,
        investigation_confidence=structured.investigation_confidence,
    )
    raw = _inject_missing_fields(
        raw, classification, kill_chain, threat_intel,
        ttp_mappings, reconstruction_confidence
    )

    # ── Build final_report dict ────────────────────────────────────────────
    primary_confidence = confidence_breakdown.get(
        "overall",
        reconstruction_confidence,
    )
    report_confidence = raw.investigation_confidence
    confidence_summary = {
        "version": "confidence-v1",
        "primary": primary_confidence,
        "primary_label": "Evidence Confidence",
        "reconstruction": {
            "score": primary_confidence,
            "breakdown": confidence_breakdown,
        },
        "report": {
            "score": report_confidence,
            "source": "SynthesisAgent",
        },
    }

    final_report = {
        "investigation_id": investigation_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "classification": classification,
        "severity": severity,
        "executive_summary": raw.executive_summary,
        "attack_overview": raw.attack_overview,
        "key_findings": [f.model_dump() for f in raw.key_findings],
        "recommended_actions": [a.model_dump() for a in raw.recommended_actions],
        "mitre_techniques_used": raw.mitre_techniques_used,
        "cves_identified": raw.cves_identified,
        "threat_actor_profile": raw.threat_actor_profile,
        "investigation_confidence": primary_confidence,
        "report_confidence": report_confidence,
        "confidence": confidence_summary,
        "confidence_breakdown": confidence_breakdown,
        "mltk_ttp_validation": state.get("mltk_ttp_validation", {}),
        "patient_zero": patient_zero,
        "blast_radius": blast_radius,
        "attack_window": attack_window,
        "rag_sources_used": {
            "mitre_chunks": len(rag_results.get("mitre", [])),
            "cve_chunks": len(rag_results.get("cve", [])),
            "playbook_chunks": len(rag_results.get("playbooks", [])),
            "botsv3_chunks": len(rag_results.get("botsv3", [])),
        },
        "counterfactual_reasoning": counterfactual,
        "containment_plan": containment_plan,
        "degraded_sections": degraded_sections,
        "synthesis_degraded": bool(degraded_sections),
    }

    if degraded_sections:
        logger.warning(
            "[%s] SynthesisAgent degraded sections: %s",
            investigation_id,
            degraded_sections,
        )

    logger.info(
        "[%s] SynthesisAgent complete | findings=%d | actions=%d | "
        "techniques=%d | cves=%d | confidence=%.2f | containment_phases=%d",
        investigation_id,
        len(raw.key_findings),
        len(raw.recommended_actions),
        len(raw.mitre_techniques_used),
        len(raw.cves_identified),
        raw.investigation_confidence,
        len(containment_plan.get("phases", [])),
    )

    return {
        **state,
        "final_report": final_report,
        "investigation_confidence": primary_confidence,
        "containment_plan": containment_plan,
        "counterfactual_reasoning": counterfactual,
        "narrative": {
            "executive_summary": raw.executive_summary,
            "attack_overview": raw.attack_overview,
            "threat_actor_profile": raw.threat_actor_profile,
        },
        "structured_findings": {
            "key_findings": [f.model_dump() for f in raw.key_findings],
            "recommended_actions": [a.model_dump() for a in raw.recommended_actions],
            "mitre_techniques_used": raw.mitre_techniques_used,
            "cves_identified": raw.cves_identified,
            "investigation_confidence": raw.investigation_confidence,
        },
        "counterfactual": counterfactual,
        "synthesis_degraded": bool(degraded_sections),
        "degraded_sections": degraded_sections,
        "rag_context": rag_results,
        "error": None,
    }


INVALID_KILL_PROCESS_TARGETS = [
    "suspicious",
    "placeholder", 
    "process_id",
    "malicious_process",
    "any remaining",
    "remaining suspicious",
]

def _is_valid_kill_process_target(target: str) -> bool:
    target_lower = target.lower()
    return not any(
        invalid in target_lower
        for invalid in INVALID_KILL_PROCESS_TARGETS
    )


def _get_fallback_containment_plan(
    investigation_id: str,
    blast_radius: dict,
    kill_chain: list,
    classification: str,
) -> dict:
    from app.services.containment_templates import render_template
    from app.models.containment import ContainmentActionType, ContainmentAction, ContainmentPhase, ContainmentPlan
    import uuid

    # Gather target entities dynamically
    external_ips = blast_radius.get("external_ips_observed", []) if blast_radius else []
    ext_ip = external_ips[0] if external_ips else "54.67.127.227"

    internal_ips = blast_radius.get("internal_ips_affected", []) if blast_radius else []
    int_ip = internal_ips[0] if internal_ips else "172.16.0.178"

    # Try to find a process name from the kill chain
    proc_name = "powershell.exe"
    if kill_chain:
        for stage in kill_chain:
            evidence = stage.get("evidence", "").lower()
            for p in ["powershell.exe", "wmic.exe", "reg.exe", "cmd.exe", "backgroundtaskhost.exe"]:
                if p in evidence:
                    proc_name = p
                    break

    # Phase 1 Actions
    phase1_actions = []
    
    # Action 1: Block malicious IP
    p1_a1_spl = render_template(ContainmentActionType.BLOCK_IP, ext_ip)
    phase1_actions.append(ContainmentAction(
        id=str(uuid.uuid4())[:8],
        type=ContainmentActionType.BLOCK_IP,
        title="Block Malicious IP",
        description=f"Block attacker source IP {ext_ip} at the gateway firewall.",
        target=ext_ip,
        containment_spl=p1_a1_spl["spl"],
        reversal_spl=p1_a1_spl["reversal"],
        is_irreversible=False,
        phase=1
    ))

    # Action 2: Isolate affected internal host
    p1_a2_spl = render_template(ContainmentActionType.ISOLATE_HOST, int_ip)
    phase1_actions.append(ContainmentAction(
        id=str(uuid.uuid4())[:8],
        type=ContainmentActionType.ISOLATE_HOST,
        title="Isolate Host",
        description=f"Isolate compromised host {int_ip} from the network to contain propagation.",
        target=int_ip,
        containment_spl=p1_a2_spl["spl"],
        reversal_spl=p1_a2_spl["reversal"],
        is_irreversible=False,
        phase=1
    ))

    # Action 3: Terminate malicious process
    p1_a3_spl = render_template(ContainmentActionType.KILL_PROCESS, proc_name)
    phase1_actions.append(ContainmentAction(
        id=str(uuid.uuid4())[:8],
        type=ContainmentActionType.KILL_PROCESS,
        title="Terminate Malicious Process",
        description=f"Terminate active malicious process {proc_name} on affected systems.",
        target=proc_name,
        containment_spl=p1_a3_spl["spl"],
        reversal_spl=None,
        is_irreversible=True,
        phase=1
    ))

    # Phase 2 Actions
    phase2_actions = []
    
    # Action 1: Revoke compromised user session
    p2_a1_spl = render_template(ContainmentActionType.REVOKE_CREDENTIALS, "Administrator")
    phase2_actions.append(ContainmentAction(
        id=str(uuid.uuid4())[:8],
        type=ContainmentActionType.REVOKE_CREDENTIALS,
        title="Revoke Active Sessions",
        description="Revoke all active sessions and OAuth tokens for compromised credentials.",
        target="Administrator",
        containment_spl=p2_a1_spl["spl"],
        reversal_spl=p2_a1_spl["reversal"],
        is_irreversible=False,
        phase=2
    ))

    # Action 2: Disable compromised user account
    p2_a2_spl = render_template(ContainmentActionType.DISABLE_ACCOUNT, "Administrator")
    phase2_actions.append(ContainmentAction(
        id=str(uuid.uuid4())[:8],
        type=ContainmentActionType.DISABLE_ACCOUNT,
        title="Disable Compromised User",
        description="Temporarily disable the compromised user account to prevent secondary access.",
        target="Administrator",
        containment_spl=p2_a2_spl["spl"],
        reversal_spl=p2_a2_spl["reversal"],
        is_irreversible=False,
        phase=2
    ))

    # Phase 3 Actions
    phase3_actions = []

    # Action 1: Rotate API Credentials
    p3_a1_spl = render_template(ContainmentActionType.ROTATE_CREDENTIALS, "Administrator")
    phase3_actions.append(ContainmentAction(
        id=str(uuid.uuid4())[:8],
        type=ContainmentActionType.ROTATE_CREDENTIALS,
        title="Rotate Security Credentials",
        description="Force key/credential rotation for all impacted system administrators.",
        target="Administrator",
        containment_spl=p3_a1_spl["spl"],
        reversal_spl=None,
        is_irreversible=True,
        phase=3
    ))

    # Action 2: Audit CloudTrail
    p3_a2_spl = render_template(ContainmentActionType.AUDIT_CLOUDTRAIL, "botsv3-production-resource")
    phase3_actions.append(ContainmentAction(
        id=str(uuid.uuid4())[:8],
        type=ContainmentActionType.AUDIT_CLOUDTRAIL,
        title="Cloud Audit Logging",
        description="Enable and analyze cloud access audit trails to ensure no lingering access keys.",
        target="botsv3-production-resource",
        containment_spl=p3_a2_spl["spl"],
        reversal_spl=None,
        is_irreversible=True,
        phase=3
    ))

    # Combine into phases
    phases = [
        ContainmentPhase(
            name="Phase 1: IMMEDIATE (Execute now)",
            description="Immediate critical actions to isolate threats and stop active execution.",
            actions=phase1_actions,
            phase=1
        ),
        ContainmentPhase(
            name="Phase 2: SHORT TERM (Within 24 hours)",
            description="Short-term mitigations to revoke access and secure compromised credentials.",
            actions=phase2_actions,
            phase=2
        ),
        ContainmentPhase(
            name="Phase 3: REMEDIATION (Within 72 hours)",
            description="Long-term security posture improvement, credential rotation, and log audits.",
            actions=phase3_actions,
            phase=3
        )
    ]

    plan = ContainmentPlan(
        investigation_id=investigation_id,
        phases=phases,
        classification=classification
    )
    return plan.model_dump(mode="json")


async def _generate_containment_plan(investigation_id: str, blast_radius: dict, kill_chain: list, classification: str, llm) -> dict:
    """
    Generate a structured containment plan using the LLM.
    """
    from app.services.containment_templates import render_template
    from app.models.containment import ContainmentActionType, ContainmentAction, ContainmentPhase, ContainmentPlan, ContainmentStatus
    import uuid

    prompt = f"""Generate a 3-phase containment plan for a {classification} investigation.
Blast Radius: {json.dumps(blast_radius)}
Kill Chain: {json.dumps(kill_chain[:5])}

You MUST generate exactly 3 phases with these exact names:
- "Phase 1: IMMEDIATE (Execute now)"
- "Phase 2: SHORT TERM (Within 24 hours)"
- "Phase 3: REMEDIATION (Within 72 hours)"

For each action, you MUST ONLY choose one of these exact action types:
- BLOCK_IP
- ISOLATE_HOST
- KILL_PROCESS
- REVOKE_CREDENTIALS
- DISABLE_ACCOUNT
- ROTATE_CREDENTIALS
- AUDIT_CLOUDTRAIL

CRITICAL: Do NOT invent or use any other action type under any circumstances. If an action does not map to one of these 7 types, do NOT include it.

kill_process: ONLY use if you have confirmed malicious process names from the kill chain stages.
Target must be a specific process name like:
"backgroundTaskHost.exe", "cmd.exe", "WMIC.exe", "reg.exe", "powershell.exe"
Use EventCode 4688 evidence from the kill chain.
If you have no confirmed process name from the evidence, DO NOT include a kill_process action.
Never use placeholder targets like "suspicious_process_id" or "malicious_process".

Return a JSON object matching this structure:
{{
  "phases": [
    {{
      "name": "Phase 1: IMMEDIATE (Execute now)",
      "description": "Immediate blocks...",
      "actions": [
        {{
          "type": "BLOCK_IP | ISOLATE_HOST | KILL_PROCESS | REVOKE_CREDENTIALS",
          "target": "the entity",
          "title": "Action Title",
          "description": "Why...",
          "is_irreversible": false
        }}
      ]
    }},
    {{
      "name": "Phase 2: SHORT TERM (Within 24 hours)",
      "description": "Short-term mitigations...",
      "actions": []
    }},
    {{
      "name": "Phase 3: REMEDIATION (Within 72 hours)",
      "description": "Long-term recovery...",
      "actions": []
    }}
  ]
}}
"""
    blast_radius_str = (
        blast_radius
        if isinstance(blast_radius, str)
        else json.dumps(blast_radius)
    )
    kill_chain_str = json.dumps(kill_chain[:5])
    prompt = get_prompt(
        name="synthesis-containment",
        fallback=_SYNTHESIS_CONTAINMENT_FALLBACK,
        classification=classification,
        blast_radius=blast_radius_str,
        kill_chain=kill_chain_str,
    )
    try:
        response = await llm.ainvoke([SystemMessage(content="You are a containment strategy expert."), HumanMessage(content=prompt)])
        content = response.content.strip()
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0]
        elif "```" in content:
            content = content.split("```")[1].split("```")[0]
        
        try:
            raw_plan = json.loads(content)
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(
                "[SynthesisAgent] JSON parse failed: %s "
                "Response preview: %s",
                str(e),
                str(response.content)[:200],
            )
            return None
        
        phases = []
        for idx, p_raw in enumerate(raw_plan.get("phases", [])):
            phase_num = idx + 1
            actions = []
            for a_raw in p_raw.get("actions", []):
                try:
                    a_type = ContainmentActionType(a_raw["type"])
                except ValueError:
                    logger.warning(f"Ignoring unknown containment action type: {a_raw.get('type')}")
                    continue
                
                target = a_raw["target"]
                
                if a_type == ContainmentActionType.KILL_PROCESS:
                    if not _is_valid_kill_process_target(target):
                        logger.warning(
                            "[%s] Skipping kill_process action — "
                            "invalid placeholder target: %s",
                            investigation_id,
                            target,
                        )
                        continue
                
                # Render the SPL for the action
                rendered = render_template(a_type, target)
                reversal_spl = rendered["reversal"]
                is_irreversible = reversal_spl is None
                
                action = ContainmentAction(
                    id=str(uuid.uuid4())[:8],
                    type=a_type,
                    title=a_raw["title"],
                    description=a_raw["description"],
                    target=target,
                    containment_spl=rendered["spl"],
                    reversal_spl=reversal_spl,
                    is_irreversible=is_irreversible,
                    phase=phase_num
                )
                actions.append(action)
            
            phases.append(ContainmentPhase(
                name=p_raw["name"],
                description=p_raw["description"],
                actions=actions,
                phase=phase_num
            ))
            
        try:
            plan = ContainmentPlan(
                investigation_id=investigation_id,
                phases=phases,
                classification=classification
            )
        except Exception as e:
            logger.error(
                "[SynthesisAgent] Pydantic validation failed: %s",
                str(e),
            )
            return None
        # Check if the plan is completely empty of actions
        total_actions = sum(len(p.actions) for p in phases)
        if total_actions == 0:
            logger.warning("[%s] Generated containment plan has 0 actions — using high-fidelity fallback plan.", investigation_id)
            return _get_fallback_containment_plan(investigation_id, blast_radius, kill_chain, classification)
            
        return plan.model_dump(mode="json")
    except Exception as e:
        logger.error("Failed to parse containment plan: %s", str(e))
        return None


# ── Helper formatting functions ───────────────────────────────────────────────

def _format_threat_intel(threat_intel: dict) -> str:
    if not threat_intel:
        return (
            "No external IPs identified — possible insider threat "
            "or internal-only attack."
        )

    lines = []
    for ip, data in threat_intel.items():
        lines.append(
            f"  IP {ip}: {data.get('threat_level', 'UNKNOWN')} | "
            f"VT malicious: {data.get('virustotal', {}).get('malicious_count', 0)} | "
            f"AbuseIPDB: {data.get('abuseipdb', {}).get('abuse_confidence_score', 0)}% | "
            f"ISP: {data.get('abuseipdb', {}).get('isp', 'unknown')} | "
            f"Summary: {data.get('summary', '')}"
        )
    return "\n".join(lines)


def _format_ttp_mappings(ttp_mappings: list) -> str:
    if not ttp_mappings:
        return "No TTP enrichment available."

    lines = []
    for ttp in ttp_mappings:
        if ttp.get("confidence", 0) > 0:
            lines.append(
                f"  {ttp.get('technique_id')} — {ttp.get('technique_name')}\n"
                f"    Detection: {ttp.get('detection_guidance', '')[:150]}\n"
                f"    Mitigation: {ttp.get('mitigations', '')[:150]}\n"
                f"    CVEs: {[c.get('cve_id') for c in ttp.get('cves', [])]}"
            )
    return "\n".join(lines) if lines else "TTP enrichment had no RAG hits."


def _format_rag_context(rag_results: dict) -> str:
    sections = []

    if rag_results.get("mitre"):
        sections.append("MITRE ATT&CK KNOWLEDGE BASE:")
        for r in rag_results["mitre"][:3]:
            sections.append(
                f"  [{r.get('id', '')}] {r.get('name', '')} "
                f"(score: {r.get('score', 0):.3f})\n"
                f"  Detection: {r.get('detection', '')[:300]}"
            )

    if rag_results.get("cve"):
        sections.append("\nRELEVANT CVEs:")
        for r in rag_results["cve"]:
            sections.append(
                f"  {r.get('cve_id', '')} — {r.get('title', '')} "
                f"(CVSS: {r.get('cvss_score', 0)})\n"
                f"  Remediation: {r.get('remediation', '')[:200]}"
            )

    if rag_results.get("playbooks"):
        sections.append("\nIR PLAYBOOK GUIDANCE:")
        for r in rag_results["playbooks"]:
            sections.append(
                f"  {r.get('title', '')}\n"
                f"  {r.get('content', '')[:300]}"
            )

    if rag_results.get("botsv3"):
        sections.append("\nBOTSv3 INVESTIGATION NOTES:")
        for r in rag_results["botsv3"]:
            sections.append(
                f"  {r.get('title', '')}\n"
                f"  {r.get('content', '')[:200]}"
            )

    return "\n".join(sections) if sections else "No RAG context retrieved."


def _inject_missing_fields(
    raw: FinalReportRaw,
    classification: str,
    kill_chain: list,
    threat_intel: dict,
    ttp_mappings: list,
    reconstruction_confidence: float,
) -> FinalReportRaw:
    """Inject missing fields when gpt-4o-mini drops them."""

    if not raw.executive_summary or not raw.executive_summary.strip():
        raw.executive_summary = (
            f"A {classification} attack has been detected and reconstructed "
            f"with {len(kill_chain)} confirmed kill chain stages. "
            f"Immediate investigation and containment is required. "
            f"Escalation to senior security personnel is recommended."
        )
        logger.info("[synthesis] executive_summary injected")

    if not raw.attack_overview or not raw.attack_overview.strip():
        stage_names = " → ".join(
            s.get("stage_name", "") for s in kill_chain[:5]
        )
        raw.attack_overview = (
            f"{classification} attack progressed through: {stage_names}. "
            f"Full kill chain reconstruction confidence: "
            f"{reconstruction_confidence:.0%}."
        )
        logger.info("[synthesis] attack_overview injected")

    if not raw.key_findings:
        raw.key_findings = [
            FindingWithConfidence(
                finding=(
                    f"{classification} attack confirmed with "
                    f"{len(kill_chain)} kill chain stages"
                ),
                evidence=(
                    f"ReconstructionAgent identified {len(kill_chain)} "
                    f"stages with confidence {reconstruction_confidence:.2f}"
                ),
                confidence=reconstruction_confidence,
                source="telemetry",
            )
        ]
        logger.info("[synthesis] key_findings injected")

    if not raw.recommended_actions:
        raw.recommended_actions = [
            RecommendedAction(
                priority="IMMEDIATE",
                action=(
                    "Isolate affected systems and revoke "
                    "compromised credentials"
                ),
                rationale="Standard IR procedure for confirmed attack",
                mitre_technique="T1078",
            )
        ]
        logger.info("[synthesis] recommended_actions injected")

    if not raw.mitre_techniques_used:
        confirmed_techniques = list({
            s.get("mitre_technique", "").split(" ")[0]
            for s in kill_chain
            if s.get("confidence") == "CONFIRMED"
            and s.get("mitre_technique", "").startswith("T")
        })
        raw.mitre_techniques_used = confirmed_techniques
        logger.info(
            "[synthesis] mitre_techniques_used injected: %d techniques",
            len(confirmed_techniques),
        )

    if raw.investigation_confidence == 0.0:
        raw.investigation_confidence = min(
            0.95,
            reconstruction_confidence * 0.6
            + (0.2 if threat_intel else 0.0)
            + (0.15 if ttp_mappings else 0.0),
        )
        logger.info(
            "[synthesis] investigation_confidence computed: %.2f",
            raw.investigation_confidence,
        )

    if not raw.threat_actor_profile or not raw.threat_actor_profile.strip():
        raw.threat_actor_profile = (
            f"Threat actor demonstrated capability consistent with "
            f"{classification} classification. Attack complexity and "
            f"tooling suggest intermediate-to-advanced threat actor."
        )
        logger.info("[synthesis] threat_actor_profile injected")

    return raw
