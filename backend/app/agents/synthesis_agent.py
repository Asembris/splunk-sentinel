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


class FinalReportRaw(BaseModel):
    """Relaxed model for gpt-4o-mini structured output."""
    executive_summary: str = ""
    attack_overview: str = ""
    key_findings: list[FindingWithConfidence] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    mitre_techniques_used: list[str] = Field(default_factory=list)
    cves_identified: list[str] = Field(default_factory=list)
    threat_actor_profile: str = ""
    investigation_confidence: float = 0.0


# ── System prompt ─────────────────────────────────────────────────────────────

_SYNTHESIS_SYSTEM_PROMPT = """You are a senior threat intelligence \
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
- Minimum 3 findings, maximum 8
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
"""


# ── LLM setup ─────────────────────────────────────────────────────────────────

_LLM = ChatOpenAI(model="gpt-4o-mini", temperature=0)
_LLM_STRUCTURED = _LLM.with_structured_output(FinalReportRaw)


# ── Main agent ────────────────────────────────────────────────────────────────

async def synthesis_agent(state: AgentState) -> AgentState:
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
    kill_chain_text = json.dumps(kill_chain, indent=2)

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

    # ── LLM call ──────────────────────────────────────────────────────────
    try:
        raw: FinalReportRaw = await _LLM_STRUCTURED.with_config({
            "run_name": "synthesis_llm_call",
            "metadata": {
                "investigation_id": investigation_id,
                "classification": classification,
                "kill_chain_stages": len(kill_chain),
                "ttp_mappings": len(ttp_mappings),
                "threat_intel_ips": len(threat_intel),
            }
        }).ainvoke([
            SystemMessage(content=_SYNTHESIS_SYSTEM_PROMPT),
            HumanMessage(content=synthesis_context),
        ])

    except Exception as exc:
        logger.error(
            "[%s] SynthesisAgent LLM call failed: %s",
            investigation_id, exc,
        )
        return {
            **state,
            "error": f"SynthesisAgent: LLM call failed — {exc}",
            "escalate_to_human": True,
        }

    # ── Field injection — gpt-4o-mini drops fields on complex schemas ──────
    raw = _inject_missing_fields(
        raw, classification, kill_chain, threat_intel,
        ttp_mappings, reconstruction_confidence
    )

    # ── Build final_report dict ────────────────────────────────────────────
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
        "investigation_confidence": raw.investigation_confidence,
        "patient_zero": patient_zero,
        "blast_radius": blast_radius,
        "attack_window": attack_window,
        "rag_sources_used": {
            "mitre_chunks": len(rag_results.get("mitre", [])),
            "cve_chunks": len(rag_results.get("cve", [])),
            "playbook_chunks": len(rag_results.get("playbooks", [])),
            "botsv3_chunks": len(rag_results.get("botsv3", [])),
        },
    }

    logger.info(
        "[%s] SynthesisAgent complete | findings=%d | actions=%d | "
        "techniques=%d | cves=%d | confidence=%.2f",
        investigation_id,
        len(raw.key_findings),
        len(raw.recommended_actions),
        len(raw.mitre_techniques_used),
        len(raw.cves_identified),
        raw.investigation_confidence,
    )

    return {
        **state,
        "final_report": final_report,
        "rag_context": rag_results,
        "error": None,
    }


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
                f"    Detection: {ttp.get('detection_guidance', '')[:200]}\n"
                f"    Mitigation: {ttp.get('mitigations', '')[:200]}\n"
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
                f"  {r.get('content', '')[:500]}"
            )

    if rag_results.get("botsv3"):
        sections.append("\nBOTSv3 INVESTIGATION NOTES:")
        for r in rag_results["botsv3"]:
            sections.append(
                f"  {r.get('title', '')}\n"
                f"  {r.get('content', '')[:300]}"
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
