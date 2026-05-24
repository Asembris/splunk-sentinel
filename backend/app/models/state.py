"""
state.py
--------
Defines the shared AgentState TypedDict used throughout the LangGraph
investigation pipeline for Splunk Sentinel.

Each field is populated by a specific agent in the graph.  Fields that are
not yet populated default to sensible empty values so that early nodes can
always read the state safely.
"""

from __future__ import annotations

from typing import TypedDict


class AgentState(TypedDict, total=False):
    """
    Shared state that flows through every node of the LangGraph
    investigation pipeline.

    All fields use ``total=False`` so that nodes can update only the
    subset of fields they are responsible for without needing to pass
    the full dictionary on every transition.
    """

    # ── Investigation identity ────────────────────────────────────────────────
    investigation_id: str
    """Unique identifier for this investigation run (UUID4)."""

    trigger: str
    """The alert text, user prompt, or detection rule that started this investigation."""

    # ── Temporal scope ────────────────────────────────────────────────────────
    attack_window: dict
    """
    High-level time window of the attack, e.g.:
    {
        "start":       "2018-08-20 12:00",
        "end":         "2018-08-24 23:00",
        "peak_hour":   "2018-08-21 03:00",
        "peak_count":  18423,
        "total_events": 2083056
    }
    Populated by TriageAgent via SplunkClient.get_attack_window().
    """

    # ── Source attribution ────────────────────────────────────────────────────
    top_source_ips: list[dict]
    """
    Ranked list of source IPs by event volume, e.g.:
    [{"ip": "10.0.2.106", "event_count": 45312}, ...]
    Populated by TriageAgent via SplunkClient.get_top_source_ips().
    """

    # ── Classification ────────────────────────────────────────────────────────
    attack_classification: str
    """
    Coarse attack category.
    One of: "APT" | "RANSOMWARE" | "INSIDER" | "DDOS" | "UNKNOWN"
    """

    classification_confidence: float
    """LLM-assigned confidence for the classification. Range: 0.0 – 1.0."""

    severity: str
    """Assessed severity of the incident: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"."""

    triage_summary: str
    """Human-readable 2-3 sentence assessment produced by TriageAgent."""

    key_indicators: list[str]
    """3-5 specific telemetry data points cited as evidence for the classification."""

    # ── Kill-chain reconstruction ──────────────────────────────────────────────
    kill_chain: list[dict]
    """
    Chronological MITRE ATT&CK kill-chain stages, e.g.:
    [{
        "stage_number": 1,
        "stage_name": "Initial Access",
        "mitre_tactic": "TA0001",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "timestamp": "2018-08-20 12:34:56",
        "evidence": "src_ip 10.0.x.x queried 169.254.169.254 73 times",
        "confidence": "CONFIRMED",
        "affected_assets": ["172.16.0.178"]
    }, ...]
    Populated by ReconstructionAgent.
    """

    # ── Patient-zero attribution ──────────────────────────────────────────────
    patient_zero: dict
    """
    The first compromised host / initial attacker IP, e.g.:
    {
        "ip_address": "192.168.3.130",
        "first_seen": "2018-08-20 12:34:56",
        "role": "External Attacker",
        "evidence": "Earliest stream:http request to internal web server",
        "confidence": "CONFIRMED"
    }
    Populated by ReconstructionAgent.
    """

    # ── Blast-radius assessment ───────────────────────────────────────────────
    blast_radius: dict
    """
    Full scope of assets touched by the attack, e.g.:
    {
        "total_affected_ips": 4,
        "internal_ips_affected": ["172.16.0.178"],
        "external_ips_observed": ["192.168.3.130"],
        "affected_sourcetypes": ["stream:http", "WinEventLog:Security"],
        "data_at_risk": "AWS IAM credentials, internal web server",
        "containment_priority": "IMMEDIATE"
    }
    Populated by ReconstructionAgent.
    """

    # ── Attack narrative ──────────────────────────────────────────────────────
    attack_narrative: str
    """
    2-3 sentence plain English summary of the full attack produced by
    ReconstructionAgent, suitable for executive briefing.
    """

    # ── Reconstruction confidence ─────────────────────────────────────────────
    reconstruction_confidence: float
    """
    Overall confidence in the kill chain reconstruction. Range: 0.0 – 0.95.
    Capped at 0.95 to reflect forensic uncertainty.
    Populated by ReconstructionAgent.
    """

    confidence_breakdown: dict
    """Explainable confidence score factors and weighted contributions."""

    react_iterations: int
    """Number of ReAct iterations completed by ReconstructionAgent."""

    # ── Threat intelligence ───────────────────────────────────────────────────
    threat_intel: dict
    """
    External threat-intel enrichment (IP reputation, hashes, CVEs), e.g.:
    {"ioc_hits": [...], "cve_matches": [...]}
    Populated by ThreatIntelAgent (future node).
    """

    # ── MITRE ATT&CK mapping ──────────────────────────────────────────────────
    ttp_mappings: list[dict]
    """
    Mapped MITRE ATT&CK techniques, e.g.:
    [{"technique_id": "T1566.001", "technique_name": "Spear-phishing Attachment",
      "tactic": "Initial Access", "evidence": "..."}]
    Populated by TTPAgent (future node).
    """

    mltk_ttp_validation: dict
    """MLTK ai command validation summary for TTPAgent mappings."""

    rag_context: dict
    """
    Consolidated RAG retrieval results (MITRE, CVE, Playbooks, BOTSv3).
    Populated by SynthesisAgent (future node) — default {}.
    """

    # ── Confidence tracking ───────────────────────────────────────────────────
    confidence_scores: dict[str, float]
    """
    Per-finding confidence keyed by agent name, e.g.:
    {"triage": 0.82, "patient_zero": 0.74, "blast_radius": 0.61}
    """

    # ── Final report ──────────────────────────────────────────────────────────
    final_report: dict
    """
    Consolidated investigation report, e.g.:
    {"executive_summary": "...", "technical_details": {...}, "recommendations": [...]}
    Populated by ReportAgent (future node).
    """

    investigation_confidence: float
    """Final investigation confidence mirrored from final_report for API clients."""

    report_pdf_path: str
    """Path to generated PDF."""

    supabase_record_id: str
    """Supabase UUID."""

    splunk_notable_event_id: str
    """Splunk write-back ID."""

    # ── Escalation flag ───────────────────────────────────────────────────────
    escalate_to_human: bool
    """
    Set to True when overall confidence falls below 0.5, indicating that a
    human analyst should review the findings before any automated response.
    """

    # ── Error tracking ────────────────────────────────────────────────────────
    error: str | None
    """
    Human-readable error message if a node encounters an unrecoverable failure.
    The graph routes to END when this is not None.
    """

    # ── Triage Rich Context ───────────────────────────────────────────────────
    sourcetype_distribution: list[dict]
    """Top 15 sourcetypes by event count."""

    auth_failures: list[dict]
    """Top 10 authentication failures (EventCode 4625) by src_ip and Account_Name."""

    external_ips: list[dict]
    """Top 5 external source IPs in stream:http traffic."""

    # ── Audit trail ───────────────────────────────────────────────────────────
    spl_audit_log: list[str]
    """
    Chronological list of every SPL query executed during the investigation,
    including timestamps.  Used for compliance, debugging, and transparency.
    """

    slo_report: dict          # SLO compliance report from slo_engine
    slo_breaches: list        # List of SLO breach messages

    prompt_injection_attempts: int   # count of injection patterns found
    sanitization_log: list           # detailed sanitization event log

    counterfactual_reasoning: dict  # why alternatives were ruled out
    narrative: dict                 # synthesized narrative section
    structured_findings: dict       # synthesized structured findings
    counterfactual: dict            # synthesized counterfactual payload
    synthesis_degraded: bool        # synthesis fallback indicator
    degraded_sections: list[str]    # synthesis sections that degraded

    containment_plan: dict
    """
    Phased remediation plan produced by SynthesisAgent.
    See app.models.containment for structure.
    """
