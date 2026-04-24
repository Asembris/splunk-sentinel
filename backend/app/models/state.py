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

    triage_summary: str
    """Human-readable 2-3 sentence assessment produced by TriageAgent."""

    # ── Kill-chain reconstruction ──────────────────────────────────────────────
    kill_chain: list[dict]
    """
    Causal event chain (ATT&CK kill-chain stages), e.g.:
    [{"stage": "Reconnaissance", "timestamp": "...", "evidence": "..."}, ...]
    Populated by ReconstructionAgent (future node).
    """

    # ── Patient-zero attribution ──────────────────────────────────────────────
    patient_zero: dict
    """
    The first compromised host/account, e.g.:
    {"host": "wrk-btun", "ip": "10.0.2.106", "first_seen": "...", "method": "..."}
    Populated by PatientZeroAgent (future node).
    """

    # ── Blast-radius assessment ───────────────────────────────────────────────
    blast_radius: dict
    """
    Scope of lateral movement and data exposure, e.g.:
    {"affected_hosts": [...], "exfil_bytes": 0, "lateral_moves": 3}
    Populated by BlastRadiusAgent (future node).
    """

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

    # ── Audit trail ───────────────────────────────────────────────────────────
    spl_audit_log: list[str]
    """
    Chronological list of every SPL query executed during the investigation,
    including timestamps.  Used for compliance, debugging, and transparency.
    """
