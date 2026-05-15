"""
ReportAgent — Final node in the Splunk Sentinel investigation pipeline.

Responsibilities:
1. Generate PDF incident report (ReportLab)
2. Persist investigation to Supabase
3. Write notable event back to Splunk (4-tier confidence ladder)
4. Return updated state
"""
import json
import logging
from datetime import datetime, timezone

from app.models.state import AgentState
from app.services.pdf_generator import generate_pdf, get_confidence_tier
from app.services.supabase_client import persist_investigation
from app.tools.splunk_tools import SplunkClient
from app.services.slo_engine import get_monitor, cleanup_monitor

logger = logging.getLogger(__name__)


def _build_splunk_notable_event(state: AgentState) -> dict:
    """
    Build the Splunk notable event payload.
    Uses 4-tier confidence ladder (Vigil pattern).
    """
    final_report = state.get("final_report", {})
    # Try multiple confidence sources with fallback chain
    confidence = (
        float(final_report.get("investigation_confidence", 0.0))
        or float(state.get("reconstruction_confidence", 0.0))
        or float(state.get("classification_confidence", 0.0))
    )
    confidence_tier = get_confidence_tier(confidence)
    kill_chain = state.get("kill_chain", [])
    patient_zero = state.get("patient_zero", {})
    recommended_actions = final_report.get("recommended_actions", [])

    # Build kill chain summary (one line per stage)
    kill_chain_summary = " -> ".join([
        f"{s.get('stage_name', '')} ({s.get('mitre_technique', '')})"
        for s in kill_chain
    ])

    # Top 2 immediate actions
    immediate_actions = [
        a.get("action", "")
        for a in recommended_actions
        if a.get("priority") == "IMMEDIATE"
    ][:2]

    # Tier-based severity mapping
    tier_severity = {
        "AUTO_EXECUTE": "critical",
        "ANALYST_REVIEW": "high",
        "MONITOR": "medium",
        "ESCALATE_TO_HUMAN": "low",
    }

    return {
        "index": "sentinel_findings",
        "sourcetype": "sentinel:investigation",
        "source": "splunk_sentinel",
        "event": {
            "investigation_id": state.get("investigation_id"),
            "classification": state.get("attack_classification", "UNKNOWN"),
            "severity": state.get("severity", "UNKNOWN"),
            "reconstruction_confidence": round(confidence, 3),
            "confidence_pct": f"{round(confidence * 100)}%",
            "confidence_tier": confidence_tier,
            "splunk_severity": tier_severity.get(
                confidence_tier, "medium"
            ),
            "kill_chain_stages": len(kill_chain),
            "kill_chain_summary": kill_chain_summary,
            "patient_zero_ip": patient_zero.get("ip_address", ""),
            "patient_zero_first_seen": patient_zero.get(
                "first_seen", ""
            ),
            "containment_priority": state.get("blast_radius", {}).get(
                "containment_priority", "UNKNOWN"
            ),
            "immediate_actions": immediate_actions,
            "react_iterations": state.get("react_iterations", 0),
            "total_spl_queries": len(state.get("spl_audit_log", [])),
            "escalate_to_human": state.get("escalate_to_human", False),
            "executive_summary": final_report.get(
                "executive_summary", ""
            )[:500],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "sentinel_version": "1.0.0",
        },
    }


async def report_agent(state: AgentState, config=None) -> AgentState:
    """
    Final pipeline node. Generates PDF, persists to Supabase,
    writes notable event to Splunk.
    """
    investigation_id = state.get("investigation_id", "unknown")
    logger.info("[%s] ReportAgent starting", investigation_id)

    updates = {}

    # ── STEP 1: Generate SLO Compliance Report ───────────────────────
    try:
        final_confidence = (
            float(state.get("final_report", {}).get("investigation_confidence", 0.0))
            or float(state.get("reconstruction_confidence", 0.0))
            or float(state.get("classification_confidence", 0.0))
        )
        slo_monitor = get_monitor(investigation_id)
        slo_report = slo_monitor.generate_report(final_confidence)
        updates["slo_report"] = slo_report
        updates["slo_breaches"] = slo_report.get("slo_breaches", [])
        logger.info(
            "[%s] SLO report | status=%s | breaches=%d",
            investigation_id,
            slo_report.get("overall_slo_status"),
            slo_report.get("breaches_count", 0),
        )
    except Exception as e:
        logger.error("[%s] SLO report generation failed | error=%s", investigation_id, str(e))
        updates["slo_report"] = {}
        updates["slo_breaches"] = []

    # ── STEP 2: Generate PDF ─────────────────────────────────────────
    try:
        # Pass updates into generate_pdf so it has SLO data if needed
        pdf_path = generate_pdf({**state, **updates})
        updates["report_pdf_path"] = pdf_path
        logger.info("[%s] PDF generated | path=%s", investigation_id, pdf_path)
    except Exception as e:
        logger.error("[%s] PDF generation failed | error=%s", investigation_id, str(e))
        updates["report_pdf_path"] = ""

    # ── STEP 3: Persist to Supabase ──────────────────────────────────
    try:
        state_with_updates = {**state, **updates}
        record_id = await persist_investigation(state_with_updates)
        updates["supabase_record_id"] = record_id or ""
        logger.info("[%s] Supabase record created | record_id=%s", investigation_id, record_id)
    except Exception as e:
        logger.error("[%s] Supabase persistence failed | error=%s", investigation_id, str(e))
        updates["supabase_record_id"] = ""

    # ── STEP 4: Write Notable Event to Splunk ────────────────────────
    try:
        splunk = SplunkClient()
        notable_payload = _build_splunk_notable_event({**state, **updates})

        idx = splunk.service.indexes["sentinel_findings"]
        idx.submit(
            json.dumps(notable_payload["event"]),
            sourcetype="sentinel:investigation",
            host="splunk-sentinel",
        )

        notable_id = f"sentinel-{investigation_id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        updates["splunk_notable_event_id"] = notable_id
        logger.info("[%s] Splunk notable event written", investigation_id)
    except Exception as e:
        logger.error("[%s] Splunk write-back failed | error=%s", investigation_id, str(e))
        updates["splunk_notable_event_id"] = ""

    # ── FINAL: Cleanup ───────────────────────────────────────────────
    cleanup_monitor(investigation_id)

    logger.info(
        "[%s] ReportAgent complete | pdf=%s | supabase=%s | splunk=%s",
        investigation_id,
        "✓" if updates.get("report_pdf_path") else "✗",
        "✓" if updates.get("supabase_record_id") else "✗",
        "✓" if updates.get("splunk_notable_event_id") else "✗",
    )

    # Ensure we return at least one key to avoid LangGraph InvalidUpdateError
    if not updates:
        return {"slo_breaches": []}

    return updates
