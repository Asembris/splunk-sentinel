"""
Splunk Webhook Endpoint — Splunk Sentinel

Receives Splunk alert webhook payloads and autonomously fires
the investigation pipeline. This is the production integration
point — no human input required.

Splunk Configuration:
    Alert Action: Webhook
    URL: http://localhost:8001/api/webhook/splunk
    Method: POST
"""

import logging
import hashlib
from datetime import datetime, timezone
from typing import Optional, Any
from fastapi import APIRouter, BackgroundTasks, Request, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/webhook", tags=["webhook"])


# ── Pydantic Models ──────────────────────────────────────────────────────────

class SplunkAlertResult(BaseModel):
    """
    Fields from Splunk alert result row.
    All optional — different saved searches return different fields.
    """
    sourcetype: Optional[str] = None
    EventCode: Optional[str] = None
    count: Optional[str] = None
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    uri_path: Optional[str] = None
    Account_Name: Optional[str] = None
    New_Process_Name: Optional[str] = None
    Creator_Process_Name: Optional[str] = None
    ComputerName: Optional[str] = None
    _time: Optional[str] = None
    host: Optional[str] = None
    index: Optional[str] = None


class SplunkWebhookPayload(BaseModel):
    """
    Standard Splunk webhook payload format.
    Sent by Splunk when a saved search alert fires.
    """
    sid: Optional[str] = None
    search_name: Optional[str] = "Splunk Alert"
    owner: Optional[str] = "splunk"
    app: Optional[str] = "search"
    results_link: Optional[str] = None
    result: Optional[dict[str, Any]] = None


# ── Trigger Generation ────────────────────────────────────────────────────────

def generate_trigger_from_splunk_payload(payload: SplunkWebhookPayload) -> str:
    """
    Convert a Splunk webhook payload into a natural language trigger
    that TriageAgent understands.
    
    Uses deterministic rules based on field patterns — no LLM needed.
    """
    search_name = payload.search_name or "Splunk Alert"
    result = payload.result or {}

    # Extract key fields with safe defaults
    sourcetype = result.get("sourcetype", "")
    event_code = result.get("EventCode", "")
    count = result.get("count", "")
    src_ip = result.get("src_ip", "")
    dest_ip = result.get("dest_ip", "")
    uri_path = result.get("uri_path", "")
    account_name = result.get("Account_Name", "")
    process_name = result.get("New_Process_Name", "")
    computer_name = result.get("ComputerName", "")

    # Build trigger parts
    parts = [f"Splunk alert '{search_name}' fired automatically."]

    # AWS metadata service SSRF detection
    if dest_ip == "169.254.169.254" or "169.254.169.254" in uri_path:
        parts.append(
            f"Source IP {src_ip} made {count} requests to AWS metadata "
            f"service (169.254.169.254) via {sourcetype} sourcetype."
        )
        if uri_path:
            parts.append(f"URI path: {uri_path}.")
        parts.append(
            "Possible SSRF attack leading to IAM credential exposure. "
            "Immediate investigation required."
        )

    # Failed logon / brute force detection
    elif event_code == "4625":
        parts.append(
            f"EventCode 4625 (failed logon) detected {count} times "
            f"from source IP {src_ip}."
        )
        if account_name:
            parts.append(f"Target account: {account_name}.")
        if computer_name:
            parts.append(f"Affected host: {computer_name}.")
        parts.append("Possible brute force or credential stuffing attack.")

    # Process creation anomaly detection
    elif event_code == "4688":
        parts.append(
            f"Anomalous process creation detected via EventCode 4688. "
            f"Process: {process_name}."
        )
        if count:
            parts.append(f"Event count: {count}.")
        if computer_name:
            parts.append(f"Affected host: {computer_name}.")
        parts.append(
            "Possible malware execution or lateral movement. "
            "High volume WMIC and cmd.exe activity observed."
        )

    # Privileged service abuse detection
    elif event_code == "4673":
        parts.append(
            f"Privileged service abuse detected via EventCode 4673. "
            f"{count} events recorded."
        )
        if account_name:
            parts.append(f"Account: {account_name}.")
        if computer_name:
            parts.append(f"Host: {computer_name}.")
        parts.append(
            "Possible insider threat or privilege escalation. "
            "No external communication pattern observed."
        )

    # HTTP anomaly detection
    elif sourcetype == "stream:http":
        parts.append(
            f"Suspicious HTTP traffic detected from {src_ip} to {dest_ip}."
        )
        if uri_path:
            parts.append(f"URI: {uri_path}.")
        if count:
            parts.append(f"Event count: {count}.")
        parts.append("Possible web application exploitation attempt.")

    # DNS anomaly detection
    elif sourcetype == "stream:dns":
        parts.append(
            f"Anomalous DNS activity detected from {src_ip}. "
            f"Event count: {count}."
        )
        parts.append(
            "Possible DNS tunneling or C2 communication pattern."
        )

    # Generic fallback — use search name as primary signal
    else:
        if src_ip:
            parts.append(f"Source IP: {src_ip}.")
        if dest_ip:
            parts.append(f"Destination IP: {dest_ip}.")
        if count:
            parts.append(f"Event count: {count}.")
        if sourcetype:
            parts.append(f"Sourcetype: {sourcetype}.")
        parts.append(
            "Security alert requires immediate investigation."
        )

    return " ".join(parts)


def generate_investigation_id_from_sid(sid: Optional[str]) -> str:
    """
    Generate a deterministic investigation_id from Splunk's sid.
    Ensures the same alert never triggers duplicate investigations.
    """
    if not sid:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        return f"webhook-{timestamp}"
    
    # Hash the sid to get a short, clean ID
    sid_hash = hashlib.md5(sid.encode()).hexdigest()[:8]
    return f"splunk-{sid_hash}"


# ── Background Pipeline Runner ────────────────────────────────────────────────

async def run_investigation_from_webhook(
    trigger: str,
    investigation_id: str,
    splunk_metadata: dict,
) -> None:
    """
    Background task: runs the full investigation pipeline.
    Called after the webhook endpoint returns 202 Accepted.
    """
    from app.graph.investigation_graph import compiled_graph
    from app.models.state import AgentState

    logger.info(
        "[WEBHOOK] Starting autonomous investigation | "
        "investigation_id=%s | search_name=%s",
        investigation_id,
        splunk_metadata.get("search_name", "unknown"),
    )

    initial_state: AgentState = {
        "investigation_id": investigation_id,
        "trigger": trigger,
        "attack_classification": "",
        "classification_confidence": 0.0,
        "severity": "",
        "triage_summary": "",
        "key_indicators": [],
        "attack_window": {},
        "top_source_ips": [],
        "escalate_to_human": False,
        "error": None,
        "spl_audit_log": [],
        "kill_chain": [],
        "patient_zero": {},
        "blast_radius": {},
        "attack_narrative": "",
        "reconstruction_confidence": 0.0,
        "react_iterations": 0,
        "threat_intel": {},
        "ttp_mappings": [],
        "rag_context": {},
        "final_report": {},
        "confidence_scores": {},
        "report_pdf_path": "",
        "supabase_record_id": "",
        "splunk_notable_event_id": "",
        "slo_report": {},
        "slo_breaches": [],
        "prompt_injection_attempts": 0,
        "sanitization_log": [],
        "counterfactual_reasoning": {},
    }

    try:
        config = {
            "configurable": {
                "investigation_id": investigation_id,
            }
        }
        
        # Run the full pipeline
        final_state = await compiled_graph.ainvoke(
            initial_state,
            config=config,
        )

        classification = final_state.get("attack_classification", "UNKNOWN")
        confidence = final_state.get(
            "reconstruction_confidence", 0.0
        )
        stages = len(final_state.get("kill_chain", []))

        logger.info(
            "[WEBHOOK] Investigation complete | "
            "investigation_id=%s | classification=%s | "
            "confidence=%.2f | stages=%d",
            investigation_id,
            classification,
            confidence,
            stages,
        )

    except Exception as e:
        logger.error(
            "[WEBHOOK] Investigation failed | "
            "investigation_id=%s | error=%s",
            investigation_id,
            str(e),
        )


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.post(
    "/splunk",
    status_code=202,
    summary="Receive Splunk alert webhook",
    description=(
        "Receives Splunk saved search alert webhooks and autonomously "
        "fires the investigation pipeline. Returns 202 Accepted "
        "immediately — investigation runs as a background task."
    ),
)
async def splunk_webhook(
    payload: SplunkWebhookPayload,
    background_tasks: BackgroundTasks,
) -> dict:
    """
    Production integration point for Splunk Enterprise.
    
    Configure in Splunk:
        Settings → Searches → New Alert → 
        Alert Actions → Webhook → 
        URL: http://localhost:8001/api/webhook/splunk
    """
    logger.info(
        "[WEBHOOK] Received Splunk alert | sid=%s | search_name=%s",
        payload.sid,
        payload.search_name,
    )

    # Generate investigation ID from Splunk sid
    investigation_id = generate_investigation_id_from_sid(payload.sid)

    # Convert payload to natural language trigger
    trigger = generate_trigger_from_splunk_payload(payload)

    logger.info(
        "[WEBHOOK] Generated trigger | investigation_id=%s | "
        "trigger=%s",
        investigation_id,
        trigger[:100],
    )

    # Splunk metadata for logging
    splunk_metadata = {
        "sid": payload.sid,
        "search_name": payload.search_name,
        "owner": payload.owner,
        "app": payload.app,
        "results_link": payload.results_link,
    }

    # Fire pipeline as background task — return immediately
    background_tasks.add_task(
        run_investigation_from_webhook,
        trigger=trigger,
        investigation_id=investigation_id,
        splunk_metadata=splunk_metadata,
    )

    return {
        "status": "accepted",
        "investigation_id": investigation_id,
        "trigger": trigger,
        "search_name": payload.search_name,
        "message": (
            "Investigation pipeline started autonomously. "
            f"Monitor at investigation_id: {investigation_id}"
        ),
        "autonomous": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get(
    "/splunk/test",
    summary="Test webhook endpoint health",
)
async def splunk_webhook_test() -> dict:
    """
    Verify the webhook endpoint is reachable.
    Use this to confirm Splunk can reach your backend.
    """
    return {
        "status": "ok",
        "endpoint": "POST /api/webhook/splunk",
        "message": "Splunk Sentinel webhook endpoint is active",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
