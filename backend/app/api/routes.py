"""
routes.py
---------
FastAPI router for Splunk Sentinel's investigation API.

Endpoints:
  POST /api/investigate   — start a new investigation (JSON or SSE stream)
  GET  /api/health        — liveness + Splunk connectivity check
  GET  /api/audit-log     — tail the last 100 lines of the SPL audit log
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from pathlib import Path
from typing import AsyncGenerator

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from app.graph.investigation_graph import compiled_graph
from app.models.state import AgentState
from app.tools.splunk_tools import SplunkClient
from app.services.supabase_client import (
    update_feedback,
    get_investigation_history,
    get_investigation_details
)
from app.utils.audit_chain import verify_chain

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")

AUDIT_LOG_PATH = Path("logs") / "spl_audit.log"


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class InvestigateRequest(BaseModel):
    """Body for POST /api/investigate."""

    trigger: str = Field(
        ...,
        description="The alert text, detection rule, or analyst prompt that initiated the investigation.",
        min_length=1,
    )
    investigation_id: str | None = Field(
        default=None,
        description="Optional caller-supplied investigation ID. Auto-generated if omitted.",
    )


class HealthResponse(BaseModel):
    """Response for GET /api/health."""

    status: str
    splunk_connected: bool
    splunk_version: str


class FeedbackRequest(BaseModel):
    """Body for POST /api/investigations/{id}/feedback."""

    rating: str = Field(..., description="'helpful' | 'unhelpful' | 'needs_tuning'")
    notes: str = Field("", description="Optional analyst notes.")


# ---------------------------------------------------------------------------
# Helper: stream graph progress as SSE events
# ---------------------------------------------------------------------------


async def _stream_investigation(initial_state: AgentState) -> AsyncGenerator[dict, None]:
    """
    Stream investigation progress as Server-Sent Events.

    Yields:
        - 'progress' events when graph nodes complete
        - 'reconstruction_progress' events during ReAct iterations
        - 'complete' event with final full state
    """
    investigation_id = initial_state.get("investigation_id", "unknown")
    queue = asyncio.Queue()
    final_state_container = {}

    async def progress_callback(event_data):
        # This is called from inside the ReconstructionAgent ReAct loop
        await queue.put(event_data)

    async def run_graph():
        try:
            async for chunk in compiled_graph.astream(
                initial_state, 
                config={
                    "run_name": "Investigation Pipeline",
                    "configurable": {"progress_callback": progress_callback}
                }
            ):
                for node_name, node_state in chunk.items():
                    final_state_container.update(node_state)
                    await queue.put({
                        "event": "progress",
                        "stage": node_name,
                        "investigation_id": investigation_id,
                        "attack_classification": node_state.get("attack_classification"),
                        "classification_confidence": node_state.get("classification_confidence"),
                        "error": node_state.get("error"),
                    })
            await queue.put({"event": "complete"})
        except Exception as e:
            logger.error("[%s] Graph error in SSE: %s", investigation_id, e)
            await queue.put({"event": "error", "error": str(e)})

    # Start investigation in background
    task = asyncio.create_task(run_graph())

    # Initial start event
    yield {
        "event": "progress",
        "data": json.dumps({"stage": "started", "investigation_id": investigation_id})
    }

    while True:
        item = await queue.get()
        event_type = item.get("event")

        if event_type == "complete":
            await task
            yield {
                "event": "complete",
                "data": json.dumps(final_state_container)
            }
            break
        elif event_type == "error":
            yield {
                "event": "error",
                "data": json.dumps({
                    "error": item.get("error"),
                    "investigation_id": investigation_id
                })
            }
            break
        else:
            # Emit progress or reconstruction_progress
            yield {
                "event": event_type,
                "data": json.dumps(item)
            }


# ---------------------------------------------------------------------------
# POST /api/investigate
# ---------------------------------------------------------------------------


@router.post("/investigate", summary="Start a security investigation")
async def investigate(request: Request, body: InvestigateRequest):
    """
    Launch a new security investigation using the LangGraph pipeline.

    If the client sends ``Accept: text/event-stream``, the endpoint streams
    per-node progress updates as Server-Sent Events, then a final ``complete``
    event with the full state.

    Otherwise, it awaits the entire graph and returns the final AgentState
    as a JSON response.

    Args:
        request: FastAPI Request (used to inspect the Accept header).
        body:    InvestigateRequest with trigger text and optional ID.

    Returns:
        Full AgentState as JSON, or an SSE stream.

    Raises:
        HTTPException 500 if the graph raises an unhandled exception.
    """
    investigation_id = body.investigation_id or str(uuid.uuid4())
    logger.info(
        "Investigation requested | id=%s | trigger=%r",
        investigation_id,
        body.trigger[:80],
    )

    initial_state: AgentState = {
        "investigation_id": investigation_id,
        "trigger": body.trigger,
        "attack_window": {},
        "top_source_ips": [],
        "attack_classification": "UNKNOWN",
        "classification_confidence": 0.0,
        "triage_summary": "",
        "kill_chain": [],
        "patient_zero": {},
        "blast_radius": {},
        "threat_intel": {},
        "ttp_mappings": [],
        "confidence_scores": {},
        "final_report": {},
        "escalate_to_human": False,
        "report_pdf_path": "",
        "supabase_record_id": "",
        "splunk_notable_event_id": "",
        "error": None,
        "spl_audit_log": [],
        "slo_report": {},
        "slo_breaches": [],
        "prompt_injection_attempts": 0,
        "sanitization_log": [],
    }

    accept_header = request.headers.get("Accept", "")
    if "text/event-stream" in accept_header:
        return EventSourceResponse(
            _stream_investigation(initial_state),
            media_type="text/event-stream",
            ping=15,
            headers={
                "Cache-Control": "no-cache, no-transform",
                "X-Accel-Buffering": "no",
            }
        )

    # Non-streaming path: await full graph execution
    try:
        final_state: AgentState = await compiled_graph.ainvoke(
            initial_state,
            config={"run_name": "Triage Agent"}
        )
    except Exception as exc:
        logger.error(
            "Graph execution failed | id=%s | error=%s",
            investigation_id,
            exc,
            exc_info=True,
        )
        raise HTTPException(
            status_code=500,
            detail={"error": str(exc), "investigation_id": investigation_id},
        ) from exc

    logger.info(
        "Investigation complete | id=%s | classification=%s | "
        "confidence=%.2f | stages=%d | patient_zero=%s | containment=%s | slo=%s",
        final_state.get("investigation_id"),
        final_state.get("attack_classification"),
        final_state.get("classification_confidence", 0.0),
        len(final_state.get("kill_chain", [])),
        final_state.get("patient_zero", {}).get("ip_address", "N/A"),
        final_state.get("blast_radius", {}).get("containment_priority", "N/A"),
        final_state.get("slo_report", {}).get("overall_slo_status", "N/A"),
    )
    return JSONResponse(content=final_state)



# ---------------------------------------------------------------------------
# GET /api/health
# ---------------------------------------------------------------------------


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness and Splunk connectivity check",
)
async def health_check() -> HealthResponse:
    """
    Return the service liveness status and Splunk connectivity.

    Actually establishes a Splunk connection on each call to verify that
    the credentials and host are reachable — not just an in-memory flag.

    Returns:
        HealthResponse with ``status``, ``splunk_connected``, and
        ``splunk_version`` fields.
    """
    splunk_connected = False
    splunk_version = "unknown"

    try:
        loop = asyncio.get_event_loop()
        splunk = await loop.run_in_executor(None, SplunkClient)
        splunk_version = splunk.service.info.get("version", "unknown")
        splunk_connected = True
    except Exception as exc:
        logger.warning("Health check: Splunk unreachable — %s", exc)

    return HealthResponse(
        status="ok",
        splunk_connected=splunk_connected,
        splunk_version=splunk_version,
    )


# ---------------------------------------------------------------------------
# GET /api/audit-log
# ---------------------------------------------------------------------------


@router.get("/audit-log", summary="Tail the SPL audit log")
async def get_audit_log():
    """
    Return the last 100 lines of the SPL audit log file.

    The audit log records every SPL query executed by Splunk Sentinel,
    with UTC timestamps, for compliance and forensic review.

    Returns:
        JSON with ``lines`` (list of strings) and ``total_lines`` (int).

    Raises:
        HTTPException 404 if the audit log file does not yet exist.
    """
    if not AUDIT_LOG_PATH.exists():
        raise HTTPException(
            status_code=404,
            detail="Audit log not found. No searches have been executed yet.",
        )

    try:
        all_lines = AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines()
        last_100 = all_lines[-100:] if len(all_lines) > 100 else all_lines
    except OSError as exc:
        logger.error("Failed to read audit log: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Could not read audit log: {exc}",
        ) from exc

    return {"lines": last_100, "total_lines": len(all_lines)}


@router.get("/audit-log/verify-latest", summary="Verify the latest SPL audit chain")
async def verify_latest_audit_chain():
    """
    Verify the integrity of the hash-chained SPL audit log for the most recent investigation.
    """
    history = await get_investigation_history(limit=1)
    if not history:
        raise HTTPException(status_code=404, detail="No investigations found")
    
    latest_id = history[0].get("investigation_id")
    data = await get_investigation_details(latest_id)
    if not data:
        raise HTTPException(status_code=404, detail="Investigation details not found")
    
    audit_log = data.get("report_json", {}).get("spl_audit_log", [])
    result = verify_chain(audit_log)
    return {**result, "investigation_id": latest_id}


@router.get("/audit-log/verify/{investigation_id}", summary="Verify the SPL audit chain")
async def verify_audit_chain(investigation_id: str):
    """
    Verify the integrity of the hash-chained SPL audit log for a specific investigation.
    """
    data = await get_investigation_details(investigation_id)
    if not data:
        raise HTTPException(status_code=404, detail="Investigation not found")
    
    audit_log = data.get("report_json", {}).get("spl_audit_log", [])
    result = verify_chain(audit_log)
    return result


# ---------------------------------------------------------------------------
# Investigation Persistence & Reporting
# ---------------------------------------------------------------------------


@router.get("/investigations/history", summary="Get investigation history")
async def history():
    """
    Fetch investigation history from Supabase.
    """
    data = await get_investigation_history(limit=50)
    return {"investigations": data}


@router.get("/investigations/{investigation_id}", summary="Get investigation details")
async def get_investigation(investigation_id: str):
    """
    Fetch a single investigation's full state from Supabase.
    """
    data = await get_investigation_details(investigation_id)
    if not data:
        raise HTTPException(status_code=404, detail="Investigation not found")
    
    # Map Supabase record back to AgentState-like structure for the frontend
    # The frontend expects state.result.final_report
    return {
        "investigation_id": data.get("investigation_id"),
        "attack_classification": data.get("classification"),
        "classification_confidence": data.get("confidence"),
        "severity": data.get("severity"),
        "trigger": data.get("trigger_text"),
        "kill_chain": [{} for _ in range(data.get("kill_chain_stages", 0))],
        "final_report": data.get("report_json"),
        "report_pdf_path": data.get("pdf_path"),
        "splunk_notable_event_id": data.get("splunk_notable_id"),
        "escalate_to_human": data.get("escalate_to_human"),
        "spl_audit_log": data.get("spl_audit_log", []),
    }


@router.post("/investigations/{investigation_id}/feedback", summary="Submit analyst feedback")
async def feedback(investigation_id: str, body: FeedbackRequest):
    """
    Submit qualitative feedback for a completed investigation.
    """
    success = await update_feedback(
        investigation_id=investigation_id,
        rating=body.rating,
        notes=body.notes
    )
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update feedback")
    return {"status": "ok"}


@router.get("/investigations/{investigation_id}/report/pdf", summary="Download PDF report")
async def download_report(investigation_id: str):
    """
    Download the generated PDF report for an investigation.
    """
    pdf_path = Path("reports") / f"{investigation_id}.pdf"
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="Report PDF not found")
    
    return FileResponse(
        path=pdf_path,
        filename=f"sentinel_report_{investigation_id}.pdf",
        media_type="application/pdf"
    )


@router.get("/slo/status")
async def get_slo_status() -> dict:
    """
    Aggregate SLO compliance across recent investigations.
    Reads from Supabase investigations table.
    Shows what percentage of investigations met each SLO.
    """
    from app.services.supabase_client import get_supabase_client
    from datetime import datetime, timezone

    try:
        client = get_supabase_client()
        response = (
            client.table("investigations")
            .select("report_json")
            .order("created_at", desc=True)
            .limit(20)
            .execute()
        )

        records = response.data or []
        total = len(records)

        if total == 0:
            return {
                "investigations_analyzed": 0,
                "message": "No investigations found",
            }

        # Extract SLO reports from report_json
        slo_reports = []
        for record in records:
            report_json = record.get("report_json", {})
            slo = report_json.get("slo_report", {})
            if slo:
                slo_reports.append(slo)

        if not slo_reports:
            return {
                "investigations_analyzed": total,
                "message": (
                    "No SLO reports found — "
                    "investigations may predate SLO enforcement"
                ),
            }

        # Calculate compliance rates
        def pct(met_count: int, total: int) -> str:
            return f"{round(met_count / total * 100)}%"

        time_met = sum(
            1 for s in slo_reports
            if s.get("slo_1_time", {}).get("met", False)
        )
        token_met = sum(
            1 for s in slo_reports
            if s.get("slo_2_tokens", {}).get("met", False)
        )
        confidence_met = sum(
            1 for s in slo_reports
            if s.get("slo_3_confidence", {}).get("met", False)
        )
        all_met = sum(
            1 for s in slo_reports
            if s.get("overall_slo_status") == "ALL_MET"
        )

        n = len(slo_reports)

        # Average actual times
        avg_time = round(
            sum(
                s.get("slo_1_time", {}).get("actual_seconds", 0)
                for s in slo_reports
            ) / n,
            1,
        )
        avg_tokens = round(
            sum(
                s.get("slo_2_tokens", {}).get("actual_tokens", 0)
                for s in slo_reports
            ) / n,
        )
        avg_confidence = round(
            sum(
                s.get("slo_3_confidence", {}).get("actual", 0)
                for s in slo_reports
            ) / n,
            3,
        )

        return {
            "investigations_analyzed": n,
            "slo_1_time_compliance": pct(time_met, n),
            "slo_2_token_compliance": pct(token_met, n),
            "slo_3_confidence_compliance": pct(confidence_met, n),
            "overall_compliance": pct(all_met, n),
            "averages": {
                "investigation_time_seconds": avg_time,
                "reconstruction_tokens": avg_tokens,
                "final_confidence": avg_confidence,
            },
            "budgets": {
                "time_budget_seconds": 120,
                "token_budget": 45000,
                "confidence_floor": 0.50,
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error("SLO status endpoint failed | error=%s", str(e))
        raise HTTPException(
            status_code=500,
            detail=f"SLO status retrieval failed: {str(e)}",
        )
