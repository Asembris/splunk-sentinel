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
    get_investigation_count,
    get_investigation_details,
    persist_investigation,
    patch_containment_plan,
)
from app.utils.audit_chain import verify_chain
from app.models.containment import ContainmentPlan
from app.services.containment_engine import execute_phase_stream, rollback_action
from app.services.detection_gap_analyzer import (
    analyze_detection_gaps,
    deploy_detection,
)
from app.tools.splunk_tools import get_splunk_service
from app.utils.prompt_loader import get_prompt_version_info


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api")

AUDIT_LOG_PATH = Path("logs") / "spl_audit.log"


def _normalize_report_confidence(report: dict, state: dict | None = None) -> dict:
    """
    Normalize historical and live report payloads so the headline
    confidence is the explainable evidence confidence.
    """
    state = state or {}
    normalized = dict(report or {})
    breakdown = (
        normalized.get("confidence_breakdown")
        or state.get("confidence_breakdown", {})
        or {}
    )
    primary = (
        breakdown.get("overall")
        or state.get("investigation_confidence")
        or state.get("reconstruction_confidence")
        or normalized.get("investigation_confidence")
        or 0.0
    )
    report_confidence = (
        normalized.get("report_confidence")
        or normalized.get("investigation_confidence")
        or primary
    )

    normalized["investigation_confidence"] = primary
    normalized["report_confidence"] = report_confidence
    normalized["confidence_breakdown"] = breakdown
    normalized["confidence"] = {
        "version": "confidence-v1",
        "primary": primary,
        "primary_label": "Evidence Confidence",
        "reconstruction": {
            "score": primary,
            "breakdown": breakdown,
        },
        "report": {
            "score": report_confidence,
            "source": "SynthesisAgent",
        },
    }
    return normalized


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
    prompt_versions: dict
    promptops: str


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
        "mltk_ttp_validation": {},
        "confidence_scores": {},
        "confidence_breakdown": {},
        "final_report": {},
        "investigation_confidence": 0.0,
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
        "counterfactual_reasoning": {},
        "narrative": {},
        "structured_findings": {},
        "counterfactual": {},
        "synthesis_degraded": False,
        "degraded_sections": [],
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
    final_state["final_report"] = _normalize_report_confidence(
        final_state.get("final_report", {}),
        final_state,
    )
    final_state["investigation_confidence"] = final_state[
        "final_report"
    ].get("investigation_confidence", 0.0)
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

    prompt_versions = {
        name: get_prompt_version_info(name)
        for name in [
            "triage-agent",
            "synthesis-narrative",
            "containment-refinement",
        ]
    }

    return HealthResponse(
        status="ok",
        splunk_connected=splunk_connected,
        splunk_version=splunk_version,
        prompt_versions=prompt_versions,
        promptops="langfuse",
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
    total = get_investigation_count()
    return {
        "investigations": data,
        "total": total,
        "returned": len(data),
    }


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
        "final_report": _normalize_report_confidence(
            data.get("report_json", {}),
            data,
        ),
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


# ---------------------------------------------------------------------------
# Containment Plan API
# ---------------------------------------------------------------------------


@router.get("/investigations/{investigation_id}/containment-plan", summary="Get containment plan")
async def get_containment_plan(investigation_id: str):
    """
    Fetch the containment plan for a specific investigation.
    """
    data = await get_investigation_details(investigation_id)
    if not data:
        raise HTTPException(status_code=404, detail="Investigation not found")
    
    report = data.get("report_json", {})
    plan = report.get("containment_plan")
    if not plan:
        raise HTTPException(status_code=404, detail="Containment plan not found")
    
    return plan


@router.put("/investigations/{investigation_id}/containment-plan", summary="Update containment plan")
async def update_containment_plan(investigation_id: str, plan: dict):
    """
    Update the targets or actions in a containment plan before execution.
    Uses a targeted Supabase patch rather than a full re-persist so that
    kill_chain, audit_log, and other Supabase fields are never dropped.
    """
    data = await get_investigation_details(investigation_id)
    if not data:
        raise HTTPException(status_code=404, detail="Investigation not found")

    success = await patch_containment_plan(investigation_id, plan)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update containment plan")

    return {"status": "ok"}


class ExecutePhaseRequest(BaseModel):
    phase: int | None = None
    confirmed: bool | None = None


class RollbackRequest(BaseModel):
    action_id: str | None = None
    reason: str | None = None


@router.get(
    "/investigations/{investigation_id}/containment-plan/execute",
    summary="Execute a containment phase (SSE stream — EventSource GET)",
)
async def execute_containment_phase_get(
    investigation_id: str,
    phase_idx: int,
):
    """
    SSE stream for containment phase execution.
    Accepts GET because the browser EventSource API only issues GET requests.
    phase_idx is a 0-based index into the containment plan phases array.
    """
    return EventSourceResponse(
        execute_phase_stream(investigation_id, phase_idx),
        media_type="text/event-stream",
    )


@router.post(
    "/investigations/{investigation_id}/containment-plan/execute",
    summary="Execute a containment phase (POST — non-browser clients)",
)
async def execute_containment_phase_post(
    investigation_id: str,
    phase_idx: int | None = None,
    body: ExecutePhaseRequest | None = None,
):
    """
    POST variant for non-browser clients (curl, test runners).
    Accepts phase_idx as query param or body.phase (1-based, converted internally).
    """
    actual_idx = phase_idx
    if actual_idx is None and body is not None and body.phase is not None:
        actual_idx = body.phase - 1

    if actual_idx is None:
        raise HTTPException(status_code=400, detail="Missing phase or phase_idx")

    return EventSourceResponse(
        execute_phase_stream(investigation_id, actual_idx),
        media_type="text/event-stream",
    )


@router.post("/investigations/{investigation_id}/containment-plan/rollback", summary="Rollback a containment action")
async def rollback_containment_action(
    investigation_id: str,
    action_id: str | None = None,
    body: RollbackRequest | None = None
):
    """
    Rollback a specific containment action.
    """
    actual_action_id = action_id
    if not actual_action_id and body and body.action_id:
        actual_action_id = body.action_id

    if not actual_action_id:
        raise HTTPException(status_code=400, detail="Missing action_id")

    result = await rollback_action(investigation_id, actual_action_id)
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("message"))
    
    return result


class ContainmentChatRequest(BaseModel):
    message: str


@router.get("/investigations/{investigation_id}/containment-plan/chat/init", summary="Initialize or fetch containment chat history")
async def get_containment_chat_init(investigation_id: str):
    """
    Fetches existing chat history or generates a deterministic initial message.
    Zero LLM calls.
    """
    from app.services.containment_chat import get_initial_chat_message
    from app.services.supabase_client import get_containment_plan_sync
    from app.services.supabase_client import get_supabase_client
    
    try:
        plan = get_containment_plan_sync(investigation_id)
        if not plan:
            # Initialize a basic containment plan with empty phases
            default_plan = {
                "investigation_id": investigation_id,
                "phases": [
                    {"name": "Phase 1: IMMEDIATE (Execute now)", "description": "Immediate actions to isolate threats.", "actions": []},
                    {"name": "Phase 2: SHORT TERM (Within 24 hours)", "description": "Short-term mitigations.", "actions": []},
                    {"name": "Phase 3: REMEDIATION (Within 72 hours)", "description": "Long-term recovery actions.", "actions": []}
                ],
                "chat_history": []
            }
            client = get_supabase_client()
            response = client.table("investigations").select("report_json").eq("investigation_id", investigation_id).single().execute()
            existing = response.data or {}
            report_json = existing.get("report_json") or {}
            report_json["containment_plan"] = default_plan
            client.table("investigations").update({"report_json": report_json}).eq("investigation_id", investigation_id).execute()
            plan = default_plan

        history = plan.get("chat_history") or []
        if not history:
            init_msg = get_initial_chat_message()
            plan["chat_history"] = [init_msg]
            
            client = get_supabase_client()
            response = client.table("investigations").select("report_json").eq("investigation_id", investigation_id).single().execute()
            existing = response.data or {}
            report_json = existing.get("report_json") or {}
            report_json["containment_plan"] = plan
            client.table("investigations").update({"report_json": report_json}).eq("investigation_id", investigation_id).execute()
            
            history = [init_msg]
        return history
    except Exception as e:
        logger.error("[CHAT_INIT] Error initializing containment chat: %s", str(e))
        return [get_initial_chat_message()]


@router.post("/investigations/{investigation_id}/containment-plan/chat", summary="Interact with containment refinement chat assistant")
async def post_containment_chat(investigation_id: str, body: ContainmentChatRequest):
    """
    Conversational containment refinement assistant using structured SSE streaming.
    """
    from fastapi.responses import StreamingResponse
    from app.services.containment_chat import handle_containment_chat_stream
    
    if not body or not body.message:
        raise HTTPException(status_code=400, detail="Missing message parameter")
    
    return StreamingResponse(
        handle_containment_chat_stream(investigation_id, body.message),
        media_type="text/event-stream"
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


@router.get(
    "/investigations/{investigation_id}/ttp-enrichment"
)
async def get_ttp_enrichment(
    investigation_id: str,
) -> dict:
    """
    Get MLTK enrichment status and results.
    Frontend polls this until status=complete.
    """
    investigation = await get_investigation_details(investigation_id)
    if not investigation:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found",
        )

    report_json = investigation.get("report_json", {})
    status = report_json.get("mltk_enrichment_status")
    summary = report_json.get("mltk_enrichment_summary", {})
    ttp_mappings = report_json.get("ttp_mappings", [])
    error = report_json.get("mltk_enrichment_error")

    # Legacy investigations may not have MLTK enrichment metadata.
    # Return a terminal status to prevent infinite frontend polling.
    if not status:
        has_any_mltk_data = any(
            mapping.get("mltk_validation_run") is not None
            for mapping in ttp_mappings
            if isinstance(mapping, dict)
        )
        status = "not_started" if not has_any_mltk_data else "complete"

    return {
        "status": status,
        "summary": summary,
        "ttp_mappings": ttp_mappings if status == "complete" else [],
        "error": error,
        "investigation_id": investigation_id,
    }


@router.get(
    "/investigations/{investigation_id}/confidence-breakdown",
    summary="Get explainable confidence breakdown",
)
async def get_confidence_breakdown(
    investigation_id: str,
) -> dict:
    """
    Return the explainable confidence breakdown for an investigation.
    Reads from report_json in Supabase.
    """
    investigation = await get_investigation_details(investigation_id)
    if not investigation:
        raise HTTPException(
            status_code=404,
            detail="Investigation not found",
        )

    report_json = investigation.get("report_json", {})
    breakdown = report_json.get("confidence_breakdown", {})

    if not breakdown:
        raise HTTPException(
            status_code=404,
            detail=(
                "Confidence breakdown not available "
                "for this investigation"
            ),
        )

    return breakdown


@router.get(
    "/investigations/{investigation_id}/detection-gaps"
)
async def get_detection_gaps(
    investigation_id: str,
) -> dict:
    """
    Analyze detection coverage for an investigation.
    Lazy evaluation — runs on analyst request only.
    Returns coverage report with recommended SPL
    for uncovered techniques.
    """
    # Load investigation from Supabase
    investigation = await get_investigation_details(
        investigation_id
    )
    if not investigation:
        raise HTTPException(
            status_code=404,
            detail=f"Investigation {investigation_id} not found",
        )

    report_json = investigation.get("report_json", {})

    # Extract data needed for gap analysis
    ttp_mappings = report_json.get("ttp_mappings", [])
    kill_chain = report_json.get("kill_chain_stages", [])
    threat_intel = report_json.get("threat_intel", {})
    blast_radius = report_json.get("blast_radius", {})

    if not ttp_mappings:
        # Try alternative key names
        ttp_mappings = report_json.get("mitre_techniques", [])

    try:
        splunk_service = get_splunk_service()
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Splunk connection failed: {str(e)}",
        )

    result = await analyze_detection_gaps(
        investigation_id=investigation_id,
        ttp_mappings=ttp_mappings,
        kill_chain=kill_chain,
        threat_intel=threat_intel,
        blast_radius=blast_radius,
        splunk_service=splunk_service,
    )

    return result


@router.post(
    "/investigations/{investigation_id}/detection-gaps/deploy"
)
async def deploy_gap_detection(
    investigation_id: str,
    body: dict,
) -> dict:
    """
    Deploy a recommended detection as a Splunk saved search.
    Body: {
        "technique_id": "T1552.005",
        "spl": "index=botsv3 ...",
        "name": "Sentinel — T1552.005 Detection"
    }
    """
    technique_id = body.get("technique_id", "")
    spl = body.get("spl", "")
    name = body.get(
        "name",
        f"Sentinel — {technique_id} Detection",
    )

    if not technique_id or not spl:
        raise HTTPException(
            status_code=400,
            detail="technique_id and spl are required",
        )

    if len(spl) > 5000:
        raise HTTPException(
            status_code=400,
            detail="SPL too long (max 5000 chars)",
        )

    try:
        splunk_service = get_splunk_service()
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Splunk connection failed: {str(e)}",
        )

    result = await deploy_detection(
        technique_id=technique_id,
        spl=spl,
        name=name,
        investigation_id=investigation_id,
        splunk_service=splunk_service,
    )

    if not result.get("success"):
        raise HTTPException(
            status_code=500,
            detail=result.get("error", "Deploy failed"),
        )

    return result
