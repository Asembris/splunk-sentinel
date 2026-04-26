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
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from app.graph.investigation_graph import compiled_graph
from app.models.state import AgentState
from app.tools.splunk_tools import SplunkClient

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


# ---------------------------------------------------------------------------
# Helper: stream graph progress as SSE events
# ---------------------------------------------------------------------------


async def _stream_investigation(initial_state: AgentState) -> AsyncGenerator[dict, None]:
    """
    Stream investigation progress as Server-Sent Events.

    Yields a ``progress`` event for each graph state update, followed by a
    final ``complete`` event containing the full state when the graph finishes.

    Args:
        initial_state: The starting AgentState passed to the graph.

    Yields:
        Dict with ``event`` and ``data`` keys compatible with SSE protocol.
    """
    investigation_id = initial_state.get("investigation_id", "unknown")

    try:
        yield {
            "event": "progress",
            "data": json.dumps(
                {"stage": "started", "investigation_id": investigation_id}
            ),
        }

        final_state: AgentState = {}

        # LangGraph's astream yields intermediate state dicts per node
        async for chunk in compiled_graph.astream(
            initial_state, 
            config={"run_name": "Triage Agent"}
        ):
            for node_name, node_state in chunk.items():
                logger.info(
                    "[%s] SSE progress: node '%s' completed.",
                    investigation_id,
                    node_name,
                )
                yield {
                    "event": "progress",
                    "data": json.dumps(
                        {
                            "stage": node_name,
                            "investigation_id": investigation_id,
                            "escalate_to_human": node_state.get("escalate_to_human"),
                            "attack_classification": node_state.get("attack_classification"),
                            "classification_confidence": node_state.get(
                                "classification_confidence"
                            ),
                            "error": node_state.get("error"),
                        }
                    ),
                }
                final_state.update(node_state)

        yield {
            "event": "complete",
            "data": json.dumps(final_state),
        }

    except Exception as exc:
        logger.error(
            "[%s] SSE stream error: %s", investigation_id, exc, exc_info=True
        )
        yield {
            "event": "error",
            "data": json.dumps(
                {"error": str(exc), "investigation_id": investigation_id}
            ),
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
        "error": None,
        "spl_audit_log": [],
    }

    accept_header = request.headers.get("Accept", "")
    if "text/event-stream" in accept_header:
        return EventSourceResponse(
            _stream_investigation(initial_state),
            media_type="text/event-stream",
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
        "confidence=%.2f | stages=%d | patient_zero=%s | containment=%s",
        final_state.get("investigation_id"),
        final_state.get("attack_classification"),
        final_state.get("classification_confidence", 0.0),
        len(final_state.get("kill_chain", [])),
        final_state.get("patient_zero", {}).get("ip_address", "N/A"),
        final_state.get("blast_radius", {}).get("containment_priority", "N/A"),
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
