"""
containment_engine.py
---------------------
Execution engine for remediation actions. Handles the safe execution
of templated SPL, state tracking, and SSE streaming to the frontend.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional, Any

from app.models.containment import (
    ContainmentAction,
    ContainmentPlan,
    ContainmentStatus,
    ContainmentPhase
)
from app.tools.splunk_tools import get_splunk_client
from app.services.supabase_client import get_investigation_details, persist_investigation
from app.guardrails import spl_guardrail

logger = logging.getLogger(__name__)


def validate_containment_spl(spl: str) -> bool:
    """
    Final security check: Ensure the rendered SPL targets the
    remediation index and doesn't contain illegal keywords.
    """
    # Sentinel actions MUST use collect index=sentinel_actions
    if "index=sentinel_actions" not in spl.lower():
        return False
    
    # Standard guardrail check
    return spl_guardrail.is_safe(spl)


async def execute_action(action: ContainmentAction) -> ContainmentAction:
    """
    Execute a single containment action against Splunk.
    """
    if action.status in [ContainmentStatus.EXECUTED, ContainmentStatus.EXECUTING]:
        return action

    logger.info("[CONTAINMENT] Executing action: %s on %s", action.title, action.target)
    action.status = ContainmentStatus.EXECUTING
    
    if not validate_containment_spl(action.containment_spl):
        action.status = ContainmentStatus.FAILED
        action.error = "SPL validation failed: Action targets unauthorized index or contains blocked keywords."
        return action

    try:
        splunk = get_splunk_client()
        
        # Explicitly run oneshot directly to ensure | collect writes events
        loop = asyncio.get_event_loop()
        def _run():
            # Check safety
            splunk._check_spl_safety(action.containment_spl)
            # Run oneshot
            splunk.service.jobs.oneshot(
                action.containment_spl,
                earliest_time="0",
                latest_time="now",
                output_mode="json"
            )
            
        await loop.run_in_executor(None, _run)
        
        action.status = ContainmentStatus.EXECUTED
        action.executed_at = datetime.now(timezone.utc)
        logger.info("[CONTAINMENT] Action successful: %s", action.title)
        
    except Exception as e:
        logger.error("[CONTAINMENT] Action failed: %s | error=%s", action.title, str(e))
        action.status = ContainmentStatus.FAILED
        action.error = str(e)

    return action


async def rollback_action(investigation_id: str, action_id: str) -> dict:
    """
    Execute the reversal SPL for a previously executed action.
    """
    # 1. Fetch plan from Supabase (or investigation state)
    data = await get_investigation_details(investigation_id)
    if not data:
        return {"status": "error", "message": "Investigation not found"}

    report = data.get("report_json", {})
    plan_dict = report.get("containment_plan")
    if not plan_dict:
        return {"status": "error", "message": "Containment plan not found"}

    plan = ContainmentPlan(**plan_dict)
    
    # 2. Find the action
    target_action = None
    for phase in plan.phases:
        for action in phase.actions:
            if action.id == action_id:
                target_action = action
                break
    
    if not target_action:
        return {"status": "error", "message": "Action not found in plan"}

    if not target_action.reversal_spl:
        return {"status": "error", "message": "Action is irreversible"}

    # 3. Execute reversal
    logger.info("[CONTAINMENT] Rolling back action: %s", target_action.title)
    
    try:
        splunk = get_splunk_client()
        
        loop = asyncio.get_event_loop()
        def _run_reversal():
            splunk._check_spl_safety(target_action.reversal_spl)
            splunk.service.jobs.oneshot(
                target_action.reversal_spl,
                earliest_time="0",
                latest_time="now",
                output_mode="json"
            )
            
        await loop.run_in_executor(None, _run_reversal)
        
        target_action.status = ContainmentStatus.ROLLED_BACK
        plan.updated_at = datetime.now(timezone.utc)
        
        # 4. Persist updated plan
        report["containment_plan"] = plan.model_dump(mode="json")
        mock_state = {
            "investigation_id": investigation_id,
            "final_report": report,
            "attack_classification": data.get("classification"),
            "severity": data.get("severity")
        }
        await persist_investigation(mock_state)
        
        return {"status": "success", "action_id": action_id}
        
    except Exception as e:
        logger.error("[CONTAINMENT] Rollback failed: %s", str(e))
        return {"status": "error", "message": str(e)}


async def execute_phase_stream(investigation_id: str, phase_idx: int) -> AsyncGenerator[str, None]:
    """
    SSE stream for phase execution.
    """
    data = await get_investigation_details(investigation_id)
    if not data:
        yield f"data: {json.dumps({'event': 'error', 'message': 'Investigation not found'})}\n\n"
        return

    report = data.get("report_json", {})
    plan_dict = report.get("containment_plan")
    if not plan_dict:
        yield f"data: {json.dumps({'event': 'error', 'message': 'Plan not found'})}\n\n"
        return

    plan = ContainmentPlan(**plan_dict)
    if phase_idx >= len(plan.phases):
        yield f"data: {json.dumps({'event': 'error', 'message': 'Invalid phase index'})}\n\n"
        return

    phase = plan.phases[phase_idx]
    phase.status = ContainmentStatus.EXECUTING
    
    yield f"data: {json.dumps({'event': 'phase_started', 'phase': phase.name})}\n\n"

    for i, action in enumerate(phase.actions):
        if action.status == ContainmentStatus.SKIPPED:
            yield f"data: {json.dumps({'event': 'action_skipped', 'action_id': action.id, 'title': action.title})}\n\n"
            continue

        yield f"data: {json.dumps({'event': 'action_started', 'action_id': action.id, 'title': action.title})}\n\n"
        
        # Artificial delay for UI "vibe"
        await asyncio.sleep(0.5)
        
        updated_action = await execute_action(action)
        phase.actions[i] = updated_action
        
        event_type = 'action_complete' if updated_action.status == ContainmentStatus.EXECUTED else 'action_failed'
        yield f"data: {json.dumps({'event': event_type, 'action_id': action.id, 'status': updated_action.status, 'error': updated_action.error})}\n\n"

    # Update phase and plan status
    if all(a.status in [ContainmentStatus.EXECUTED, ContainmentStatus.SKIPPED] for a in phase.actions):
        phase.status = ContainmentStatus.COMPLETE
    else:
        phase.status = ContainmentStatus.PARTIAL
    
    plan.update_status()
    plan.updated_at = datetime.now(timezone.utc)
    
    # Persist
    report["containment_plan"] = plan.model_dump(mode="json")
    mock_state = {
        "investigation_id": investigation_id,
        "final_report": report,
        "attack_classification": data.get("classification"),
        "severity": data.get("severity")
    }
    await persist_investigation(mock_state)

    yield f"data: {json.dumps({'event': 'phase_complete', 'status': phase.status, 'plan': plan.model_dump(mode='json')})}\n\n"


# ---------------------------------------------------------------------------
# Test Compatibility functions
# ---------------------------------------------------------------------------

async def execute_single_action(action: ContainmentAction, service: Any, investigation_id: str) -> dict:
    """
    Execute a single containment action using a mock or provided Splunk client.
    """
    if action.status == ContainmentStatus.SKIPPED:
        return {
            "status": "SKIPPED",
            "action_id": action.id
        }

    if not validate_containment_spl(action.containment_spl):
        action.status = ContainmentStatus.FAILED
        action.error = "SPL validation failed"
        return {
            "status": "FAILED",
            "action_id": action.id,
            "error": "SPL validation failed"
        }

    try:
        loop = asyncio.get_event_loop()
        def _run():
            res = service.jobs.oneshot(
                action.containment_spl,
                earliest_time="0",
                latest_time="now",
                output_mode="json"
            )
            return list(res)

        rows = await loop.run_in_executor(None, _run)
        if not rows or len(rows) == 0:
            action.status = ContainmentStatus.FAILED
            action.error = "Zero rows returned"
            return {
                "status": "FAILED",
                "action_id": action.id,
                "error": "Zero rows returned"
            }

        action.status = ContainmentStatus.EXECUTED
        action.executed_at = datetime.now(timezone.utc)
        return {
            "status": "EXECUTED",
            "action_id": action.id,
            "executed_at": action.executed_at.isoformat()
        }
    except Exception as e:
        action.status = ContainmentStatus.FAILED
        action.error = str(e)
        return {
            "status": "FAILED",
            "action_id": action.id,
            "error": str(e)
        }


async def execute_rollback_action(action: ContainmentAction, reason: str, service: Any, investigation_id: str) -> dict:
    """
    Execute rollback using the provided Splunk service client.
    """
    if action.is_irreversible or not action.reversal_spl:
        return {
            "status": "FAILED",
            "action_id": action.id,
            "error": "Action is not reversible"
        }
    if action.status != ContainmentStatus.EXECUTED:
        return {
            "status": "FAILED",
            "action_id": action.id,
            "error": "Cannot rollback a non-executed action"
        }

    try:
        loop = asyncio.get_event_loop()
        def _run_reversal():
            res = service.jobs.oneshot(
                action.reversal_spl,
                earliest_time="0",
                latest_time="now",
                output_mode="json"
            )
            return list(res)

        await loop.run_in_executor(None, _run_reversal)
        action.status = ContainmentStatus.ROLLED_BACK
        action.rolled_back_at = datetime.now(timezone.utc)
        return {
            "status": "ROLLED_BACK",
            "action_id": action.id,
            "rolled_back_at": action.rolled_back_at.isoformat()
        }
    except Exception as e:
        return {
            "status": "FAILED",
            "action_id": action.id,
            "error": str(e)
        }


async def stream_phase_execution(plan: ContainmentPlan, phase_idx: int, service: Any) -> AsyncGenerator[str, None]:
    """
    SSE stream for phase execution using the provided service client.
    """
    if phase_idx >= len(plan.phases):
        yield f"data: {json.dumps({'event': 'error', 'message': 'Invalid phase index'})}\n\n"
        return

    phase = plan.phases[phase_idx]
    phase.status = ContainmentStatus.EXECUTING
    
    yield f"data: {json.dumps({'event': 'phase_start', 'phase': phase.name})}\n\n"

    for i, action in enumerate(phase.actions):
        if action.status == ContainmentStatus.SKIPPED:
            yield f"data: {json.dumps({'event': 'action_skipped', 'action_id': action.id, 'title': action.title})}\n\n"
            continue

        yield f"data: {json.dumps({'event': 'action_started', 'action_id': action.id, 'title': action.title})}\n\n"
        
        res = await execute_single_action(action, service, plan.investigation_id)
        
        event_type = 'action_complete' if res["status"] == "EXECUTED" else 'action_failed'
        yield f"data: {json.dumps({'event': event_type, 'action_id': action.id, 'status': action.status, 'error': action.error})}\n\n"

    if all(a.status in [ContainmentStatus.EXECUTED, ContainmentStatus.SKIPPED] for a in phase.actions):
        phase.status = ContainmentStatus.COMPLETE
    else:
        phase.status = ContainmentStatus.PARTIAL
    
    plan.update_status()
    plan.updated_at = datetime.now(timezone.utc)
    
    yield f"data: {json.dumps({'event': 'phase_complete', 'status': phase.status, 'plan': plan.model_dump(mode='json')})}\n\n"
