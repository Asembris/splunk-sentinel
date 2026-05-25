"""
containment_engine.py
---------------------
Execution engine for remediation actions. Handles the safe execution
of templated SPL, state tracking, and SSE streaming to the frontend.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional, Any

from app.models.containment import (
    ContainmentAction,
    ContainmentPlan,
    ContainmentStatus,
    ContainmentPhase
)
from app.tools.splunk_tools import get_splunk_client
from app.tools.splunk_tools import get_splunk_service
from app.services.supabase_client import get_investigation_details, patch_containment_plan
from app.guardrails import spl_guardrail
from app.services.containment_verifier import verify_action, get_before_count

logger = logging.getLogger(__name__)


_VERIFICATION_TERMINAL_STATUSES = {
    ContainmentStatus.VERIFIED_EFFECTIVE,
    ContainmentStatus.PARTIAL_EFFECT,
    ContainmentStatus.VERIFICATION_FAILED,
    ContainmentStatus.ROLLBACK_RECOMMENDED,
    ContainmentStatus.VERIFICATION_SKIPPED,
}


def _action_key(action: ContainmentAction) -> str:
    return action.action_id or action.id


def _dedupe_phase_actions_in_place(
    phase: ContainmentPhase,
    allowed_keys: set[str],
) -> None:
    """
    Keep phase actions stable across concurrent writes:
    - no duplicate action ids
    - no new action ids beyond initial phase snapshot
    """
    seen: set[str] = set()
    deduped: list[ContainmentAction] = []
    for action in phase.actions:
        key = _action_key(action)
        if not key:
            continue
        if key not in allowed_keys:
            continue
        if key in seen:
            continue
        seen.add(key)
        deduped.append(action)
    phase.actions = deduped


def _merge_verification_state(
    plan: ContainmentPlan,
    latest_plan_dict: dict,
) -> None:
    """
    Preserve async verifier writes when execute_phase_stream persists the
    plan. Without this merge, a stale in-memory plan can overwrite
    VERIFIED_* status back to VERIFYING.
    """
    latest_phases = latest_plan_dict.get("phases", []) if latest_plan_dict else []
    latest_by_key: dict[str, dict] = {}
    for phase in latest_phases:
        for action in phase.get("actions", []):
            key = action.get("action_id") or action.get("id") or ""
            if key:
                latest_by_key[key] = action

    for phase in plan.phases:
        for action in phase.actions:
            key = _action_key(action)
            if not key:
                continue
            latest_action = latest_by_key.get(key)
            if not latest_action:
                continue
            latest_status = latest_action.get("status")
            if latest_status in {s.value for s in _VERIFICATION_TERMINAL_STATUSES}:
                action.status = ContainmentStatus(latest_status)
                action.verification_result = latest_action.get("verification_result")


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


async def execute_action(
    action: ContainmentAction,
    investigation_id: str = "",
) -> ContainmentAction:
    """
    Execute a single containment action against Splunk.
    """
    if action.status in [ContainmentStatus.EXECUTED, ContainmentStatus.EXECUTING]:
        return action

    logger.info("[CONTAINMENT] Executing action: %s on %s", action.title, action.target)
    action.status = ContainmentStatus.EXECUTING

    # Baseline before execution for deterministic verification.
    before_count = 0
    verification_service = None
    try:
        verification_service = get_splunk_service()
        before_count = await get_before_count(
            action_type=action.type.value,
            target=action.target or "",
            splunk_service=verification_service,
            investigation_id=investigation_id,
        )
    except Exception as e:
        logger.warning("[Engine] Before count failed: %s", str(e))
        before_count = 0
        verification_service = None
    
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
        
        action.status = (
            ContainmentStatus.VERIFYING
            if investigation_id
            else ContainmentStatus.EXECUTED
        )
        action.executed_at = datetime.now(timezone.utc)
        logger.info("[CONTAINMENT] Action successful: %s", action.title)

        # Fire background verification without blocking the UI.
        if (
            investigation_id
            and verification_service is not None
            and not os.getenv("PYTEST_CURRENT_TEST")
        ):
            try:
                asyncio.create_task(
                    verify_action(
                        investigation_id=investigation_id,
                        action_id=action.action_id or action.id,
                        action_type=action.type.value,
                        target=action.target or "",
                        splunk_service=verification_service,
                        before_count=before_count,
                    )
                )
                logger.info(
                    "[Engine] Verification task fired for %s",
                    action.action_id or action.id,
                )
            except Exception as e:
                logger.warning(
                    "[Engine] Failed to fire verification task: %s",
                    str(e),
                )
        
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
        target_action.rolled_back_at = datetime.now(timezone.utc).isoformat()
        plan.updated_at = datetime.now(timezone.utc)

        # 4. Persist updated plan — targeted patch, never drops Supabase fields
        await patch_containment_plan(
            investigation_id, plan.model_dump(mode="json")
        )

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
        yield {"data": json.dumps({'event': 'error', 'message': 'Investigation not found'})}
        return

    report = data.get("report_json", {})
    plan_dict = report.get("containment_plan")
    if not plan_dict:
        yield {"data": json.dumps({'event': 'error', 'message': 'Plan not found'})}
        return

    plan = ContainmentPlan(**plan_dict)
    if phase_idx >= len(plan.phases):
        yield {"data": json.dumps({'event': 'error', 'message': 'Invalid phase index'})}
        return

    # Acquire lock
    plan_dict["plan_locked"] = True
    plan_dict["lock_acquired_at"] = datetime.now(timezone.utc).isoformat()
    await patch_containment_plan(investigation_id, plan_dict)

    try:
        phase = plan.phases[phase_idx]
        initial_phase_action_keys = {
            _action_key(a) for a in phase.actions if _action_key(a)
        }
        phase.status = ContainmentStatus.EXECUTING
        
        yield {"data": json.dumps({'event': 'phase_started', 'phase': phase.name})}

        for i, action in enumerate(phase.actions):
            if action.status == ContainmentStatus.SKIPPED:
                yield {"data": json.dumps({'event': 'action_skipped', 'action_id': action.id, 'title': action.title})}
                continue

            yield {"data": json.dumps({'event': 'action_started', 'action_id': action.id, 'title': action.title})}
            
            # Artificial delay for UI "vibe"
            await asyncio.sleep(0.5)
            
            updated_action = await execute_action(action, investigation_id)
            phase.actions[i] = updated_action

            # Persist each action update so VERIFYING status is visible immediately.
            latest_data = await get_investigation_details(investigation_id)
            latest_report = latest_data.get("report_json", {}) if latest_data else {}
            latest_plan_dict = latest_report.get("containment_plan", {}) or {}
            _merge_verification_state(plan, latest_plan_dict)
            _dedupe_phase_actions_in_place(phase, initial_phase_action_keys)
            plan.updated_at = datetime.now(timezone.utc)
            await patch_containment_plan(
                investigation_id, plan.model_dump(mode="json")
            )

            event_type = (
                'action_complete'
                if updated_action.status in [
                    ContainmentStatus.EXECUTED,
                    ContainmentStatus.VERIFYING,
                ]
                else 'action_failed'
            )
            yield {"data": json.dumps({'event': event_type, 'action_id': action.id, 'status': updated_action.status, 'error': updated_action.error})}

        # Update phase and plan status
        if all(
            a.status in [
                ContainmentStatus.EXECUTED,
                ContainmentStatus.VERIFYING,
                ContainmentStatus.VERIFIED_EFFECTIVE,
                ContainmentStatus.PARTIAL_EFFECT,
                ContainmentStatus.VERIFICATION_FAILED,
                ContainmentStatus.ROLLBACK_RECOMMENDED,
                ContainmentStatus.VERIFICATION_SKIPPED,
                ContainmentStatus.SKIPPED,
            ]
            for a in phase.actions
        ):
            phase.status = ContainmentStatus.COMPLETE
        else:
            phase.status = ContainmentStatus.PARTIAL
        
        plan.update_status()
        latest_data = await get_investigation_details(investigation_id)
        latest_report = latest_data.get("report_json", {}) if latest_data else {}
        latest_plan_dict = latest_report.get("containment_plan", {}) or {}
        _merge_verification_state(plan, latest_plan_dict)
        _dedupe_phase_actions_in_place(phase, initial_phase_action_keys)
        plan.updated_at = datetime.now(timezone.utc)

        # Persist updated plan — targeted patch, never drops Supabase fields
        await patch_containment_plan(
            investigation_id, plan.model_dump(mode="json")
        )

        yield {"data": json.dumps({'event': 'phase_complete', 'status': phase.status, 'plan': plan.model_dump(mode='json')})}

    finally:
        # Release lock
        try:
            curr_data = await get_investigation_details(investigation_id)
            if curr_data:
                curr_report = curr_data.get("report_json", {})
                curr_plan_dict = curr_report.get("containment_plan") or {}
                curr_plan_dict["plan_locked"] = False
                curr_plan_dict["lock_acquired_at"] = None
                await patch_containment_plan(investigation_id, curr_plan_dict)
        except Exception as e:
            logger.error("[LOCK] Failed to auto-release lock inside finally: %s", str(e))



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


async def stream_phase_execution(plan: ContainmentPlan, phase_idx: int, service: Any) -> AsyncGenerator[dict, None]:
    """
    SSE stream for phase execution using the provided service client.
    """
    if phase_idx >= len(plan.phases):
        yield {"data": json.dumps({'event': 'error', 'message': 'Invalid phase index'})}
        return

    phase = plan.phases[phase_idx]
    phase.status = ContainmentStatus.EXECUTING
    
    yield {"data": json.dumps({'event': 'phase_start', 'phase': phase.name})}

    for i, action in enumerate(phase.actions):
        if action.status == ContainmentStatus.SKIPPED:
            yield {"data": json.dumps({'event': 'action_skipped', 'action_id': action.id, 'title': action.title})}
            continue

        yield {"data": json.dumps({'event': 'action_started', 'action_id': action.id, 'title': action.title})}
        
        res = await execute_single_action(action, service, plan.investigation_id)
        
        event_type = 'action_complete' if res["status"] == "EXECUTED" else 'action_failed'
        yield {"data": json.dumps({'event': event_type, 'action_id': action.id, 'status': action.status, 'error': action.error})}

    if all(a.status in [ContainmentStatus.EXECUTED, ContainmentStatus.SKIPPED] for a in phase.actions):
        phase.status = ContainmentStatus.COMPLETE
    else:
        phase.status = ContainmentStatus.PARTIAL
    
    plan.update_status()
    plan.updated_at = datetime.now(timezone.utc)
    
    yield {"data": json.dumps({'event': 'phase_complete', 'status': phase.status, 'plan': plan.model_dump(mode='json')})}
