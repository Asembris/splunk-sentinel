"""
Containment Verification Service - Splunk Sentinel

Runs deterministic SPL verification after each
containment action executes. Proves whether the
action had measurable effect on Splunk telemetry.

Design principles:
- Pure deterministic SPL - no LLM
- Never blocks execution - always async
- Never raises - all exceptions logged and status
  set to VERIFICATION_SKIPPED
- Compares before/after event counts in botsv3
- Updates action status and verification_result
  in Supabase permanently

Status lifecycle:
  EXECUTED -> VERIFYING -> VERIFIED_EFFECTIVE
                       -> PARTIAL_EFFECT
                       -> VERIFICATION_FAILED
                       -> ROLLBACK_RECOMMENDED
                       -> VERIFICATION_SKIPPED
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

MLTK_CONNECTION = "openai_sentinel"

# Verification SPL templates per action type
VERIFICATION_SPL = {
    "BLOCK_IP": (
        "search index=botsv3 earliest=0 "
        "(src_ip=\"{target}\" OR dest_ip=\"{target}\") "
        "| stats count"
    ),
    "ISOLATE_HOST": (
        "search index=botsv3 earliest=0 "
        "host=\"{target}\" "
        "| stats count"
    ),
    "REVOKE_CREDENTIALS": (
        "search index=botsv3 earliest=0 "
        "sourcetype=WinEventLog:Security "
        "EventCode=4624 "
        "Account_Name=\"{target}\" "
        "| stats count"
    ),
    "DISABLE_ACCOUNT": (
        "search index=botsv3 earliest=0 "
        "sourcetype=WinEventLog:Security "
        "(EventCode=4624 OR EventCode=4625) "
        "Account_Name=\"{target}\" "
        "| stats count"
    ),
    "ROTATE_CREDENTIALS": (
        "search index=botsv3 earliest=0 "
        "sourcetype=WinEventLog:Security "
        "EventCode=4648 "
        "Account_Name=\"{target}\" "
        "| stats count"
    ),
    "AUDIT_CLOUDTRAIL": (
        "search index=botsv3 earliest=0 "
        "sourcetype=aws:cloudtrail "
        "| eval verification_target=\"{target}\" "
        "| stats count"
    ),
}

# Thresholds for verdict determination
EFFECTIVE_THRESHOLD = 0.80
PARTIAL_THRESHOLD = 0.20
ROLLBACK_THRESHOLD = 0.10


def _sanitize_target(target: str) -> str:
    """
    Sanitize action targets before template interpolation.
    Removes quote/pipe characters plus common boolean injection fragments.
    """
    safe = (
        str(target)
        .replace('"', "")
        .replace("'", "")
        .replace("|", "")
        .strip()
    )
    safe = re.sub(
        r"\b(OR|AND)\b\s+\w+\s*=\s*\*?",
        "",
        safe,
        flags=re.IGNORECASE,
    )
    safe = re.sub(r"\s+", " ", safe).strip()
    return safe[:100]


def _get_verdict(before: int, after: int) -> str:
    """
    Compute verdict from before/after event counts.
    Pure deterministic function - no LLM.
    """
    if before == 0 and after == 0:
        # before=0 and after=0 means no baseline exists
        # Cannot distinguish "action worked" from
        # "no recent traffic" - skip verification
        return "VERIFICATION_SKIPPED"

    if before == 0 and after > 0:
        return "VERIFICATION_FAILED"

    delta = before - after
    delta_pct = delta / before if before > 0 else 0.0

    if delta_pct >= EFFECTIVE_THRESHOLD:
        return "VERIFIED_EFFECTIVE"
    if delta_pct >= PARTIAL_THRESHOLD:
        return "PARTIAL_EFFECT"
    if delta_pct <= -ROLLBACK_THRESHOLD:
        return "ROLLBACK_RECOMMENDED"
    return "VERIFICATION_FAILED"


async def _run_verification_spl(
    spl: str,
    splunk_service,
    investigation_id: str,
    action_id: str,
) -> Optional[int]:
    """
    Run a verification SPL and return event count.
    Returns None on failure.
    Never raises.
    """
    try:
        import splunklib.results as splunk_results

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: splunk_service.jobs.oneshot(
                spl,
                output_mode="json",
                timeout=15,
            ),
        )

        reader = splunk_results.JSONResultsReader(result)
        rows = [r for r in reader if isinstance(r, dict)]

        if not rows:
            return 0

        count = int(rows[0].get("count", 0))
        logger.debug(
            "[Verifier] %s | %s | count=%d",
            investigation_id,
            action_id,
            count,
        )
        return count

    except Exception as e:
        logger.warning(
            "[Verifier] SPL failed for %s/%s: %s",
            investigation_id,
            action_id,
            str(e),
        )
        return None


async def _patch_action_verification(
    investigation_id: str,
    action_id: str,
    status: str,
    verification_result: dict,
) -> None:
    """
    Patch action status and verification_result
    in Supabase report_json.
    Never raises.
    """
    try:
        from app.services.supabase_client import get_supabase_client

        loop = asyncio.get_event_loop()

        def _patch():
            client = get_supabase_client()
            response = (
                client.table("investigations")
                .select("report_json")
                .eq("investigation_id", investigation_id)
                .single()
                .execute()
            )
            investigation = response.data or {}
            if not investigation:
                return

            report_json = investigation.get("report_json", {})
            containment_plan = report_json.get("containment_plan", {})
            phases = containment_plan.get("phases", [])

            updated = False
            for phase in phases:
                for action in phase.get("actions", []):
                    aid = action.get("action_id", action.get("id", ""))
                    if aid == action_id:
                        action["status"] = status
                        action["verification_result"] = verification_result
                        updated = True
                        break
                if updated:
                    break

            if updated:
                report_json["containment_plan"] = containment_plan
                client.table("investigations").update(
                    {"report_json": report_json}
                ).eq("investigation_id", investigation_id).execute()
                logger.info(
                    "[Verifier] Patched %s/%s -> %s",
                    investigation_id,
                    action_id,
                    status,
                )

        await loop.run_in_executor(None, _patch)

    except Exception as e:
        logger.error(
            "[Verifier] Patch failed for %s/%s: %s",
            investigation_id,
            action_id,
            str(e),
        )


async def verify_action(
    investigation_id: str,
    action_id: str,
    action_type: str,
    target: str,
    splunk_service,
    before_count: Optional[int] = None,
) -> None:
    """
    Main verification entry point.
    Called by containment_engine after execution.
    Runs async - never blocks UI.
    Never raises.
    """
    logger.info(
        "[Verifier] Starting verification | "
        "investigation=%s action=%s type=%s target=%s",
        investigation_id,
        action_id,
        action_type,
        target,
    )

    # Normalize action_type to string
    if hasattr(action_type, "value"):
        action_type = action_type.value
    elif hasattr(action_type, "name"):
        action_type = action_type.name
    action_type = str(action_type).upper()
    # Strip class prefix if present
    # e.g. "ContainmentActionType.BLOCK_IP" -> "BLOCK_IP"
    if "." in action_type:
        action_type = action_type.split(".")[-1]

    spl_template = VERIFICATION_SPL.get(action_type)
    if not spl_template:
        logger.info("[Verifier] No SPL template for %s - skipping", action_type)
        await _patch_action_verification(
            investigation_id=investigation_id,
            action_id=action_id,
            status="VERIFICATION_SKIPPED",
            verification_result={
                "reason": f"No verification template for {action_type}",
                "verified_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        return

    safe_target = _sanitize_target(target)
    verification_spl = spl_template.format(target=safe_target)

    await asyncio.sleep(5)

    after_count = await _run_verification_spl(
        spl=verification_spl,
        splunk_service=splunk_service,
        investigation_id=investigation_id,
        action_id=action_id,
    )

    if after_count is None:
        logger.warning("[Verifier] SPL failed for %s/%s", investigation_id, action_id)
        await _patch_action_verification(
            investigation_id=investigation_id,
            action_id=action_id,
            status="VERIFICATION_SKIPPED",
            verification_result={
                "reason": "Verification SPL failed",
                "verified_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        return

    effective_before = before_count if before_count is not None else 0
    verdict = _get_verdict(effective_before, after_count)

    delta = effective_before - after_count
    delta_pct = delta / effective_before if effective_before > 0 else 0.0

    verification_result = {
        "before_count": effective_before,
        "after_count": after_count,
        "delta": delta,
        "delta_pct": round(delta_pct, 3),
        "verification_spl": verification_spl,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
    }

    logger.info(
        "[Verifier] %s/%s | before=%d after=%d "
        "delta_pct=%.1f%% -> %s",
        investigation_id,
        action_id,
        effective_before,
        after_count,
        delta_pct * 100,
        verdict,
    )

    await _patch_action_verification(
        investigation_id=investigation_id,
        action_id=action_id,
        status=verdict,
        verification_result=verification_result,
    )


async def get_before_count(
    action_type: str,
    target: str,
    splunk_service,
    investigation_id: str,
) -> int:
    """
    Get event count BEFORE execution for baseline.
    Call this immediately before executing an action.
    Returns 0 on failure - safe default.
    """
    # Normalize action_type to string
    if hasattr(action_type, "value"):
        action_type = action_type.value
    elif hasattr(action_type, "name"):
        action_type = action_type.name
    action_type = str(action_type).upper()
    # Strip class prefix if present
    # e.g. "ContainmentActionType.BLOCK_IP" -> "BLOCK_IP"
    if "." in action_type:
        action_type = action_type.split(".")[-1]

    spl_template = VERIFICATION_SPL.get(action_type)
    if not spl_template:
        return 0

    safe_target = _sanitize_target(target)
    spl = spl_template.format(target=safe_target)

    count = await _run_verification_spl(
        spl=spl,
        splunk_service=splunk_service,
        investigation_id=investigation_id,
        action_id="pre_execution",
    )
    return count if count is not None else 0
