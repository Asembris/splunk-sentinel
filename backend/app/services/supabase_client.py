"""
Supabase persistence client for Splunk Sentinel investigations.
"""
import logging
import os
from typing import Optional
from supabase import create_client, Client

logger = logging.getLogger(__name__)

_client: Optional[Client] = None


def get_supabase_client() -> Client:
    global _client
    if _client is None:
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_SERVICE_KEY")
        if not url or not key:
            raise ValueError(
                "SUPABASE_URL and SUPABASE_SERVICE_KEY must be set"
            )
        _client = create_client(url, key)
    return _client


def _normalize_report_confidence(report: dict, state: dict) -> dict:
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


async def persist_investigation(state: dict) -> Optional[str]:
    """
    Persist a completed investigation to Supabase.
    Returns the Supabase record UUID or None on failure.
    """
    try:
        client = get_supabase_client()

        final_report = _normalize_report_confidence(
            state.get("final_report", {}),
            state,
        )
        final_report.setdefault("mltk_enrichment_status", "pending")
        kill_chain = state.get("kill_chain", [])
        patient_zero = state.get("patient_zero", {})
        blast_radius = state.get("blast_radius", {})

        record = {
            "investigation_id": state.get("investigation_id"),
            "classification": state.get("attack_classification", "UNKNOWN"),
            "severity": state.get("severity", "UNKNOWN"),
            "confidence": float(
                final_report.get("investigation_confidence", 0.0)
            ),
            "trigger_text": state.get("trigger", "")[:500],
            "kill_chain_stages": len(kill_chain),
            "patient_zero_ip": patient_zero.get("ip_address", ""),
            "containment_priority": blast_radius.get(
                "containment_priority", "UNKNOWN"
            ),
            "report_json": final_report,
            "pdf_path": state.get("report_pdf_path", ""),
            "splunk_notable_id": state.get("splunk_notable_event_id", ""),
            "escalate_to_human": state.get("escalate_to_human", False),
            "analyst_feedback": None,
            "analyst_rating": None,
        }
        
        # Inject audit log and SLO report into report_json to avoid schema migrations
        if "spl_audit_log" in state:
            record["report_json"]["spl_audit_log"] = state["spl_audit_log"]
        if "slo_report" in state:
            record["report_json"]["slo_report"] = state["slo_report"]
        if "containment_plan" in state:
            record["report_json"]["containment_plan"] = state["containment_plan"]
        if "ttp_mappings" in state:
            record["report_json"]["ttp_mappings"] = state["ttp_mappings"]
        if "mltk_ttp_validation" in state:
            record["report_json"]["mltk_ttp_validation"] = state[
                "mltk_ttp_validation"
            ]
        if "kill_chain" in state:
            record["report_json"]["kill_chain_stages"] = state["kill_chain"]
        if "threat_intel" in state:
            record["report_json"]["threat_intel"] = state["threat_intel"]
        if "blast_radius" in state:
            record["report_json"]["blast_radius"] = state["blast_radius"]

        response = (
            client.table("investigations")
            .upsert(record, on_conflict="investigation_id")
            .execute()
        )

        if response.data:
            record_id = response.data[0].get("id")
            logger.info(
                "[SUPABASE] Investigation persisted | id=%s | "
                "investigation_id=%s",
                record_id,
                state.get("investigation_id"),
            )
            return record_id

    except Exception as e:
        logger.error("[SUPABASE] Persistence failed | error=%s", str(e))

    return None


async def patch_containment_plan(
    investigation_id: str,
    containment_plan: dict,
) -> bool:
    """
    Patch only the containment_plan key inside report_json for a given
    investigation. Reads the existing report_json, merges the new plan,
    and writes back — without touching kill_chain_stages, confidence,
    analyst_rating, or any other Supabase column.

    This is safer than persist_investigation() for post-synthesis edits
    because it never overwrites audit_log, slo_report, or other fields
    that are stored inside report_json but are absent from the caller's
    mock state.
    """
    try:
        client = get_supabase_client()

        # Fetch existing report_json only
        response = (
            client.table("investigations")
            .select("report_json")
            .eq("investigation_id", investigation_id)
            .single()
            .execute()
        )
        existing = response.data or {}
        report_json = existing.get("report_json") or {}

        # Merge — only update containment_plan key
        report_json["containment_plan"] = containment_plan

        client.table("investigations").update(
            {"report_json": report_json}
        ).eq("investigation_id", investigation_id).execute()

        logger.info(
            "[SUPABASE] Containment plan patched | investigation_id=%s",
            investigation_id,
        )
        return True

    except Exception as e:
        logger.error(
            "[SUPABASE] Containment plan patch failed | id=%s | error=%s",
            investigation_id,
            str(e),
        )
        return False


async def update_feedback(
    investigation_id: str,
    rating: str,
    notes: str,
) -> bool:
    """
    Update analyst feedback for a completed investigation.
    """
    try:
        client = get_supabase_client()
        client.table("investigations").update(
            {
                "analyst_rating": rating,
                "analyst_feedback": notes,
            }
        ).eq("investigation_id", investigation_id).execute()
        logger.info(
            "[SUPABASE] Feedback updated | investigation_id=%s | rating=%s",
            investigation_id,
            rating,
        )
        return True
    except Exception as e:
        logger.error("[SUPABASE] Feedback update failed | error=%s", str(e))
        return False


async def get_investigation_history(limit: int = 20) -> list[dict]:
    """
    Retrieve recent investigations from Supabase for History page.
    """
    try:
        client = get_supabase_client()
        response = (
            client.table("investigations")
            .select(
                "investigation_id, classification, severity, confidence, "
                "trigger_text, kill_chain_stages, created_at, "
                "analyst_rating, escalate_to_human, containment_priority"
            )
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return response.data or []
    except Exception as e:
        logger.error(
            "[SUPABASE] History retrieval failed | error=%s", str(e)
        )
        return []


async def get_investigation_details(investigation_id: str) -> Optional[dict]:
    """
    Retrieve full investigation details from Supabase.
    """
    try:
        client = get_supabase_client()
        response = (
            client.table("investigations")
            .select("*")
            .eq("investigation_id", investigation_id)
            .single()
            .execute()
        )
        return response.data
    except Exception as e:
        logger.error(
            "[SUPABASE] Detail retrieval failed | id=%s | error=%s", 
            investigation_id, 
            str(e)
        )
        return None


def get_containment_plan_sync(investigation_id: str) -> Optional[dict]:
    """
    Fetch containment plan synchronously for chat functions.
    """
    try:
        client = get_supabase_client()
        response = (
            client.table("investigations")
            .select("report_json")
            .eq("investigation_id", investigation_id)
            .single()
            .execute()
        )
        existing = response.data or {}
        report_json = existing.get("report_json") or {}
        return report_json.get("containment_plan")
    except Exception as e:
        logger.error("[SUPABASE] get_containment_plan_sync failed | id=%s | error=%s", investigation_id, str(e))
        return None


def get_chat_history(investigation_id: str) -> Optional[dict]:
    """
    Retrieve chat_history from inside report_json["containment_plan"]["chat_history"].
    Returns None if not found.
    """
    plan = get_containment_plan_sync(investigation_id)
    if plan:
        return plan.get("chat_history")
    return None


def save_chat_history(investigation_id: str, chat_history: dict) -> bool:
    """
    Save the chat_history inside report_json["containment_plan"]["chat_history"] synchronously.
    """
    try:
        client = get_supabase_client()
        response = (
            client.table("investigations")
            .select("report_json")
            .eq("investigation_id", investigation_id)
            .single()
            .execute()
        )
        existing = response.data or {}
        report_json = existing.get("report_json") or {}
        
        containment_plan = report_json.get("containment_plan") or {}
        containment_plan["chat_history"] = chat_history
        report_json["containment_plan"] = containment_plan
        
        client.table("investigations").update(
            {"report_json": report_json}
        ).eq("investigation_id", investigation_id).execute()
        
        logger.info("[SUPABASE] Chat history saved successfully synchronously | id=%s", investigation_id)
        return True
    except Exception as e:
        logger.error("[SUPABASE] save_chat_history failed | id=%s | error=%s", investigation_id, str(e))
        return False


def is_plan_locked(investigation_id: str) -> bool:
    """
    Check if a containment plan is currently locked for execution,
    supporting a 300-second auto-release timeout.
    """
    plan = get_containment_plan_sync(investigation_id)
    if not plan:
        return False
    locked = plan.get("plan_locked", False)
    if not locked:
        return False
    
    # Check 300s timeout auto-release
    acquired_at_str = plan.get("lock_acquired_at")
    if acquired_at_str:
        try:
            from datetime import datetime, timezone
            acquired_at = datetime.fromisoformat(acquired_at_str.replace("Z", "+00:00"))
            delta = (datetime.now(timezone.utc) - acquired_at).total_seconds()
            if delta > 300:
                logger.warning("[LOCK] Auto-releasing lock for investigation_id=%s after 300 seconds", investigation_id)
                release_plan_lock_sync(investigation_id)
                return False
        except Exception as e:
            logger.error("[LOCK] Error checking lock expiry: %s", str(e))
            pass
    return True


def release_plan_lock_sync(investigation_id: str) -> bool:
    """
    Release the containment plan lock synchronously.
    """
    try:
        client = get_supabase_client()
        response = (
            client.table("investigations")
            .select("report_json")
            .eq("investigation_id", investigation_id)
            .single()
            .execute()
        )
        existing = response.data or {}
        report_json = existing.get("report_json") or {}
        
        containment_plan = report_json.get("containment_plan") or {}
        containment_plan["plan_locked"] = False
        containment_plan["lock_acquired_at"] = None
        report_json["containment_plan"] = containment_plan
        
        client.table("investigations").update(
            {"report_json": report_json}
        ).eq("investigation_id", investigation_id).execute()
        
        logger.info("[LOCK] Plan lock released successfully | id=%s", investigation_id)
        return True
    except Exception as e:
        logger.error("[LOCK] release_plan_lock_sync failed | id=%s | error=%s", investigation_id, str(e))
        return False
