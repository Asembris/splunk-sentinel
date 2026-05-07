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


async def persist_investigation(state: dict) -> Optional[str]:
    """
    Persist a completed investigation to Supabase.
    Returns the Supabase record UUID or None on failure.
    """
    try:
        client = get_supabase_client()

        final_report = state.get("final_report", {})
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
