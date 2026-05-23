"""
MLTK TTP Enrichment Service - Splunk Sentinel

Runs MLTK ai command validation AFTER investigation completes, as a
background asyncio task.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

MLTK_CONNECTION = "openai_sentinel"
MLTK_TIMEOUT_PER_TECHNIQUE = 30
MLTK_MAX_TECHNIQUES = 6


async def enrich_ttp_with_mltk(investigation_id: str) -> None:
    """
    Background task: enrich TTP mappings with MLTK ai command validation.
    Never raises; investigation outcome must remain unaffected.
    """
    logger.info(
        "[MLTK] Starting background enrichment | investigation_id=%s",
        investigation_id,
    )

    try:
        from app.services.supabase_client import get_investigation_details
        from app.tools.splunk_tools import get_splunk_service
        from app.agents.ttp_agent import _check_mltk_available

        investigation = await get_investigation_details(investigation_id)
        if not investigation:
            await _patch_enrichment_status(
                investigation_id,
                "failed",
                error="Investigation not found",
            )
            return

        report_json = investigation.get("report_json", {}) or {}
        current_status = report_json.get("mltk_enrichment_status")
        if current_status == "complete":
            logger.info(
                "[MLTK] Enrichment already complete | investigation_id=%s",
                investigation_id,
            )
            return

        await _patch_enrichment_status(investigation_id, "running")

        ttp_mappings = report_json.get("ttp_mappings", []) or []
        kill_chain = report_json.get("kill_chain_stages", []) or []

        if not ttp_mappings:
            await _patch_enrichment_status(
                investigation_id,
                "complete",
                summary={
                    "techniques_validated": 0,
                    "agreements": 0,
                    "disagreements": 0,
                    "failed": 0,
                    "skipped": 0,
                    "connection": MLTK_CONNECTION,
                    "mltk_version": "5.7.4",
                    "enriched_at": datetime.now(timezone.utc).isoformat(),
                },
            )
            return

        try:
            splunk_service = get_splunk_service()
        except Exception as exc:
            await _patch_enrichment_status(
                investigation_id,
                "failed",
                error=f"Splunk connection failed: {exc}",
            )
            return

        if not _check_mltk_available(splunk_service):
            await _patch_enrichment_status(
                investigation_id,
                "failed",
                error="MLTK app not installed",
            )
            return

        techniques_to_validate = ttp_mappings[:MLTK_MAX_TECHNIQUES]
        enriched_mappings: list[dict] = []
        agreements = 0
        disagreements = 0
        failed = 0
        skipped = len(ttp_mappings) - len(techniques_to_validate)

        enriched_results = await asyncio.gather(
            *[
                _enrich_single_technique(
                    mapping=mapping,
                    kill_chain=kill_chain,
                    splunk_service=splunk_service,
                    investigation_id=investigation_id,
                )
                for mapping in techniques_to_validate
            ]
        )
        enriched_mappings.extend(enriched_results)

        for enriched in enriched_results:
            if enriched.get("mltk_validation_run"):
                if enriched.get("mltk_agrees"):
                    agreements += 1
                else:
                    disagreements += 1
            else:
                failed += 1

        enriched_mappings.extend(ttp_mappings[MLTK_MAX_TECHNIQUES:])

        summary = {
            "techniques_validated": len(techniques_to_validate),
            "agreements": agreements,
            "disagreements": disagreements,
            "failed": failed,
            "skipped": skipped,
            "connection": MLTK_CONNECTION,
            "mltk_version": "5.7.4",
            "enriched_at": datetime.now(timezone.utc).isoformat(),
        }

        await _patch_enriched_ttp_mappings(
            investigation_id=investigation_id,
            enriched_mappings=enriched_mappings,
            summary=summary,
        )

        logger.info(
            "[MLTK] Enrichment complete | investigation_id=%s | "
            "agreements=%d | disagreements=%d | failed=%d",
            investigation_id,
            agreements,
            disagreements,
            failed,
        )

    except Exception as exc:
        logger.error(
            "[MLTK] Enrichment task crashed | investigation_id=%s | error=%s",
            investigation_id,
            str(exc),
        )
        try:
            await _patch_enrichment_status(
                investigation_id,
                "failed",
                error=str(exc),
            )
        except Exception:
            pass


async def _enrich_single_technique(
    mapping: dict,
    kill_chain: list,
    splunk_service,
    investigation_id: str,
) -> dict:
    """
    Enrich a single technique mapping with MLTK.
    Never raises.
    """
    from app.agents.ttp_agent import _run_mltk_technique_validation

    technique_id = mapping.get("technique_id", "")
    technique_name = mapping.get("technique_name", "")
    qdrant_confidence = float(mapping.get("confidence", 0.5))

    stage = next(
        (
            s for s in kill_chain
            if technique_id.split(".")[0] in s.get("mitre_technique", "")
            or s.get("mitre_technique", "").startswith(
                technique_id.split(".")[0]
            )
        ),
        None,
    )

    if stage:
        parts = []
        tactic = stage.get("tactic") or stage.get("mitre_tactic")
        if tactic:
            parts.append(f"Tactic: {tactic}")
        if stage.get("evidence"):
            parts.append(f"Evidence: {stage['evidence'][:300]}")
        if stage.get("affected_assets"):
            assets = stage["affected_assets"]
            parts.append(f"Assets: {', '.join(str(a) for a in assets[:3])}")
        evidence_text = " | ".join(parts) or technique_name
    else:
        evidence_text = f"Technique {technique_id}: {technique_name}"

    try:
        mltk_result = await asyncio.wait_for(
            _run_mltk_technique_validation(
                technique_id=technique_id,
                technique_name=technique_name,
                evidence_text=evidence_text,
                splunk_service=splunk_service,
                investigation_id=investigation_id,
            ),
            timeout=MLTK_TIMEOUT_PER_TECHNIQUE,
        )
    except asyncio.TimeoutError:
        enriched = dict(mapping)
        enriched["mltk_validation_run"] = False
        enriched["mltk_error"] = f"timeout after {MLTK_TIMEOUT_PER_TECHNIQUE}s"
        return enriched

    enriched = dict(mapping)

    if mltk_result.get("success"):
        mltk_technique_id = mltk_result.get("technique_id", "")
        mltk_confidence = float(mltk_result.get("confidence", 0.5))
        mltk_reasoning = mltk_result.get("reasoning", "")

        qdrant_parent = technique_id.split(".")[0]
        mltk_parent = mltk_technique_id.split(".")[0]
        agrees = (
            mltk_technique_id == technique_id
            or mltk_parent == qdrant_parent
        )

        enriched.update({
            "mltk_technique_id": mltk_technique_id,
            "mltk_confidence": mltk_confidence,
            "mltk_reasoning": mltk_reasoning,
            "mltk_agrees": agrees,
            "mltk_validation_run": True,
            "mltk_unavailable": False,
        })

        if agrees:
            boosted = qdrant_confidence * 0.6 + mltk_confidence * 0.4
            enriched["confidence"] = round(min(boosted, 0.95), 3)
            enriched["confidence_source"] = "qdrant_mltk_agreement"
        else:
            enriched["confidence"] = round(qdrant_confidence * 0.75, 3)
            enriched["confidence_source"] = "qdrant_mltk_disagreement"
            enriched["mltk_alternative"] = mltk_technique_id

        logger.info(
            "[MLTK] %s validated | agrees=%s | confidence %.3f -> %.3f",
            technique_id,
            agrees,
            qdrant_confidence,
            enriched["confidence"],
        )
    else:
        enriched["mltk_validation_run"] = False
        enriched["mltk_error"] = mltk_result.get("error", "unknown")

    return enriched


async def _patch_enrichment_status(
    investigation_id: str,
    status: str,
    summary: Optional[dict] = None,
    error: Optional[str] = None,
) -> None:
    """
    Patch mltk_enrichment status keys inside report_json.
    """
    try:
        from app.services.supabase_client import get_supabase_client

        loop = asyncio.get_event_loop()

        def _patch():
            client = get_supabase_client()
            current = (
                client.table("investigations")
                .select("report_json")
                .eq("investigation_id", investigation_id)
                .single()
                .execute()
            )
            if not current.data:
                return
            report_json = current.data.get("report_json", {}) or {}
            report_json["mltk_enrichment_status"] = status
            if summary is not None:
                report_json["mltk_enrichment_summary"] = summary
            if error is not None:
                report_json["mltk_enrichment_error"] = error

            (
                client.table("investigations")
                .update({"report_json": report_json})
                .eq("investigation_id", investigation_id)
                .execute()
            )

        await loop.run_in_executor(None, _patch)
    except Exception as exc:
        logger.error(
            "[MLTK] Failed to patch status %s for %s: %s",
            status,
            investigation_id,
            str(exc),
        )


async def _patch_enriched_ttp_mappings(
    investigation_id: str,
    enriched_mappings: list,
    summary: dict,
) -> None:
    """
    Patch enriched mappings and completion metadata into report_json.
    """
    try:
        from app.services.supabase_client import get_supabase_client

        loop = asyncio.get_event_loop()

        def _patch():
            client = get_supabase_client()
            current = (
                client.table("investigations")
                .select("report_json")
                .eq("investigation_id", investigation_id)
                .single()
                .execute()
            )
            if not current.data:
                return

            report_json = current.data.get("report_json", {}) or {}
            report_json["ttp_mappings"] = enriched_mappings
            report_json["mltk_enrichment_status"] = "complete"
            report_json["mltk_enrichment_summary"] = summary
            report_json.pop("mltk_enrichment_error", None)

            (
                client.table("investigations")
                .update({"report_json": report_json})
                .eq("investigation_id", investigation_id)
                .execute()
            )

        await loop.run_in_executor(None, _patch)
    except Exception as exc:
        logger.error(
            "[MLTK] Failed to patch enriched mappings for %s: %s",
            investigation_id,
            str(exc),
        )
        await _patch_enrichment_status(
            investigation_id,
            "failed",
            error=str(exc),
        )
