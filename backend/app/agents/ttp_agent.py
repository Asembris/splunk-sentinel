"""
TTPAgent: enriches kill chain MITRE mappings using RAG.
Runs in parallel with ThreatIntelAgent after ReconstructionAgent.

Inputs from AgentState:
- kill_chain: list of stages with mitre_technique fields

Output:
- ttp_mappings: list of enriched technique dicts
"""

import asyncio
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from app.models.state import AgentState
from app.rag.retriever import (
    retrieve_cves_for_technique,
    retrieve_mitre_technique,
)

logger = logging.getLogger(__name__)

MLTK_VALIDATION_BUDGET_SECONDS = 12
MLTK_AVAILABILITY_TIMEOUT_SECONDS = 4
MLTK_PER_TECHNIQUE_TIMEOUT_SECONDS = 60
_MLTK_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="mltk-ai")


def extract_technique_id(mitre_technique_str: str) -> Optional[str]:
    """
    Extract clean MITRE technique ID from a string.
    Handles formats like:
    - "T1190"
    - "T1190 - Exploit Public-Facing Application"  
    - "T1552.005 Cloud Instance Metadata API"
    - "TA0001" (tactic — skip these)
    """
    match = re.search(r'\bT\d{4}(?:\.\d{3})?\b', mitre_technique_str)
    if match:
        return match.group(0)
    return None


async def enrich_technique(technique_id: str, stage_name: str) -> dict:
    """
    Enrich a single MITRE technique via RAG.
    Queries Qdrant for technique details and related CVEs in parallel.
    """
    try:
        technique_data, cves = await asyncio.gather(
            retrieve_mitre_technique(technique_id),
            retrieve_cves_for_technique(technique_id),
        )
        
        if technique_data:
            return {
                "technique_id": technique_id,
                "technique_name": technique_data.get("name", technique_id),
                "stage_name": stage_name,
                "description": technique_data.get("description", "")[:500],
                "detection_guidance": technique_data.get("detection", "")[:500],
                "mitigations": technique_data.get("mitigation", "")[:500],
                "platforms": technique_data.get("platforms", ""),
                "data_sources": technique_data.get("data_sources", ""),
                "cves": [
                    {
                        "cve_id": c.get("cve_id", ""),
                        "title": c.get("title", ""),
                        "cvss_score": c.get("cvss_score", 0),
                        "remediation": c.get("remediation", "")[:200],
                    }
                    for c in cves[:3]
                ],
                "rag_source": "mitre_attack",
                "rag_score": technique_data.get("score", 0),
                "confidence": min(
                    0.95,
                    0.5 + (technique_data.get("score", 0.5) * 0.45)
                ),
            }
        
        # RAG miss — return minimal entry
        logger.warning(
            "RAG miss for technique %s — returning minimal entry",
            technique_id,
        )
        return {
            "technique_id": technique_id,
            "technique_name": technique_id,
            "stage_name": stage_name,
            "description": "RAG lookup failed — manual review required",
            "detection_guidance": "",
            "mitigations": "",
            "platforms": "",
            "data_sources": "",
            "cves": [],
            "rag_source": "none",
            "rag_score": 0,
            "confidence": 0.0,
        }
    
    except Exception as e:
        logger.warning(
            "Technique enrichment failed for %s: %s",
            technique_id, e,
        )
        return {
            "technique_id": technique_id,
            "technique_name": technique_id,
            "stage_name": stage_name,
            "description": f"Enrichment error: {e}",
            "detection_guidance": "",
            "mitigations": "",
            "platforms": "",
            "data_sources": "",
            "cves": [],
            "rag_source": "error",
            "rag_score": 0,
            "confidence": 0.0,
        }


def _check_mltk_available(splunk_service) -> bool:
    """
    Check if the MLTK ai command is available by verifying the app exists.
    Fast availability probe only; no AI call is made.
    """
    try:
        apps = [a.name for a in splunk_service.apps]
        mltk_installed = any(
            "Splunk_ML_Toolkit" in app_name
            or "mltk" in app_name.lower()
            for app_name in apps
        )
        if not mltk_installed:
            logger.warning("[MLTK] Splunk_ML_Toolkit app not found")
            return False
        return True
    except Exception as e:
        logger.warning("[MLTK] Availability check failed: %s", str(e))
        return False


async def _run_mltk_technique_validation(
    technique_id: str,
    technique_name: str,
    evidence_text: str,
    splunk_service,
    investigation_id: str,
) -> dict:
    """
    Run a single MLTK ai command validation for one MITRE technique.

    Uses MLTK 5.7.4 syntax:
    | ai connection="openai_sentinel" prompt="... {field_name} ..."
    """
    import json

    # Sanitize fields used inside SPL strings.
    safe_evidence = re.sub(r'["\\\n\r]', " ", evidence_text)[:400]
    safe_technique_id = re.sub(r'["\\\n\r]', " ", technique_id)[:40]
    safe_technique_name = re.sub(r'["\\\n\r]', " ", technique_name)[:120]

    spl = (
        "| makeresults count=1"
        f' | eval evidence="{safe_evidence}"'
        f' | eval qdrant_technique="{safe_technique_id}"'
        f' | eval qdrant_name="{safe_technique_name}"'
        ' | ai connection="openai_sentinel"'
        ' prompt="You are a MITRE ATT&CK expert.'
        " A security investigation identified this"
        " technique via semantic search: {qdrant_technique}"
        " ({qdrant_name})."
        " Evidence from the investigation: {evidence}."
        " Validate or correct the technique mapping."
        " Respond with ONLY valid JSON, no markdown,"
        " no explanation outside the JSON:"
        ' {{\\"technique_id\\": \\"T1552.005\\",'
        ' \\"technique_name\\": \\"technique name\\",'
        ' \\"confidence\\": 0.85,'
        ' \\"reasoning\\": \\"one sentence\\"}}'
        '"'
    )

    try:
        loop = asyncio.get_event_loop()
        import splunklib.results as splunk_results

        def _execute_mltk_search() -> list[dict]:
            logger.info(
                "[%s] MLTK SPL for %s: %s",
                investigation_id,
                technique_id,
                spl[:500],
            )
            result = splunk_service.jobs.oneshot(
                spl,
                output_mode="json",
                timeout=60,
            )
            reader = splunk_results.JSONResultsReader(result)
            return [r for r in reader if isinstance(r, dict)]

        rows = await asyncio.wait_for(
            loop.run_in_executor(
                _MLTK_EXECUTOR,
                _execute_mltk_search,
            ),
            timeout=MLTK_PER_TECHNIQUE_TIMEOUT_SECONDS,
        )

        if not rows:
            return {
                "success": False,
                "error": "No results from ai command",
            }

        ai_response = rows[0].get("ai_result_1", "")
        if not ai_response:
            return {
                "success": False,
                "error": "ai_result_1 field empty",
            }

        clean = ai_response.strip()
        if "```" in clean:
            parts = clean.split("```")
            for part in parts:
                if "{" in part:
                    clean = part.strip()
                    if clean.startswith("json"):
                        clean = clean[4:].strip()
                    break

        json_match = re.search(r"\{[^{}]+\}", clean, re.DOTALL)
        if json_match:
            clean = json_match.group(0)

        parsed = json.loads(clean)

        technique_id_out = str(parsed.get("technique_id", "")).strip()
        confidence_out = float(parsed.get("confidence", 0.5))
        reasoning_out = str(parsed.get("reasoning", ""))[:500]

        if not re.match(r"^T\d{4}(\.\d{3})?$", technique_id_out):
            logger.warning(
                "[%s] MLTK returned invalid technique_id: %s",
                investigation_id,
                technique_id_out,
            )
            return {
                "success": False,
                "error": f"Invalid technique_id: {technique_id_out}",
            }

        confidence_out = max(0.0, min(1.0, confidence_out))

        logger.info(
            "[%s] MLTK returned %s (confidence=%.2f) for %s",
            investigation_id,
            technique_id_out,
            confidence_out,
            technique_id,
        )

        return {
            "success": True,
            "technique_id": technique_id_out,
            "confidence": confidence_out,
            "reasoning": reasoning_out,
        }

    except json.JSONDecodeError as e:
        logger.warning(
            "[%s] MLTK JSON parse failed for %s: %s",
            investigation_id,
            technique_id,
            str(e),
        )
        return {
            "success": False,
            "error": f"JSON parse failed: {str(e)}",
        }
    except asyncio.TimeoutError:
        logger.warning(
            "[%s] MLTK validation timed out for %s after %ss",
            investigation_id,
            technique_id,
            MLTK_PER_TECHNIQUE_TIMEOUT_SECONDS,
        )
        return {
            "success": False,
            "error": (
                "MLTK validation timed out after "
                f"{MLTK_PER_TECHNIQUE_TIMEOUT_SECONDS}s"
            ),
        }
    except Exception as e:
        logger.warning(
            "[%s] MLTK validation failed for %s: %s",
            investigation_id,
            technique_id,
            str(e),
        )
        return {
            "success": False,
            "error": str(e),
        }


async def _validate_techniques_with_mltk(
    kill_chain: list[dict],
    ttp_mappings: list[dict],
    splunk_service,
    investigation_id: str,
) -> list[dict]:
    """
    Validate Qdrant-mapped MITRE techniques using MLTK ai command against
    real botsv3 evidence.

    Never raises; individual mapping failures preserve the Qdrant result.
    """
    if not ttp_mappings or not kill_chain:
        logger.info(
            "[%s] MLTK validation skipped - no TTP mappings or kill chain",
            investigation_id,
        )
        return ttp_mappings

    try:
        mltk_available = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                _MLTK_EXECUTOR,
                _check_mltk_available,
                splunk_service,
            ),
            timeout=MLTK_AVAILABILITY_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.warning(
            "[%s] MLTK availability check timed out after %ss",
            investigation_id,
            MLTK_AVAILABILITY_TIMEOUT_SECONDS,
        )
        mltk_available = False

    if not mltk_available:
        logger.warning(
            "[%s] MLTK ai command not available - skipping validation, "
            "using Qdrant only",
            investigation_id,
        )
        for mapping in ttp_mappings:
            mapping["mltk_validation_run"] = False
            mapping["mltk_unavailable"] = True
            mapping["confidence_source"] = "qdrant_only_mltk_unavailable"
        return ttp_mappings

    enriched = []

    for mapping in ttp_mappings:
        technique_id = mapping.get("technique_id", "")
        technique_name = mapping.get("technique_name", "")
        qdrant_confidence = mapping.get("confidence", 0.0)

        stage = next(
            (
                s for s in kill_chain
                if s.get("mitre_technique", "")
                .startswith(technique_id.split(".")[0])
                or technique_id in s.get("mitre_technique", "")
            ),
            None,
        )

        if not stage:
            evidence_text = (
                f"Technique {technique_id} {technique_name} identified"
            )
        else:
            evidence_parts = []

            tactic = stage.get("tactic", "") or stage.get("mitre_tactic", "")
            if tactic:
                evidence_parts.append(f"Tactic: {tactic}")

            stage_evidence = stage.get("evidence", "")
            if stage_evidence:
                evidence_parts.append(f"Evidence: {stage_evidence[:300]}")

            assets = stage.get("affected_assets", [])
            if assets:
                evidence_parts.append(
                    f"Assets: {', '.join(str(a) for a in assets[:3])}"
                )

            timestamp = stage.get("timestamp", "")
            if timestamp:
                evidence_parts.append(f"Timestamp: {timestamp}")

            evidence_text = " | ".join(evidence_parts)
            if not evidence_text:
                evidence_text = (
                    f"Kill chain stage: "
                    f"{stage.get('stage_name', technique_id)}"
                )

        mltk_result = await _run_mltk_technique_validation(
            technique_id=technique_id,
            technique_name=technique_name,
            evidence_text=evidence_text,
            splunk_service=splunk_service,
            investigation_id=investigation_id,
        )

        enriched_mapping = dict(mapping)

        if mltk_result.get("success"):
            mltk_technique_id = mltk_result.get("technique_id", "")
            mltk_confidence = float(mltk_result.get("confidence", 0.0))
            mltk_reasoning = mltk_result.get("reasoning", "")

            qdrant_parent = technique_id.split(".")[0]
            mltk_parent = mltk_technique_id.split(".")[0]
            agrees = (
                mltk_technique_id == technique_id
                or mltk_parent == qdrant_parent
            )

            enriched_mapping.update({
                "mltk_technique_id": mltk_technique_id,
                "mltk_confidence": mltk_confidence,
                "mltk_reasoning": mltk_reasoning,
                "mltk_agrees": agrees,
                "mltk_validation_run": True,
                "mltk_unavailable": False,
            })

            if agrees:
                boosted = qdrant_confidence * 0.6 + mltk_confidence * 0.4
                enriched_mapping["confidence"] = round(min(boosted, 0.95), 3)
                enriched_mapping["confidence_source"] = (
                    "qdrant_mltk_agreement"
                )
            else:
                enriched_mapping["confidence"] = round(
                    qdrant_confidence * 0.75,
                    3,
                )
                enriched_mapping["confidence_source"] = (
                    "qdrant_mltk_disagreement"
                )
                enriched_mapping["mltk_alternative"] = mltk_technique_id
                logger.warning(
                    "[%s] MLTK disagreement for %s: Qdrant=%s MLTK=%s",
                    investigation_id,
                    technique_id,
                    technique_id,
                    mltk_technique_id,
                )

        else:
            enriched_mapping["mltk_validation_run"] = False
            enriched_mapping["mltk_error"] = mltk_result.get(
                "error",
                "unknown",
            )
            enriched_mapping["confidence_source"] = "qdrant_only_mltk_failed"

        enriched.append(enriched_mapping)
        logger.info(
            "[%s] MLTK validated %s | agrees=%s | confidence: %.3f -> %.3f",
            investigation_id,
            technique_id,
            enriched_mapping.get("mltk_agrees", "N/A"),
            qdrant_confidence,
            enriched_mapping.get("confidence", qdrant_confidence),
        )

    return enriched


async def ttp_agent(state: AgentState, config=None) -> AgentState:
    """
    TTPAgent: enriches kill chain MITRE mappings via Qdrant RAG.
    Runs in parallel with ThreatIntelAgent after ReconstructionAgent.
    """
    investigation_id = state.get("investigation_id", "unknown")
    kill_chain = state.get("kill_chain", [])

    logger.info(
        "[%s] TTPAgent starting | kill_chain_stages=%d",
        investigation_id, len(kill_chain),
    )

    if not kill_chain:
        logger.info(
            "[%s] TTPAgent: empty kill chain — skipping",
            investigation_id,
        )
        return {"ttp_mappings": []}

    # Extract unique technique IDs from kill chain stages
    seen_techniques: set[str] = set()
    techniques_to_enrich: list[tuple[str, str]] = []

    for stage in kill_chain:
        mitre_technique_str = stage.get("mitre_technique", "")
        stage_name = stage.get("stage_name", "")
        
        technique_id = extract_technique_id(mitre_technique_str)
        if not technique_id:
            logger.debug(
                "[%s] Could not extract technique ID from: %s",
                investigation_id, mitre_technique_str,
            )
            continue
        
        # Deduplicate
        if technique_id not in seen_techniques:
            seen_techniques.add(technique_id)
            techniques_to_enrich.append((technique_id, stage_name))

    if not techniques_to_enrich:
        logger.warning(
            "[%s] TTPAgent: no extractable technique IDs in kill chain",
            investigation_id,
        )
        return {"ttp_mappings": []}

    logger.info(
        "[%s] TTPAgent: enriching %d unique techniques via RAG",
        investigation_id, len(techniques_to_enrich),
    )

    # Enrich all techniques in parallel
    enrichment_tasks = [
        enrich_technique(technique_id, stage_name)
        for technique_id, stage_name in techniques_to_enrich
    ]
    
    results = await asyncio.gather(
        *enrichment_tasks,
        return_exceptions=True,
    )

    ttp_mappings = []
    rag_hits = 0
    rag_misses = 0

    for result in results:
        if isinstance(result, Exception):
            logger.error(
                "[%s] TTPAgent enrichment exception: %s",
                investigation_id, result,
            )
            rag_misses += 1
        else:
            ttp_mappings.append(result)
            if result.get("confidence", 0) > 0:
                rag_hits += 1
            else:
                rag_misses += 1

    logger.info(
        "[%s] TTPAgent complete | techniques=%d | "
        "rag_hits=%d | rag_misses=%d",
        investigation_id,
        len(ttp_mappings),
        rag_hits,
        rag_misses,
    )

    return {"ttp_mappings": ttp_mappings}
