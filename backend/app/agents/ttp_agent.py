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
from typing import Optional

from app.models.state import AgentState
from app.rag.retriever import (
    retrieve_cves_for_technique,
    retrieve_mitre_technique,
)

logger = logging.getLogger(__name__)


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


async def ttp_agent(state: AgentState) -> AgentState:
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
