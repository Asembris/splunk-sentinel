"""
RAG Retriever module for Splunk Sentinel.

Provides:
- retrieve_mitre_technique(): get technique details by ID
- retrieve_for_synthesis(): parallel search across all collections
- retrieve_playbook(): get relevant IR playbook by attack type
- semantic_search(): generic search on any collection

Used by TTPAgent and SynthesisAgent.
"""

import asyncio
import logging
import os
from typing import Any, Optional

from openai import AsyncOpenAI
from qdrant_client import AsyncQdrantClient
from qdrant_client.models import Filter, FieldCondition, MatchValue

from app.rag.collections import (
    BOTSV3_COLLECTION,
    CVE_COLLECTION,
    DEFAULT_TOP_K,
    EMBEDDING_MODEL,
    MITRE_COLLECTION,
    PLAYBOOK_COLLECTION,
    SIMILARITY_THRESHOLD,
)

logger = logging.getLogger(__name__)

# Async clients for use inside async agents
_openai_client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
_qdrant_client = AsyncQdrantClient(
    url=os.getenv("QDRANT_URL"),
    api_key=os.getenv("QDRANT_API_KEY"),
)


async def _embed_query(query: str) -> list[float]:
    """Generate embedding for a search query."""
    # Note: text-embedding-3-large supports dimensions, but we stick to the model default or EMBEDDING_DIMS
    response = await _openai_client.embeddings.create(
        model=EMBEDDING_MODEL,
        input=query,
    )
    return response.data[0].embedding


async def semantic_search(
    collection_name: str,
    query: str,
    top_k: int = DEFAULT_TOP_K,
    threshold: float = SIMILARITY_THRESHOLD,
    payload_filter: Optional[Filter] = None,
) -> list[dict[str, Any]]:
    """
    Semantic search on a Qdrant collection.
    Returns list of results with score and payload.
    """
    try:
        query_vector = await _embed_query(query)

        results = await _qdrant_client.search(
            collection_name=collection_name,
            query_vector=query_vector,
            limit=top_k,
            query_filter=payload_filter,
            with_payload=True,
            score_threshold=threshold,
        )

        return [
            {
                "score": result.score,
                "collection": collection_name,
                **result.payload,
            }
            for result in results
        ]
    except Exception as e:
        logger.error(
            "Semantic search failed on %s: %s", collection_name, e
        )
        return []


async def retrieve_mitre_technique(technique_id: str) -> Optional[dict]:
    """
    Retrieve full MITRE technique details by technique ID.
    Used by TTPAgent to enrich kill chain stage mappings.
    
    Args:
        technique_id: e.g. "T1190" or "T1552.005"
    
    Returns:
        Technique dict with description, detection, mitigations
        or None if not found.
    """
    try:
        # First try exact match via filter
        results = await _qdrant_client.scroll(
            collection_name=MITRE_COLLECTION,
            scroll_filter=Filter(
                must=[
                    FieldCondition(
                        key="id",
                        match=MatchValue(value=technique_id)
                    )
                ]
            ),
            limit=1,
            with_payload=True,
        )

        if results[0]:
            payload = results[0][0].payload
            logger.debug(
                "Found MITRE technique %s via exact match", technique_id
            )
            return payload

        # Fallback: semantic search
        logger.debug(
            "Exact match not found for %s — trying semantic search",
            technique_id
        )
        query = f"MITRE ATT&CK technique {technique_id}"
        search_results = await semantic_search(
            MITRE_COLLECTION,
            query,
            top_k=1,
            threshold=0.3,
        )

        if search_results:
            return search_results[0]

        return None

    except Exception as e:
        logger.error(
            "retrieve_mitre_technique failed for %s: %s",
            technique_id, e
        )
        return None


async def retrieve_for_synthesis(
    attack_classification: str,
    kill_chain_stages: list[dict],
    patient_zero_ip: str,
    attack_narrative: str,
) -> dict[str, list[dict]]:
    """
    Parallel retrieval from all 4 collections for SynthesisAgent.
    
    Returns dict with results from each collection:
    {
        "mitre": [...],
        "cve": [...],
        "playbooks": [...],
        "botsv3": [...]
    }
    """
    # Build targeted queries per collection
    mitre_tactics = " ".join(
        f"{s.get('mitre_tactic', '')} {s.get('mitre_technique', '')}"
        for s in kill_chain_stages[:3]
    )
    
    stage_names = " ".join(
        s.get("stage_name", "") for s in kill_chain_stages[:3]
    )

    mitre_query = (
        f"{attack_classification} attack techniques: {mitre_tactics} "
        f"detection and mitigation"
    )
    cve_query = (
        f"{attack_classification} vulnerability exploitation "
        f"{stage_names} CVE remediation"
    )
    playbook_query = (
        f"{attack_classification} incident response playbook "
        f"{stage_names}"
    )
    botsv3_query = (
        f"botsv3 {attack_classification} investigation "
        f"{patient_zero_ip} {stage_names}"
    )

    # Run all 4 searches in parallel
    mitre_results, cve_results, playbook_results, botsv3_results = (
        await asyncio.gather(
            semantic_search(MITRE_COLLECTION, mitre_query, top_k=5),
            semantic_search(CVE_COLLECTION, cve_query, top_k=3),
            semantic_search(PLAYBOOK_COLLECTION, playbook_query, top_k=2),
            semantic_search(BOTSV3_COLLECTION, botsv3_query, top_k=3),
        )
    )

    logger.info(
        "RAG retrieval complete | mitre=%d | cve=%d | playbooks=%d | botsv3=%d",
        len(mitre_results), len(cve_results),
        len(playbook_results), len(botsv3_results),
    )

    return {
        "mitre": mitre_results,
        "cve": cve_results,
        "playbooks": playbook_results,
        "botsv3": botsv3_results,
    }


async def retrieve_playbook(
    attack_type: str,
    kill_chain_summary: str,
) -> Optional[dict]:
    """
    Retrieve the most relevant IR playbook for an attack type.
    Used by SynthesisAgent for response recommendations.
    """
    query = f"{attack_type} incident response {kill_chain_summary}"
    results = await semantic_search(
        PLAYBOOK_COLLECTION,
        query,
        top_k=1,
        threshold=0.3,
    )
    return results[0] if results else None


async def retrieve_cves_for_technique(
    mitre_technique: str,
) -> list[dict]:
    """
    Retrieve CVEs related to a specific MITRE technique.
    Used by TTPAgent to link techniques to known vulnerabilities.
    """
    query = f"CVE vulnerability {mitre_technique} exploitation"
    return await semantic_search(
        CVE_COLLECTION,
        query,
        top_k=3,
        threshold=0.35,
    )
