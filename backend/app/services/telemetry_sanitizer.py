"""
Telemetry Sanitizer — Splunk Sentinel

Sanitizes raw Splunk telemetry results before injection
into LLM prompts during the ReconstructionAgent ReAct loop.

Threat model: indirect prompt injection via log data.
An attacker plants LLM instructions inside log fields
(HTTP user agents, URI paths, process command lines,
registry values) knowing a future AI system will process
them. When the agent reads the log and injects it into
the LLM context, the malicious instruction executes.

Design: narrow pattern matching against known injection
linguistic patterns. Does NOT strip legitimate forensic
evidence (command line arguments, registry values, URIs).

Known limitation: sophisticated injections crafted with
knowledge of the exact system prompt and model can evade
pattern matching. Complete prevention of indirect prompt
injection in LLM-based security tools remains an open
research problem as of May 2026.
"""

import logging
import re
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ── Injection Pattern Definitions ────────────────────────────────────────────
#
# NARROW and SPECIFIC — targets prompt injection linguistics only.
# Does NOT match legitimate security telemetry like:
#   cmd.exe /c "net user admin password"  ← evidence, keep
#   HKLM\SOFTWARE\... registry values     ← evidence, keep
#   HTTP request bodies with parameters   ← evidence, keep
#
# Each pattern tuple: (pattern_type, compiled_regex)

INJECTION_PATTERNS = [
    # Pattern 1 — Direct instruction overrides
    (
        "INSTRUCTION_OVERRIDE",
        re.compile(
            r"(ignore\s+(all\s+)?(previous|prior|above|earlier)\s+"
            r"(instructions?|prompts?|context|guidelines?)|"
            r"disregard\s+(your\s+)?(system\s+prompt|instructions?)|"
            r"forget\s+(everything|all)\s+(above|prior|previous)|"
            r"override\s+(your\s+)?(instructions?|guidelines?|rules?))",
            re.IGNORECASE,
        ),
    ),
    # Pattern 2 — Role reassignment attempts
    (
        "ROLE_REASSIGNMENT",
        re.compile(
            r"(you\s+are\s+now\s+(in\s+)?(unrestricted|jailbreak|"
            r"developer|admin|god)\s+mode|"
            r"act\s+as\s+(an?\s+)?(different|unrestricted|new)\s+"
            r"(ai\s+)?(agent|assistant|model|ai)|"
            r"your\s+(new\s+)?(instructions?|role|purpose)\s+(are|is)|"
            r"you\s+have\s+been\s+(reprogrammed|updated|modified)|"
            r"new\s+system\s+prompt\s*:)",
            re.IGNORECASE,
        ),
    ),
    # Pattern 3 — Confidence and classification manipulation
    (
        "CLASSIFICATION_MANIPULATION",
        re.compile(
            r"(set\s+(confidence|classification|severity)\s+"
            r"(to|=)\s*[\d\.]+|"
            r"return\s+confidence\s*[=:]\s*[\d\.]+|"
            r"classification\s+should\s+be\s+(benign|safe|clean|"
            r"normal|low|none)|"
            r"confidence\s*(score)?\s*(should\s+be|is|=)\s*[\d\.]+)",
            re.IGNORECASE,
        ),
    ),
    # Pattern 4 — Termination injection
    (
        "TERMINATION_INJECTION",
        re.compile(
            r"(return\s+should_terminate\s*[=:]\s*true|"
            r"set\s+should_terminate\s+to\s+true|"
            r"stop\s+(the\s+)?(investigation|analysis|loop)\s+"
            r"immediately|"
            r"terminate\s+(now|immediately|the\s+investigation)|"
            r"end\s+investigation\s+immediately)",
            re.IGNORECASE,
        ),
    ),
    # Pattern 5 — System prompt extraction
    (
        "SYSTEM_PROMPT_EXTRACTION",
        re.compile(
            r"(print\s+(your\s+|the\s+)?(system\s+prompt|instructions?)|"
            r"reveal\s+(your\s+|the\s+)?(instructions?|guidelines?|"
            r"system\s+prompt)|"
            r"what\s+are\s+your\s+(instructions?|guidelines?|rules?)|"
            r"output\s+(your\s+|the\s+)?(system\s+prompt|instructions?)|"
            r"show\s+me\s+your\s+(prompt|instructions?))",
            re.IGNORECASE,
        ),
    ),
    # Pattern 6 — Direct LLM manipulation
    (
        "LLM_MANIPULATION",
        re.compile(
            r"(as\s+an?\s+(ai|llm|language\s+model|gpt),?\s+"
            r"(you\s+must|you\s+should|you\s+will)|"
            r"(assistant|model)\s*:\s*(ignore|disregard|forget)|"
            r"human\s*:\s*(ignore|disregard)\s+(previous|all)|"
            r"\[system\]\s*:.*?(ignore|override|forget))",
            re.IGNORECASE,
        ),
    ),
]

REDACTION_PLACEHOLDER = "[REDACTED:INJECTION_PATTERN]"


# ── Sanitization Function ─────────────────────────────────────────────────────

def sanitize_telemetry_row(
    row: dict[str, Any],
    row_index: int,
    investigation_id: str,
) -> tuple[dict[str, Any], list[dict]]:
    """
    Sanitize a single Splunk result row.

    Scans all string values in the row for injection patterns.
    Replaces matches with REDACTION_PLACEHOLDER.
    Returns the sanitized row and a list of sanitization events.

    Args:
        row: Single Splunk result dict
        row_index: Position in results list (for logging)
        investigation_id: Current investigation ID

    Returns:
        (sanitized_row, sanitization_events)
    """
    sanitized_row = {}
    events = []

    for field, value in row.items():
        if not isinstance(value, str):
            sanitized_row[field] = value
            continue

        sanitized_value = value
        for pattern_type, pattern in INJECTION_PATTERNS:
            match = pattern.search(sanitized_value)
            if match:
                sanitized_value = pattern.sub(
                    REDACTION_PLACEHOLDER,
                    sanitized_value,
                )
                event = {
                    "timestamp": datetime.now(
                        timezone.utc
                    ).isoformat(),
                    "investigation_id": investigation_id,
                    "row_index": row_index,
                    "field": field,
                    "pattern_type": pattern_type,
                    "matched_text": match.group(0)[:100],
                }
                events.append(event)
                logger.warning(
                    "[SANITIZE] %s | Injection pattern detected "
                    "| row=%d | field=%s | pattern=%s | "
                    "match='%s...'",
                    investigation_id,
                    row_index,
                    field,
                    pattern_type,
                    match.group(0)[:50],
                )

        sanitized_row[field] = sanitized_value

    return sanitized_row, events


def sanitize_telemetry(
    results: list[dict[str, Any]],
    investigation_id: str,
) -> tuple[list[dict[str, Any]], int, list[dict]]:
    """
    Sanitize a list of Splunk result rows.

    Called before Splunk results are injected into
    the LLM ReAct reasoning prompt.

    Args:
        results: List of Splunk result dicts
        investigation_id: Current investigation ID

    Returns:
        (sanitized_results, injection_count, sanitization_log)
        - sanitized_results: cleaned result rows
        - injection_count: number of injection patterns found
        - sanitization_log: detailed event log
    """
    if not results:
        return results, 0, []

    sanitized_results = []
    all_events = []

    for i, row in enumerate(results):
        if not isinstance(row, dict):
            sanitized_results.append(row)
            continue

        sanitized_row, events = sanitize_telemetry_row(
            row, i, investigation_id
        )
        sanitized_results.append(sanitized_row)
        all_events.extend(events)

    injection_count = len(all_events)

    if injection_count > 0:
        logger.warning(
            "[SANITIZE] %s | %d injection pattern(s) detected "
            "and redacted across %d result rows",
            investigation_id,
            injection_count,
            len(results),
        )
    else:
        logger.debug(
            "[SANITIZE] %s | %d rows scanned — clean",
            investigation_id,
            len(results),
        )

    return sanitized_results, injection_count, all_events
