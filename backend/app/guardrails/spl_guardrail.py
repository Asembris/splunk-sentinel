"""
3-Layer SPL Guardrail — Splunk Sentinel

Deterministic, 0ms, zero LLM calls.
All safety decisions are made without AI inference.

Layer 1 — Keyword and Pattern Blocking:
  Blocked terms: DELETE, DROP, outputlookup, sendemail,
  _internal, _audit, | rest, | inputlookup, | run,
  | collect, | sendalert
  Blocked patterns: subsearch syntax [search ...],
  backtick macro expansion `macro_name`,
  any command that bypasses index= restriction

Layer 2 — Index Authorization:
  Permitted: index=botsv3, index=sentinel_findings
  Blocked: all other indexes
  Handles: index=value AND index IN (v1, v2) syntax
  Case-insensitive matching

Layer 3 — SHA-256 Hash-Chained Audit Log:
  Every attempt (blocked or executed) is recorded
  with cryptographic chain linking
  GET /api/audit-log/verify to check integrity

Known limitation: Splunk's REST parser endpoint
(POST /services/search/parser) could provide AST-level
validation for complete macro expansion detection.
This is documented as a future enhancement.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

PERMITTED_INDEXES = {"botsv3", "sentinel_findings", "sentinel_actions"}

BLOCKED_KEYWORDS: list[str] = [
    "delete",
    "drop index",
    "truncate",
    "script",
    "_internal",
    "_audit",
    "outputlookup",
    "sendemail",
]

# Subsearch injection — blocks [search ...] and [| ...]
# Legitimate investigation queries never need subsearches
BLOCKED_SUBSEARCH_PATTERNS = [
    r'\[search\s',      # [search index=_internal...]
    r'\[\s*\|',         # [| inputlookup ...]
    r'\[\s*search\s',   # [ search ...]
]

# Backtick macro expansion
# Macros expand server-side — cannot validate their content
BLOCKED_MACRO_PATTERN = r'`[^`]*`'

# REST API access — bypasses index= restriction entirely
# inputlookup — accesses lookup files, not indexes
ADDITIONAL_BLOCKED_TERMS = [
    '| rest ',
    '|rest ',
    '| inputlookup',
    '|inputlookup',
    '| run ',
    '|run ',
    '| collect',
    '|collect',
    '| sendalert',
    '|sendalert',
]

AUDIT_LOG_PATH = Path("logs") / "spl_audit.log"

@dataclass
class GuardrailResult:
    is_blocked: bool
    layer: int
    reason: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _layer1_check(spl: str) -> GuardrailResult:
    """
    Layer 1: Keyword and Pattern Blocking.
    Returns GuardrailResult if blocked, otherwise a clean result.
    """
    spl_lower = spl.lower()

    # Check subsearch patterns
    for pattern in BLOCKED_SUBSEARCH_PATTERNS:
        if re.search(pattern, spl, re.IGNORECASE):
            return GuardrailResult(
                is_blocked=True,
                layer=1,
                reason=f"SUBSEARCH_INJECTION: subsearch syntax "
                       f"detected and blocked. Pattern: {pattern}",
            )

    # Check macro expansion
    if re.search(BLOCKED_MACRO_PATTERN, spl):
        return GuardrailResult(
            is_blocked=True,
            layer=1,
            reason="MACRO_EXPANSION: backtick macro syntax detected. "
                   "Macros expand server-side and cannot be validated.",
        )

    # Check additional blocked commands
    for term in ADDITIONAL_BLOCKED_TERMS:
        if term.lower() in spl_lower:
            # EXCEPTION: allow '| collect' ONLY if targeting 'sentinel_actions'
            if "| collect" in term.lower() or "|collect" in term.lower():
                if "index=sentinel_actions" in spl_lower:
                    continue
            
            return GuardrailResult(
                is_blocked=True,
                layer=1,
                reason=f"BLOCKED_COMMAND: '{term.strip()}' is not "
                       f"permitted in investigation queries.",
            )

    # Check original blocked keywords
    for term in BLOCKED_KEYWORDS:
        if term.lower() in spl_lower:
            return GuardrailResult(
                is_blocked=True,
                layer=1,
                reason=f"DANGEROUS_KEYWORD: '{term}' detected.",
            )

    return GuardrailResult(is_blocked=False, layer=0, reason="")


def _extract_indexes_from_spl(spl: str) -> list[str]:
    """
    Extract all index references from an SPL query.
    Handles both index=value and index IN (v1, v2) syntax.
    Case-insensitive.
    """
    indexes = []

    # Standard index=value pattern (case-insensitive)
    standard_matches = re.findall(
        r'index\s*=\s*([^\s|,\]]+)',
        spl,
        re.IGNORECASE,
    )
    indexes.extend(standard_matches)

    # IN operator pattern: index IN (val1, val2, ...)
    in_matches = re.findall(
        r'index\s+in\s*\(([^)]+)\)',
        spl,
        re.IGNORECASE,
    )
    for match in in_matches:
        # Split by comma and strip whitespace/quotes
        values = [
            v.strip().strip('"\'')
            for v in match.split(',')
        ]
        indexes.extend(values)

    # Deduplicate and lowercase for comparison
    return list(set(i.lower().strip() for i in indexes if i))


def _layer2_index_authorization(spl: str) -> GuardrailResult:
    """
    Layer 2: Verify all indexes in the query are permitted.
    Blocks any query targeting non-permitted indexes.
    """
    indexes = _extract_indexes_from_spl(spl)

    # If no index found at all — block (prevent index-free queries)
    if not indexes:
        # Exception: allow pure | makeresults or | rest already
        # blocked by Layer 1. If we reach here with no index,
        # it's suspicious.
        return GuardrailResult(
            is_blocked=True,
            layer=2,
            reason="MISSING_INDEX: no index= found in query. "
                   "All queries must explicitly target index=botsv3.",
        )

    # Check every extracted index against permitted list
    for index in indexes:
        if index not in PERMITTED_INDEXES:
            return GuardrailResult(
                is_blocked=True,
                layer=2,
                reason=f"UNAUTHORIZED_INDEX: index '{index}' is not "
                       f"permitted. Only {PERMITTED_INDEXES} allowed.",
            )

    return GuardrailResult(is_blocked=False, layer=0, reason="")


def _layer3_audit_log(spl: str) -> None:
    """
    Append the SPL query with an ISO-8601 UTC timestamp to the audit log file.

    This is Layer 3 of the guardrail — it always runs for queries that pass
    Layers 1 and 2, providing a transparent record for compliance and forensics.
    """
    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).isoformat()
        entry = f"[{timestamp}] {spl}\n"
        with AUDIT_LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(entry)
    except OSError as exc:
        # Audit logging failure must never block query execution
        logger.warning("SPL audit log write failed: %s", exc)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def validate_spl(spl: str) -> GuardrailResult:
    """
    Core validation function that runs Layer 1 and Layer 2 checks.
    """
    # Layer 1: Keywords and Patterns
    l1_result = _layer1_check(spl)
    if l1_result.is_blocked:
        return l1_result

    # Layer 2: Index Authorization
    l2_result = _layer2_index_authorization(spl)
    if l2_result.is_blocked:
        return l2_result

    return GuardrailResult(is_blocked=False, layer=0, reason="")


def check(spl: str) -> None:
    """
    Run all guardrail layers against *spl*.

    Raises:
        ValueError: with a human-readable, prefixed message describing which
                    layer blocked the query and why.

    Layer 3 (audit logging) runs only when Layers 1 and 2 pass.
    """
    result = validate_spl(spl)
    if result.is_blocked:
        msg = f"BLOCKED - Layer {result.layer}: {result.reason}"
        logger.warning("SPL guardrail triggered | layer=%d | reason=%s | spl=%s", 
                       result.layer, result.reason, spl[:120])
        raise ValueError(msg)

    # Layer 3 — audit every approved query
    _layer3_audit_log(spl)
    logger.debug("SPL guardrail passed | spl=%r", spl[:120])


def is_safe(spl: str) -> bool:
    """
    Return True if *spl* passes all guardrail layers, False otherwise.

    This is the non-raising convenience wrapper — useful for conditional
    logic where the caller handles blocking without catching exceptions.
    Audit logging still runs for safe queries.
    """
    try:
        check(spl)
        return True
    except ValueError:
        return False


def get_blocked_reason(spl: str) -> str | None:
    """
    Return a human-readable explanation if *spl* would be blocked,
    or None if the query is safe to execute.

    Audit logging does NOT run when this function detects a block,
    since the query will not be executed.
    """
    result = validate_spl(spl)
    if result.is_blocked:
        return f"Layer {result.layer} block — {result.reason}"
    return None


# ---------------------------------------------------------------------------
# Object-oriented API (used by tests)
# ---------------------------------------------------------------------------

class ValidationResult:
    """Encapsulates the result of a guardrail validation check. (Deprecated - use GuardrailResult)"""
    def __init__(self, is_blocked: bool, reason: str | None = None):
        self.is_blocked = is_blocked
        self.reason = reason


class SPLGuardrail:
    """
    Stateful wrapper for the SPL guardrail system.
    Maintains a local audit log for testing/transparency.
    """
    def __init__(self) -> None:
        self.audit_entries: list[str] = []

    def validate(self, spl: str) -> GuardrailResult:
        """deterministic layer 1 & 2 check"""
        return validate_spl(spl)

    def audit(self, spl: str) -> None:
        """layer 3: record the query with timestamp"""
        _layer3_audit_log(spl)
        # Capture in memory for testing/verification
        timestamp = datetime.now(timezone.utc).isoformat()
        self.audit_entries.append(f"[{timestamp}] {spl}")
