"""
spl_guardrail.py
----------------
Standalone, import-friendly 3-layer SPL safety guardrail.

This module is intentionally decoupled from SplunkClient so it can be:
  - Unit-tested independently
  - Imported by any future agent that generates SPL before execution
  - Audited without touching the Splunk connection layer

Layer 1 — Deterministic keyword block  (zero LLM calls, instant)
Layer 2 — Index protection             (only botsv3 is permitted)
Layer 3 — Audit logging                (timestamp + SPL written to file)
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

PERMITTED_INDEX = "botsv3"

BLOCKED_KEYWORDS: list[str] = [
    "| delete",
    "delete-index",
    "drop index",
    "| truncate",
    "| outputlookup overwrite=true",
    "| sendemail",
    "| script",
]

AUDIT_LOG_PATH = Path("logs") / "spl_audit.log"

# Regex to extract index names from SPL: captures the value after "index="
_INDEX_PATTERN = re.compile(r"\bindex\s*=\s*(\S+)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _layer1_keyword_check(spl: str) -> str | None:
    """
    Return the first blocked keyword found in *spl* (case-insensitive),
    or None if the query is clean.

    This is Layer 1 of the guardrail — a pure string scan with no LLM calls.
    """
    spl_lower = spl.lower()
    for term in BLOCKED_KEYWORDS:
        if term.lower() in spl_lower:
            return term
    return None


def _layer2_index_check(spl: str) -> str | None:
    """
    Return the first non-permitted index name found in *spl*, or None.

    Uses a regex to extract all index= values and rejects any that are
    not the permitted botsv3 index.
    """
    index_matches = re.findall(r'index\s*=\s*([^\s|]+)', spl, re.IGNORECASE)

    # Strictly require at least one index specification
    if not index_matches:
        return "MISSING_INDEX"

    for idx in index_matches:
        idx_clean = idx.strip().strip('"').strip("'")
        if idx_clean.lower() != PERMITTED_INDEX.lower():
            return idx_clean
    return None


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

def check(spl: str) -> None:
    """
    Run all guardrail layers against *spl*.

    Raises:
        ValueError: with a human-readable, prefixed message describing which
                    layer blocked the query and why.

    Layer 3 (audit logging) runs only when Layers 1 and 2 pass.
    """
    blocked_keyword = _layer1_keyword_check(spl)
    if blocked_keyword is not None:
        msg = (
            f"BLOCKED - Layer 1: Dangerous SPL keyword detected: '{blocked_keyword}'. "
            f"This query has been rejected to protect Splunk data integrity."
        )
        logger.warning("SPL guardrail Layer 1 triggered | keyword=%r | spl=%r", blocked_keyword, spl[:120])
        raise ValueError(msg)

    unauthorized_index = _layer2_index_check(spl)
    if unauthorized_index is not None:
        msg = (
            f"BLOCKED - Layer 2: SPL targets unauthorized index: '{unauthorized_index}'. "
            f"Only index={PERMITTED_INDEX} is permitted."
        )
        logger.warning(
            "SPL guardrail Layer 2 triggered | index=%r | spl=%r",
            unauthorized_index,
            spl[:120],
        )
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
    blocked_keyword = _layer1_keyword_check(spl)
    if blocked_keyword is not None:
        return (
            f"Layer 1 block — dangerous keyword detected: '{blocked_keyword}'"
        )

    unauthorized_index = _layer2_index_check(spl)
    if unauthorized_index is not None:
        return (
            f"Layer 2 block — unauthorized index: '{unauthorized_index}' "
            f"(only '{PERMITTED_INDEX}' is permitted)"
        )

    return None


# ---------------------------------------------------------------------------
# Object-oriented API (used by tests)
# ---------------------------------------------------------------------------

class ValidationResult:
    """Encapsulates the result of a guardrail validation check."""
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

    def validate(self, spl: str) -> ValidationResult:
        """deterministic layer 1 & 2 check"""
        reason = get_blocked_reason(spl)
        return ValidationResult(is_blocked=reason is not None, reason=reason)

    def audit(self, spl: str) -> None:
        """layer 3: record the query with timestamp"""
        _layer3_audit_log(spl)
        # Capture in memory for testing/verification
        timestamp = datetime.now(timezone.utc).isoformat()
        self.audit_entries.append(f"[{timestamp}] {spl}")
