"""
Hash-chained audit log for Splunk Sentinel.

Every SPL query executed by any agent is recorded as a
tamper-evident entry. Each entry's hash depends on all
previous entries, forming a cryptographic chain.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

def calculate_entry_hash(content: dict, prev_hash: str) -> str:
    """
    Calculate the SHA-256 hash of an entry's content plus the previous hash.
    
    Args:
        content: The dictionary containing entry fields.
        prev_hash: The hash of the previous entry in the chain.
        
    Returns:
        A hex string of the SHA-256 hash.
    """
    # Canonicalize content (sort keys, no extra whitespace)
    content_json = json.dumps(content, sort_keys=True)
    combined = content_json + prev_hash
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()

def append_chained_entry(audit_log: list[str], content: dict) -> None:
    """
    Appends a new chained entry to the audit log.
    
    Args:
        audit_log: The list of JSON-serialized audit entries.
        content: The new entry's content (without hashes).
    """
    # 1. Get the previous hash
    if not audit_log:
        prev_hash = "0" * 64
    else:
        try:
            last_entry = json.loads(audit_log[-1])
            prev_hash = last_entry.get("entry_hash", "0" * 64)
        except (json.JSONDecodeError, KeyError):
            logger.warning("Failed to decode last audit entry; starting new chain")
            prev_hash = "0" * 64

    # 2. Calculate this entry's hash
    entry_hash = calculate_entry_hash(content, prev_hash)
    
    # 3. Create the chained entry
    chained_entry = {
        **content,
        "prev_hash": prev_hash,
        "entry_hash": entry_hash
    }
    
    # 4. Append to log as JSON
    audit_log.append(json.dumps(chained_entry))

def verify_chain(audit_log: list[str]) -> dict:
    """
    Verifies the integrity of the hash chain.
    
    Returns:
        A dict with 'valid' (bool) and 'details' (str).
    """
    if not audit_log:
        return {"valid": True, "details": "Audit log is empty (valid by default)."}

    expected_prev_hash = "0" * 64
    
    for i, entry_json in enumerate(audit_log):
        try:
            entry = json.loads(entry_json)
        except json.JSONDecodeError:
            return {"valid": False, "details": f"Entry {i} is not valid JSON."}
            
        # Check prev_hash matches
        if entry.get("prev_hash") != expected_prev_hash:
            return {
                "valid": False, 
                "details": f"Entry {i} has invalid prev_hash. Expected {expected_prev_hash}, got {entry.get('prev_hash')}."
            }
            
        # Check entry_hash matches
        content = {k: v for k, v in entry.items() if k not in ["prev_hash", "entry_hash"]}
        actual_hash = calculate_entry_hash(content, expected_prev_hash)
        
        if entry.get("entry_hash") != actual_hash:
            return {
                "valid": False,
                "details": f"Entry {i} has been tampered with. Calculated hash {actual_hash} does not match stored hash {entry.get('entry_hash')}."
            }
            
        # Move to next
        expected_prev_hash = entry.get("entry_hash")
        
    return {"valid": True, "details": f"Successfully verified {len(audit_log)} entries."}
