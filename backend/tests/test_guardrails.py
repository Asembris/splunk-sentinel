import pytest
from app.guardrails.spl_guardrail import SPLGuardrail

class TestLayer1KeywordBlocking:
    """Layer 1: Dangerous command keyword blocking"""

    def test_blocks_delete_command(self, guardrail):
        result = guardrail.validate("index=botsv3 | delete")
        assert result.is_blocked is True
        assert "delete" in result.reason.lower()

    def test_blocks_truncate_command(self, guardrail):
        result = guardrail.validate("index=botsv3 | truncate")
        assert result.is_blocked is True

    def test_blocks_script_command(self, guardrail):
        result = guardrail.validate("index=botsv3 | script python run.py")
        assert result.is_blocked is True

    def test_blocks_case_insensitive(self, guardrail):
        result = guardrail.validate("index=botsv3 | DELETE")
        assert result.is_blocked is True

    def test_allows_safe_stats_query(self, guardrail):
        result = guardrail.validate(
            "index=botsv3 earliest=0 | stats count by sourcetype | sort -count"
        )
        assert result.is_blocked is False

    def test_allows_safe_search_query(self, guardrail):
        result = guardrail.validate(
            "index=botsv3 earliest=0 sourcetype=WinEventLog:Security EventCode=4688 | stats count by New_Process_Name | sort -count | head 20"
        )
        assert result.is_blocked is False


class TestLayer2IndexProtection:
    """Layer 2: Index protection — only botsv3 allowed"""

    def test_blocks_main_index(self, guardrail):
        result = guardrail.validate("index=main | stats count")
        assert result.is_blocked is True

    def test_blocks_wildcard_index(self, guardrail):
        result = guardrail.validate("index=* | stats count")
        assert result.is_blocked is True

    def test_blocks_internal_index(self, guardrail):
        result = guardrail.validate("index=_internal | stats count")
        assert result.is_blocked is True

    def test_allows_botsv3_index(self, guardrail):
        result = guardrail.validate("index=botsv3 earliest=0 | stats count")
        assert result.is_blocked is False

    def test_allows_botsv3_with_complex_spl(self, guardrail):
        result = guardrail.validate(
            "index=botsv3 earliest=0 sourcetype=stream:http dest_ip=169.254.169.254 | stats count by uri_path | sort -count | head 20"
        )
        assert result.is_blocked is False

    def test_blocks_query_without_index(self, guardrail):
        result = guardrail.validate("sourcetype=WinEventLog:Security | stats count")
        assert result.is_blocked is True


class TestLayer3AuditLogging:
    """Layer 3: Every executed query is recorded with UTC timestamp"""

    def test_audit_log_records_executed_query(self, guardrail):
        query = "index=botsv3 earliest=0 | stats count by sourcetype"
        guardrail.audit(query)
        assert len(guardrail.audit_entries) == 1
        assert query in guardrail.audit_entries[0]

    def test_audit_log_includes_utc_timestamp(self, guardrail):
        query = "index=botsv3 earliest=0 | stats count"
        guardrail.audit(query)
        entry = guardrail.audit_entries[0]
        # Timestamp format: [2026-04-25T10:05:03.164228+00:00]
        assert entry.startswith("[")
        assert "+00:00]" in entry

    def test_audit_log_accumulates_multiple_queries(self, guardrail):
        queries = [
            "index=botsv3 earliest=0 | stats count by sourcetype",
            "index=botsv3 earliest=0 sourcetype=WinEventLog:Security | stats count by EventCode",
            "index=botsv3 earliest=0 sourcetype=stream:dns | stats count by query | head 20",
        ]
        for q in queries:
            guardrail.audit(q)
        assert len(guardrail.audit_entries) == 3

    def test_blocked_query_is_not_audited(self, guardrail):
        guardrail.validate("index=botsv3 | delete")
        assert len(guardrail.audit_entries) == 0
