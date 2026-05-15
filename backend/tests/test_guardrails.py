from app.guardrails.spl_guardrail import SPLGuardrail, validate_spl

class TestLayer1KeywordBlocking:
    """Layer 1: Dangerous command keyword blocking"""

    def test_blocks_delete_command(self, guardrail):
        result = guardrail.validate("index=botsv3 | delete")
        assert result.is_blocked is True
        assert "dangerous_keyword" in result.reason.lower()

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


# ── Bypass Vector Tests ──────────────────────────────────────────────

class TestSubsearchBypassBlocked:
    def test_subsearch_search_syntax_blocked(self):
        """[search index=_internal] must be blocked at Layer 1"""
        spl = (
            "index=botsv3 earliest=0 "
            "[search index=_internal | head 1 | fields host] "
            "| stats count by host"
        )
        result = validate_spl(spl)
        assert result.is_blocked is True
        assert result.layer == 1
        assert "SUBSEARCH" in result.reason

    def test_subsearch_pipe_syntax_blocked(self):
        """[| inputlookup ...] subsearch variant must be blocked"""
        spl = (
            "index=botsv3 earliest=0 "
            "[| inputlookup users.csv | fields username] "
            "| stats count"
        )
        result = validate_spl(spl)
        assert result.is_blocked is True
        assert result.layer == 1


class TestMacroBypassBlocked:
    def test_backtick_macro_blocked(self):
        """`my_macro` syntax must be blocked at Layer 1"""
        spl = "index=botsv3 earliest=0 `malicious_macro` | stats count"
        result = validate_spl(spl)
        assert result.is_blocked is True
        assert result.layer == 1
        assert "MACRO" in result.reason

    def test_empty_macro_blocked(self):
        """Even empty backtick macro must be blocked"""
        spl = "index=botsv3 earliest=0 `` | stats count"
        result = validate_spl(spl)
        assert result.is_blocked is True
        assert result.layer == 1


class TestInOperatorBypassBlocked:
    def test_in_operator_with_internal_blocked(self):
        """index IN (botsv3, _internal) must be blocked at Layer 2"""
        spl = (
            "index IN (botsv3, _internal) earliest=0 "
            "| stats count by sourcetype"
        )
        result = validate_spl(spl)
        assert result.is_blocked is True

    def test_in_operator_botsv3_only_passes(self):
        """index IN (botsv3) with only botsv3 must pass"""
        spl = (
            "index IN (botsv3) earliest=0 "
            "| stats count by sourcetype"
        )
        result = validate_spl(spl)
        assert result.is_blocked is False


class TestRestAndInputlookupBlocked:
    def test_rest_command_blocked(self):
        """| rest /services/... must be blocked at Layer 1"""
        spl = "| rest /services/authentication/users | table username"
        result = validate_spl(spl)
        assert result.is_blocked is True
        assert result.layer == 1

    def test_inputlookup_blocked(self):
        """| inputlookup must be blocked at Layer 1"""
        spl = "| inputlookup users.csv | table username, password_hash"
        result = validate_spl(spl)
        assert result.is_blocked is True
        assert result.layer == 1


class TestLegitimateQueriesStillPass:
    def test_standard_apt_query_passes(self):
        """Standard APT investigation query must still pass"""
        spl = (
            "index=botsv3 earliest=0 sourcetype=stream:http "
            "dest_ip=169.254.169.254 "
            "| stats count by src_ip, uri_path "
            "| sort -count | head 20"
        )
        result = validate_spl(spl)
        assert result.is_blocked is False

    def test_sentinel_findings_write_passes(self):
        """sentinel_findings index must still be permitted"""
        spl = (
            "index=sentinel_findings earliest=0 "
            "| stats count by classification"
        )
        result = validate_spl(spl)
        assert result.is_blocked is False

    def test_case_insensitive_internal_blocked(self):
        """INDEX=_INTERNAL (uppercase) must still be blocked"""
        spl = "INDEX=_INTERNAL earliest=0 | stats count"
        result = validate_spl(spl)
        assert result.is_blocked is True
