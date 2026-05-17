"""
Tests for containment templates and SPL generation logic.
All deterministic — no LLM, Splunk, or Supabase.
"""
import pytest
from app.models.containment import ContainmentActionType
from app.services.containment_templates import (
    _sanitize_spl_value,
    render_template,
    generate_action_spl,
    validate_containment_spl,
    get_template_metadata,
)


class TestSanitizeSplValue:
    def test_strips_forbidden_characters(self):
        # Forbidden: " | ` \ [ ]
        dirty = 'host"|`\\host[123]'
        clean = _sanitize_spl_value(dirty)
        assert clean == "hosthost123"

    def test_truncates_long_value(self):
        long_val = "a" * 300
        clean = _sanitize_spl_value(long_val)
        assert len(clean) == 200
        assert clean == "a" * 200

    def test_handles_empty_or_none(self):
        assert _sanitize_spl_value("") == ""
        assert _sanitize_spl_value(None) == ""


class TestRenderTemplate:
    def test_renders_block_ip_correctly(self):
        rendered = render_template(ContainmentActionType.BLOCK_IP, "1.1.1.1")
        assert 'ip="1.1.1.1"' in rendered["spl"]
        assert 'ip="1.1.1.1"' in rendered["reversal"]
        assert rendered["is_irreversible"] is False
        assert rendered["title"] == "Block Malicious IP"

    def test_renders_isolate_host_correctly(self):
        rendered = render_template(ContainmentActionType.ISOLATE_HOST, "host-a")
        assert 'host="host-a"' in rendered["spl"]
        assert 'host="host-a"' in rendered["reversal"]
        assert rendered["is_irreversible"] is False

    def test_renders_disable_account_correctly(self):
        rendered = render_template(ContainmentActionType.DISABLE_ACCOUNT, "admin_user")
        assert 'user="admin_user"' in rendered["spl"]
        assert 'user="admin_user"' in rendered["reversal"]
        assert rendered["is_irreversible"] is False

    def test_renders_rotate_credentials_is_irreversible(self):
        rendered = render_template(ContainmentActionType.ROTATE_CREDENTIALS, "api_key_owner")
        assert 'user="api_key_owner"' in rendered["spl"]
        assert rendered["reversal"] is None
        assert rendered["is_irreversible"] is True

    def test_renders_audit_cloudtrail_is_irreversible(self):
        rendered = render_template(ContainmentActionType.AUDIT_CLOUDTRAIL, "s3-bucket-xyz")
        assert 'resource="s3-bucket-xyz"' in rendered["spl"]
        assert rendered["reversal"] is None
        assert rendered["is_irreversible"] is True

    def test_renders_kill_process_is_irreversible(self):
        rendered = render_template(ContainmentActionType.KILL_PROCESS, "powershell.exe")
        assert 'process="powershell.exe"' in rendered["spl"]
        assert rendered["reversal"] is None
        assert rendered["is_irreversible"] is True

    def test_renders_revoke_credentials_is_irreversible(self):
        rendered = render_template(ContainmentActionType.REVOKE_CREDENTIALS, "hacked_user")
        assert 'user="hacked_user"' in rendered["spl"]
        assert rendered["reversal"] is None
        assert rendered["is_irreversible"] is True

    def test_raises_for_unknown_template_type(self):
        with pytest.raises(ValueError):
            render_template("NON_EXISTENT_TYPE", "target")


class TestGenerateActionSpl:
    def test_generates_valid_block_ip_spl_with_all_context(self):
        spl, reversal = generate_action_spl(
            action_type=ContainmentActionType.BLOCK_IP,
            target="8.8.8.8",
            reason="Malicious C2 node",
            investigation_id="inv-999",
            action_id="act-123",
            confidence=0.95,
            phase=1,
        )
        # Check primary SPL eval fields
        assert 'ip="8.8.8.8"' in spl
        assert 'reason="Malicious C2 node"' in spl
        assert 'investigation_id="inv-999"' in spl
        assert 'action_id="act-123"' in spl
        assert 'confidence="0.95"' in spl
        assert 'phase="1"' in spl
        assert "collect index=sentinel_actions" in spl

        # Check reversal SPL eval fields
        assert 'ip="8.8.8.8"' in reversal
        assert 'action="unblock"' in reversal
        assert 'investigation_id="inv-999"' in reversal
        assert 'action_id="act-123"' in reversal
        assert "collect index=sentinel_actions" in reversal

    def test_generates_correct_irreversible_action_spl(self):
        spl, reversal = generate_action_spl(
            action_type=ContainmentActionType.KILL_PROCESS,
            target="cmd.exe",
            reason="Malicious execution shell",
            investigation_id="inv-100",
            action_id="act-555",
        )
        assert 'process="cmd.exe"' in spl
        assert 'action_id="act-555"' in spl
        assert reversal is None

    def test_accepts_string_action_type(self):
        spl, reversal = generate_action_spl(
            action_type="block_ip",
            target="1.1.1.1",
            reason="testing string type",
            investigation_id="inv-123",
            action_id="act-111",
        )
        assert 'ip="1.1.1.1"' in spl
        assert reversal is not None

    def test_raises_for_invalid_string_action_type(self):
        with pytest.raises(ValueError):
            generate_action_spl(
                action_type="UNKNOWN_ACTION_STRING",
                target="target",
                reason="reason",
                investigation_id="inv-1",
                action_id="act-1",
            )


class TestValidateContainmentSpl:
    def test_validates_correct_spl(self):
        valid_spl = '| makeresults | eval ip="1.2.3.4", action="block" | collect index=sentinel_actions'
        assert validate_containment_spl(valid_spl, ContainmentActionType.BLOCK_IP) is True

    def test_rejects_missing_sentinel_actions_index(self):
        invalid_spl = '| makeresults | eval ip="1.2.3.4", action="block" | collect index=other_index'
        assert validate_containment_spl(invalid_spl, ContainmentActionType.BLOCK_IP) is False

    def test_rejects_empty_spl(self):
        assert validate_containment_spl("", ContainmentActionType.BLOCK_IP) is False

    def test_rejects_unknown_action_type(self):
        valid_spl = '| makeresults | eval ip="1.2.3.4", action="block" | collect index=sentinel_actions'
        assert validate_containment_spl(valid_spl, "UNKNOWN_ACTION") is False


class TestGetTemplateMetadata:
    def test_returns_reversible_for_reversible_actions(self):
        meta = get_template_metadata(ContainmentActionType.BLOCK_IP)
        assert meta["reversible"] is True

        meta2 = get_template_metadata(ContainmentActionType.ISOLATE_HOST)
        assert meta2["reversible"] is True

    def test_returns_irreversible_for_irreversible_actions(self):
        meta = get_template_metadata(ContainmentActionType.ROTATE_CREDENTIALS)
        assert meta["reversible"] is False

        meta2 = get_template_metadata(ContainmentActionType.KILL_PROCESS)
        assert meta2["reversible"] is False

    def test_raises_for_unknown_action_type(self):
        with pytest.raises(ValueError):
            get_template_metadata("UNKNOWN_ACTION")
