"""
Tests for containment verification service.
All deterministic - no Splunk or Supabase calls.
"""

from app.services.containment_verifier import VERIFICATION_SPL, _get_verdict


class TestGetVerdict:
    def test_zero_before_zero_after_is_skipped(self):
        # before=0 and after=0 means no baseline exists
        # Cannot distinguish effective from no traffic
        assert _get_verdict(0, 0) == "VERIFICATION_SKIPPED"

    def test_zero_before_events_after_is_failed(self):
        assert _get_verdict(0, 10) == "VERIFICATION_FAILED"

    def test_100_pct_reduction_is_effective(self):
        assert _get_verdict(100, 0) == "VERIFIED_EFFECTIVE"

    def test_90_pct_reduction_is_effective(self):
        assert _get_verdict(100, 10) == "VERIFIED_EFFECTIVE"

    def test_50_pct_reduction_is_partial(self):
        assert _get_verdict(100, 50) == "PARTIAL_EFFECT"

    def test_25_pct_reduction_is_partial(self):
        assert _get_verdict(100, 75) == "PARTIAL_EFFECT"

    def test_no_reduction_is_failed(self):
        assert _get_verdict(100, 100) == "VERIFICATION_FAILED"

    def test_increase_is_rollback_recommended(self):
        assert _get_verdict(100, 115) == "ROLLBACK_RECOMMENDED"

    def test_small_reduction_below_partial_is_failed(self):
        # 10% reduction is below PARTIAL_THRESHOLD (20%)
        assert _get_verdict(100, 90) == "VERIFICATION_FAILED"


class TestVerificationSPLTemplates:
    def test_block_ip_template_exists(self):
        assert "BLOCK_IP" in VERIFICATION_SPL

    def test_isolate_host_template_exists(self):
        assert "ISOLATE_HOST" in VERIFICATION_SPL

    def test_revoke_credentials_template_exists(self):
        assert "REVOKE_CREDENTIALS" in VERIFICATION_SPL

    def test_all_templates_target_botsv3(self):
        for action_type, spl in VERIFICATION_SPL.items():
            assert "botsv3" in spl, f"{action_type} template missing botsv3"

    def test_all_templates_have_target_placeholder(self):
        for action_type, spl in VERIFICATION_SPL.items():
            assert "{target}" in spl, (
                f"{action_type} template missing " f"{{target}} placeholder"
            )

    def test_block_ip_queries_src_and_dest(self):
        spl = VERIFICATION_SPL["BLOCK_IP"]
        assert "src_ip" in spl
        assert "dest_ip" in spl

    def test_templates_use_full_history_window(self):
        for action_type, spl in VERIFICATION_SPL.items():
            assert "earliest=0" in spl, (
                f"{action_type} template missing " f"time window"
            )

    def test_block_ip_interpolation(self):
        spl = VERIFICATION_SPL["BLOCK_IP"].format(target="184.85.20.125")
        assert "184.85.20.125" in spl
        assert "{target}" not in spl

    def test_isolate_host_interpolation(self):
        spl = VERIFICATION_SPL["ISOLATE_HOST"].format(target="BSTOLL-L")
        assert "BSTOLL-L" in spl
        assert "{target}" not in spl


class TestGetVerdictBoundaries:
    def test_exactly_80_pct_reduction_is_effective(self):
        # 80% reduction = EFFECTIVE_THRESHOLD exactly
        # before=100, after=20 -> delta=80 -> 80% -> VERIFIED_EFFECTIVE
        assert _get_verdict(100, 20) == "VERIFIED_EFFECTIVE"

    def test_just_below_80_pct_is_partial(self):
        # 79% reduction -> PARTIAL_EFFECT
        # before=100, after=21 -> delta=79 -> 79% -> PARTIAL_EFFECT
        assert _get_verdict(100, 21) == "PARTIAL_EFFECT"

    def test_exactly_20_pct_reduction_is_partial(self):
        # 20% reduction = PARTIAL_THRESHOLD exactly
        # before=100, after=80 -> delta=20 -> 20% -> PARTIAL_EFFECT
        assert _get_verdict(100, 80) == "PARTIAL_EFFECT"

    def test_just_below_20_pct_is_failed(self):
        # 19% reduction -> VERIFICATION_FAILED
        # before=100, after=81 -> delta=19 -> 19% -> VERIFICATION_FAILED
        assert _get_verdict(100, 81) == "VERIFICATION_FAILED"

    def test_exactly_10_pct_increase_is_rollback(self):
        # 10% increase = ROLLBACK_THRESHOLD exactly
        # before=100, after=110 -> delta=-10 -> -10% -> ROLLBACK_RECOMMENDED
        assert _get_verdict(100, 110) == "ROLLBACK_RECOMMENDED"

    def test_single_event_full_reduction_is_effective(self):
        # before=1, after=0 -> 100% -> VERIFIED_EFFECTIVE
        assert _get_verdict(1, 0) == "VERIFIED_EFFECTIVE"

    def test_large_numbers_work_correctly(self):
        # before=10000, after=100 -> 99% -> VERIFIED_EFFECTIVE
        assert _get_verdict(10000, 100) == "VERIFIED_EFFECTIVE"


class TestTargetSanitization:
    def test_double_quote_injection_removed(self):
        from app.services.containment_verifier import _sanitize_target
        malicious = '184.85.20.125" OR src_ip="*'
        safe = _sanitize_target(malicious)
        assert '"' not in safe
        assert "OR src_ip=" not in safe

    def test_pipe_injection_removed(self):
        from app.services.containment_verifier import _sanitize_target
        malicious = "hostname | delete index=*"
        safe = _sanitize_target(malicious)
        assert "|" not in safe
        assert "delete" not in safe.split()[0]

    def test_oversized_target_truncated(self):
        from app.services.containment_verifier import _sanitize_target
        malicious = "A" * 200
        safe = _sanitize_target(malicious)
        assert len(safe) <= 100

    def test_valid_ip_unchanged(self):
        from app.services.containment_verifier import _sanitize_target
        valid = "184.85.20.125"
        safe = _sanitize_target(valid)
        assert safe == "184.85.20.125"

    def test_valid_hostname_unchanged(self):
        from app.services.containment_verifier import _sanitize_target
        valid = "BSTOLL-L"
        safe = _sanitize_target(valid)
        assert safe == "BSTOLL-L"

    def test_single_quote_injection_removed(self):
        from app.services.containment_verifier import _sanitize_target
        malicious = "172.16.0.1' OR '1'='1"
        safe = _sanitize_target(malicious)
        assert "'" not in safe
