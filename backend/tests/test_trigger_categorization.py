import pytest
from app.agents.triage_agent import categorize_trigger

class TestAPTCredentialTheftCategory:
    def test_detects_apt_keyword(self):
        category, count = categorize_trigger("APT attack detected on internal systems")
        assert "APT" in category
        assert count > 0

    def test_detects_credential_keyword(self):
        category, count = categorize_trigger("IAM credential exposure via SSRF attack")
        assert "APT" in category or "CREDENTIAL" in category
        assert count > 0

    def test_detects_metadata_keyword(self):
        category, count = categorize_trigger(
            "AWS metadata service queried from internal host"
        )
        assert "APT" in category
        assert count >= 3  # expects 3 APT dynamic queries

    def test_detects_dns_tunnel_keyword(self):
        category, count = categorize_trigger("DNS tunneling C2 communication detected")
        assert "APT" in category
        assert count > 0


class TestWebAttackCategory:
    def test_detects_web_keyword(self):
        category, count = categorize_trigger("Web application exploitation detected")
        assert "WEB" in category
        assert count > 0

    def test_detects_php_keyword(self):
        category, count = categorize_trigger("Suspicious PHP execution on web server")
        assert "WEB" in category
        assert count > 0

    def test_detects_scanning_keyword(self):
        category, count = categorize_trigger("Port scanning and enumeration activity")
        assert "WEB" in category
        assert count > 0


class TestLateralMovementRansomwareCategory:
    def test_detects_ransomware_keyword(self):
        category, count = categorize_trigger("Ransomware staging detected")
        assert "RANSOMWARE" in category or "LATERAL" in category
        assert count >= 3  # expects 3 lateral dynamic queries

    def test_detects_wmic_keyword(self):
        category, count = categorize_trigger("WMIC process creation from non-interactive session")
        assert "LATERAL" in category or "RANSOMWARE" in category
        assert count > 0

    def test_detects_lateral_keyword(self):
        category, count = categorize_trigger("Lateral movement across internal hosts")
        assert "LATERAL" in category or "RANSOMWARE" in category
        assert count > 0

    def test_detects_shadow_copy_keyword(self):
        category, count = categorize_trigger("Shadow copy deletion attempt detected")
        assert "LATERAL" in category or "RANSOMWARE" in category
        assert count > 0


class TestBruteForceCategory:
    def test_detects_brute_force_keyword(self):
        category, count = categorize_trigger("Brute force attack on domain admin account")
        assert "BRUTE" in category or "AUTH" in category
        assert count >= 2

    def test_detects_failed_login_keyword(self):
        category, count = categorize_trigger("Multiple failed login attempts detected")
        assert "BRUTE" in category or "AUTH" in category
        assert count > 0


class TestGenericCategory:
    def test_vague_trigger_returns_generic(self):
        category, count = categorize_trigger("Anomalous network activity detected. Investigate.")
        assert category == "GENERIC"
        assert count == 0

    def test_empty_trigger_returns_generic(self):
        category, count = categorize_trigger("Something happened")
        assert category == "GENERIC"
        assert count == 0

    def test_generic_fires_zero_dynamic_queries(self):
        _, count = categorize_trigger("Investigate this alert")
        assert count == 0


class TestMultiCategoryTrigger:
    def test_apt_plus_web_trigger_selects_both_query_sets(self):
        trigger = (
            "SSRF attack on web application leading to AWS metadata credential theft. "
            "External IP hitting internal PHP endpoints."
        )
        category, count = categorize_trigger(trigger)
        assert "APT" in category
        assert "WEB" in category
        assert count >= 6  # 3 APT + 3 WEB queries, deduped
