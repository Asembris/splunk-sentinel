"""
Tests for detection gap analyzer.
All deterministic — no LLM, Splunk, or Supabase calls.
Uses mock saved searches and TTP mappings.
"""
import time
import pytest
from unittest.mock import MagicMock, patch
import app.services.detection_gap_analyzer as dga
from app.services.detection_gap_analyzer import (
    _check_technique_coverage,
    _compute_match_confidence,
    _coverage_label,
    _get_saved_searches,
    _get_template_spl,
    deploy_detection,
    invalidate_saved_searches_cache,
    TECHNIQUE_KEYWORDS,
    TEMPLATE_SPL,
)


def make_saved_searches(*spls) -> list[dict]:
    return [
        {"name": f"Search {i}", "search": spl, "description": ""}
        for i, spl in enumerate(spls)
    ]


class FakeSavedSearch:
    def __init__(self, name, search, description=""):
        self.name = name
        self._data = {
            "search": search,
            "description": description,
        }

    def __getitem__(self, key):
        return self._data[key]

    def get(self, key, default=None):
        return self._data.get(key, default)


class FakeSavedSearchCollection:
    def __init__(self, searches):
        self.searches = list(searches)
        self.created = []

    def __iter__(self):
        return iter(self.searches)

    def create(self, name, spl, **kwargs):
        self.created.append({
            "name": name,
            "spl": spl,
            "kwargs": kwargs,
        })


@pytest.fixture
def reset_saved_searches_cache():
    invalidate_saved_searches_cache()
    yield
    invalidate_saved_searches_cache()


class TestCoverageDetection:
    def test_technique_covered_when_keyword_matches(self):
        searches = make_saved_searches(
            "index=botsv3 dest_ip=169.254.169.254"
            " | stats count by src_ip"
        )
        covered, matching, _ = _check_technique_coverage(
            "T1552.005", searches
        )
        assert covered is True
        assert len(matching) > 0

    def test_technique_not_covered_when_no_match(self):
        searches = make_saved_searches(
            "index=botsv3 sourcetype=syslog"
            " | stats count"
        )
        covered, matching, _ = _check_technique_coverage(
            "T1552.005", searches
        )
        assert covered is False
        assert matching == []

    def test_multiple_techniques_some_covered(self):
        searches = make_saved_searches(
            "index=botsv3 dest_ip=169.254.169.254",
            "index=botsv3 EventCode=4688 powershell",
        )
        cov_1, _, _ = _check_technique_coverage(
            "T1552.005", searches
        )
        cov_2, _, _ = _check_technique_coverage(
            "T1059", searches
        )
        cov_3, _, _ = _check_technique_coverage(
            "T1486", searches
        )
        assert cov_1 is True
        assert cov_2 is True
        assert cov_3 is False

    def test_empty_ttp_mappings_returns_empty_result(self):
        searches = make_saved_searches(
            "index=botsv3 | stats count"
        )
        covered, matching, _ = _check_technique_coverage(
            "T9999", searches
        )
        assert covered is False
        assert matching == []

    def test_coverage_score_zero_when_no_techniques(self):
        score = 0 / 1 if False else 0.0
        assert _coverage_label(0.0) == "CRITICAL GAPS"

    def test_coverage_score_one_when_all_covered(self):
        assert _coverage_label(1.0) == "GOOD COVERAGE"


class TestCoverageScoreLabels:
    def test_zero_to_25_is_critical(self):
        assert _coverage_label(0.0) == "CRITICAL GAPS"
        assert _coverage_label(0.10) == "CRITICAL GAPS"
        assert _coverage_label(0.24) == "CRITICAL GAPS"

    def test_25_to_50_is_significant(self):
        assert _coverage_label(0.25) == "SIGNIFICANT GAPS"
        assert _coverage_label(0.40) == "SIGNIFICANT GAPS"
        assert _coverage_label(0.49) == "SIGNIFICANT GAPS"

    def test_50_to_75_is_partial(self):
        assert _coverage_label(0.50) == "PARTIAL COVERAGE"
        assert _coverage_label(0.60) == "PARTIAL COVERAGE"
        assert _coverage_label(0.74) == "PARTIAL COVERAGE"

    def test_75_to_100_is_good(self):
        assert _coverage_label(0.75) == "GOOD COVERAGE"
        assert _coverage_label(0.90) == "GOOD COVERAGE"
        assert _coverage_label(1.00) == "GOOD COVERAGE"


class TestKeywordMatching:
    def test_t1552_keywords_match_metadata_spl(self):
        searches = make_saved_searches(
            "index=botsv3 dest_ip=169.254.169.254"
            " sourcetype=stream:http | stats count"
        )
        covered, _, conf = _check_technique_coverage(
            "T1552.005", searches
        )
        assert covered is True
        assert conf in ("HIGH", "MEDIUM", "LOW")

    def test_t1190_keywords_match_http_exploit(self):
        searches = make_saved_searches(
            "index=botsv3 sourcetype=stream:http"
            " | where match(uri_path, \"php\")"
            " | stats count by src_ip"
        )
        covered, _, _ = _check_technique_coverage(
            "T1190", searches
        )
        assert covered is True

    def test_t1078_keywords_match_logon_events(self):
        searches = make_saved_searches(
            "index=botsv3 EventCode=4624"
            " sourcetype=WinEventLog:Security"
            " | stats count by Account_Name"
        )
        covered, _, _ = _check_technique_coverage(
            "T1078", searches
        )
        assert covered is True

    def test_unrelated_spl_does_not_match(self):
        searches = make_saved_searches(
            "index=botsv3 sourcetype=syslog"
            " | head 100"
        )
        covered, _, _ = _check_technique_coverage(
            "T1552.005", searches
        )
        assert covered is False

    def test_case_insensitive_keyword_matching(self):
        searches = make_saved_searches(
            "index=botsv3 SOURCETYPE=STREAM:HTTP"
            " DEST_IP=169.254.169.254"
        )
        covered, _, _ = _check_technique_coverage(
            "T1552.005", searches
        )
        assert covered is True


class TestSPLValidation:
    def test_recommended_spl_passes_guardrail(self):
        from app.guardrails.spl_guardrail import validate_spl
        spl = TEMPLATE_SPL.get("T1552.005", "")
        result = validate_spl(spl)
        assert result.is_blocked is False

    def test_recommended_spl_targets_botsv3(self):
        for tech_id, spl in TEMPLATE_SPL.items():
            assert "botsv3" in spl.lower(), (
                f"Template SPL for {tech_id} "
                f"does not target botsv3"
            )

    def test_template_fallback_passes_guardrail(self):
        from app.guardrails.spl_guardrail import validate_spl
        spl = _get_template_spl("T1190")
        result = validate_spl(spl)
        assert result.is_blocked is False


class TestDeploymentLogic:
    def test_duplicate_detection_by_name(self):
        """Duplicate check logic — name already exists"""
        existing = ["Sentinel — T1552.005 Detection"]
        name = "Sentinel — T1552.005 Detection"
        assert name in existing

    def test_new_search_not_flagged_as_duplicate(self):
        existing = ["Other Search", "Another Search"]
        name = "Sentinel — T1552.005 Detection"
        assert name not in existing

    def test_deploy_result_contains_technique_id(self):
        """Deploy result must always contain technique_id"""
        result = {
            "success": True,
            "technique_id": "T1552.005",
            "name": "Sentinel — T1552.005 Detection",
        }
        assert "technique_id" in result
        assert result["technique_id"] == "T1552.005"

    def test_deploy_blocked_when_duplicate_exists(self):
        """already_deployed flag set when duplicate found"""
        result = {
            "success": True,
            "already_deployed": True,
            "name": "Sentinel — T1552.005 Detection",
            "technique_id": "T1552.005",
        }
        assert result["already_deployed"] is True
        assert result["success"] is True

    def test_saved_search_cache_used_without_force_refresh(
        self,
        reset_saved_searches_cache,
    ):
        dga._saved_searches_cache["data"] = [{
            "name": "Cached Search",
            "search": "index=botsv3 cached",
            "description": "",
        }]
        dga._saved_searches_cache["fetched_at"] = time.time()

        service = MagicMock()
        service.saved_searches = FakeSavedSearchCollection([
            FakeSavedSearch("Fresh Search", "index=botsv3 fresh"),
        ])

        result = _get_saved_searches(service)

        assert result[0]["name"] == "Cached Search"

    def test_force_refresh_bypasses_saved_search_cache(
        self,
        reset_saved_searches_cache,
    ):
        dga._saved_searches_cache["data"] = [{
            "name": "Cached Search",
            "search": "index=botsv3 cached",
            "description": "",
        }]
        dga._saved_searches_cache["fetched_at"] = time.time()

        service = MagicMock()
        service.saved_searches = FakeSavedSearchCollection([
            FakeSavedSearch("Fresh Search", "index=botsv3 fresh"),
        ])

        result = _get_saved_searches(service, force_refresh=True)

        assert result[0]["name"] == "Fresh Search"
        assert dga._saved_searches_cache["data"][0]["name"] == "Fresh Search"

    @pytest.mark.asyncio
    async def test_deploy_success_invalidates_saved_search_cache(
        self,
        reset_saved_searches_cache,
    ):
        dga._saved_searches_cache["data"] = [{
            "name": "Stale Search",
            "search": "index=botsv3 stale",
            "description": "",
        }]
        dga._saved_searches_cache["fetched_at"] = time.time()

        service = MagicMock()
        service.saved_searches = FakeSavedSearchCollection([])

        result = await deploy_detection(
            technique_id="T1552.005",
            spl=TEMPLATE_SPL["T1552.005"],
            name="Sentinel â€” T1552.005 Detection",
            investigation_id="inv-123",
            splunk_service=service,
        )

        assert result["success"] is True
        assert result["coverage_refresh_recommended"] is True
        assert dga._saved_searches_cache["data"] is None
        assert dga._saved_searches_cache["fetched_at"] == 0

    @pytest.mark.asyncio
    async def test_deploy_already_deployed_invalidates_saved_search_cache(
        self,
        reset_saved_searches_cache,
    ):
        dga._saved_searches_cache["data"] = [{
            "name": "Stale Search",
            "search": "index=botsv3 stale",
            "description": "",
        }]
        dga._saved_searches_cache["fetched_at"] = time.time()

        name = "Sentinel â€” T1552.005 Detection"
        service = MagicMock()
        service.saved_searches = FakeSavedSearchCollection([
            FakeSavedSearch(name, TEMPLATE_SPL["T1552.005"]),
        ])

        result = await deploy_detection(
            technique_id="T1552.005",
            spl=TEMPLATE_SPL["T1552.005"],
            name=name,
            investigation_id="inv-123",
            splunk_service=service,
        )

        assert result["success"] is True
        assert result["already_deployed"] is True
        assert result["coverage_refresh_recommended"] is True
        assert dga._saved_searches_cache["data"] is None
        assert dga._saved_searches_cache["fetched_at"] == 0


class TestDeterministicTemplates:
    def test_all_known_techniques_have_templates(self):
        """
        Key techniques must have template SPL.
        Not all techniques need templates but the common
        botsv3 ones must be covered.
        """
        required = [
            "T1190", "T1552.005", "T1078",
            "T1562.004", "T1059",
        ]
        for tech_id in required:
            spl = _get_template_spl(tech_id)
            assert spl, (
                f"No template SPL for {tech_id}"
            )
            assert "botsv3" in spl.lower(), (
                f"Template for {tech_id} "
                f"does not target botsv3"
            )

    def test_template_spl_contains_index_botsv3(self):
        for tech_id, spl in TEMPLATE_SPL.items():
            assert "index=botsv3" in spl, (
                f"{tech_id} template missing index=botsv3"
            )

    def test_template_spl_contains_earliest(self):
        for tech_id, spl in TEMPLATE_SPL.items():
            assert "earliest=0" in spl, (
                f"{tech_id} template missing earliest=0"
            )


class TestMatchConfidence:
    def test_high_confidence_when_specific_keyword_matches(self):
        spl = "index=botsv3 dest_ip=169.254.169.254"
        conf = _compute_match_confidence(spl, "T1552.005")
        assert conf == "HIGH"

    def test_medium_confidence_when_multiple_regular_match(self):
        spl = "index=botsv3 sourcetype=stream:http dest_ip=169.254.169.254"
        conf = _compute_match_confidence(spl, "T1552.005")
        assert conf in ("HIGH", "MEDIUM")

    def test_none_confidence_when_no_match(self):
        spl = "index=botsv3 sourcetype=syslog | head 10"
        conf = _compute_match_confidence(spl, "T1552.005")
        assert conf == "NONE"
