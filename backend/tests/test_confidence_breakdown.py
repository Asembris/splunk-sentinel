"""
Tests for explainable confidence breakdown.
All deterministic - no LLM or Splunk calls.
"""

import pytest

from app.agents.reconstruction_agent import (
    compute_reconstruction_confidence,
)


def _sample_result(**overrides):
    params = {
        "confirmed_stages": 4,
        "total_stages": 5,
        "sourcetypes_covered": {
            "stream:http",
            "WinEventLog:Security",
            "WinEventLog:System",
        },
        "has_patient_zero": True,
        "has_blast_radius": False,
        "has_external_ip": True,
    }
    params.update(overrides)
    return compute_reconstruction_confidence(**params)


class TestComputeReconstructionConfidenceBreakdown:
    def test_returns_tuple_not_scalar(self):
        result = _sample_result()

        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_scalar_matches_sum_of_contributions(self):
        scalar, breakdown = _sample_result()
        contribution_sum = sum(
            factor["contribution"]
            for factor in breakdown["factors"]
        )

        assert contribution_sum == pytest.approx(scalar, abs=0.01)

    def test_breakdown_has_five_factors(self):
        _, breakdown = _sample_result()

        assert len(breakdown["factors"]) == 5

    def test_all_factors_have_required_fields(self):
        _, breakdown = _sample_result()
        required = {
            "name",
            "description",
            "raw_score",
            "weight",
            "contribution",
            "detail",
        }

        for factor in breakdown["factors"]:
            assert required.issubset(factor.keys())

    def test_overall_score_matches_scalar(self):
        scalar, breakdown = _sample_result()

        assert breakdown["overall"] == scalar

    def test_weakest_factor_has_lowest_raw_score(self):
        _, breakdown = _sample_result()
        min_score = min(
            factor["raw_score"]
            for factor in breakdown["factors"]
        )

        assert breakdown["weakest_factor"]["raw_score"] == min_score

    def test_strongest_factor_has_highest_raw_score(self):
        _, breakdown = _sample_result()
        max_score = max(
            factor["raw_score"]
            for factor in breakdown["factors"]
        )

        assert breakdown["strongest_factor"]["raw_score"] == max_score

    def test_contributions_sum_to_overall(self):
        _, breakdown = _sample_result()
        contribution_sum = sum(
            factor["contribution"]
            for factor in breakdown["factors"]
        )

        assert contribution_sum == pytest.approx(
            breakdown["overall"],
            abs=0.01,
        )

    def test_weights_sum_to_approximately_one(self):
        _, breakdown = _sample_result()
        weight_sum = sum(
            factor["weight"]
            for factor in breakdown["factors"]
        )

        assert weight_sum == pytest.approx(1.0, abs=0.001)

    def test_all_raw_scores_between_zero_and_one(self):
        _, breakdown = _sample_result()

        for factor in breakdown["factors"]:
            assert 0.0 <= factor["raw_score"] <= 1.0

    def test_all_contributions_between_zero_and_weight(self):
        _, breakdown = _sample_result()

        for factor in breakdown["factors"]:
            assert 0.0 <= factor["contribution"] <= factor["weight"]

    def test_weakest_factor_has_recommendation(self):
        _, breakdown = _sample_result()

        assert breakdown["weakest_factor"]["recommendation"]

    def test_zero_evidence_produces_zero_scores(self):
        scalar, breakdown = _sample_result(
            confirmed_stages=0,
            total_stages=0,
            sourcetypes_covered=set(),
            has_patient_zero=False,
            has_blast_radius=False,
            has_external_ip=False,
        )

        assert scalar == 0.0
        assert breakdown["overall"] == 0.0
        assert all(
            factor["raw_score"] == 0.0
            for factor in breakdown["factors"]
        )
        assert all(
            factor["contribution"] == 0.0
            for factor in breakdown["factors"]
        )

    def test_full_evidence_produces_high_scores(self):
        scalar, breakdown = _sample_result(
            confirmed_stages=5,
            total_stages=5,
            sourcetypes_covered={"a", "b", "c", "d"},
            has_patient_zero=True,
            has_blast_radius=True,
            has_external_ip=True,
        )

        assert scalar == pytest.approx(0.95, abs=0.001)
        assert breakdown["overall"] == pytest.approx(0.95, abs=0.001)
        assert all(
            factor["raw_score"] == 1.0
            for factor in breakdown["factors"]
        )

    def test_factor_names_are_analyst_friendly(self):
        _, breakdown = _sample_result()
        names = {
            factor["name"]
            for factor in breakdown["factors"]
        }

        assert names == {
            "Evidence Variety",
            "Kill Chain Completeness",
            "Patient Zero Identification",
            "External Threat Corroboration",
            "Blast Radius Assessment",
        }
