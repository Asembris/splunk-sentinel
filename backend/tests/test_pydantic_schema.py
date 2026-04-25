import pytest
from pydantic import ValidationError
from app.agents.triage_agent import TriageResult

class TestTriageResultValidSchema:
    def test_valid_apt_result(self):
        result = TriageResult(
            attack_classification="APT",
            severity="CRITICAL",
            classification_confidence=0.90,
            triage_summary="SSRF attack confirmed via AWS metadata queries.",
            escalate_to_human=True,
            key_indicators=["169.254.169.254 queried", "External HTTP traffic", "Long DNS queries"]
        )
        assert result.attack_classification == "APT"
        assert result.severity == "CRITICAL"

    def test_valid_unknown_result(self):
        result = TriageResult(
            attack_classification="UNKNOWN",
            severity="LOW",
            classification_confidence=0.3,
            triage_summary="Insufficient telemetry to classify.",
            escalate_to_human=True,
            key_indicators=["No external IPs", "Low event counts"]
        )
        assert result.attack_classification == "UNKNOWN"


class TestTriageResultInvalidSchema:
    def test_rejects_invalid_classification(self):
        with pytest.raises(ValidationError):
            TriageResult(
                attack_classification="DDOS",  # not in Literal
                severity="HIGH",
                classification_confidence=0.8,
                triage_summary="Test",
                escalate_to_human=False,
                key_indicators=[]
            )

    def test_rejects_invalid_severity(self):
        with pytest.raises(ValidationError):
            TriageResult(
                attack_classification="APT",
                severity="EXTREME",  # not in Literal
                classification_confidence=0.8,
                triage_summary="Test",
                escalate_to_human=False,
                key_indicators=[]
            )

    def test_rejects_confidence_above_1(self):
        with pytest.raises(ValidationError):
            TriageResult(
                attack_classification="APT",
                severity="HIGH",
                classification_confidence=1.5,  # exceeds ge=0, le=1
                triage_summary="Test",
                escalate_to_human=False,
                key_indicators=[]
            )

    def test_rejects_negative_confidence(self):
        with pytest.raises(ValidationError):
            TriageResult(
                attack_classification="APT",
                severity="HIGH",
                classification_confidence=-0.1,
                triage_summary="Test",
                escalate_to_human=False,
                key_indicators=[]
            )

    def test_rejects_missing_required_fields(self):
        with pytest.raises(ValidationError):
            TriageResult(
                attack_classification="APT",
                severity="HIGH"
                # missing classification_confidence, triage_summary,
                # escalate_to_human, key_indicators
            )

    def test_rejects_empty_triage_summary(self):
        # triage_summary must be non-empty string
        with pytest.raises(ValidationError):
            TriageResult(
                attack_classification="APT",
                severity="HIGH",
                classification_confidence=0.8,
                triage_summary="",  # empty string not allowed
                escalate_to_human=False,
                key_indicators=[]
            )
