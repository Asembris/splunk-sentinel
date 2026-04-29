"""
DeepEval evaluation suite for ReconstructionAgent.
10 goldens covering APT, RANSOMWARE, INSIDER_THREAT, 
hallucination trap, and UNKNOWN bypass.

Run with backend on port 8001:
    python -m pytest tests/eval/test_reconstruction_eval.py -v -s --timeout=900
"""

import json
import httpx
import pytest
import time
from datetime import datetime, timezone
from deepeval.test_case import LLMTestCase
from deepeval.dataset import EvaluationDataset

from tests.eval.goldens_reconstruction import RECONSTRUCTION_GOLDENS
from tests.eval.metrics_reconstruction import (
    kill_chain_faithfulness,
    kill_chain_coherence,
    blast_radius_completeness,
    attack_narrative_quality,
    task_completion_reconstruction,
)

BASE_URL = "http://localhost:8001"
RESULTS_PATH = "tests/eval/eval_results_reconstruction.json"
JUDGE_MODEL = "gpt-4o-mini"


def run_investigation(trigger: str, investigation_id: str) -> dict:
    """Call the live pipeline and return the full JSON response."""
    response = httpx.post(
        f"{BASE_URL}/api/investigate",
        json={"trigger": trigger, "investigation_id": investigation_id},
        timeout=360.0,
    )
    response.raise_for_status()
    return response.json()


def build_test_case(golden, result: dict) -> LLMTestCase:
    """Build a DeepEval LLMTestCase from golden + live result."""
    kill_chain = result.get("kill_chain", [])
    patient_zero = result.get("patient_zero", {})
    blast_radius = result.get("blast_radius", {})
    spl_audit_log = result.get("spl_audit_log", [])

    actual_output = json.dumps({
        "kill_chain": kill_chain,
        "patient_zero": patient_zero,
        "blast_radius": blast_radius,
        "attack_narrative": result.get("attack_narrative", ""),
        "reconstruction_confidence": result.get("reconstruction_confidence", 0),
        "react_iterations": result.get("react_iterations", 0),
    }, indent=2)

    return LLMTestCase(
        input=golden.input,
        actual_output=actual_output,
        expected_output=golden.expected_output,
        retrieval_context=spl_audit_log,
    )


def run_deterministic_checks(golden, result: dict) -> dict:
    """
    Rule-based checks that don't require an LLM judge.
    These are fast, free, and deterministic.
    """
    meta = golden.additional_metadata or {}
    checks = {}

    kill_chain = result.get("kill_chain", [])
    patient_zero = result.get("patient_zero", {})
    blast_radius = result.get("blast_radius", {})
    attack_narrative = result.get("attack_narrative", "")
    error = result.get("error")

    # No error in response
    checks["no_error"] = error is None

    expected_cls = meta.get("expected_classification")

    # UNKNOWN bypass check
    if expected_cls == "UNKNOWN":
        checks["kill_chain_empty"] = len(kill_chain) == 0
        checks["patient_zero_empty"] = (
            not patient_zero or patient_zero == {}
        )
        checks["blast_radius_empty"] = (
            not blast_radius or blast_radius == {}
        )
        return checks

    # For non-UNKNOWN: reconstruction must have run
    checks["kill_chain_not_empty"] = len(kill_chain) > 0
    checks["patient_zero_present"] = bool(
        patient_zero and patient_zero.get("ip_address")
    )
    checks["blast_radius_present"] = bool(
        blast_radius and blast_radius.get("total_affected_ips", 0) > 0
    )
    checks["attack_narrative_not_empty"] = bool(
        attack_narrative and len(attack_narrative.strip()) > 20
    )
    checks["reconstruction_confidence_positive"] = (
        result.get("reconstruction_confidence", 0) > 0
    )

    # Patient zero role check
    expected_pz_role = meta.get("patient_zero_role")
    if expected_pz_role:
        checks["patient_zero_role_correct"] = (
            patient_zero.get("role") == expected_pz_role
        )

    # No external IPs for insider threat
    if meta.get("no_external_ips"):
        checks["no_external_ips"] = (
            len(blast_radius.get("external_ips_observed", [])) == 0
        )

    # Containment priority check
    expected_containment = meta.get("containment_priority")
    if expected_containment:
        checks["containment_priority_correct"] = (
            blast_radius.get("containment_priority") == expected_containment
        )

    # Minimum kill chain stages
    min_stages = meta.get("min_kill_chain_stages")
    if min_stages:
        checks["min_stages_met"] = len(kill_chain) >= min_stages

    # Required MITRE tactics present
    required_tactics = meta.get("required_mitre_tactics", [])
    if required_tactics:
        found_tactics = {
            stage.get("mitre_tactic", "") for stage in kill_chain
        }
        checks["required_mitre_tactics_present"] = any(
            tactic in found_tactics for tactic in required_tactics
        )

    # Required evidence keywords present somewhere in kill chain
    required_keywords = meta.get("required_evidence_keywords", [])
    if required_keywords:
        all_evidence = " ".join(
            stage.get("evidence", "") for stage in kill_chain
        ).lower()
        all_evidence += " " + json.dumps(blast_radius).lower()
        all_evidence += " " + (attack_narrative or "").lower()
        checks["required_evidence_keywords_present"] = all(
            kw.lower() in all_evidence for kw in required_keywords
        )

    # Forbidden keywords for hallucination trap
    forbidden_keywords = meta.get("forbidden_evidence_keywords", [])
    if forbidden_keywords:
        all_content = json.dumps(kill_chain).lower()
        all_content += " " + (attack_narrative or "").lower()
        checks["no_hallucinated_evidence"] = not any(
            kw.lower() in all_content for kw in forbidden_keywords
        )

    # patient_zero must not be empty for APT/RANSOMWARE
    if meta.get("patient_zero_must_not_be_empty"):
        checks["patient_zero_not_empty"] = bool(
            patient_zero and patient_zero.get("ip_address")
        )

    return checks


def run_full_evaluation() -> dict:
    """Run all 10 goldens and collect results."""
    all_results = []
    run_suffix = datetime.now(timezone.utc).strftime("%H%M%S")
    dataset = EvaluationDataset(goldens=RECONSTRUCTION_GOLDENS)

    for i, golden in enumerate(dataset.goldens):
        # Rate limit protection: pause every 3 goldens
        if i > 0 and i % 3 == 0:
            print(f"\nPausing 30s for rate limit protection...")
            time.sleep(30)
        meta = golden.additional_metadata or {}
        name = meta.get("name", f"golden-{i+1}")
        investigation_id = f"eval-recon-{name}-{run_suffix}"
        expected_cls = meta.get("expected_classification", "UNKNOWN")

        print(f"\n[{i+1}/10] Running: {name}")

        try:
            result = run_investigation(golden.input, investigation_id)
            test_case = build_test_case(golden, result)
            deterministic_checks = run_deterministic_checks(golden, result)

            metric_scores = {}

            # Select metrics based on golden type
            if expected_cls == "UNKNOWN":
                # UNKNOWN goldens: only deterministic checks
                # No LLM metrics needed — agent shouldn't have run
                pass
            elif meta.get("faithfulness_critical"):
                # Hallucination trap: faithfulness is covered by deterministic check
                for metric in [attack_narrative_quality]:
                    try:
                        metric.measure(test_case)
                        metric_scores[metric.name] = {
                            "score": metric.score,
                            "passed": metric.is_successful(),
                            "reason": getattr(metric, "reason", None),
                        }
                    except Exception as e:
                        metric_scores[metric.name] = {
                            "score": None,
                            "passed": False,
                            "reason": str(e),
                        }
            else:
                # Standard goldens: all 4 LLM metrics
                for metric in [
                    kill_chain_faithfulness,
                    kill_chain_coherence,
                    blast_radius_completeness,
                    attack_narrative_quality,
                ]:
                    try:
                        metric.measure(test_case)
                        metric_scores[metric.name] = {
                            "score": metric.score,
                            "passed": metric.is_successful(),
                            "reason": getattr(metric, "reason", None),
                        }
                    except Exception as e:
                        metric_scores[metric.name] = {
                            "score": None,
                            "passed": False,
                            "reason": str(e),
                        }

            # Determine pass/fail
            all_deterministic_passed = all(deterministic_checks.values())
            all_metrics_passed = all(
                v.get("passed", False)
                for v in metric_scores.values()
            ) if metric_scores else True

            status = "PASS" if (
                all_deterministic_passed and all_metrics_passed
            ) else "FAIL"

            all_results.append({
                "golden": name,
                "trigger": golden.input[:100] + "...",
                "investigation_id": investigation_id,
                "agent_result": {
                    "attack_classification": result.get(
                        "attack_classification"
                    ),
                    "reconstruction_confidence": result.get(
                        "reconstruction_confidence", 0
                    ),
                    "react_iterations": result.get("react_iterations", 0),
                    "kill_chain_stages": len(
                        result.get("kill_chain", [])
                    ),
                    "patient_zero_ip": result.get(
                        "patient_zero", {}
                    ).get("ip_address", "N/A"),
                    "patient_zero_role": result.get(
                        "patient_zero", {}
                    ).get("role", "N/A"),
                    "containment_priority": result.get(
                        "blast_radius", {}
                    ).get("containment_priority", "N/A"),
                    "attack_narrative_length": len(
                        result.get("attack_narrative", "")
                    ),
                    "error": result.get("error"),
                },
                "deterministic_checks": deterministic_checks,
                "metric_scores": metric_scores,
                "all_deterministic_passed": all_deterministic_passed,
                "all_metrics_passed": all_metrics_passed,
                "status": status,
            })

            # Summary
            summary = {
                "run_timestamp": datetime.now(timezone.utc).isoformat(),
                "judge_model": JUDGE_MODEL,
                "total_goldens": len(dataset.goldens),
                "processed": len(all_results),
                "passed": sum(1 for r in all_results if r.get("status") == "PASS"),
                "failed": sum(1 for r in all_results if r.get("status") == "FAIL"),
                "errors": sum(1 for r in all_results if r.get("status") == "ERROR"),
                "results": all_results,
            }
            with open(RESULTS_PATH, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)

            print(f"  Status: {status} | Stages: "
                  f"{len(result.get('kill_chain', []))} | "
                  f"Confidence: "
                  f"{result.get('reconstruction_confidence', 0):.2f}")

        except Exception as e:
            all_results.append({
                "golden": name,
                "trigger": golden.input[:100] + "...",
                "investigation_id": investigation_id,
                "status": "ERROR",
                "error": str(e),
            })
            print(f"  Status: ERROR | {e}")
            
            # Save even on error
            summary = {
                "run_timestamp": datetime.now(timezone.utc).isoformat(),
                "judge_model": JUDGE_MODEL,
                "total_goldens": len(dataset.goldens),
                "processed": len(all_results),
                "passed": sum(1 for r in all_results if r.get("status") == "PASS"),
                "failed": sum(1 for r in all_results if r.get("status") == "FAIL"),
                "errors": sum(1 for r in all_results if r.get("status") == "ERROR"),
                "results": all_results,
            }
            with open(RESULTS_PATH, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)

    # Final Summary
    total = len(all_results)
    passed = sum(1 for r in all_results if r.get("status") == "PASS")
    failed = sum(1 for r in all_results if r.get("status") == "FAIL")
    errors = sum(1 for r in all_results if r.get("status") == "ERROR")

    summary = {
        "run_timestamp": datetime.now(timezone.utc).isoformat(),
        "judge_model": JUDGE_MODEL,
        "total_goldens": total,
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "pass_rate": round(passed / total * 100, 1) if total > 0 else 0,
        "results": all_results,
    }

    return summary


def test_reconstruction_agent_eval():
    """
    PyTest entry point for the ReconstructionAgent DeepEval suite.
    Runs all 10 goldens and saves to eval_results_reconstruction.json.
    Fails if pass_rate < 70%.
    """
    print("\n" + "=" * 60)
    print("SPLUNK SENTINEL — ReconstructionAgent DeepEval Suite")
    print(f"Judge: {JUDGE_MODEL} | Goldens: 10 | Threshold: 70%")
    print("=" * 60)

    results = run_full_evaluation()

    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\n{'=' * 60}")
    print(f"RESULTS SAVED TO: {RESULTS_PATH}")
    print(
        f"Total: {results['total_goldens']} | "
        f"Passed: {results['passed']} | "
        f"Failed: {results['failed']} | "
        f"Errors: {results['errors']}"
    )
    print(f"Pass Rate: {results['pass_rate']}%")
    print("=" * 60)

    assert results["pass_rate"] >= 70.0, (
        f"Reconstruction eval pass rate {results['pass_rate']}% "
        f"is below 70% threshold. "
        f"Check {RESULTS_PATH} for details."
    )


if __name__ == "__main__":
    results = run_full_evaluation()
    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(json.dumps({
        "pass_rate": results["pass_rate"],
        "passed": results["passed"],
        "total": results["total_goldens"],
    }, indent=2))
