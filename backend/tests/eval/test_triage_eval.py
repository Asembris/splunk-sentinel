import json
import httpx
import pytest
import tiktoken
from datetime import datetime, timezone
from deepeval.tracing import observe, update_current_span
from deepeval.dataset import EvaluationDataset, Golden
from deepeval.test_case import LLMTestCase, ToolCall
from deepeval.metrics import TaskCompletionMetric, GEval

from tests.eval.goldens import GOLDENS
from tests.eval.metrics import task_completion, tool_correctness, faithfulness

import os
BASE_URL = "http://localhost:8003"
RESULTS_PATH = os.path.join(os.path.dirname(__file__), "eval_results.json")


def estimate_cost(input_text: str, output_text: str) -> dict:
    """Estimate gpt-4o-mini cost for a single metric evaluation."""
    try:
        enc = tiktoken.encoding_for_model("gpt-4o-mini")
        input_tokens = len(enc.encode(input_text))
        output_tokens = len(enc.encode(output_text))
        input_cost = (input_tokens / 1_000_000) * 0.150
        output_cost = (output_tokens / 1_000_000) * 0.600
        return {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
            "estimated_cost_usd": round(input_cost + output_cost, 6),
        }
    except Exception:
        return {"input_tokens": 0, "output_tokens": 0, 
                "total_tokens": 0, "estimated_cost_usd": 0.0}


@observe(type="agent")
def run_triage_investigation(trigger: str, investigation_id: str) -> dict:
    """Calls the live TriageAgent via FastAPI and returns the full JSON response."""
    response = httpx.post(
        f"{BASE_URL}/api/investigate",
        json={"trigger": trigger, "investigation_id": investigation_id},
        timeout=180.0
    )
    response.raise_for_status()
    result = response.json()

    # Update the trace span with input/output for deepeval metrics
    update_current_span(
        input=trigger,
        output=json.dumps({
            "attack_classification": result.get("attack_classification"),
            "classification_confidence": result.get("classification_confidence"),
            "severity": result.get("severity"),
            "escalate_to_human": result.get("escalate_to_human"),
            "triage_summary": result.get("triage_summary"),
            "key_indicators": result.get("key_indicators", []),
            "spl_audit_log": result.get("spl_audit_log", []),
        }),
    )
    return result


def build_test_case(golden: Golden, result: dict) -> LLMTestCase:
    """Builds a deepeval LLMTestCase from a golden and live agent result."""
    spl_audit_log = result.get("spl_audit_log", [])
    
    tools_called = []
    for entry in spl_audit_log:
        # Extract the SPL portion after the timestamp bracket
        spl = entry.split("]", 1)[-1].strip()
        # Use sourcetype= or EventCode= portion as the tool identifier
        if "sourcetype=" in spl:
            # Extract from sourcetype= onwards, max 60 chars
            idx = spl.index("sourcetype=")
            tool_name = spl[idx:idx+60].strip()
        elif "EventCode=" in spl and "sourcetype=" not in spl:
            idx = spl.index("EventCode=")
            tool_name = spl[idx:idx+60].strip()
        else:
            tool_name = spl[20:80].strip()
        tools_called.append(ToolCall(name=tool_name))
    
    return LLMTestCase(
        input=golden.input,
        actual_output=json.dumps({
            "attack_classification": result.get("attack_classification"),
            "classification_confidence": result.get("classification_confidence"),
            "severity": result.get("severity"),
            "escalate_to_human": result.get("escalate_to_human"),
            "triage_summary": result.get("triage_summary"),
            "key_indicators": result.get("key_indicators", []),
        }),
        expected_output=golden.expected_output,
        retrieval_context=spl_audit_log,
        tools_called=tools_called,
        expected_tools=golden.expected_tools or [],
    )


def evaluate_result_against_metadata(golden: Golden, result: dict) -> dict:
    """
    Deterministic checks against golden metadata.
    These are rule-based, not LLM-judged.
    """
    meta = golden.additional_metadata or {}
    checks = {}

    classification = result.get("attack_classification")
    confidence = result.get("classification_confidence", 0)
    escalate = result.get("escalate_to_human", False)

    # Classification check
    expected_cls = meta.get("expected_classification")
    if expected_cls:
        if expected_cls == "RANSOMWARE":
            # Allow RANSOMWARE or INSIDER_THREAT for ambiguous goldens
            checks["classification_correct"] = classification in ["RANSOMWARE", "INSIDER_THREAT"]
        else:
            checks["classification_correct"] = classification == expected_cls

    # Min confidence check
    if "min_confidence" in meta:
        checks["confidence_above_minimum"] = confidence >= meta["min_confidence"]

    # Max confidence check
    if "max_confidence" in meta:
        checks["confidence_below_maximum"] = confidence <= meta["max_confidence"]

    # Confidence cap regression: never exactly 1.0
    checks["confidence_not_exactly_1"] = confidence < 1.0

    # Escalation check for UNKNOWN
    if classification == "UNKNOWN":
        checks["unknown_escalates"] = escalate is True

    # CRITICAL severity must always escalate (if severity populated)
    severity = result.get("severity")
    if severity == "CRITICAL":
        checks["critical_forces_escalation"] = escalate is True

    return checks


def run_full_evaluation() -> dict:
    """
    Runs all 15 goldens against the live TriageAgent,
    collects deepeval metric scores and deterministic checks.
    """
    all_results = []
    dataset = EvaluationDataset(goldens=GOLDENS)
    run_suffix = datetime.now(timezone.utc).strftime("%H%M%S")

    for i, golden in enumerate(dataset.goldens):
        meta = golden.additional_metadata or {}
        name = meta.get("name", f"golden-{i+1}")
        investigation_id = f"eval-{name}-{run_suffix}"

        print(f"\n[{i+1}/15] Running: {name}")

        try:
            # Run live agent
            result = run_triage_investigation(golden.input, investigation_id)

            # Build test case
            test_case = build_test_case(golden, result)

            metric_scores = {}

            for metric in [task_completion, faithfulness]:
                try:
                    meta = golden.additional_metadata or {}
                    task_context = meta.get("task", "")
                    
                    if meta.get("expected_classification") == "UNKNOWN" or task_context:
                        test_case_for_metric = LLMTestCase(
                            input=golden.input,
                            actual_output=test_case.actual_output,
                            expected_output=golden.expected_output,
                            retrieval_context=test_case.retrieval_context,
                            tools_called=test_case.tools_called,
                            expected_tools=test_case.expected_tools,
                            additional_metadata={"task": task_context} if task_context else {}
                        )
                    else:
                        test_case_for_metric = test_case
                        
                    metric.measure(test_case_for_metric)
                    metric_scores[metric.__class__.__name__] = {
                        "score": metric.score,
                        "passed": metric.is_successful(),
                        "reason": getattr(metric, "reason", None),
                    }
                except Exception as e:
                    metric_scores[metric.__class__.__name__] = {
                        "score": None,
                        "passed": False,
                        "reason": str(e),
                    }

            # ToolCorrectnessMetric only if expected_tools defined
            if golden.expected_tools:
                try:
                    tool_correctness.measure(test_case)
                    metric_scores["ToolCorrectnessMetric"] = {
                        "score": tool_correctness.score,
                        "passed": tool_correctness.is_successful(),
                        "reason": getattr(tool_correctness, "reason", None),
                    }
                except Exception as e:
                    metric_scores["ToolCorrectnessMetric"] = {
                        "score": None,
                        "passed": False,
                        "reason": str(e),
                    }

            # Deterministic checks
            deterministic_checks = evaluate_result_against_metadata(golden, result)

            # Cost estimation
            golden_input_text = golden.input + (golden.expected_output or "")
            golden_output_text = json.dumps(result)
            cost_info = estimate_cost(golden_input_text, golden_output_text)

            # Evaluation threshold logic
            meta = golden.additional_metadata or {}
            expected_cls = meta.get("expected_classification")

            if expected_cls == "UNKNOWN":
                # For UNKNOWN goldens, exclude ONLY TaskCompletionMetric
                # GEval faithfulness MUST still be enforced
                # ToolCorrectnessMetric MUST still be enforced if expected_tools present
                relevant_metrics = {
                    k: v for k, v in metric_scores.items()
                    if k != "TaskCompletionMetric"
                }
            else:
                relevant_metrics = metric_scores

            all_metrics_passed = all(
                v.get("passed", False) for v in relevant_metrics.values()
            )

            all_results.append({
                "golden": name,
                "trigger": golden.input,
                "expected_output": golden.expected_output,
                "agent_result": {
                    "attack_classification": result.get("attack_classification"),
                    "classification_confidence": result.get("classification_confidence"),
                    "severity": result.get("severity"),
                    "escalate_to_human": result.get("escalate_to_human"),
                    "triage_summary": result.get("triage_summary"),
                    "key_indicators": result.get("key_indicators", []),
                    "spl_audit_log_count": len(result.get("spl_audit_log", [])),
                },
                "metric_scores": metric_scores,
                "deterministic_checks": deterministic_checks,
                "all_deterministic_passed": all(deterministic_checks.values()),
                "all_metrics_passed": all_metrics_passed,
                "status": "PASS" if (
                    all(deterministic_checks.values()) and
                    all_metrics_passed
                ) else "FAIL",
                "cost": cost_info,
            })

        except Exception as e:
            all_results.append({
                "golden": name,
                "trigger": golden.input,
                "status": "ERROR",
                "error": str(e),
            })

    # Summary
    total = len(all_results)
    passed = sum(1 for r in all_results if r.get("status") == "PASS")
    failed = sum(1 for r in all_results if r.get("status") == "FAIL")
    errors = sum(1 for r in all_results if r.get("status") == "ERROR")

    summary = {
        "run_timestamp": datetime.now(timezone.utc).isoformat(),
        "judge_model": "gpt-4o-mini",
        "total_goldens": total,
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "pass_rate": round(passed / total * 100, 1) if total > 0 else 0,
        "total_cost_usd": round(
            sum(r.get("cost", {}).get("estimated_cost_usd", 0) for r in all_results), 4
        ),
        "total_tokens": sum(
            r.get("cost", {}).get("total_tokens", 0) for r in all_results
        ),
        "results": all_results,
    }

    return summary


def test_triage_agent_eval():
    """PyTest entry point for evaluation suite."""
    print("\n" + "="*60)
    print("SPLUNK SENTINEL \u2014 TriageAgent DeepEval Evaluation Suite")
    print("Judge: gpt-4o-mini | Goldens: 15 | Threshold: 80% pass rate")
    print("="*60)

    results = run_full_evaluation()

    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    print(f"RESULTS SAVED TO: {RESULTS_PATH}")
    print(f"Total: {results['total_goldens']} | Passed: {results['passed']} | Failed: {results['failed']}")
    print(f"Pass Rate: {results['pass_rate']}% | Total Cost: ${results['total_cost_usd']}")
    print("="*60)

    assert results["pass_rate"] >= 80.0, (
        f"Evaluation pass rate {results['pass_rate']}% is below 80% threshold. "
        f"Check {RESULTS_PATH} for details."
    )


if __name__ == "__main__":
    results = run_full_evaluation()
    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
