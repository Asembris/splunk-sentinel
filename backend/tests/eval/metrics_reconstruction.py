"""
DeepEval metrics for ReconstructionAgent evaluation.
Judge: gpt-4o-mini (budget constraint).
"""

from deepeval.metrics import GEval, TaskCompletionMetric
from deepeval.test_case import LLMTestCaseParams

JUDGE_MODEL = "gpt-4o-mini"

kill_chain_faithfulness = GEval(
    name="Kill Chain Faithfulness",
    criteria=(
        "Evaluate whether each kill chain stage's evidence field is "
        "grounded in the actual telemetry data provided in the retrieval "
        "context (SPL query results). A stage is faithful if its evidence "
        "cites at least one of: a specific IP address that appears in the "
        "telemetry, a specific EventCode with count that matches the data, "
        "a specific process name (like WMIC.exe or cmd.exe) with a count "
        "that appears in query results, a specific URI path from stream:http "
        "results, or a specific DNS query pattern from stream:dns results. "
        "A stage is NOT faithful if its evidence only paraphrases the "
        "trigger text, mentions attack techniques not present in the "
        "telemetry, or cites specific counts/IPs that don't appear in "
        "the query results. Score 0 if any stage contains hallucinated "
        "evidence. Score 1 if all confirmed stages cite real telemetry."
    ),
    evaluation_params=[
        LLMTestCaseParams.ACTUAL_OUTPUT,
        LLMTestCaseParams.RETRIEVAL_CONTEXT,
    ],
    model=JUDGE_MODEL,
    threshold=0.7,
    async_mode=True,
)

kill_chain_coherence = GEval(
    name="Kill Chain Coherence",
    criteria=(
        "Evaluate whether the kill chain stages form a coherent, "
        "temporally logical attack narrative. Score based on: "
        "(1) Chronological order — stages must be ordered by timestamp "
        "with earlier events first. Score 0 if timestamps are clearly "
        "out of sequence. "
        "(2) Causal logic — each stage should plausibly follow from "
        "the previous one in an attack progression. Initial Access "
        "must come before Execution, which must come before "
        "Lateral Movement or Impact. "
        "(3) MITRE plausibility — the assigned MITRE tactic must be "
        "a reasonable interpretation of the evidence described. "
        "Multiple valid tactic interpretations exist for the same "
        "evidence — do not penalize for choosing Persistence vs "
        "Execution for the same service installation event. "
        "Penalize only if the tactic is clearly wrong: e.g., "
        "assigning TA0010 (Exfiltration) to a process creation event. "
        "(4) Stage count — a complete kill chain should have >= 3 stages "
        "for APT and RANSOMWARE, >= 2 for INSIDER_THREAT. "
        "Score 0 if kill_chain is empty. "
        "Score 1 if all 4 criteria are fully met."
    ),
    evaluation_params=[
        LLMTestCaseParams.ACTUAL_OUTPUT,
        LLMTestCaseParams.EXPECTED_OUTPUT,
    ],
    model=JUDGE_MODEL,
    threshold=0.65,
    async_mode=True,
)

blast_radius_completeness = GEval(
    name="Blast Radius Completeness",
    criteria=(
        "Evaluate whether the blast radius assessment is complete and "
        "specific. A complete blast radius must: "
        "(1) List actual IP addresses in internal_ips_affected that appear "
        "in the telemetry — not placeholder or made-up IPs. "
        "(2) data_at_risk must be specific — naming actual systems, "
        "credential types, or data. Generic statements like 'data may "
        "be at risk' or 'systems affected' score 0. Good examples: "
        "'IAM credentials via AWS metadata service 169.254.169.254' or "
        "'EC2 instance role credentials exfiltrated'. "
        "(3) containment_priority must be appropriate for the severity — "
        "IMMEDIATE for confirmed APT or ransomware, HIGH for insider threat. "
        "Score 0 if data_at_risk is generic. "
        "Score 1 if all three components are specific and accurate."
    ),
    evaluation_params=[
        LLMTestCaseParams.ACTUAL_OUTPUT,
        LLMTestCaseParams.RETRIEVAL_CONTEXT,
    ],
    model=JUDGE_MODEL,
    threshold=0.7,
    async_mode=True,
)

attack_narrative_quality = GEval(
    name="Attack Narrative Quality",
    criteria=(
        "Evaluate whether the attack_narrative is a high-quality forensic "
        "summary. It must: "
        "(1) Be 2-3 sentences long — not a single generic sentence. "
        "(2) Name the attack type specifically (APT, ransomware, insider). "
        "(3) Describe the initial vector with specific evidence — not just "
        "restate the trigger text. "
        "(4) State what was compromised or impacted with specifics. "
        "(5) Include a recommended immediate action. "
        "Score 0 if the narrative only restates the trigger. "
        "Score 0 if the narrative is a single sentence. "
        "Score 1 if all 5 criteria are met."
    ),
    evaluation_params=[
        LLMTestCaseParams.INPUT,
        LLMTestCaseParams.ACTUAL_OUTPUT,
        LLMTestCaseParams.RETRIEVAL_CONTEXT,
    ],
    model=JUDGE_MODEL,
    threshold=0.6,
    async_mode=True,
)

task_completion_reconstruction = TaskCompletionMetric(
    threshold=0.7,
    model=JUDGE_MODEL,
    async_mode=True,
)
