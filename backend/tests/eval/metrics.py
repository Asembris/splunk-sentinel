from deepeval.metrics import TaskCompletionMetric, ToolCorrectnessMetric, GEval
from deepeval.test_case import LLMTestCaseParams

# --- METRICS CONFIGURATION ---
# Production-grade thresholds — do NOT lower to make tests pass.

task_completion = TaskCompletionMetric(
    model="gpt-4o-mini",
    threshold=0.7,
    async_mode=True
)

faithfulness = GEval(
    name="Triage Faithfulness",
    model="gpt-4o-mini",
    evaluation_params=[LLMTestCaseParams.ACTUAL_OUTPUT, LLMTestCaseParams.RETRIEVAL_CONTEXT],
    criteria="""
Evaluate whether the triage_summary is grounded in the actual telemetry data returned by Splunk queries, rather than simply restating or paraphrasing the trigger text. A faithful summary must reference specific evidence such as IP addresses, EventCodes, process names, URI paths, or query counts that were returned in the telemetry. A summary that only restates what the trigger said without citing telemetry evidence scores 0. A summary that accurately reflects what the Splunk data showed scores 1.
""",
    evaluation_steps=[
        "Check if the triage_summary includes specific telemetry data such as IP addresses, EventCodes, process names, URI paths, or query counts.",
        "Compare the content of the triage_summary with the actual telemetry data returned by the Splunk queries to identify any direct references to the data.",
        "Determine if the triage_summary merely restates or paraphrases the trigger text without citing specific telemetry evidence; if so, score it 0.",
        "If the triage_summary accurately reflects the Splunk data and includes specific evidence, score it 1."
    ],
    threshold=0.7,
    async_mode=True
)

tool_correctness = ToolCorrectnessMetric(
    threshold=0.7,
    async_mode=True
)

# Export metrics
METRICS = [task_completion, faithfulness, tool_correctness]
