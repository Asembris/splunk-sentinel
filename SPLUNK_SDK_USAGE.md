## MLTK AI Toolkit Integration

### Version
Splunk AI Toolkit (MLTK): 5.7.4
Python for Scientific Computing (PSC): 4.3.2 (Windows)

### Installation
- PSC installed via direct extraction to Splunk apps directory
  (UI upload timed out for 417MB package)
- MLTK installed via Apps -> Manage Apps -> Install from file
- Connection configured via Connection Management UI tab:
  connection name: openai_sentinel
  provider: OpenAI
  model: gpt-4o-mini
  endpoint: https://api.openai.com/v1/chat/completions

### Permissions Required
authorize.conf additions for role_admin:
- apply_ai_commander_command = enabled
- list_ai_commander_config = enabled
- edit_ai_commander_config = enabled

### The ai Command - Correct Syntax for MLTK 5.7.4
The ai command syntax changed between versions.
For 5.7.4 the correct syntax is:

| ai connection="openai_sentinel"
    prompt="Your prompt with {field_name} inline references"

NOT:
- provider= (wrong - use connection=)
- field= (wrong - inline as {field_name})
- input_field= (wrong)

Output appears in field: ai_result_1

### Usage in TTPAgent
TTPAgent uses the ai command to validate Qdrant
semantic search technique mappings against real
botsv3 evidence. The ai command runs a makeresults
query with evidence context, sends it to gpt-4o-mini
via the MLTK connection, and returns structured JSON
with technique_id, confidence, and reasoning.

When Qdrant and MLTK agree: confidence is boosted
(weighted average: Qdrant 60% + MLTK 40%).
When they disagree: confidence is reduced 25% and
the MLTK alternative technique is recorded alongside
the Qdrant mapping for analyst review.

### Finding: MLTK Connection vs Direct API
Using the MLTK ai command routes OpenAI calls through
Splunk's Connection Management infrastructure, adding
Splunk-native governance, rate limiting, and audit
logging compared to direct API calls from FastAPI.
This is architecturally superior for a Splunk-native
security platform.
