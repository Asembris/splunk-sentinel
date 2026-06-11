# Splunk SDK Usage - Splunk Sentinel

> Technical documentation of the Splunk platform integrations used by
> Splunk Sentinel. Written for Splunk Agentic Ops Hackathon judges and
> Splunk developers who want to understand the SDK, saved-search, MLTK,
> audit, and containment paths.

---

## 1. Splunk Python SDK Integration

### Version and Installation

- `splunk-sdk==2.0.2`
- Splunk Enterprise 10.2.2
- Python 3.12

`backend/requirements.txt` also includes `truststore==0.10.4`.
`truststore` is imported and activated in `backend/app/utils/prompt_loader.py`,
but it is not explicitly used in the Splunk SDK connection path in
`backend/app/tools/splunk_tools.py`.

### SplunkClient Singleton

`backend/app/tools/splunk_tools.py` exposes a singleton `SplunkClient`:

```python
def get_splunk_client() -> SplunkClient:
    global _splunk_client_instance
    if _splunk_client_instance is None:
        _splunk_client_instance = SplunkClient()
    return _splunk_client_instance


def get_splunk_service() -> Any:
    return get_splunk_client().service
```

The SDK service is created with environment-backed settings:

```python
self.service = splunk_client.connect(
    host=settings.SPLUNK_HOST,
    port=settings.SPLUNK_PORT,
    username=settings.SPLUNK_USERNAME,
    password=settings.SPLUNK_PASSWORD,
)
```

The browser Splunk Web login is not used by this backend path. Backend
reads, writes, saved-search deployment, and MLTK execution authenticate
through the Splunk SDK against the management port, normally `8089`,
using `SPLUNK_HOST`, `SPLUNK_PORT`, `SPLUNK_USERNAME`, and
`SPLUNK_PASSWORD`.

### SPL Query Execution and Reconnect

`SplunkClient.run_search()`:

1. Runs the SPL guardrail before execution.
2. Adds a `search ` prefix when required by `jobs.oneshot()`.
3. Executes through `self.service.jobs.oneshot(...)`.
4. Parses JSON results with `splunklib.results.JSONResultsReader`.
5. Reconnects and retries once on Splunk SDK session/auth errors.

The search retry is triggered by error text such as:

- `Session is not logged in`
- `not logged in`
- `unauthorized`
- `http 401`

Reconnect uses a thread lock around `splunk_client.connect(...)` to
avoid concurrent reconnect races.

### Local Splunk Certificate Note

The current Splunk SDK connection code does not explicitly pass a
certificate bundle, `verify=False`, or a custom SSL context. If a local
Splunk Enterprise instance uses a self-signed certificate on management
port `8089`, verify SDK connectivity independently with the same host,
port, username, and password. If certificate validation fails in your
environment, fix trust at the local Python/Splunk SDK environment level
or configure Splunk management-port TLS appropriately. Do not assume the
installed `truststore` package alone solves Splunk SDK certificate
trust; this repository does not explicitly wire it into
`splunk_client.connect(...)`.

---

## 2. Splunk Indexes

### `sentinel_findings`

Completed investigations are written back as structured notable events
to `index=sentinel_findings`.

Useful review query:

```spl
index=sentinel_findings earliest=0 sourcetype="sentinel:investigation"
| table investigation_id, classification, confidence_tier,
        kill_chain_summary, patient_zero_ip, severity
| sort -_time
```

### `sentinel_actions`

Containment actions write audit events to `index=sentinel_actions`.
Current events can vary by action type, so demo queries should coalesce
field variants instead of assuming one target field.

Robust action review query:

```spl
index=sentinel_actions earliest=0
| eval target_value=coalesce(target, ip, user, resource, dest, orig_host)
| eval action_label=upper(coalesce(action, action_type, "AUDIT"))
| table _time, investigation_id, action_label, target_value,
        status, executed_at, verification_verdict
| sort -_time
```

Compact video/demo query:

```spl
index=sentinel_actions earliest=0
| eval target_value=coalesce(target, ip, user, resource, dest, orig_host)
| eval action_label=upper(coalesce(action, action_type, "AUDIT"))
| stats latest(status) as status latest(verification_verdict) as verdict
        by investigation_id, action_label, target_value
| sort investigation_id, action_label
```

---

## 3. Splunk Webhook Integration

Splunk saved searches can trigger autonomous investigations via:

```text
POST http://localhost:8001/api/webhook/splunk
```

Example botsv3 alert SPL:

```spl
index=botsv3 earliest=0 sourcetype=stream:http dest_ip=169.254.169.254
| stats count by src_ip
| where count > 5
```

The webhook handler converts the Splunk alert payload into a trigger and
starts the investigation pipeline. Results are later persisted and can
be written back to `sentinel_findings`.

---

## 4. Detection Gap Analysis and Saved-Search Deployment

Detection Gap Analysis is analyst-triggered and compares mapped MITRE
techniques against Splunk saved searches. It reports saved-search
coverage posture; it does not prove detection effectiveness or attack
prevention.

### API Flow

Initial coverage run:

```text
GET /api/investigations/{id}/detection-gaps
```

Deploy generated SPL as a Splunk saved search:

```text
POST /api/investigations/{id}/detection-gaps/deploy
```

Refresh after deployment using fresh saved-search data:

```text
GET /api/investigations/{id}/detection-gaps?force_refresh=true
```

### Saved-Search Cache

Saved-search reads are cached for five minutes:

```python
_saved_searches_cache = {
    "data": None,
    "fetched_at": 0,
    "ttl_seconds": 300,
}
```

`force_refresh=true` bypasses this cache and fetches fresh saved
searches from Splunk. Successful saved-search deployment and
already-deployed duplicate success both invalidate the cache and return:

```json
{
  "coverage_refresh_recommended": true
}
```

### Deployment Guardrails and Retry

Before deploying a saved search, `deploy_detection(...)`:

1. Blocks placeholder SPL such as `your_sourcetype`, `<sourcetype>`,
   `TODO`, `replace_me`, fake fields, and similar tokens.
2. Blocks raw sourcetype terms such as `stream:http OR stream:dns`
   unless expressed as fielded filters like `sourcetype=stream:http`.
3. Runs `validate_spl(...)`.
4. Checks for duplicate saved-search names.
5. Creates the saved search through `splunk_service.saved_searches.create(...)`.
6. Invalidates the saved-search cache on success or duplicate success.

The deploy path also retries once after reconnecting the SDK session
when Splunk returns session/auth errors:

- `Session is not logged in`
- `not logged in`
- `unauthorized`
- HTTP 401

This is separate from browser Splunk Web login. A user can be logged
into Splunk Web while the backend SDK service object has expired.

### Sentinel Saved-Search Exact Matching

Coverage matching checks Sentinel-deployed saved searches first. A
Sentinel saved search is treated as a high-confidence match only when
the exact technique ID appears in the saved-search name or in the
deployment description field written as:

```text
Technique: {technique_id}
```

The exact-match regex prevents parent/sub-technique accidents. For
example, `T1547` should not satisfy `T1547.001`, and `T1547.001` should
not satisfy `T1547`.

Keyword-based matching is used for non-Sentinel saved searches. Match
confidence levels are:

- `HIGH`: high-confidence technique keywords matched.
- `MEDIUM`: two or more regular keywords matched.
- `LOW`: one regular keyword matched.
- `NONE`: no useful match.

Only `HIGH` and `MEDIUM` count as covered in the coverage posture.
`LOW` and `NONE` saved-search matches are review signals.

### Before/After Coverage UI

The frontend stores the first pre-deploy detection-gap result as the
baseline. After deploy success, it tracks deployed technique IDs and
shows a CTA to rerun coverage with `force_refresh=true`.

The before/after comparison uses normalized `technique_id` sets only.
It never compares generated SPL text.

Displayed comparison fields:

- before coverage %
- after coverage %
- delta percentage points
- newly covered techniques
- gaps closed
- moved to review
- remaining gaps
- saved searches checked before/after

Semantics:

- Covered means latest `covered_techniques` with `match_confidence`
  `HIGH` or `MEDIUM`.
- Newly covered means a technique is covered after refresh but was not
  covered in the baseline.
- Gaps closed means baseline gap technique IDs are now in latest
  `HIGH`/`MEDIUM` covered techniques.
- Moved to review means a baseline gap moved into weak matches, not
  covered.
- Remaining gaps are latest gap technique IDs with no usable coverage.

Use this wording in demos: saved-search coverage improved, coverage
posture refreshed, newly covered by saved-search matching. Avoid claims
that imply real-world attack prevention or executed detection efficacy.

---

## 5. MLTK AI Toolkit Integration

### Version and Setup

- Splunk AI Toolkit / MLTK: 5.7.4
- Python for Scientific Computing: 4.3.2
- Connection Management name: `openai_sentinel`
- Model: `gpt-4o-mini`

Role capability examples for the MLTK `ai` command:

```conf
[role_admin]
apply_ai_commander_command = enabled
list_ai_commander_config = enabled
edit_ai_commander_config = enabled
```

### Correct MLTK 5.7.4 `ai` Syntax

```spl
| ai connection="openai_sentinel"
    prompt="Your prompt with {field_name} inline"
```

Do not use:

- `provider=`
- `field=`
- `input_field=`

Output appears in:

```text
ai_result_1
```

### Async Post-Persistence Enrichment

MLTK validation runs asynchronously after investigation persistence when
MLTK 5.7.4 and the configured `openai_sentinel` connection are
available.

Flow:

1. Investigation completes and report persists.
2. Background `enrich_ttp_with_mltk(investigation_id)` starts.
3. `mltk_enrichment.py` processes persisted `ttp_mappings`.
4. Results patch `report_json["ttp_mappings"]`,
   `mltk_enrichment_status`, and `mltk_enrichment_summary`.
5. Frontend polls `GET /api/investigations/{id}/ttp-enrichment`.

Technique status in the UI:

- `MLTK Validated`: MLTK agreed with the Qdrant mapping.
- `MLTK Review`: MLTK disagreed, failed, was unavailable, or produced
  no usable result after enrichment.
- `NOT RUN`: enrichment has not completed or was unavailable for that
  investigation.

Avoid blanket validation wording. The enrichment service records whether
validation ran, whether MLTK agreed, and whether MLTK was unavailable.

### MLTK Validation SPL Pattern

```spl
| makeresults count=1
| eval evidence="HTTP requests to 169.254.169.254 AWS metadata service"
| eval qdrant_technique="T1552.005"
| eval qdrant_name="Cloud Instance Metadata API"
| ai connection="openai_sentinel"
    prompt="Validate technique: {qdrant_technique} ({qdrant_name}).
    Evidence: {evidence}.
    Return ONLY JSON with technique_id, technique_name, confidence, reasoning."
```

When MLTK agrees, confidence is blended using Qdrant 60% + MLTK 40%.
When MLTK disagrees or is unavailable, the technique remains visible for
analyst review.

---

## 6. Containment Verification SPL

Containment execution writes audit events to `sentinel_actions` and
fires background verification when possible. Verification uses
deterministic before/after SPL counts, not an LLM.

Verification templates include:

```spl
search index=botsv3 earliest=0 (src_ip="{target}" OR dest_ip="{target}")
| stats count
```

```spl
search index=botsv3 earliest=0 host="{target}"
| stats count
```

```spl
search index=botsv3 earliest=0 sourcetype=WinEventLog:Security
EventCode=4624 Account_Name="{target}"
| stats count
```

Verdicts:

- `VERIFIED_EFFECTIVE`: 80%+ reduction.
- `PARTIAL_EFFECT`: 20-80% reduction.
- `VERIFICATION_FAILED`: under 20% reduction.
- `ROLLBACK_RECOMMENDED`: events increased 10%+.
- `VERIFICATION_SKIPPED`: no template for the action type.

Targets are sanitized before SPL interpolation by removing quotes,
pipes, common boolean fragments, excess whitespace, and truncating to
100 characters.

---

## 7. Recommended Detection SPL Generation

For uncovered techniques, Detection Gap Analysis generates recommended
SPL from investigation evidence and falls back to deterministic
templates when needed.

Generation rules include:

- Query must start with `index=botsv3 earliest=0`.
- Use concrete fielded sourcetypes, such as `sourcetype=stream:http`.
- Do not emit raw terms like `stream:http OR stream:dns`.
- Do not emit placeholders such as `your_sourcetype`, `<sourcetype>`,
  `TODO`, or `replace_me`.
- For T1078, use account/authentication-oriented fields and Windows
  auth events such as `EventCode=4624`, `EventCode=4672`, or
  `EventCode=4673`.
- Validate through the SPL guardrail before UI display and deployment.

Example T1552.005 template:

```spl
index=botsv3 earliest=0 sourcetype=stream:http dest_ip=169.254.169.254
| stats count by src_ip, uri_path
| where count > 5
| sort -count
```

Example T1078 template:

```spl
index=botsv3 earliest=0 sourcetype=WinEventLog:Security
(EventCode=4624 OR EventCode=4672 OR EventCode=4673)
| eval account=coalesce(Account_Name, user)
| stats count dc(host) as host_count by account, src_ip, EventCode
| where count > 3 OR host_count > 1
| sort -count
```

---

## 8. SPL Guardrail and Audit Chain

### Guardrail Scope

Layered SPL validation blocks:

- destructive commands such as `| delete`
- `delete-index`
- `| outputlookup overwrite=true`
- `| sendemail`
- `DROP`, `TRUNCATE`
- internal indexes such as `_internal` and `_audit`
- subsearch injection patterns
- backtick macros
- multi-index `index IN (...)` bypasses
- `| rest /services/...`
- unsafe lookup/input paths

Detection Gap Analysis adds deployment-specific blocking for placeholder
SPL and unfielded sourcetype tokens.

### SHA-256 Hash Chain

`backend/app/utils/audit_chain.py` stores each audit entry with:

- `prev_hash`
- `entry_hash`

`entry_hash` is SHA-256 over canonical JSON content plus the previous
hash. The first entry uses `"0" * 64` as the genesis previous hash.
Changing any entry invalidates that entry and all later entries.

Audit endpoints:

```text
GET /api/audit-log
GET /api/audit-log/verify/{investigation_id}
GET /api/audit-log/verify-latest
```

Example verification response shape:

```json
{
  "valid": true,
  "details": "Successfully verified 16 entries.",
  "investigation_id": "sentinel-..."
}
```

---

## 9. Health Endpoint

`GET /api/health` establishes a Splunk SDK connection on each request
and returns connectivity plus core prompt metadata.

Expected response shape:

```json
{
  "status": "ok",
  "splunk_connected": true,
  "splunk_version": "10.2.2",
  "prompt_versions": {
    "triage-agent": {
      "name": "triage-agent",
      "version": 1,
      "label": "production"
    },
    "synthesis-narrative": {
      "name": "synthesis-narrative",
      "version": 1,
      "label": "production"
    },
    "containment-refinement": {
      "name": "containment-refinement",
      "version": 1,
      "label": "production"
    }
  },
  "promptops": "langfuse"
}
```

Current `/api/health` behavior: `promptops` currently returns
`"langfuse"` unconditionally. If Langfuse credentials are missing or
Langfuse is unreachable, `prompt_versions` entries may be empty objects
while the prompt loader internally falls back to memory cache or
built-in hardcoded prompts. The health endpoint exposes core prompt
metadata only; it should not be read as a complete list of every prompt
or as a full PromptOps fallback-state indicator.

---

## 10. API Surface Summary

| Integration | SDK/API Used | Purpose |
|------------|--------------|---------|
| SPL queries | `service.jobs.oneshot()` | Investigation telemetry retrieval |
| SDK reconnect | `splunk_client.connect(...)` | Session renewal on auth/session errors |
| Saved searches read | `service.saved_searches` | Detection gap coverage posture |
| Saved searches create | `service.saved_searches.create()` | Detection saved-search deployment |
| Force refresh | `GET /detection-gaps?force_refresh=true` | Bypass saved-search cache |
| MLTK `ai` command | `jobs.oneshot()` with `| ai` SPL | Async MITRE mapping validation |
| Containment audit | `jobs.oneshot()` with `collect` | `sentinel_actions` write |
| Verification SPL | `jobs.oneshot()` | Before/after containment counts |
| Health check | `service.info` | Splunk connectivity and version |
| Audit verification | FastAPI + SHA-256 chain | Hash-chain integrity checks |
| Webhook receive | FastAPI endpoint | Autonomous Splunk alert trigger |

---

## 11. Tests and Current Verification

Current backend verification target:

```bash
python -m pytest tests/ --ignore=tests/eval/ -v
```

Current expected result from the project docs:

```text
425 passed, 0 failed
```

Eval tests are directional and should be run separately when needed:

```bash
python -m pytest tests/eval/ -v
```

---

*Splunk Sentinel - built for the Splunk Agentic Ops Hackathon 2026.*
*Full source: github.com/Asembris/splunk-sentinel*
