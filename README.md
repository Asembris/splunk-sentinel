# Splunk Sentinel

> Autonomous AI-powered SOC investigation platform.
> A 4-hour manual investigation in 100 seconds —
> 6 specialized AI agents, ReAct kill chain
> reconstruction, and Splunk-native AI validation.

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)
![LangGraph](https://img.shields.io/badge/LangGraph-0.2-orange?logo=langchain)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)
![Vite](https://img.shields.io/badge/Vite-5.0-646CFF?logo=vite&logoColor=white)

![GPT-4o-mini](https://img.shields.io/badge/GPT--4o--mini-OpenAI-412991?logo=openai&logoColor=white)
![Qdrant Cloud](https://img.shields.io/badge/Qdrant-Cloud-DC244C?logo=qdrant&logoColor=white)
![Splunk Enterprise](https://img.shields.io/badge/Splunk-Enterprise_10.2.2-000000?logo=splunk&logoColor=white)
![LangSmith Traced](https://img.shields.io/badge/LangSmith-Traced-1C3C3C)
![Langfuse PromptOps](https://img.shields.io/badge/Langfuse-PromptOps-4B5563)

![Tests](https://img.shields.io/badge/Tests-397_passing-brightgreen)
![CI](https://github.com/Asembris/splunk-sentinel/actions/workflows/ci.yml/badge.svg)
![DeepEval](https://img.shields.io/badge/DeepEval-93.3%25_pass-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

## What Judges Can Verify In 10 Minutes

### Option A — Watch the demo video
[Demo video (TBD)](https://example.com)

### Option B — Run it locally

**Prerequisites:** Splunk Enterprise + botsv3, Python 3.12, Node 18, OpenAI API key, Qdrant Cloud (free tier), VirusTotal API key, AbuseIPDB API key, Langfuse account (free tier)

**1. Clone and install**

```bash
git clone https://github.com/Asembris/splunk-sentinel.git
cd splunk-sentinel

# Backend
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

# Frontend
cd ..\frontend
npm install
```

**2. Configure .env**

Use `backend/app/.env.example` and set:

```env
SPLUNK_HOST=localhost
SPLUNK_PORT=8089
SPLUNK_USERNAME=your_splunk_username
SPLUNK_PASSWORD=your_splunk_password
OPENAI_API_KEY=sk-your_openai_api_key
QDRANT_URL=https://your-cluster.qdrant.io
QDRANT_API_KEY=your_qdrant_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_KEY=your_supabase_service_key
LANGCHAIN_API_KEY=your_langsmith_api_key
LANGCHAIN_TRACING_V2=true
LANGCHAIN_PROJECT=splunk-sentinel
LANGFUSE_PUBLIC_KEY=your_langfuse_public_key
LANGFUSE_SECRET_KEY=your_langfuse_secret_key
LANGFUSE_BASE_URL=https://cloud.langfuse.com
```

**3. Install Splunk app (one click)**

`sentinel.spl` packaging is coming. Manual setup for now:
- Create `sentinel_findings` index
- Create `sentinel_actions` index
- Add `authorize.conf` MLTK capabilities

**4. Ingest RAG knowledge base (run once)**

```bash
cd backend
.venv\Scripts\activate
python -m app.rag.ingest
```

**5. Start backend**

```bash
cd backend
.venv\Scripts\activate
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```

**6. Start frontend**

```bash
cd frontend
npm run dev
# http://localhost:5173
```

**7. Verify health**

`GET http://localhost:8001/api/health`

Expected:

```json
{
  "status": "ok",
  "splunk_connected": true,
  "splunk_version": "10.2.2",
  "promptops": "langfuse",
  "prompt_versions": {
    "triage-agent": {"version": 1, "label": "production"},
    "synthesis-narrative": {"version": 1, "label": "production"},
    "containment-refinement": {"version": 1, "label": "production"}
  }
}
```

**8. Run your first investigation**

`POST http://localhost:8001/api/investigate`

```json
{
  "trigger": "Suspicious outbound requests to AWS metadata endpoint detected from internal web server. Possible SSRF attack leading to IAM credential exposure.",
  "investigation_id": "judge-test-001"
}
```

Expected response includes:
- `attack_classification: APT`
- `investigation_confidence: ~0.75`
- `kill_chain_stages: 4+ stages`
- `ttp_mappings: 4+ MITRE techniques`
- `containment_plan: 3 phases with actions`

**9. Run the test suite**

```bash
cd backend
.venv\Scripts\activate
python -m pytest tests/ --ignore=tests/eval/ -v
```

Expected: `397 passed, 0 failed`

## The Problem

SOC analysts investigating APT incidents spend 4+ hours manually
pivoting between data sources — running 15-20 sequential Splunk
queries, each informed by the last. During this time:

- **Alert fatigue** causes critical kill chain events to be missed
- **Manual correlation** across 2M+ events is error-prone and slow
- **Context switching** between tools breaks investigative flow
- **Dwell time increases** — attackers operate undetected for longer

The BOTS v3 dataset demonstrates this problem exactly: 2,083,056 log
events across 20 sourcetypes. A human analyst needs 3-4 hours to
reconstruct the kill chain. **Splunk Sentinel does it in ~100 seconds.**

## How It Works — Architecture Overview

### Full Agent Pipeline

```mermaid
graph TD
    A[🔔 Alert Trigger<br/>Splunk Webhook / User Prompt] --> B

    subgraph TRIAGE ["⚡ Phase 1 — Triage"]
        B[TriageAgent<br/>Classification · Confidence · SPL Routing]
    end

    subgraph RECONSTRUCTION ["🔍 Phase 2 — Reconstruction ReAct Loop"]
        C[ReconstructionAgent<br/>Iterative SPL Generation · Kill Chain Building<br/>Self-Correction · Patient Zero · Blast Radius]
    end

    subgraph PARALLEL ["⚡ Phase 3 — Parallel Enrichment"]
        D[ThreatIntelAgent<br/>VirusTotal · AbuseIPDB<br/>IP Reputation]
        E[TTPAgent<br/>MITRE ATT&CK RAG<br/>697 Techniques · CVE Lookup]
    end

    subgraph SYNTHESIS ["📊 Phase 4 — Synthesis"]
        F[SynthesisAgent<br/>RAG Retrieval · Evidence Citation<br/>Confidence Scoring · Report Generation]
    end

    subgraph REPORTING ["📋 Phase 5 — Reporting"]
        RA[ReportAgent<br/>PDF · Supabase · Splunk Write-back<br/>4-Tier Confidence Ladder]
    end

    B -->|APT/Ransomware/Insider| C
    B -->|UNKNOWN| Z[🔚 END — Escalate to Human]
    C --> D
    C --> E
    D --> F
    E --> F
    F --> RA[ReportAgent<br/>PDF Generation · Supabase · Splunk Write-back]
    RA --> G[📄 Complete Investigation Package<br/>PDF Report · Notable Event · Analyst Feedback]

    style TRIAGE fill:#1e3a5f,stroke:#3b82f6
    style RECONSTRUCTION fill:#1e3a5f,stroke:#3b82f6
    style PARALLEL fill:#1a2e1a,stroke:#10b981
    style SYNTHESIS fill:#2d1b1b,stroke:#ef4444
    style REPORTING fill:#1a1a2e,stroke:#8b5cf6
```

### ReAct Loop — ReconstructionAgent

```mermaid
sequenceDiagram
    participant T as Trigger
    participant R as ReconstructionAgent
    participant S as Splunk (botsv3)
    participant L as LLM (gpt-4o-mini)
    participant Q as Qdrant RAG
    participant G as SPL Guardrail

    T->>R: AgentState (classification, indicators)
    
    loop ReAct Iterations (max 3)
        R->>G: Validate SPL query
        G-->>R: ✅ Approved / ❌ Blocked
        R->>S: Execute SPL query
        S-->>R: Telemetry results
        R->>L: Reason: what did we find?<br/>Act: what to query next?
        L-->>R: ReActObservation<br/>(new_stages, gaps, next_queries)
        R->>R: Update kill chain stages
        R->>R: Compute confidence score
        alt confidence >= 0.85 OR stages >= 5
            R->>R: Terminate loop
        end
    end

    R->>L: Synthesis: produce final report
    L-->>R: ReconstructionResult
    R->>Q: Retrieve MITRE technique details
    Q-->>R: Enriched TTP mappings
    R-->>T: kill_chain, patient_zero, blast_radius
```

### RAG Knowledge Pipeline

```mermaid
graph LR
    subgraph SOURCES ["📚 Knowledge Sources"]
        A[MITRE ATT&CK<br/>Enterprise STIX<br/>697 techniques]
        B[CVE / NVD<br/>Filtered to botsv3<br/>attack surface]
        C[IR Playbooks<br/>APT · Ransomware<br/>Insider Threat]
        D[botsv3 Notes<br/>Manual forensic<br/>ground truth]
    end

    subgraph EMBEDDING ["🔢 Embedding Pipeline"]
        E[text-embedding-3-large<br/>3072 dimensions<br/>OpenAI]
    end

    subgraph STORE ["🗄️ Qdrant Cloud"]
        F[mitre_attack<br/>697 techniques]
        G[cve_nvd<br/>botsv3 attack surface]
        H[ir_playbooks<br/>APT · Ransomware · Insider]
        I[botsv3_investigation<br/>forensic ground truth]
    end

    subgraph RETRIEVAL ["🔍 Parallel Retrieval"]
        J[retrieve_for_synthesis<br/>4 collections in parallel<br/>threshold 0.45]
    end

    A --> E --> F --> J
    B --> E --> G --> J
    C --> E --> H --> J
    D --> E --> I --> J
    J --> K[SynthesisAgent<br/>RAG-grounded report]
```

### LangGraph State Machine

```mermaid
stateDiagram-v2
    [*] --> triage_agent
    
    triage_agent --> reconstruction_agent: APT/Ransomware/Insider
    triage_agent --> END: UNKNOWN / low confidence
    
    reconstruction_agent --> threat_intel_agent: parallel fan-out
    reconstruction_agent --> ttp_agent: parallel fan-out
    
    threat_intel_agent --> synthesis_agent: merge
    ttp_agent --> synthesis_agent: merge
    
    synthesis_agent --> report_agent: final_report populated
    report_agent --> END: PDF · Supabase · Splunk write-back
    
    note right of report_agent
        ReportLab PDF generation
        Supabase persistence
        Splunk notable event write-back
        4-tier confidence ladder
    end note
    
    note right of reconstruction_agent
        ReAct loop
        max 3 iterations
        SPL guardrail on every query
    end note
    
    note right of triage_agent
        3-layer SPL guardrail
        Layer 1: deterministic 0ms
        Layer 2: index authorization
        Layer 3: audit logging
    end note
```

### 3-Layer SPL Guardrail

```mermaid
flowchart TD
    Q[SPL Query] --> L1

    subgraph L1 ["Layer 1 — Deterministic 0ms"]
        L1C{Contains blocked terms?<br/>DELETE · DROP · outputlookup<br/>sendemail · _internal}
    end

    subgraph L2 ["Layer 2 — Index Authorization"]
        L2C{Targets only<br/>index=botsv3?}
    end

    subgraph L3 ["Layer 3 — Audit Log"]
        L3C[Write to audit log<br/>timestamp · query · result]
    end

    L1C -->|YES| BLOCKED1[🚫 BLOCKED<br/>Reason logged]
    L1C -->|NO| L2C
    L2C -->|NO| BLOCKED2[🚫 BLOCKED<br/>Out of scope]
    L2C -->|YES| L3C
    L3C --> EXEC[✅ Execute against Splunk]
    EXEC --> RESULTS[Return results to agent]
```

### Post-Pipeline Services

```mermaid
graph TD
    R[ReportAgent<br/>Investigation persisted] --> CE
    R --> ME

    subgraph POST ["Post-Pipeline Services (analyst-triggered)"]
        CE[containment_engine<br/>Phase execution + rollback]
        CC[containment_chat<br/>ContainmentRefinementAgent<br/>ReAct tool calling]
        CV[containment_verifier<br/>SPL verification of effects]
        DG[detection_gap_analyzer<br/>MITRE coverage analysis]
        ME[mltk_enrichment<br/>Async MLTK ai command validation]
    end

    CE --> CV
    CE --> CC
    R --> DG

    style POST fill:#1a1a2e,stroke:#8b5cf6
```

## Key Features

### Feature 1 — ReAct Kill Chain Reconstruction
ReconstructionAgent runs a bounded ReAct loop (max 3 iterations) to reason over telemetry, issue next SPL queries, self-correct query failures, and converge on a complete kill chain with patient zero and blast radius.

### Feature 2 — Explainable Confidence Scores
Deterministic 5-factor confidence, not LLM-generated:
- Kill chain completeness: `0.35`
- Evidence variety: `0.30`
- Patient zero identification: `0.10`
- Threat corroboration: `0.10`
- Blast radius assessment: `0.15`

Includes weakest-factor callout plus a concrete recommendation.

### Feature 3 — MLTK Async TTP Validation
After persistence, Splunk MLTK `ai` validates MITRE mappings asynchronously (~30s post-investigation). Validation runs in parallel and never blocks pipeline SLO. Qdrant/MLTK agreement boosts confidence using `Qdrant 60% + MLTK 40%`. UI updates via polling.

### Feature 4 — Containment Plan + Verification
3-phase IR plan (`IMMEDIATE`, `SHORT TERM`, `REMEDIATION`) with analyst edits, SSE execution, and rollback via reversal SPL. `containment_verifier` proves measurable effect with deterministic before/after SPL counts and verdicts:
- `VERIFIED_EFFECTIVE`
- `PARTIAL_EFFECT`
- `VERIFICATION_FAILED`
- `ROLLBACK_RECOMMENDED`

### Feature 5 — Conversational Containment Refinement
ContainmentRefinementAgent supports natural-language plan edits with ReAct tool calling, bulk operations, RFC1918 validation, deduplication, phase targeting, and conversation memory. Uses `fetch ReadableStream` SSE for Safari compatibility.

### Feature 6 — Detection Gap Analysis
Compares MITRE techniques against existing Splunk saved searches, identifies uncovered techniques, generates recommended detection SPL (LLM + templates), and deploys in one click through Splunk SDK. Includes cache, duplicate checks, and guardrails.

### Feature 7 — PromptOps via Langfuse
All 6 prompts managed in Langfuse (v1), with production/staging labels, startup validation, 5-minute TTL caching, memory fallback, and hardcoded fallback to prevent pipeline outages.

### Feature 8 — Parallel Agent Fan-Out
ThreatIntelAgent and TTPAgent run in parallel after reconstruction, reducing total latency versus sequential enrichment.

### Feature 9 — RAG-Grounded Reporting
Synthesis pulls from Qdrant (`697 MITRE + 50 CVEs + 15 IR playbooks`) to ground techniques, recommendations, and contextual explanations.

### Feature 10 — Tamper-Evident Audit Log
Every SPL query is recorded in a SHA-256 chain. Integrity is verifiable per investigation via API.

### Feature 11 — Full Observability
LangSmith traces every LLM call. Langfuse manages prompt versions. Cost is approximately **$0.009 per investigation** with `gpt-4o-mini` exclusively.

## Agent and Service Reference

### Investigation Pipeline (LangGraph)

| Agent | Role | Key Logic |
|-------|------|-----------|
| TriageAgent | Classification, severity, SPL routing | 3-layer guardrail, UNKNOWN routing |
| ReconstructionAgent | Kill chain, patient zero, blast radius | ReAct max 3 iter, SPL self-correction |
| ThreatIntelAgent | IP reputation | VirusTotal + AbuseIPDB parallel, RFC1918 filter |
| TTPAgent | MITRE mapping + MLTK validation | Qdrant RAG + async MLTK enrichment |
| SynthesisAgent | Report generation | 4 parallel LLM calls, graceful degradation |
| ReportAgent | PDF, Supabase, Splunk write-back | MLTK task fire, containment persistence |

### Post-Pipeline Services

| Service | Trigger | Role |
|---------|---------|------|
| containment_engine | Analyst executes phase | SPL execution, sentinel_actions write |
| containment_chat | Analyst chat message | ContainmentRefinementAgent ReAct |
| containment_verifier | After action executes | SPL before/after verification |
| detection_gap_analyzer | Analyst opens gaps panel | MITRE coverage vs saved searches |
| mltk_enrichment | After investigation persists | Async MLTK ai command TTP validation |

## Splunk Integration

### Autonomous Alert Webhook
Configure Splunk alert actions to call Sentinel for autonomous investigations from detections.

### Splunk Write-back
Completed investigations are written back to `index=sentinel_findings`.

### MLTK AI Toolkit Integration
MLTK `5.7.4` + PSC `4.3.2` with Connection Management (`openai_sentinel`, `gpt-4o-mini`):

```spl
| makeresults count=1
| eval evidence="..."
| ai connection="openai_sentinel"
    prompt="Validate MITRE technique: {qdrant_technique}..."
```

Results enrich report content asynchronously after investigation completion.

### Detection Gap Deployment
One-click deployment creates Splunk saved searches:

```spl
| rest /services/saved/searches
| where match(title, "Sentinel")
| table title, updated
```

### Containment Actions Audit
Every action execution and verification is auditable:

```spl
index=sentinel_actions earliest=0
| table investigation_id, action_type, target,
        status, executed_at, verification_verdict
| sort -executed_at
```

## API Reference

### Core investigation

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/investigate` | Start a new investigation (JSON/SSE) |
| `POST` | `/api/webhook/splunk` | Splunk autonomous trigger |
| `GET` | `/api/health` | Health and Splunk connectivity |
| `GET` | `/api/investigations` | Investigation list |
| `GET` | `/api/investigations/{id}` | Investigation details |
| `POST` | `/api/investigations/{id}/feedback` | Analyst feedback |
| `GET` | `/api/investigations/{id}/report/pdf` | Download PDF |

### Analysis

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/investigations/{id}/confidence-breakdown` | Explainable confidence factors |
| `GET` | `/api/investigations/{id}/ttp-enrichment` | Async MLTK enrichment status/results |
| `GET` | `/api/investigations/{id}/detection-gaps` | MITRE coverage analysis |
| `POST` | `/api/investigations/{id}/detection-gaps/deploy` | Deploy saved search |

### Containment

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/investigations/{id}/containment-plan` | Load plan |
| `POST` | `/api/investigations/{id}/containment-plan/execute` | Execute phase |
| `POST` | `/api/investigations/{id}/containment-plan/rollback` | Rollback action |
| `GET` | `/api/investigations/{id}/containment-plan/chat/init` | Init chat |
| `POST` | `/api/investigations/{id}/containment-plan/chat` | Refinement chat |

### Audit

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/audit-log/verify/{id}` | Verify audit chain for investigation |
| `GET` | `/api/audit-log/verify-latest` | Verify latest investigation |

## Evaluation Results

### TriageAgent — DeepEval Suite

| Golden | Classification | Confidence | Status |
|:---|:---|:---|:---|
| APT SSRF + IAM credential theft | APT | 0.90 | ✅ Pass |
| DNS tunneling C2 beaconing | APT | 0.90 | ✅ Pass |
| C2 beaconing periodic connections | APT | 0.90 | ✅ Pass |
| WMIC + cmd.exe ransomware staging | RANSOMWARE | 0.80 | ✅ Pass |
| Shadow copy deletion + lateral movement | RANSOMWARE | 0.90 | ✅ Pass |
| reg.exe + svchost.exe execution chain | RANSOMWARE | 0.80 | ✅ Pass |
| EventCode 4673 privilege abuse | INSIDER_THREAT | 0.80 | ✅ Pass |
| Mass file access EventCode 4670 | INSIDER_THREAT | 0.80 | ✅ Pass |
| Special privileges EventCode 4672 | INSIDER_THREAT | 0.80 | ✅ Pass |
| Vague trigger (UNKNOWN) | UNKNOWN | 0.35 | ✅ Pass |
| Empty trigger (UNKNOWN) | UNKNOWN | 0.35 | ✅ Pass |
| **Hallucination trap**: 847 failed logins | UNKNOWN | 0.30 | ✅ Pass |
| Multi-vector SSRF + DNS tunnel | APT | 0.90 | ✅ Pass |
| CRITICAL ransomware guardrail | RANSOMWARE | 0.90 | ✅ Pass |
| Confidence cap regression | APT | 0.95 | ✅ Pass |

**Pass rate: 14/15 (93.3%) at 0.7 threshold with gpt-4o-mini judge**

### Unit Test Coverage

| Module | Tests |
|--------|-------|
| Guardrails (SPL, escalation, telemetry) | 73 |
| ReconstructionAgent (confidence, Pydantic) | 44 |
| Containment (engine, models, routes, templates, chat) | 75 |
| Detection gap analyzer | 28 |
| Confidence breakdown | 15 |
| Containment verifier | 31 |
| API contracts | 27 |
| Other (audit, parallel, schema, synthesis, triggers) | 104 |
| **Total** | **397** |

### LangSmith Pipeline Trace

| Step | Latency | Tokens | Cost |
|:---|:---|:---|:---|
| triage_agent | 27.3s | 3.5K | ~$0.001 |
| reconstruction_agent (3 ReAct iters) | 70.1s | 40.6K | ~$0.006 |
| threat_intel_agent | 0.4s | — | — |
| ttp_agent | 3.3s | — | — |
| synthesis_agent | 9.9s | 6.3K | ~$0.001 |
| report_agent | ~5s | — | — |
| **Total** | **~100s** | **~50.4K** | **~$0.009** |

## Security Design

### Read-Only Agent Operation

The investigation agent operates in strict read-only mode against
`index=botsv3` exclusively. Three layers of protection enforce this:

**Layer 1 — Deterministic keyword blocking (0ms, zero LLM calls)**
Blocked terms: `| delete`, `delete-index`, `| outputlookup overwrite=true`,
`| sendemail`, `DROP`, `TRUNCATE`, `index=_internal`, `index=_audit`

**Layer 2 — Index authorization**  
Every SPL query is validated to target only `index=botsv3`. Queries
targeting production indexes, internal Splunk indexes, or customer
data are blocked before execution.

**Layer 3 — Immutable audit log**
Every query attempt (whether blocked or executed) is timestamped and
logged with: `timestamp`, `investigation_id`, `query`, `layer1_result`,
`layer2_result`, `executed`, `results_count`. This log cannot be
modified by the agent.

### Confidence-Gated Escalation

Investigations with `reconstruction_confidence < 0.5` or
`severity = CRITICAL` automatically set `escalate_to_human = True`.
The system never produces a high-confidence report from low-quality
evidence — it escalates instead.

### Hash-Chained Audit Log

Every SPL query attempt — whether blocked or executed — is
recorded as a tamper-evident entry in a SHA-256 hash chain.
Each entry contains:

- `prev_hash` — hash of the previous entry (genesis: `"0"*64`)
- `entry_hash` — SHA-256 of `prev_hash + canonical(entry content)`
- `correction_attempts` — number of LLM self-correction rewrites
- `was_corrected` — whether the query was rewritten before execution
- `rows_returned` — result count for executed queries

Modifying any entry invalidates all subsequent hashes, making
tampering immediately detectable. The `GET /api/audit-log/verify`
endpoint provides real-time chain integrity verification.

### Splunk Notable Event Write-back

When an investigation completes, ReportAgent writes a structured
notable event to `index=sentinel_findings` via the Splunk Python
SDK. The event includes the full kill chain summary, confidence
tier, patient zero, and immediate recommended actions — making
Sentinel findings searchable in Splunk alongside native alerts:

```spl
index=sentinel_findings sourcetype="sentinel:investigation"
| table investigation_id, classification, confidence_tier,
        kill_chain_summary, patient_zero_ip, severity
```

## BOTS v3 Attack Scenario

The system is evaluated against the Boss of the SOC v3 dataset —
a realistic APT simulation used in Splunk .conf competitions.

### Dataset
- **Total events:** 2,083,056
- **Sourcetypes:** 20 (stream:http, stream:dns, WinEventLog:Security, osquery, syslog, ...)
- **Attack window:** 2018-08-20 to 2019-09-19
- **Peak hour:** 2018-08-20 15:00 (443,808 events)

### Confirmed Kill Chain (botsv3 Ground Truth)

```mermaid
timeline
    title botsv3 APT Attack Timeline
    section 2018-08-20
        11h00 : Initial Access
              : 54.67.127.227 to 172.16.0.178
              : /forumdisplay.php exploitation
              : T1190
        11h05 : SSRF Exploitation
              : 172.16.0.127 to 169.254.169.254
              : /latest/meta-data/iam/security-credentials/
              : T1552.005
        11h06 : Credential Theft
              : EC2InstanceRole exfiltrated
              : 73 metadata queries
              : T1528
        11h15 : Execution
              : cmd.exe x1091, WMIC.exe x536
              : reg.exe x523 via EventCode 4688
              : T1059.003 and T1047
        12h10 : Defense Evasion
              : EventCode 1102 on BSTOLL-L
              : Security log cleared
              : T1070.001
```

### Key IOCs

| IOC | Value | Role |
|:---|:---|:---|
| External attacker IPs | 54.67.127.227, 184.85.20.125, 23.73.195.90 | Initial access |
| Internal SSRF source | 172.16.0.127, 172.31.12.76 | Compromised web server |
| Metadata endpoint | 169.254.169.254 | AWS credential theft target |
| Metadata URI | /latest/meta-data/iam/security-credentials/EC2InstanceRole | Stolen credential path |
| Compromised host | BSTOLL-L | EventCode 1102 — log cleared |
| Compromised account | BSTOLL | Admin privileges |
| Dominant EventCodes | 5156 (11,501), 4688 (7,427), 4673 (4,122) | Key investigation signals |

## Getting Started

> Note: This project requires Splunk Enterprise
> with the botsv3 dataset. If you cannot run
> it locally, the demo video shows the complete
> investigation flow end to end.

### Option A — Watch the demo video
[Demo video (TBD)](https://example.com)

### Option B — Run locally with full commands

#### 1) Clone repository

```bash
git clone https://github.com/Asembris/splunk-sentinel.git
cd splunk-sentinel
```

#### 2) Backend setup

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

#### 3) Frontend setup

```bash
cd ..\frontend
npm install
```

#### 4) Configure environment
Create `backend/app/.env` from `backend/app/.env.example` with:

- `SPLUNK_HOST`
- `SPLUNK_PORT`
- `SPLUNK_USERNAME`
- `SPLUNK_PASSWORD`
- `OPENAI_API_KEY`
- `QDRANT_URL`
- `QDRANT_API_KEY`
- `VIRUSTOTAL_API_KEY`
- `ABUSEIPDB_API_KEY`
- `SUPABASE_URL`
- `SUPABASE_SERVICE_KEY`
- `LANGCHAIN_API_KEY`
- `LANGCHAIN_TRACING_V2`
- `LANGCHAIN_PROJECT`
- `LANGFUSE_PUBLIC_KEY`
- `LANGFUSE_SECRET_KEY`
- `LANGFUSE_BASE_URL`

#### 5) Splunk setup (manual until app package)

- Create `sentinel_findings` index
- Create `sentinel_actions` index
- Apply MLTK capabilities in `authorize.conf`
- Confirm Splunk on local ports `8000` and `8089`

#### 6) Ingest RAG data (one-time)

```bash
cd backend
.venv\Scripts\activate
python -m app.rag.ingest
```

#### 7) Run backend

```bash
cd backend
.venv\Scripts\activate
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
```

#### 8) Run frontend

```bash
cd frontend
npm run dev
```

Open: `http://localhost:5173`

#### 9) Verify health endpoint

```bash
curl http://localhost:8001/api/health
```

Expect:
- `"status": "ok"`
- `"splunk_connected": true`
- `"splunk_version": "10.2.2"`
- `"promptops": "langfuse"`
- prompt versions metadata

#### 10) Run investigation

```bash
curl -X POST http://localhost:8001/api/investigate ^
  -H "Content-Type: application/json" ^
  -d "{\"trigger\":\"Suspicious outbound requests to AWS metadata endpoint detected from internal web server. Possible SSRF attack leading to IAM credential exposure.\",\"investigation_id\":\"judge-test-001\"}"
```

Expect:
- `attack_classification: APT`
- `investigation_confidence: ~0.75`
- `kill_chain_stages: 4+`
- `ttp_mappings: 4+`
- `containment_plan: 3 phases`

#### 11) Run tests

```bash
cd backend
.venv\Scripts\activate
python -m pytest tests/ --ignore=tests/eval/ -v
```

Expected: `397 passed, 0 failed`

## Tech Stack

| Layer | Technology | Version | Purpose |
|:---|:---|:---|:---|
| Agent Orchestration | LangGraph | 0.2 | State machine + parallel fan-out |
| LLM | GPT-4o-mini | OpenAI | SPL generation, reasoning, synthesis |
| Security Platform | Splunk Enterprise | 10.2.2 | Log ingestion + search execution |
| Dataset | BOTS v3 | — | 2,083,056 events |
| Vector Store | Qdrant Cloud | 1.11 | RAG retrieval |
| Embeddings | text-embedding-3-large | 3072 dims | Semantic search |
| Backend | FastAPI | 0.115 | REST API + SSE streaming |
| Frontend | React 18 + Vite | 18 / 5.0 | Real-time dashboard |
| Persistence | Supabase | PostgreSQL | Investigation storage (JSONB) |
| PromptOps | Langfuse | 3.14.6 | Prompt versioning + validation |
| AI Toolkit | Splunk MLTK | 5.7.4 | Native Splunk AI command |
| ML Runtime | Python for Scientific Computing | 4.3.2 | MLTK dependency |
| Tracing | LangSmith | — | End-to-end LLM traces |

## Documentation

- [FINDINGS.md](FINDINGS.md) — 8 architectural findings
  including MLTK latency analysis, SPL guardrail design,
  Langfuse PromptOps, and containment verification
- [SPLUNK_SDK_USAGE.md](SPLUNK_SDK_USAGE.md) — Complete
  Splunk SDK integration guide including MLTK 5.7.4
  syntax, Connection Management setup, and ai command
  usage
- [architecture_diagram.md](architecture_diagram.md) —
  Full system architecture as required by hackathon rules

## License

MIT — see [LICENSE](LICENSE)

## Acknowledgements

- [Splunk BOTS v3](https://github.com/splunk/botsv3) — Ryan Kovar et al.
- [MITRE ATT&CK](https://attack.mitre.org/) — MITRE Corporation
- [LangGraph](https://github.com/langchain-ai/langgraph) — LangChain
- [Qdrant](https://qdrant.tech/) — Vector similarity search
- [DeepEval](https://github.com/confident-ai/deepeval) — LLM evaluation
- [vis-network](https://visjs.github.io/vis-network/docs/network/) — Graph visualization
- Langfuse — Prompt management
- Supabase — Investigation persistence
- Splunk MLTK — AI Toolkit integration
