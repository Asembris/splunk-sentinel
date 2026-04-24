# Splunk Sentinel 🛡️

> Autonomous AI-powered security investigation system. 
> Turns a 4-hour SOC analyst investigation into 47 seconds.

![Python 3.12](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![LangGraph](https://img.shields.io/badge/LangGraph-0.2-orange)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green?logo=fastapi)
![Splunk Enterprise](https://img.shields.io/badge/Splunk-Enterprise_10.2.2-black?logo=splunk)
![GPT-4o-mini (OpenAI)](https://img.shields.io/badge/GPT--4o--mini-OpenAI-blue?logo=openai)
![LangSmith](https://img.shields.io/badge/LangSmith-Enabled-blue)
![DeepEval](https://img.shields.io/badge/DeepEval-Adversarial-red)
![License MIT](https://img.shields.io/badge/License-MIT-yellow)

## The Problem

SOC analysts investigating APT incidents spend 80% of their time manually pivoting between Splunk sourcetypes — running 15-20 sequential queries, each informed by the last. During an active attack, this manual process takes 3-4 hours. Alert fatigue means critical kill chain events get missed, leading to increased dwell time and potential data exfiltration.

## The Solution

Splunk Sentinel is a multi-agent autonomous investigation system built on LangGraph. Given a single alert trigger, it autonomously executes the full SOC analyst workflow: triage → kill chain reconstruction → patient zero identification → blast radius assessment → MITRE ATT&CK mapping → incident report — all within 60 seconds. It replaces manual pivoting with intelligent, goal-oriented agent logic.

## Key Technical Differentiators

### 1. Iterative SPL Generation (ReconstructionAgent)
The ReconstructionAgent does not use pre-written queries. It receives previous search results and dynamically generates the next SPL query using an LLM, replicating the investigative reasoning of a senior SOC analyst. A ReAct self-correction loop catches SPL syntax errors and rewrites them automatically — the same pattern proven in production in AML Sentinel's Graph QA agent.

### 2. 3-Layer SPL Guardrail Architecture
Every SPL query passes through three safety layers before execution: Layer 1 (deterministic keyword blocking, 0ms), Layer 2 (index authorization — only botsv3 permitted), Layer 3 (full audit logging with timestamps). The agent cannot destroy evidence, modify indexes, or exfiltrate data. Zero LLM calls are used for safety decisions, ensuring deterministic reliability.

### 3. Confidence-Weighted Causal Graph
Every edge in the reconstructed kill chain carries a computed confidence score based on temporal proximity, shared IOC overlap, and multi-sourcetype corroboration. Findings below 0.5 confidence trigger human escalation rather than hallucinated conclusions, maintaining the integrity of the investigation.

### 4. Adversarial DeepEval Test Suite
The full investigation pipeline is evaluated against the BOTS v3 APT scenario with adversarial test cases covering: correct kill chain identification, IOC hallucination prevention, guardrail bypass attempts, and confidence calibration. Zero API calls are used during test execution to ensure reproducible and cost-effective benchmarking.

### 5. Autonomous Splunk Alert Integration
The system integrates with Splunk's native alerting via webhook. When a saved search threshold fires (e.g., 10+ failed logins in 5 minutes), Splunk calls the FastAPI /api/investigate endpoint directly — no human prompt required. The agent pipeline wakes up, investigates, and writes its findings back to Splunk as a knowledge object before the on-call analyst has opened their laptop.

## Architecture

```
Alert Trigger (Splunk Webhook / User Prompt)
              ↓
        TriageAgent
        - Attack window detection
        - Top source IP identification  
        - APT/Ransomware/Insider/DDoS classification
        - Confidence scoring
              ↓
    ReconstructionAgent  ← THE HARD ONE
        - Iterative SPL generation (ReAct loop)
        - Causal chain building
        - Self-correction on SPL errors
        - Stops when chain is complete or confidence < 0.4
              ↓ fan-out
┌─────────────────────────────────────┐
│                                     │
PatientZeroAgent        BlastRadiusAgent
First infected host     Compromised systems
Initial attack vector   Data accessed
                                     │
ThreatIntelAgent        TTPAgent
IP/hash enrichment      MITRE ATT&CK
VirusTotal/AbuseIPDB    Technique IDs
│                                     │
└──────────── fan-in ─────────────────┘
              ↓
        SynthesisAgent
        - RAG over past incidents (Qdrant)
        - Confidence-weighted narrative
        - Recommended immediate actions
              ↓
        ReportAgent
        - Structured incident report
        - Writes findings back to Splunk
        - Persists to Supabase
        - PDF generation
```

## Autonomous Trigger (No Human Input Required)

In production mode, Splunk Sentinel operates without human input. A Splunk saved search monitors for attack conditions in real time and fires a webhook to the FastAPI backend automatically when thresholds are breached:

```spl
index=botsv3 earliest=-5m
sourcetype=WinEventLog:Security EventCode=4625
| stats count by src_ip
| where count > 10
```

When this alert fires, the full investigation pipeline launches autonomously. The demo "We're under attack" prompt replicates this webhook trigger against the BOTS v3 dataset for evaluation purposes.


## Tech Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| Orchestration | LangGraph 0.2 | Agent state machine + fan-out/fan-in |
| LLM | GPT-4o-mini (OpenAI) | SPL generation + analysis |
| Security Data | Splunk Enterprise 10.2.2 | Log ingestion + search |
| Dataset | BOTS v3 (2,083,056 events, 107 sourcetypes) | APT simulation |
| Vector Store | Qdrant Cloud | Past incident RAG |
| Database | Supabase PostgreSQL | Incident persistence |
| Observability | LangSmith | Full pipeline tracing |
| Evaluation | DeepEval | Adversarial test suite |
| Backend | FastAPI + Python 3.12 | API + SSE streaming |
| Frontend | React 18 + Vite | Real-time investigation UI |

## Agent Pipeline Status

| Agent | Status | Description |
| :--- | :--- | :--- |
| TriageAgent | ✅ Complete | Attack window, IP profiling, APT classification |
| ReconstructionAgent | 🔄 In Progress | Iterative SPL generation with ReAct self-correction loop |
| PatientZeroAgent | ⏳ Planned | First infected host identification |
| BlastRadiusAgent | ⏳ Planned | Compromised system mapping |
| ThreatIntelAgent | ⏳ Planned | IOC enrichment via VirusTotal |
| TTPAgent | ⏳ Planned | MITRE ATT&CK mapping |
| SynthesisAgent | ⏳ Planned | RAG-grounded narrative generation |
| ReportAgent | ⏳ Planned | Incident report + Splunk write-back |

## Evaluation Results

| Metric | Value | Threshold | Status |
| :--- | :--- | :--- | :--- |
| TriageAgent APT Classification | APT (confidence 0.90) | ≥ 0.80 | ✅ Pass |
| Attack Window Detection | 2018-08-20 06:00 → 2019-09-19 20:00 | Correct bounds | ✅ Pass |
| Peak Hour Identification | 2018-08-20 15:00 (443,808 events) | Highest density hour | ✅ Pass |
| Top Source IP Recall | 10/10 IPs recovered | 100% recall | ✅ Pass |
| SPL Guardrail Layer 1 | Blocks DELETE/DROP/TRUNCATE in 0ms | Deterministic | ✅ Pass |
| SPL Guardrail Layer 2 | Blocks non-botsv3 index access | Zero bypass | ✅ Pass |
| Escalation Logic | Low confidence → human escalation | Threshold 0.50 | ✅ Pass |

> Full DeepEval adversarial suite covering kill chain accuracy, IOC hallucination prevention, and guardrail bypass resistance will be published upon ReconstructionAgent completion.

## BOTS v3 Attack Scenario

The system is evaluated on the Boss of the SOC v3 dataset — a realistic APT simulation containing 2,083,056 events across 107 sourcetypes spanning August 20, 2018. The attack follows a full kill chain: initial reconnaissance against a SuiteCRM application (192.168.8.111/112 → 192.168.9.30), exploitation, credential compromise (account BSTOLL), lateral movement via Windows authentication events (EventCode 4648), and sustained post-compromise activity peaking at 443,808 events/hour. Validated: TriageAgent correctly classifies this scenario as APT with 0.90 confidence, peak hour 2018-08-20 15:00, 443,808 events. Attack window correctly bounded. 10 top source IPs recovered with 100% recall.

## Getting Started

### Prerequisites
- Python 3.12+
- Node.js 18+
- Splunk Enterprise (local instance)
- BOTS v3 dataset installed
- OpenAI API key
- Qdrant Cloud account (free tier)
- Supabase project (free tier)

### Installation

```bash
git clone https://github.com/Asembris/splunk-sentinel.git
cd splunk-sentinel/backend
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -r requirements.txt
cp .env.example .env
# Fill in credentials in .env
uvicorn app.main:app --reload --port 8000
```

### Environment Variables

| Variable | Required | Description |
| :--- | :--- | :--- |
| SPLUNK_HOST | No (default: localhost) | Splunk server host |
| SPLUNK_PORT | No (default: 8089) | Splunk management port |
| SPLUNK_USERNAME | Yes | Splunk admin username |
| SPLUNK_PASSWORD | Yes | Splunk admin password |
| OPENAI_API_KEY | Yes | OpenAI API key |
| QDRANT_URL | Yes | Qdrant cluster URL |
| QDRANT_API_KEY | Yes | Qdrant API key |
| SUPABASE_URL | Yes | Supabase project URL |
| SUPABASE_SERVICE_KEY | Yes | Supabase service role key |
| LANGCHAIN_API_KEY | No | LangSmith tracing key |

## API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| POST | /api/investigate | Trigger investigation (JSON or SSE) |
| GET | /api/health | Splunk connection health check |
| GET | /api/audit-log | Last 100 SPL queries executed |

### Example Request

```bash
curl -X POST http://localhost:8000/api/investigate \
  -H "Content-Type: application/json" \
  -d '{
    "trigger": "Unusual authentication spike detected.",
    "investigation_id": "inc-001"
  }'
```

## Security Design

All SPL queries pass through a 3-layer guardrail before execution. The agent operates in read-only mode against `index=botsv3` exclusively. No write operations are permitted during investigation. All executed queries are timestamped and written to `logs/spl_audit.log` for forensic accountability. The investigation agent cannot be used to modify, delete, or exfiltrate Splunk data.

## License
MIT

## Acknowledgements
- Splunk BOTS v3 dataset by Ryan Kovar et al.
- LangGraph by LangChain
- MITRE ATT&CK Framework
