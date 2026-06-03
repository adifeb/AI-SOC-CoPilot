# AI SOC CoPilot — Technical Specification

**Version:** 1.0
**Status:** Implemented
**Author:** Aditya
**Last updated:** 2026-06-02

---

**AI SOC CoPilot** is a command-line tool that automates the first-pass triage
of a security incident. It ingests security logs, groups them into alerts, 
uses a Large Language Model (LLM) to reason about the activity,maps 
it to the MITRE ATT&CK framework, assesses the threat, recommends triage
actions, and produces a professional incident report — entirely on a local
model with no external API and no cost.

---

## 1. Goals 

- Ingest sample security logs from multiple formats (Windows Event Logs,
  Linux syslog, Apache access logs).
- Group related events into alerts and summarize each.
- Map observed activity to MITRE ATT&CK techniques *through LLM reasoning*,
  not keyword matching.
- Produce a threat assessment (1–10) and prioritized triage steps.
- Generate an incident report in multiple formats (console, TXT, JSON, HTML).
- Run on Python with a **local** LLM via Ollama — offline, no API cost.


## 2. Functional Requirements

| ID | Requirement | Acceptance criteria |
|----|-------------|---------------------|
| FR-1 | **Ingest logs** | Parse Windows Event Log (CSV), syslog, and Apache access logs into a normalized event model; merge into one chronological, source-tagged timeline. |
| FR-2 | **Summarize alerts** | Group related events and produce an LLM-generated summary per alert with a severity. |
| FR-3 | **Map to MITRE ATT&CK** | For each technique, output ID, tactic, confidence, and the model's reasoning; validate IDs against the ATT&CK reference and flag invented ones. |
| FR-4 | **Suggest triage steps** | Output prioritized, actionable recommendations. |
| FR-5 | **Extract IOCs & scope** | Deterministically extract Indicators of Compromise (IPs, URLs, accounts, files/artifacts) and affected internal assets from the parsed events; derive an incident classification, status, and detection window. |
| FR-6 | **Generate incident report** | Produce a structured incident report (HTML + console + TXT + JSON) with sections: Overview, Timeline, IOCs, Affected Assets, MITRE Mapping, Threat Assessment, Recommendations. |
| FR-7 | **Python + LLM** | Implemented in Python using a local LLM via Ollama. |

---

## 3. Non-Functional Requirements

- **Local-only / zero cost** — all inference runs on a local Ollama model; no
  external API calls, no data leaves the machine.
- **Offline** — works without internet once the model is pulled.
- **Deterministic structure, AI understanding** — parsing and formatting are
  deterministic and reproducible; reasoning is delegated to the LLM.
- **Fail loud, never silently degrade** — if the model is unavailable, the tool
  stops with a clear, actionable message rather than producing a misleading
  report (see §7.2).
- **Self-contained output** — the HTML report is a single file with embedded
  CSS, no JavaScript, openable anywhere and exportable to PDF via print.
- **Reasonable runtime** — full 5-turn analysis on the sample dataset completes
  in roughly 1–2 minutes on commodity hardware.

---

## 4. System Architecture

### 4.1 Pipeline overview

The tool is a pipeline. Raw log files enter one end; a finished incident report
exits the other.

```
[ INGEST ] -> [ GROUP ] -> [ ANALYZE ] -> [ CORRELATE ] -> [ ENRICH ] -> [ RENDER ]
 log_parser   alert_         incident_        correlation_     report_       report_
              summarizer     analyzer         analyzer         generator     generator
 (no AI)      (+ LLM)        (+ LLM, 5-turn)  (deterministic)  (IOCs,        (txt/json/
                                                               assets,        html)
                                                               classify)
```

Orchestrated by `soc_copilot.py`; entry point is `main.py` (CLI).

### 4.2 Two-layer design (the core principle)

The system deliberately separates two kinds of work:

- **Deterministic layer** — parsing, timestamp normalization, event
  classification, grouping, IOC/affected-asset extraction, incident
  classification, and report formatting. Fast, reliable, reproducible. Handles
  *structure*. Because the IOC, scope, and classification sections are computed
  here (not by the model), they remain accurate regardless of model quality.
- **Intelligence layer** — all reasoning (summaries, MITRE mapping, threat
  assessment, triage). Handles *understanding*. Every LLM call funnels through
  a single chokepoint: `OllamaClient.generate()` in `llm_client.py`.

There is intentionally **no fallback intelligence layer** (no keyword-based
MITRE mapping, no canned summaries). The model is a hard dependency; the tool's
purpose is to be genuinely AI-assisted.

### 4.3 Components

| File | Responsibility | Layer |
|------|----------------|-------|
| `main.py` | CLI args, hard pre-flight check, output routing | — |
| `soc_copilot.py` | Orchestrates the six stages | — |
| `log_parser.py` | Parse 3 log formats → `SecurityEvent`; classify events; normalize timestamps | Deterministic |
| `alert_summarizer.py` | Group events → `Alert`; LLM summaries | Both |
| `incident_analyzer.py` | Build narrative; run 5-turn analysis; extract + validate MITRE techniques | Intelligence |
| `mitre_framework.py` | MITRE ATT&CK reference (for the model and for ID validation) | Data |
| `correlation_analyzer.py` | Temporal/source correlation between alerts | Deterministic |
| `llm_client.py` | The single door to Ollama (generate, pre-flight, multi-turn) | Intelligence |
| `report_generator.py` | Extract IOCs/assets, classify incident, render reports | Deterministic |

---

## 5. Data Flow and Models

### 5.1 Transformation chain

```
raw log lines
   │  log_parser  (classify + normalize timestamps)
   ▼
List[SecurityEvent]        normalized, source-tagged, chronological
   │  alert_summarizer
   ▼
List[Alert]                grouped + AI summaries
   │  incident_analyzer (5-turn LLM)
   ▼
IncidentAnalysis           validated MITRE techniques, threat level, triage
   │  report_generator  (deterministic enrichment)
   ▼  + IOCs, affected assets, classification/status/detection window
report.{html,txt,json}     the deliverable
```

`SecurityEvent` is the **contract** of the pipeline: everything downstream of
ingestion depends only on it, not on how the logs were parsed. This makes the
ingestion layer swappable without touching analysis or reporting.

### 5.2 SecurityEvent schema

| Field | Description |
|-------|-------------|
| `timestamp` | Event time (as found in source) |
| `source` | Host/IP that generated the event |
| `event_type` | Normalized type (e.g. `EventID-4625`, `sql_injection`) |
| `severity` | low / medium / high / critical |
| `description` | Human-readable event detail |
| `raw_message` | Original log line |
| `log_source` | Origin format: `windows` / `syslog` / `apache` |
| `dt` | Normalized timestamp (naive UTC `datetime`) for cross-format chronological sorting |

### 5.3 The 5-turn LLM analysis

`incident_analyzer` builds one narrative from all events (labelled by source
and aggregated up front) and runs a chain-of-thought where each turn feeds the
next:

```
Turn 1: "What happened?"      -> initial_analysis      (report Overview)
Turn 2: "Find correlations"   -> correlations          (attack chain)
Turn 3: "Map to MITRE"        -> mitre_reasoning        (techniques)  [+ MITRE reference]
Turn 4: "Assess threat 1-10"  -> threat_assessment     (risk + impact)
Turn 5: "What to do NOW?"     -> prioritized_actions    (triage steps)
```

The full narrative + MITRE reference is sized to fit the model context window
(`num_ctx = 4096`) so no content is silently truncated.

---

## 6. Input / Output

### 6.1 Inputs

Log files are placed in a directory (default `./logs`). The current parsers
recognise three sources by content shape:

- **Windows Event Logs** — CSV with columns `timestamp, event_id, source, user, description, severity`.
- **Linux syslog** — standard `Mon DD HH:MM:SS host process[pid]: message`.
- **Apache access logs** — combined log format.

The sample dataset is *synthetic* but tells one coherent **multi-day intrusion**
(May 28 – Jun 02, 2026): recon → web exploitation → SSH breach → C2 beacon →
lateral movement to a Windows DC → privilege escalation → log clearing → data
exfiltration. Shared indicators (`203.0.113.45`, `198.51.100.200`,
`10.0.0.55 / WEBSRV-01`, `svc_backup`) span the files, so cross-source
correlation and the ~5-day attacker dwell time are demonstrable.

### 6.2 Pre-flight gate

Before any analysis, `preflight_check()` verifies in order: (1) the Ollama
server is reachable, (2) the requested model is installed, (3) the model can
actually generate. Any failure exits cleanly with an actionable message
(e.g. `ollama pull <model>`) rather than crashing mid-run.

### 6.3 Outputs

The incident report carries a header (Incident ID, auto-derived classification,
status, detection window, generated date) and an executive dashboard (threat
level, severity, and event / alert / technique counts with a severity
breakdown), followed by seven sections:

1. **Incident Overview** — LLM narrative, rendered point-wise.
2. **Event Timeline** — every event, source-tagged, in one uniform chronological format.
3. **Indicators of Compromise (IOCs)** — external IPs, URLs, accounts, files/artifacts *(deterministic)*.
4. **Affected Assets / Scope** — internal hosts, event counts, max severity *(deterministic)*.
5. **MITRE ATT&CK Mapping** — ID, tactic, confidence, reasoning; unverified IDs flagged.
6. **Impact / Threat Assessment** — risk score and business impact.
7. **Recommendations** — prioritized triage steps.

Output formats:

- **HTML** — self-contained, black-and-white base with colour reserved for the
  severity signal; print stylesheet for PDF export; no JavaScript.
- **TXT** — full plaintext report.
- **JSON** — machine-readable (includes the full alert and IOC/asset data).
- **Console** — concise summary.

Reports are written to `./reports/` (configurable via `--output`/`--format`).

---

## 7. Key Design Decisions and Trade-offs

| Decision | Rationale | Trade-off |
|----------|-----------|-----------|
| **Local model (Ollama)** | Zero cost, offline, private | Lower accuracy than frontier API models |
| **MITRE mapping via LLM reasoning, validated against the reference** | Understands context and explains *why*, while invented IDs get flagged | Coverage limited to the embedded technique set |
| **IOCs / scope / classification computed deterministically** | The most actionable sections stay correct regardless of model quality | Extraction is rule-based, so unusual formats may be missed |
| **No intelligence fallback** | Keeps the tool genuinely AI-assisted | Hard dependency on the model being up |
| **Two-layer (deterministic + AI)** | Reliability for structure, intelligence for understanding | More moving parts than a single LLM prompt |
| **HTML report, zero JavaScript** | Portable, safe, PDF-exportable, GitHub-friendly | No interactive filtering/sorting |
| **Synthetic sample data** | Labelled, reproducible, ATT&CK-aligned, safe | Less "real-world messy" than production logs |
| **`SecurityEvent` as the contract** | Ingestion is swappable without touching analysis | Requires every source to normalize to one schema |

---

## 8. Setup and Usage (summary)

```bash
# Prerequisites: Python 3, Ollama running with a model pulled
ollama pull <model>

# Install dependency
pip install requests

# Run (console summary)
python3 main.py

# Save a full report
python3 main.py --output report.html --format html
python3 main.py --output report --format both    # JSON + TXT

# Options
--log-dir DIR     # input directory (default ./logs)
--model NAME      # Ollama model to use
--format FMT      # json | txt | html | both
--explain         # print the raw 5-turn reasoning
```

See `README.md` for full usage details.
