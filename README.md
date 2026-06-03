# AI SOC CoPilot

An AI-powered Security Operations Center (SOC) CoPilot that ingests security
logs, summarizes alerts, maps activity to **MITRE ATT&CK** through LLM
reasoning, assesses the threat, suggests triage steps, and generates a
professional incident report — running entirely on a **local** model 

> See [`SPECIFICATION.md`](SPECIFICATION.md) for the full design specification.

---

## Features

- **Multi-source log ingestion** — Windows Event Logs (CSV), Linux syslog, and
  Apache access logs, normalized into one `SecurityEvent` model.
- **Unified chronological timeline** — timestamps are normalized across the
  three formats, so the merged timeline is truly chronological even when the
  incident spans multiple days.
- **High-signal event classification** — surfaces brute force, SQL injection,
  path traversal, webshell access, C2 beacons, data exfiltration, and privilege
  escalation with appropriate severities (so the worst events aren't buried).
- **LLM-powered analysis** — a 5-turn chain-of-thought (what happened →
  correlations → MITRE mapping → threat assessment → triage) on a local Ollama
  model.
- **Validated MITRE ATT&CK mapping** — techniques are *reasoned* by the LLM
  (with confidence + justification), then validated against the ATT&CK
  reference; invented technique IDs are flagged as unverified.
- **Automated IOC extraction & scoping** — Indicators of Compromise (IPs, URLs,
  accounts, files/artifacts) and Affected Assets are extracted **deterministically
  from the parsed events**, so they're reliable regardless of model quality.
- **Incident classification** — an incident category, status, and detection
  window are derived automatically.
- **Professional incident report** — a structured 7-section IR report with an
  executive dashboard, severity colour-coding, and print-to-PDF, as a
  self-contained **HTML** file (zero JavaScript). Also console, TXT, and JSON.
- **Local-first** — fully offline via Ollama; no API keys, no cost, no data
  leaves your machine.
- **Fails loud, never silently** — a hard pre-flight check verifies the model
  is ready before any analysis; the model is a required dependency by design.

---

## Architecture

```
[ INGEST ] -> [ GROUP ] -> [ ANALYZE ] -> [ CORRELATE ] -> [ ENRICH ] -> [ RENDER ]
 log_parser   alert_         incident_        correlation_     report_       report_
              summarizer     analyzer         analyzer         generator     generator
 (no AI)      (+ LLM)        (+ LLM, 5-turn)  (deterministic)  (IOCs,        (txt/json/
                                                               assets,        html)
                                                               classify)
```

Two layers by design: **deterministic** code handles structure (parsing,
timestamp normalization, IOC/asset extraction, classification, formatting); the
**LLM** handles understanding (summaries, MITRE reasoning, threat, triage). Every
LLM call funnels through one chokepoint (`llm_client.py`). Because the IOC,
affected-asset, and classification sections are built deterministically from the
parsed events, they stay accurate even if the model does not.

---

## Prerequisites

- Python 3.7+
- [Ollama](https://ollama.ai/) running locally with a model pulled

---

## Installation

```bash
# 1. Install the Python dependency
pip install -r requirements.txt

# 2. Pull and start a local model (any Ollama model)
ollama pull <model>
ollama serve         # (or: ollama run <model>)
```

---

## Quick Start

```bash
# Console summary (uses ./logs)
python3 main.py

# Save a full HTML report (opens in any browser, exports to PDF via print)
python3 main.py --output report.html --format html

# Save both JSON and TXT
python3 main.py --output report --format both

# See the raw 5-turn LLM reasoning
python3 main.py --explain
```

Reports are written to the `reports/` directory.
A pre-rendered example lives at [`examples/sample_report.html`](examples/sample_report.html).

---

## Command-line options

```
--log-dir DIR      Input log directory (default: ./logs)
--model NAME       Ollama model to use
--output FILE      Output file (bare names land in reports/)
--format FMT       json | txt | html | both   (default: txt)
--ollama-url URL   Ollama server URL (default: http://localhost:11434)
--explain          Print the raw 5-turn reasoning
```

If the model isn't reachable or installed, the tool exits with a clear message
(e.g. `ollama pull <model>`) instead of crashing mid-analysis.

---

## Input log formats

**Windows Event Logs (CSV)**
```csv
timestamp,event_id,source,user,description,severity
2026-05-31T15:30:05Z,4625,DC1,Administrator,Failed logon from WEBSRV-01 (10.0.0.55),high
```

**Linux syslog**
```
May 28 02:10:11 websrv-01 sshd[2041]: Failed password for invalid user admin from 203.0.113.45 port 54012 ssh2
```

**Apache access log (combined)**
```
203.0.113.45 - - [29/May/2026:23:41:33 +0000] "GET /products.php?id=1' UNION SELECT ... --" 500 1024 "-" "sqlmap/1.7"
```

The bundled sample dataset (`logs/`) is **synthetic** but tells one coherent
**multi-day intrusion** (May 28 – Jun 02, 2026): recon → web exploitation →
SSH breach → C2 beacon → lateral movement to a Windows DC → privilege
escalation → log clearing → data exfiltration. Shared indicators
(`203.0.113.45`, `198.51.100.200`, `10.0.0.55 / WEBSRV-01`, `svc_backup`) span
the files, so cross-source correlation and the ~5-day attacker dwell time are
both demonstrable.

---

## Report contents

**Header & metadata** — Incident ID, auto-derived classification, status,
detection window, and an executive dashboard (threat level, severity, event /
alert / technique counts with a severity breakdown).

**Sections:**

1. **Incident Overview** — point-wise narrative of what happened
2. **Event Timeline** — every event, source-tagged, in one uniform chronological format
3. **Indicators of Compromise (IOCs)** — external IPs, malicious URLs, accounts, files/artifacts *(extracted deterministically)*
4. **Affected Assets / Scope** — internal hosts involved, with event counts and max severity *(deterministic)*
5. **MITRE ATT&CK Mapping** — ID, tactic, confidence, reasoning; invalid IDs flagged unverified
6. **Impact / Threat Assessment** — risk score and business impact
7. **Recommendations** — prioritized triage steps

---

## Project structure

```
SOC/
├── main.py                     # CLI entry point + pre-flight check
├── src/
│   ├── soc_copilot.py          # Pipeline orchestrator
│   ├── log_parser.py           # Parse Windows / syslog / Apache -> SecurityEvent
│   ├── alert_summarizer.py     # Group events; LLM summaries
│   ├── incident_analyzer.py    # Build narrative; run 5-turn analysis
│   ├── mitre_framework.py      # MITRE ATT&CK reference for the model
│   ├── correlation_analyzer.py # Temporal/source correlation
│   ├── llm_client.py           # The single door to Ollama
│   └── report_generator.py     # Reports + IOC/asset extraction, classification
├── logs/                       # Sample multi-day intrusion (synthetic)
├── reports/                    # Generated output (gitignored)
├── examples/sample_report.html # Pre-rendered example report
├── SPECIFICATION.md            # Technical specification
├── requirements.txt
└── README.md
```

---

## License

[MIT](LICENSE)

---

**Built with:** Python · Ollama · MITRE ATT&CK Framework
