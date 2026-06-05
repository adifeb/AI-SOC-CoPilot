"""Tests for deterministic report enrichment and HTML rendering."""

import re

from src.report_generator import BasicIncidentReport


def _report(events, analysis=None):
    r = BasicIncidentReport("INC-TEST", analysis=analysis or {})
    r.events = events
    r.overall_severity = "critical"
    r.threat_level = 8
    r.alerts = [{"severity": "critical"}]
    return r


def test_iocs_extracted(events):
    iocs = _report(events).to_dict()["iocs"]
    assert "203.0.113.45" in iocs["External IPs (attacker / C2)"]
    assert "svc_backup" in iocs["User accounts"]


def test_classification_is_data_breach(events):
    assert _report(events).to_dict()["classification"] == "Data Breach / Exfiltration"


def test_overview_renders_numbered_list_not_orphans(events):
    analysis = {
        "initial_analysis": "Findings: 1. Alert-001: brute force. This is bad. "
                            "2. Alert-002: exfiltration occurred.",
        "threat_assessment": "Threat 8/10.",
        "mitre_techniques": [],
        "recommendations": [],
    }
    html = _report(events, analysis).to_html()
    overview = re.search(r"Incident Overview</h2>(.*?)<h2", html, re.S).group(1)
    assert "<ol" in overview and "<li>" in overview
    assert '<p class="body">1.</p>' not in overview  # no orphaned list number


def test_mitre_evidence_and_recommendation_evidence(events):
    refs = [events[0].ref, events[1].ref]
    analysis = {
        "initial_analysis": "x", "threat_assessment": "y",
        "mitre_techniques": [{"id": "T1110.001", "name": "Brute Force",
                              "tactic": "Credential Access", "confidence": 0.9,
                              "verified": True, "facts": ["fact"], "inference": "inf",
                              "evidence_refs": refs}],
        "recommendations": [
            {"action": "Block IP", "priority": "immediate", "rationale": "r",
             "evidence_refs": [events[0].ref]},
            {"action": "No-evidence action", "priority": "low", "evidence_refs": []},
        ],
    }
    html = _report(events, analysis).to_html()
    assert "Facts (observed):" in html and "Inference:" in html
    assert "ul class='evidence'" in html
    assert events[0].ref in html
    # Empty-evidence recommendation must not render an empty evidence block.
    assert "No supporting events cited" not in html


def test_ai_safety_not_shown_in_report(events):
    # AI-safety is protective only; it is NOT surfaced in the report.
    html = _report(events, {"initial_analysis": "x", "injection_attempts":
                            [{"ref": "EVT-0001", "phrases": ["SYSTEM:"]}]}).to_html()
    assert "aisafety" not in html
    assert "AI Safety" not in html


def test_attack_path_section_present(events):
    html = _report(events).to_html()
    assert "Attack Path</h2>" in html
    assert "ent-attacker" in html
