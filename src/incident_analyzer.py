import re
from typing import List, Dict
from src.log_parser import SecurityEvent
from src.alert_summarizer import Alert
from src.llm_client import OllamaClient
from src.mitre_framework import MitreFramework

# Rank for sorting/normalizing the model's self-reported confidence.
_CONFIDENCE_RANK = {'high': 3, 'medium': 2, 'low': 1}


class IncidentAnalysis:
    def __init__(self):
        self.initial_analysis = ""
        self.correlations = ""
        self.mitre_reasoning = ""
        self.threat_assessment = ""
        self.prioritized_actions = ""
        self.mitre_techniques = []
        self.threat_level = 0

    def to_dict(self) -> dict:
        return {
            'initial_analysis': self.initial_analysis,
            'correlations': self.correlations,
            'mitre_reasoning': self.mitre_reasoning,
            'threat_assessment': self.threat_assessment,
            'prioritized_actions': self.prioritized_actions,
            'mitre_techniques': self.mitre_techniques,
            'threat_level': self.threat_level,
        }


class IncidentAnalyzer:
    def __init__(self, llm_client: OllamaClient):
        self.llm_client = llm_client
        self.mitre_framework = MitreFramework()

    # Human-friendly names for each log source, so the model knows it is
    # correlating across multiple distinct log files.
    _SOURCE_LABELS = {
        'windows': 'Windows Event Log',
        'syslog': 'Linux syslog',
        'apache': 'Apache web access log',
    }

    def _build_incident_narrative(self, events: List[SecurityEvent], alerts: List[Alert]) -> str:
        """Build a rich narrative context from events.

        Every parsed event is included and each is labelled with the log
        source it came from, so the model receives ALL the logs and knows
        they span multiple correlated sources.
        """
        # Tell the model up front exactly what it is being given.
        counts = {}
        for e in events:
            counts[e.log_source] = counts.get(e.log_source, 0) + 1
        inventory = ", ".join(
            f"{n} from {self._SOURCE_LABELS.get(s, s)}" for s, n in sorted(counts.items())
        )

        narrative = "SECURITY INCIDENT - MULTI-SOURCE LOG ANALYSIS\n"
        narrative += "=" * 50 + "\n"
        narrative += f"You are given {len(events)} events aggregated from "
        narrative += f"{len(counts)} different log sources ({inventory}).\n"
        narrative += "Correlate activity ACROSS these sources.\n"
        narrative += "=" * 50 + "\nEVENT TIMELINE:\n"

        # Add timeline - every event, tagged with its source log.
        for event in events:
            src_label = self._SOURCE_LABELS.get(event.log_source, event.log_source)
            narrative += f"\n[{event.timestamp}] ({src_label}) {event.source}\n"
            narrative += f"  Type: {event.event_type}\n"
            narrative += f"  Severity: {event.severity}\n"
            narrative += f"  Description: {event.description}\n"

        # Add alert summaries
        narrative += "\n" + "=" * 50 + "\nALERT SUMMARIES:\n"
        for alert in alerts:
            narrative += f"\n[{alert.alert_id}] Severity: {alert.severity}\n"
            narrative += f"  Events: {len(alert.events)}\n"
            narrative += f"  Summary: {alert.summary}\n"

        return narrative

    def analyze(self, events: List[SecurityEvent], alerts: List[Alert]) -> IncidentAnalysis:
        """Perform intelligent multi-turn analysis of an incident."""
        analysis = IncidentAnalysis()

        # Build context
        incident_context = self._build_incident_narrative(events, alerts)

        # Get MITRE framework reference
        mitre_ref = self.mitre_framework.get_reference_text()

        # Multi-turn analysis
        results = self.llm_client.multi_turn_analysis(incident_context, mitre_ref)

        analysis.initial_analysis = results.get('initial_analysis', '')
        analysis.correlations = results.get('correlations', '')
        analysis.mitre_reasoning = results.get('mitre_reasoning', '')
        analysis.threat_assessment = results.get('threat_assessment', '')
        analysis.prioritized_actions = results.get('prioritized_actions', '')

        # Extract MITRE techniques and threat level from reasoning
        techniques = self._extract_techniques(analysis.mitre_reasoning)
        analysis.mitre_techniques = self._sort_techniques(techniques)
        analysis.threat_level = self._extract_threat_level(analysis.threat_assessment)

        return analysis

    def _sort_techniques(self, techniques: List[Dict]) -> List[Dict]:
        """Order techniques so the most trustworthy appear first:
        verified (real ATT&CK IDs) before unverified, then by confidence."""
        def key(t):
            conf = _CONFIDENCE_RANK.get(str(t.get('confidence', '')).lower(), 0)
            return (0 if t.get('verified') else 1, -conf)
        return sorted(techniques, key=key)

    def _extract_techniques(self, mitre_text: str) -> List[Dict]:
        """Extract MITRE techniques from LLM reasoning."""
        techniques = []

        if not mitre_text:
            return techniques

        lines = mitre_text.split('\n')
        current_technique = {}

        for line in lines:
            line = line.strip()

            if 'Technique ID:' in line or 'ID:' in line:
                if current_technique and 'id' in current_technique:
                    techniques.append(current_technique)
                current_technique = {'id': line.split(':')[1].strip()}

            elif 'Name:' in line:
                current_technique['name'] = line.split(':', 1)[1].strip()

            elif 'Tactic:' in line:
                current_technique['tactic'] = line.split(':', 1)[1].strip()

            elif 'Confidence:' in line:
                current_technique['confidence'] = line.split(':', 1)[1].strip()

            elif 'Reasoning:' in line:
                current_technique['reasoning'] = line.split(':', 1)[1].strip()

        if current_technique and 'id' in current_technique:
            techniques.append(current_technique)

        # Validate every technique against the real MITRE ATT&CK reference and
        # enrich verified ones with canonical name/tactic. This catches the
        # model's invented IDs (e.g. T1900) instead of presenting them as fact.
        return [self._validate_technique(t) for t in techniques]

    def _validate_technique(self, tech: Dict) -> Dict:
        """Check a technique's ID against the ATT&CK reference; flag and enrich."""
        raw = tech.get('id', '')
        m = re.search(r'T\d{4}(?:\.\d{3})?', raw)
        if not m:
            tech['verified'] = False
            return tech

        tech_id = m.group(0)
        base_id = tech_id.split('.')[0]
        tech['id'] = tech_id  # store the cleaned ID

        # Valid if the exact (sub)technique or its base technique is known.
        info = self.mitre_framework.get_technique_info(tech_id) \
            or self.mitre_framework.get_technique_info(base_id)
        tech['verified'] = bool(info)

        # For verified techniques, trust the canonical name/tactic over the
        # model's (which is sometimes slightly wrong).
        if info:
            tech['name'] = info.get('name', tech.get('name', 'Unknown'))
            tech['tactic'] = info.get('tactic', tech.get('tactic', 'N/A'))

        return tech

    def _extract_threat_level(self, threat_text: str) -> int:
        """Extract numeric threat level from assessment."""
        if not threat_text:
            return 5

        # Look for a number between 1-10
        for word in threat_text.split():
            try:
                num = int(word)
                if 1 <= num <= 10:
                    return num
            except ValueError:
                pass

        # Default to medium if not found
        return 5

    def generate_narrative_report(self, analysis: IncidentAnalysis) -> str:
        """Generate a narrative incident report from analysis."""
        report = """
╔════════════════════════════════════════════════════════════════════════════╗
║                      AI SOC COPILOT ANALYSIS REPORT                        ║
╚════════════════════════════════════════════════════════════════════════════╝

INCIDENT ANALYSIS
─────────────────────────────────────────────────────────────────────────────
"""
        report += analysis.initial_analysis + "\n\n"

        report += """
ATTACK CORRELATIONS & PATTERNS
─────────────────────────────────────────────────────────────────────────────
"""
        report += analysis.correlations + "\n\n"

        report += """
MITRE ATT&CK FRAMEWORK MAPPING
─────────────────────────────────────────────────────────────────────────────
"""
        report += analysis.mitre_reasoning + "\n\n"

        report += """
THREAT ASSESSMENT
─────────────────────────────────────────────────────────────────────────────
"""
        report += analysis.threat_assessment + "\n\n"

        report += """
PRIORITIZED ACTIONS FOR SOC
─────────────────────────────────────────────────────────────────────────────
"""
        report += analysis.prioritized_actions + "\n"

        return report
