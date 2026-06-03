import re
from src.log_parser import LogParser
from src.llm_client import OllamaClient
from src.alert_summarizer import AlertSummarizer
from src.incident_analyzer import IncidentAnalyzer
from src.correlation_analyzer import CorrelationAnalyzer
from src.report_generator import BasicIncidentReport


class SOCCoPilot:
    """
    AI-powered Security Operations Center CoPilot.

    Intelligently analyzes security incidents using:
    - Log parsing and event normalization
    - Alert grouping and correlation
    - Multi-turn LLM reasoning for threat analysis
    - MITRE ATT&CK mapping based on understanding
    - Actionable recommendations
    """

    def __init__(self, ollama_url: str = "http://localhost:11434", model: str = "llama2"):
        """Initialize SOC CoPilot with LLM connection."""
        self.llm_client = OllamaClient(base_url=ollama_url, model=model)
        self.log_parser = LogParser()
        self.alert_summarizer = AlertSummarizer(self.llm_client)
        self.incident_analyzer = IncidentAnalyzer(self.llm_client)
        self.correlation_analyzer = CorrelationAnalyzer(self.llm_client)

    def analyze_logs(self, log_dir: str = "./logs") -> dict:
        """Perform complete intelligent incident analysis."""
        print("Analyzing logs...")

        # Phase 1: Parse logs
        events = self.log_parser.parse_logs(log_dir)
        if not events:
            return {}

        # Phase 2: Group into alerts
        alerts = self.alert_summarizer.group_events(events)
        alerts = self.alert_summarizer.summarize_alerts(alerts)

        # Phase 3: Intelligent analysis
        print("Running LLM analysis...")
        incident_analysis = self.incident_analyzer.analyze(events, alerts)

        # Phase 4: Correlation analysis
        correlations = self.correlation_analyzer.correlate_events(alerts)

        # Phase 5: Generate report
        incident_id = self._generate_incident_id(events)
        report = BasicIncidentReport(incident_id, analysis=incident_analysis.to_dict())

        # Populate report data
        report.events = events
        for alert in alerts:
            report.alerts.append({
                'id': alert.alert_id,
                'severity': alert.severity,
                'summary': alert.summary,
                'event_count': len(alert.events),
                'event_types': list(set(e.event_type for e in alert.events)),
                'sources': list(set(e.source for e in alert.events)),
                'mitre_techniques': incident_analysis.mitre_techniques,
            })

        for corr in correlations:
            if hasattr(corr, 'to_dict'):
                report.correlations.append(corr.to_dict())
            else:
                report.correlations.append(corr)

        # Set severity
        report.threat_level = incident_analysis.threat_level
        severity_map = {1: 'low', 2: 'low', 3: 'medium', 4: 'medium', 5: 'medium',
                       6: 'high', 7: 'high', 8: 'critical', 9: 'critical', 10: 'critical'}
        report.overall_severity = severity_map.get(incident_analysis.threat_level, 'medium')

        print(f"Analysis complete: {incident_id}\n")

        # Return comprehensive analysis
        return {
            'incident_id': incident_id,
            'events': events,
            'alerts': alerts,
            'analysis': incident_analysis,
            'correlations': correlations,
            'report': report,
        }

    def generate_narrative_report(self, analysis_results: dict) -> str:
        """Generate a narrative incident report."""
        if not analysis_results:
            return ""

        incident_analyzer = self.incident_analyzer
        analysis = analysis_results['analysis']

        return incident_analyzer.generate_narrative_report(analysis)

    def _generate_incident_id(self, events) -> str:
        """Generate a clean incident ID (INC-YYYYMMDD) from the earliest event."""
        if events:
            e0 = events[0]  # events are sorted chronologically by .dt
            if getattr(e0, 'dt', None):
                return f"INC-{e0.dt.strftime('%Y%m%d')}"
            # Fallback: keep only digits from the raw timestamp.
            digits = re.sub(r'\D', '', e0.timestamp)[:8]
            return f"INC-{digits or 'UNKNOWN'}"
        return "INC-UNKNOWN"

    def _print_summary(self, analysis, correlations, events):
        """Print summary of analysis results."""
        print("=" * 80)
        print("INCIDENT ANALYSIS SUMMARY".center(80))
        print("=" * 80 + "\n")

        print(f"Total Events:              {len(events)}")
        print(f"Threat Level:              {analysis.threat_level}/10")
        print(f"MITRE Techniques Identified: {len(analysis.mitre_techniques)}")
        print(f"Event Correlations Found:  {len(correlations)}")

        if analysis.mitre_techniques:
            print("\nKey Techniques:")
            for tech in analysis.mitre_techniques[:3]:
                print(f"  • {tech.get('id', '?')}: {tech.get('name', 'Unknown')}")

        print("\n" + "=" * 80 + "\n")


# Helper function for CLI usage
def run_copilot_analysis(log_dir: str = "./logs", ollama_url: str = "http://localhost:11434") -> dict:
    """Quick function to run CoPilot analysis."""
    copilot = SOCCoPilot(ollama_url=ollama_url)
    return copilot.analyze_logs(log_dir=log_dir)
