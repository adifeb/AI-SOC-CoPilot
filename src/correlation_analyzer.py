from typing import List, Dict
from datetime import datetime, timedelta
from src.alert_summarizer import Alert
from src.log_parser import SecurityEvent
from src.llm_client import OllamaClient


class Correlation:
    def __init__(self, alert_ids: List[str], correlation_type: str, description: str, confidence: str = "medium"):
        self.alert_ids = alert_ids
        self.correlation_type = correlation_type  # temporal, source, pattern, semantic
        self.description = description
        self.confidence = confidence  # low, medium, high

    def to_dict(self) -> dict:
        return {
            'alerts': self.alert_ids,
            'type': self.correlation_type,
            'description': self.description,
            'confidence': self.confidence,
        }


class CorrelationAnalyzer:
    def __init__(self, llm_client: OllamaClient, time_window_minutes: int = 60):
        self.llm_client = llm_client
        # Temporal window for clustering events into the same burst/phase.
        # Cross-phase links across a multi-day campaign come from source/IOC
        # and semantic correlation, which are time-independent.
        self.time_window = timedelta(minutes=time_window_minutes)

    def correlate_events(self, alerts: List[Alert]) -> List[Correlation]:
        """Find relationships between alerts."""
        if len(alerts) < 2:
            return []

        correlations = []

        # 1. Temporal correlations (events close in time)
        correlations.extend(self._find_temporal_patterns(alerts))

        # 2. Source correlations (same source IP/system)
        correlations.extend(self._find_source_patterns(alerts))

        # 3. Event pattern correlations
        correlations.extend(self._find_pattern_correlations(alerts))

        # 4. Semantic correlations (ask LLM about relationships)
        if len(alerts) <= 10:  # Only for reasonable number of alerts
            correlations.extend(self._find_semantic_correlations(alerts))

        return correlations

    def _find_temporal_patterns(self, alerts: List[Alert]) -> List[Correlation]:
        """Find events that occurred close in time."""
        correlations = []

        window_min = self.time_window.total_seconds() / 60

        for i, alert1 in enumerate(alerts):
            for alert2 in alerts[i + 1:]:
                # Prefer the normalized datetime (correct across all log
                # formats); fall back to parsing the raw string.
                time1 = alert1.events[0].dt or self._parse_timestamp(alert1.events[0].timestamp)
                time2 = alert2.events[0].dt or self._parse_timestamp(alert2.events[0].timestamp)

                if time1 and time2:
                    time_diff = abs((time1 - time2).total_seconds() / 60)

                    if time_diff <= window_min:
                        confidence = "high" if time_diff < 5 else "medium"
                        correlation = Correlation(
                            alert_ids=[alert1.alert_id, alert2.alert_id],
                            correlation_type="temporal",
                            description=f"Events occurred {int(time_diff)} minutes apart",
                            confidence=confidence
                        )
                        correlations.append(correlation)

        return correlations

    def _find_source_patterns(self, alerts: List[Alert]) -> List[Correlation]:
        """Find events from the same source."""
        correlations = []
        source_groups = {}

        for alert in alerts:
            for event in alert.events:
                source = event.source
                if source not in source_groups:
                    source_groups[source] = []
                source_groups[source].append(alert.alert_id)

        # If multiple alerts from same source
        for source, alert_ids in source_groups.items():
            if len(set(alert_ids)) > 1:
                correlation = Correlation(
                    alert_ids=list(set(alert_ids)),
                    correlation_type="source",
                    description=f"Multiple alerts from same source: {source}",
                    confidence="high"
                )
                correlations.append(correlation)

        return correlations

    def _find_pattern_correlations(self, alerts: List[Alert]) -> List[Correlation]:
        """Find alerts with related event types."""
        correlations = []
        event_type_groups = {}

        for alert in alerts:
            for event in alert.events:
                event_type = event.event_type
                if event_type not in event_type_groups:
                    event_type_groups[event_type] = []
                event_type_groups[event_type].append(alert.alert_id)

        # Look for related patterns
        brute_force_types = ['brute_force_attempt', 'authentication_failure']
        sqli_types = ['sql_injection']
        persistence_types = ['service_start', 'privilege_escalation']

        pattern_groups = {
            'brute_force': brute_force_types,
            'web_attack': sqli_types,
            'persistence': persistence_types,
        }

        for pattern_name, types in pattern_groups.items():
            found_types = [t for t in types if t in event_type_groups]
            if len(found_types) > 1:
                all_alerts = set()
                for t in found_types:
                    all_alerts.update(event_type_groups[t])

                if len(all_alerts) > 1:
                    correlation = Correlation(
                        alert_ids=list(all_alerts),
                        correlation_type="pattern",
                        description=f"Multiple events indicating {pattern_name}",
                        confidence="high"
                    )
                    correlations.append(correlation)

        return correlations

    def _find_semantic_correlations(self, alerts: List[Alert]) -> List[Correlation]:
        """Use LLM to find semantic relationships."""
        correlations = []

        # Build context
        alert_summaries = "\n".join([
            f"{alert.alert_id}: {alert.summary}"
            for alert in alerts
        ])

        prompt = f"""Analyze these security alerts and identify if they represent a coordinated attack or single incident:

{alert_summaries}

Identify:
1. Are these events related? How?
2. Is there an attack progression (e.g., initial access -> privilege escalation -> data exfiltration)?
3. Are multiple alerts part of the same attack campaign?

Response:"""

        response = self.llm_client.generate(prompt)
        if response:
            # Create a correlation for the overall incident
            correlation = Correlation(
                alert_ids=[a.alert_id for a in alerts],
                correlation_type="semantic",
                description=response,
                confidence="medium"
            )
            correlations.append(correlation)

        return correlations

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Try to parse various timestamp formats."""
        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S %z",
            "%b %d %H:%M:%S",
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                # Convert to naive datetime (remove timezone info for comparison)
                if dt.tzinfo is not None:
                    dt = dt.replace(tzinfo=None)
                return dt
            except ValueError:
                continue

        return None

    def get_attack_chain(self, correlations: List[Correlation]) -> List[str]:
        """Extract likely attack chain from correlations."""
        attack_chain = []

        # Look for semantic correlations which might have chain info
        for corr in correlations:
            if corr.correlation_type == "semantic":
                # Could extract chain from LLM response
                attack_chain.append(corr.description)

        return attack_chain

    def summarize_correlations(self, correlations: List[Correlation]) -> str:
        """Generate a summary of all correlations."""
        if not correlations:
            return "No significant correlations found between alerts."

        summary = f"Found {len(correlations)} correlations:\n\n"

        # Group by type
        by_type = {}
        for corr in correlations:
            if corr.correlation_type not in by_type:
                by_type[corr.correlation_type] = []
            by_type[corr.correlation_type].append(corr)

        for corr_type, corrs in by_type.items():
            summary += f"{corr_type.upper()} CORRELATIONS:\n"
            for corr in corrs:
                summary += f"  • {', '.join(corr.alert_ids)}: {corr.description}\n"
            summary += "\n"

        return summary
