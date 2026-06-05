from datetime import timedelta
from typing import Dict, List

from src.log_parser import SecurityEvent


class Alert:
    def __init__(self, alert_id: str, events: List[SecurityEvent]):
        self.alert_id = alert_id
        self.events = events
        self.summary = None
        self.severity = self._determine_severity()

    def _determine_severity(self) -> str:
        """Determine alert severity based on events."""
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        max_severity = 'low'
        max_score = 0

        for event in self.events:
            score = severity_order.get(event.severity, 0)
            if score > max_score:
                max_score = score
                max_severity = event.severity

        return max_severity

    def __repr__(self):
        return f"Alert(id={self.alert_id}, events={len(self.events)}, severity={self.severity})"


class AlertSummarizer:
    def __init__(self, llm_client, time_window_minutes: int = 5):
        # llm_client: OllamaClient or FakeLLMClient (anything with summarize_event)
        self.llm_client = llm_client
        self.time_window = timedelta(minutes=time_window_minutes)

    def group_events(self, events: List[SecurityEvent]) -> List[Alert]:
        """Group related events by time window and source."""
        if not events:
            return []

        alerts = []
        event_groups: Dict[str, List[SecurityEvent]] = {}

        for event in events:
            # Create grouping key: event_type + source
            key = f"{event.event_type}_{event.source}"

            if key not in event_groups:
                event_groups[key] = []

            event_groups[key].append(event)

        # Create alerts from grouped events
        alert_counter = 1
        for _group_key, group_events in event_groups.items():
            alert = Alert(
                alert_id=f"ALERT-{str(alert_counter).zfill(3)}",
                events=group_events
            )
            alerts.append(alert)
            alert_counter += 1

        return alerts

    def summarize_alert(self, alert: Alert) -> str:
        """Generate a summary for an alert using LLM."""
        # Build context from grouped events
        event_count = len(alert.events)
        event_types = set(e.event_type for e in alert.events)
        sources = set(e.source for e in alert.events)
        descriptions = "; ".join([e.description for e in alert.events[:3]])

        # Include the real timestamp(s) so the model never invents a
        # placeholder like "[date]". Show a single time or a range.
        times = [e.timestamp for e in alert.events if e.timestamp]
        if not times:
            time_info = "unknown"
        elif len(set(times)) == 1:
            time_info = times[0]
        else:
            time_info = f"{times[0]} to {times[-1]}"

        context = f"""
Alert: {alert.alert_id}
Severity: {alert.severity}
Time: {time_info}
Event Count: {event_count}
Event Types: {', '.join(event_types)}
Sources: {', '.join(sources)}
Event Details: {descriptions}
"""

        summary = self.llm_client.summarize_event(context.strip())

        if not summary:
            # No fallback by design: this tool is AI-assisted only.
            # If the local model does not respond, stop rather than emit
            # a non-AI summary.
            raise RuntimeError(
                f"LLM did not return a summary for {alert.alert_id}. "
                f"The local Ollama model is required for analysis. "
                f"Ensure Ollama is running and the model is responsive."
            )

        alert.summary = summary
        return summary

    def summarize_alerts(self, alerts: List[Alert]) -> List[Alert]:
        """Generate summaries for all alerts."""
        for alert in alerts:
            self.summarize_alert(alert)
        return alerts

    def to_dict(self, alert: Alert) -> dict:
        """Convert alert to dictionary format."""
        return {
            'id': alert.alert_id,
            'severity': alert.severity,
            'event_count': len(alert.events),
            'summary': alert.summary,
            'event_types': list(set(e.event_type for e in alert.events)),
            'sources': list(set(e.source for e in alert.events)),
            'first_event': alert.events[0].timestamp if alert.events else None,
            'last_event': alert.events[-1].timestamp if alert.events else None,
        }
