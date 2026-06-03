import csv
import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional
from pathlib import Path


@dataclass
class SecurityEvent:
    timestamp: str
    source: str
    event_type: str
    severity: str
    description: str
    raw_message: str
    log_source: str  # 'windows', 'syslog', 'apache'
    # Normalized timestamp (naive UTC) for correct cross-source chronological
    # sorting. Populated by LogParser after all events are read. None if the
    # timestamp could not be parsed.
    dt: Optional[datetime] = None


def normalize_timestamp(ts: str, log_source: str, default_year: int) -> Optional[datetime]:
    """Convert a source-specific timestamp string into a naive UTC datetime.

    Handles the three formats the tool ingests:
      - Windows / ISO : 2025-05-31T10:30:05Z
      - Apache        : 31/May/2025:10:00:12 +0000
      - syslog        : May 31 10:02:11   (no year -> default_year)
    """
    ts = (ts or "").strip()
    if not ts:
        return None

    # ISO 8601 (Windows events)
    if "T" in ts:
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            pass

    # Apache combined-log timestamp (with or without timezone)
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=None)
        except ValueError:
            pass

    # syslog (no year in the line) -> apply the inferred default year
    try:
        return datetime.strptime(ts, "%b %d %H:%M:%S").replace(year=default_year)
    except ValueError:
        pass

    return None


class LogParser:
    def parse_windows_csv(self, filepath: str) -> List[SecurityEvent]:
        """Parse Windows Event Log CSV format."""
        events = []
        try:
            with open(filepath, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    event = SecurityEvent(
                        timestamp=row.get('timestamp', ''),
                        source=row.get('source', 'unknown'),
                        event_type=f"EventID-{row.get('event_id', 'unknown')}",
                        severity=row.get('severity', 'medium').lower(),
                        description=row.get('description', ''),
                        raw_message=str(row),
                        log_source='windows'
                    )
                    events.append(event)
        except Exception as e:
            print(f"Error parsing Windows log: {e}")
        return events

    def parse_syslog(self, filepath: str) -> List[SecurityEvent]:
        """Parse standard syslog format."""
        events = []
        syslog_pattern = r'(\w+ \d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.*)'

        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    match = re.match(syslog_pattern, line)
                    if match:
                        timestamp_str = match.group(1)
                        hostname = match.group(2)
                        process = match.group(3)
                        message = match.group(5)

                        # Determine event type and severity
                        event_type = self._classify_syslog_event(message)
                        severity = self._classify_syslog_severity(message)

                        event = SecurityEvent(
                            timestamp=timestamp_str,
                            source=hostname,
                            event_type=event_type,
                            severity=severity,
                            description=message,
                            raw_message=line,
                            log_source='syslog'
                        )
                        events.append(event)
        except Exception as e:
            print(f"Error parsing Syslog: {e}")
        return events

    def parse_apache_log(self, filepath: str) -> List[SecurityEvent]:
        """Parse Apache combined access log format."""
        events = []
        # Combined log format: IP - - [timestamp] "REQUEST" STATUS SIZE "REFERER" "USER_AGENT"
        apache_pattern = r'(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"'

        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    match = re.match(apache_pattern, line)
                    if match:
                        ip = match.group(1)
                        timestamp_str = match.group(2)
                        request = match.group(3)
                        status_code = int(match.group(4))
                        size = match.group(5)
                        user_agent = match.group(7)

                        # Classify suspicious requests
                        event_type = self._classify_http_request(request, status_code)
                        severity = self._classify_http_severity(request, status_code)

                        event = SecurityEvent(
                            timestamp=timestamp_str,
                            source=ip,
                            event_type=event_type,
                            severity=severity,
                            description=f"HTTP {request} -> {status_code}",
                            raw_message=line,
                            log_source='apache'
                        )
                        events.append(event)
        except Exception as e:
            print(f"Error parsing Apache log: {e}")
        return events

    def _classify_syslog_event(self, message: str) -> str:
        """Classify syslog message into event type."""
        msg = message.lower()
        if 'failed password' in msg or 'invalid user' in msg:
            return 'brute_force_attempt'
        elif 'rsync' in msg or '/etc/shadow' in msg or ':/exfil' in msg:
            return 'data_exfiltration'
        elif ('curl' in msg or 'wget' in msg) and ('bash' in msg or 'beacon' in msg):
            return 'c2_beacon'
        elif 'accepted password' in msg:
            return 'successful_login'
        elif 'sudo' in msg or 'command=' in msg:
            return 'privilege_escalation'
        elif 'denied' in msg or 'apparmor' in msg:
            return 'access_denied'
        elif 'kernel panic' in msg:
            return 'system_failure'
        elif 'connection from' in msg:
            return 'remote_connection'
        elif 'started' in msg:
            return 'service_start'
        else:
            return 'system_event'

    def _classify_syslog_severity(self, message: str) -> str:
        """Classify syslog severity."""
        msg = message.lower()
        if ('rsync' in msg or ':/exfil' in msg or 'kernel panic' in msg
                or (('curl' in msg or 'wget' in msg) and ('bash' in msg or 'beacon' in msg))):
            return 'critical'
        elif ('accepted password' in msg or 'failed password' in msg
              or 'sudo' in msg or 'command=' in msg):
            return 'high'
        elif 'denied' in msg or 'connection from' in msg:
            return 'medium'
        else:
            return 'low'

    def _classify_http_request(self, request: str, status_code: int) -> str:
        """Classify HTTP request type."""
        rl = request.lower()
        if 'union' in rl or 'select' in rl or '--' in request:
            return 'sql_injection'
        elif '..' in request or '\\' in request or '%2e%2e' in rl:
            return 'path_traversal'
        elif 'shell.php' in rl or 'cmd=' in rl:
            return 'webshell_access'
        elif status_code == 401:
            return 'authentication_failure'
        elif status_code == 403:
            return 'authorization_failure'
        elif status_code >= 500:
            return 'server_error'
        else:
            return 'normal_request'

    def _classify_http_severity(self, request: str, status_code: int) -> str:
        """Classify HTTP request severity."""
        rl = request.lower()
        if 'union' in rl or 'select' in rl:
            return 'critical'
        elif 'shell.php' in rl or 'cmd=' in rl:
            return 'high'
        elif '..' in request or '\\' in request:
            return 'high'
        elif 'sqlmap' in rl:
            return 'high'
        elif status_code == 401:
            return 'medium'
        elif status_code >= 500:
            return 'medium'
        else:
            return 'low'

    def parse_logs(self, log_dir: str = '.') -> List[SecurityEvent]:
        """Parse all log files in a directory."""
        all_events = []
        log_dir = Path(log_dir)

        # Parse Windows logs
        windows_file = log_dir / 'windows_events.csv'
        if windows_file.exists():
            all_events.extend(self.parse_windows_csv(str(windows_file)))

        # Parse Syslog
        syslog_file = log_dir / 'syslog.txt'
        if syslog_file.exists():
            all_events.extend(self.parse_syslog(str(syslog_file)))

        # Parse Apache logs
        apache_file = log_dir / 'apache_access.log'
        if apache_file.exists():
            all_events.extend(self.parse_apache_log(str(apache_file)))

        # Normalize every timestamp to a real datetime so the merged timeline
        # is truly chronological across the three formats (not raw string sort).
        # syslog lines carry no year, so infer one from the dated sources.
        years = re.findall(r'\b(20\d{2})\b', ' '.join(e.timestamp for e in all_events))
        default_year = int(max(years)) if years else datetime.now().year

        for e in all_events:
            e.dt = normalize_timestamp(e.timestamp, e.log_source, default_year)

        # Sort chronologically; events that failed to parse sort to the end.
        all_events.sort(key=lambda e: (e.dt is None, e.dt or datetime.max))

        return all_events
