import csv
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


@dataclass
class SecurityEvent:
    timestamp: str
    source: str
    event_type: str
    severity: str
    description: str
    raw_message: str
    log_source: str  # 'windows', 'syslog', 'apache', 'suricata', 'zeek', ...
    # Normalized timestamp (naive UTC) for correct cross-source chronological
    # sorting. Populated by LogParser after all events are read. None if the
    # timestamp could not be parsed.
    dt: Optional[datetime] = None
    # Stable citation reference (e.g. "EVT-0007"), assigned after sorting, so
    # findings and recommendations can point to the exact supporting event.
    ref: str = ""


def normalize_timestamp(ts: str, log_source: str, default_year: int) -> Optional[datetime]:
    """Convert a source-specific timestamp string into a naive UTC datetime.

    Handles the formats the tool ingests:
      - Windows / ISO     : 2025-05-31T10:30:05Z
      - Suricata/CloudTrail/Okta/Defender ISO with +0000 or fractional seconds
      - Apache            : 31/May/2025:10:00:12 +0000
      - syslog            : May 31 10:02:11   (no year -> default_year)
    """
    ts = (ts or "").strip()
    if not ts:
        return None

    # ISO 8601 (Windows, Suricata, CloudTrail, Okta, Defender)
    if "T" in ts:
        s = ts.replace("Z", "+00:00")
        s = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", s)  # +0000 -> +00:00
        try:
            return datetime.fromisoformat(s).replace(tzinfo=None)
        except ValueError:
            core = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", ts)
            if core:
                return datetime.strptime(core.group(1), "%Y-%m-%dT%H:%M:%S")

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
            with open(filepath) as f:
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
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    match = re.match(syslog_pattern, line)
                    if match:
                        timestamp_str = match.group(1)
                        hostname = match.group(2)
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
            with open(filepath) as f:
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

    # ------------------------------------------------------------------ #
    # Extended SOC formats (Suricata, Zeek, CloudTrail, Okta, Defender)
    # ------------------------------------------------------------------ #

    def parse_suricata_eve(self, filepath: str) -> List[SecurityEvent]:
        """Parse Suricata EVE JSON (newline-delimited JSON IDS alerts)."""
        events = []
        try:
            with open(filepath) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        o = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if o.get('event_type') != 'alert':
                        continue
                    sig = (o.get('alert', {}) or {}).get('signature', 'IDS alert')
                    sl = sig.lower()
                    if 'sql' in sl:
                        etype, sev = 'sql_injection', 'critical'
                    elif 'c2' in sl or 'beacon' in sl or 'trojan' in sl:
                        etype, sev = 'c2_beacon', 'critical'
                    elif 'exfil' in sl or 'data transfer' in sl:
                        etype, sev = 'data_exfiltration', 'high'
                    else:
                        etype, sev = 'ids_alert', 'medium'
                    desc = (f"{sig} ({o.get('src_ip')}:{o.get('src_port')} -> "
                            f"{o.get('dest_ip')}:{o.get('dest_port')} {o.get('proto')})")
                    events.append(SecurityEvent(
                        timestamp=o.get('timestamp', ''), source=o.get('src_ip', 'unknown'),
                        event_type=etype, severity=sev, description=desc,
                        raw_message=line, log_source='suricata'))
        except Exception as e:
            print(f"Error parsing Suricata EVE: {e}")
        return events

    def parse_zeek_conn(self, filepath: str) -> List[SecurityEvent]:
        """Parse a Zeek conn.log (tab-separated, with #fields header)."""
        events = []
        try:
            fields = []
            with open(filepath) as f:
                for line in f:
                    line = line.rstrip('\n')
                    if line.startswith('#fields'):
                        fields = line.split('\t')[1:]
                        continue
                    if line.startswith('#') or not line.strip() or not fields:
                        continue
                    row = dict(zip(fields, line.split('\t')))
                    try:
                        ts = datetime.fromtimestamp(float(row.get('ts', 0)), tz=timezone.utc)
                        ts_str = ts.strftime('%Y-%m-%dT%H:%M:%SZ')
                    except (ValueError, TypeError):
                        ts_str = row.get('ts', '')
                    resp_bytes = int(row.get('resp_bytes', 0) or 0)
                    orig_bytes = int(row.get('orig_bytes', 0) or 0)
                    state = row.get('conn_state', '')
                    if resp_bytes > 1_000_000 or orig_bytes > 1_000_000:
                        etype, sev = 'data_transfer', 'high'
                    elif state == 'REJ':
                        etype, sev = 'connection_rejected', 'medium'
                    else:
                        etype, sev = 'network_connection', 'low'
                    desc = (f"{row.get('proto','')}/{row.get('service','-')} "
                            f"{row.get('id.orig_h')}:{row.get('id.orig_p')} -> "
                            f"{row.get('id.resp_h')}:{row.get('id.resp_p')} "
                            f"({orig_bytes}B sent, {resp_bytes}B recv, {state})")
                    events.append(SecurityEvent(
                        timestamp=ts_str, source=row.get('id.orig_h', 'unknown'),
                        event_type=etype, severity=sev, description=desc,
                        raw_message=line, log_source='zeek'))
        except Exception as e:
            print(f"Error parsing Zeek conn.log: {e}")
        return events

    def parse_cloudtrail(self, filepath: str) -> List[SecurityEvent]:
        """Parse AWS CloudTrail (JSON with a Records array)."""
        events = []
        try:
            with open(filepath) as f:
                data = json.load(f)
            for r in data.get('Records', []):
                name = r.get('eventName', 'AwsApiCall')
                user = (r.get('userIdentity', {}) or {}).get('userName', 'unknown')
                no_mfa = (r.get('additionalEventData', {}) or {}).get('MFAUsed') == 'No'
                if name in ('PutObject', 'GetObject'):
                    etype, sev = 'cloud_exfiltration', 'high'
                elif name in ('GetSecretValue', 'CreateAccessKey', 'CreateUser', 'DeleteTrail'):
                    etype, sev = 'cloud_credential_access', 'high'
                elif name == 'ConsoleLogin':
                    etype, sev = 'cloud_login', ('high' if no_mfa else 'medium')
                else:
                    etype, sev = 'cloud_api_call', 'low'
                rp = r.get('requestParameters') or {}
                detail = ""
                if rp.get('secretId'):
                    detail = f" secret={rp['secretId']}"
                elif rp.get('bucketName'):
                    detail = f" bucket={rp['bucketName']}/{rp.get('key', '')}"
                desc = (f"{name} on {r.get('eventSource', '')} by {user} "
                        f"from {r.get('sourceIPAddress', '')}{detail}"
                        f"{' [no MFA]' if no_mfa else ''}")
                events.append(SecurityEvent(
                    timestamp=r.get('eventTime', ''), source=r.get('sourceIPAddress', 'unknown'),
                    event_type=etype, severity=sev, description=desc,
                    raw_message=json.dumps(r), log_source='cloudtrail'))
        except Exception as e:
            print(f"Error parsing CloudTrail: {e}")
        return events

    def parse_okta(self, filepath: str) -> List[SecurityEvent]:
        """Parse an Okta System Log export (JSON array of events)."""
        events = []
        try:
            with open(filepath) as f:
                data = json.load(f)
            for o in data:
                et = o.get('eventType', 'okta.event')
                actor = (o.get('actor', {}) or {}).get('alternateId', 'unknown')
                ip = (o.get('client', {}) or {}).get('ipAddress', 'unknown')
                if 'mfa' in et and 'deactivate' in et:
                    etype, sev = 'mfa_tampering', 'high'
                elif et == 'user.session.start':
                    etype, sev = 'identity_login', 'medium'
                elif 'membership.add' in et:
                    etype, sev = 'identity_privilege_grant', 'high'
                else:
                    etype, sev = 'identity_event', 'low'
                tgt = o.get('target') or []
                tgt_str = f" target={tgt[0].get('alternateId')}" if tgt else ""
                desc = (f"{et}: {o.get('displayMessage', '')} — actor {actor} "
                        f"from {ip}{tgt_str} [{(o.get('outcome', {}) or {}).get('result', '')}]")
                events.append(SecurityEvent(
                    timestamp=o.get('published', ''), source=ip,
                    event_type=etype, severity=sev, description=desc,
                    raw_message=json.dumps(o), log_source='okta'))
        except Exception as e:
            print(f"Error parsing Okta log: {e}")
        return events

    def parse_defender(self, filepath: str) -> List[SecurityEvent]:
        """Parse Microsoft Defender / MDE alerts (JSON with a value array)."""
        events = []
        try:
            with open(filepath) as f:
                data = json.load(f)
            alerts = data.get('value', data if isinstance(data, list) else [])
            for a in alerts:
                cmd = ""
                for ev in a.get('evidence', []) or []:
                    if ev.get('processCommandLine'):
                        cmd = f" | cmd: {ev['processCommandLine']}"
                        break
                desc = f"{a.get('title', 'Defender alert')}: {a.get('description', '')}{cmd}"
                events.append(SecurityEvent(
                    timestamp=a.get('alertCreationTime', ''),
                    source=a.get('machineId', 'unknown'),
                    event_type=f"defender_{a.get('category', 'alert').lower()}",
                    severity=str(a.get('severity', 'medium')).lower(),
                    description=desc, raw_message=json.dumps(a), log_source='defender'))
        except Exception as e:
            print(f"Error parsing Defender alerts: {e}")
        return events

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

        # Extended SOC formats (network IDS, cloud, identity, EDR).
        for fname, parser in [
            ('suricata_eve.json', self.parse_suricata_eve),
            ('zeek_conn.log', self.parse_zeek_conn),
            ('cloudtrail.json', self.parse_cloudtrail),
            ('okta_system_log.json', self.parse_okta),
            ('defender_alerts.json', self.parse_defender),
        ]:
            fpath = log_dir / fname
            if fpath.exists():
                all_events.extend(parser(str(fpath)))

        # Normalize every timestamp to a real datetime so the merged timeline
        # is truly chronological across the three formats (not raw string sort).
        # syslog lines carry no year, so infer one from the dated sources.
        years = re.findall(r'\b(20\d{2})\b', ' '.join(e.timestamp for e in all_events))
        default_year = int(max(years)) if years else datetime.now().year

        for e in all_events:
            e.dt = normalize_timestamp(e.timestamp, e.log_source, default_year)

        # Sort chronologically; events that failed to parse sort to the end.
        all_events.sort(key=lambda e: (e.dt is None, e.dt or datetime.max))

        # Assign stable citation references in chronological order.
        for i, e in enumerate(all_events, 1):
            e.ref = f"EVT-{i:04d}"

        return all_events
