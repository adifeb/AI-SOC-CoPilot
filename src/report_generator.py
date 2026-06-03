import json
import re
import html as html_lib
from typing import List, Dict, Optional
from datetime import datetime
from src.log_parser import SecurityEvent


class BasicIncidentReport:
    """Basic incident report with only essential analysis sections."""

    def __init__(self, incident_id: str, analysis: dict = None):
        self.incident_id = incident_id
        self.timestamp = datetime.utcnow().isoformat() + 'Z'
        self.analysis = analysis or {}
        self.events = []
        self.alerts = []
        self.correlations = []
        self.overall_severity = "medium"
        self.threat_level = 5

    def to_dict(self) -> dict:
        """Generate the incident report data model."""
        report = {
            # HEADER / METADATA
            'incident_id': self.incident_id,
            'timestamp': self.timestamp,
            'severity': self.overall_severity,
            'threat_level': self.threat_level,
            'classification': self._derive_classification(),
            'status': 'Open — Under Investigation',
            'detected': self._detection_window(),

            # EXECUTIVE SUMMARY (deterministic, fact-based)
            'executive_summary': self._executive_summary(),

            # AFFECTED ASSETS / SCOPE
            'assets': self._extract_assets(),

            # INDICATORS OF COMPROMISE
            'iocs': self._extract_iocs(),

            # INCIDENT OVERVIEW (LLM narrative)
            'overview': self.analysis.get('initial_analysis', ''),

            # EVENT TIMELINE
            'timeline': [
                {
                    # Use the normalized datetime so every row shares one
                    # clean format; fall back to the raw string if unparsed.
                    'time': (event.dt.strftime('%Y-%m-%d %H:%M:%S')
                             if getattr(event, 'dt', None) else event.timestamp),
                    'source': event.source,
                    'type': event.event_type,
                    'description': event.description,
                }
                for event in self.events
            ],

            # ALERTS
            'alerts': self.alerts,

            # MITRE MAPPING
            'mitre_techniques': self.analysis.get('mitre_techniques', []),

            # THREAT ASSESSMENT
            'threat_assessment': self.analysis.get('threat_assessment', ''),

            # RECOMMENDED ACTIONS
            'actions': self._extract_actions(),
        }

        return report

    # ------------------------------------------------------------------ #
    # Deterministic enrichment (built from parsed events, not the LLM)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_internal_ip(ip: str) -> bool:
        """True for RFC1918 / loopback addresses."""
        if ip.startswith(('10.', '192.168.', '127.')):
            return True
        if ip.startswith('172.'):
            try:
                return 16 <= int(ip.split('.')[1]) <= 31
            except (ValueError, IndexError):
                return False
        return False

    def _detection_window(self) -> str:
        """First → last observed event time."""
        dated = [e.dt for e in self.events if getattr(e, 'dt', None)]
        if not dated:
            return 'unknown'
        start, end = min(dated), max(dated)
        if start.date() == end.date():
            return f"{start.strftime('%Y-%m-%d %H:%M')} – {end.strftime('%H:%M UTC')}"
        return (f"{start.strftime('%Y-%m-%d %H:%M')} – "
                f"{end.strftime('%Y-%m-%d %H:%M UTC')} ({(end - start).days}d dwell)")

    def _derive_classification(self) -> str:
        """Classify the incident from the event types observed."""
        types = set(e.event_type for e in self.events)
        descs = " ".join(e.description.lower() for e in self.events)
        if any('exfil' in t for t in types) or 'shadow' in descs:
            return 'Data Breach / Exfiltration'
        if 'c2_beacon' in types:
            return 'Active Intrusion (Command & Control)'
        if 'webshell_access' in types or 'sql_injection' in types:
            return 'Web Application Intrusion'
        if 'brute_force_attempt' in types:
            return 'Attempted Unauthorized Access'
        return 'Security Incident'

    def _extract_assets(self) -> list:
        """Internal hosts/IPs involved, with event count and max severity."""
        order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'unknown': 0}
        assets = {}
        for e in self.events:
            src = e.source
            is_internal = (not self._looks_like_ip(src)) or self._is_internal_ip(src)
            if not is_internal:
                continue
            a = assets.setdefault(src, {'host': src, 'events': 0, 'severity': 'low'})
            a['events'] += 1
            if order.get(e.severity, 0) > order.get(a['severity'], 0):
                a['severity'] = e.severity
        return sorted(assets.values(), key=lambda a: -order.get(a['severity'], 0))

    @staticmethod
    def _looks_like_ip(s: str) -> bool:
        return bool(re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', s))

    def _extract_iocs(self) -> dict:
        """Pull structured indicators of compromise from the event descriptions."""
        external_ips, urls, accounts, artifacts = set(), set(), set(), set()

        account_patterns = [
            r'invalid user (\w[\w._-]*)',
            r'[Aa]ccepted password for (\w[\w._-]*)',
            r'Username=(\w[\w._-]*)',
            r'net user (\w[\w._-]*)',
            r'new logon for (\w[\w._-]*)',
            r'cleared by user "?(\w[\w._-]*)',
            r'logon for (\w[\w._-]*) from',
        ]
        artifact_patterns = [
            r'/etc/(?:passwd|shadow)',
            r'\S*shell\.php',
            r'vssadmin\.exe delete shadows[\w /]*',
            r'powershell\.exe -enc \S+',
        ]

        for e in self.events:
            text = e.description
            # Source IP (apache/syslog use the attacker IP as the source).
            if self._looks_like_ip(e.source) and not self._is_internal_ip(e.source):
                external_ips.add(e.source)
            for ip in re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', text):
                if not self._is_internal_ip(ip):
                    external_ips.add(ip)
            for url in re.findall(r'https?://[^\s"|)\\]+', text):
                urls.add(url.rstrip('.'))
            for pat in account_patterns:
                accounts.update(re.findall(pat, text))
            for pat in artifact_patterns:
                artifacts.update(m.strip() for m in re.findall(pat, text))

        accounts.discard('user')
        return {
            'External IPs (attacker / C2)': sorted(external_ips),
            'Malicious URLs': sorted(urls),
            'User accounts': sorted(accounts),
            'Files / artifacts': sorted(artifacts),
        }

    def _executive_summary(self) -> str:
        """One-paragraph, fact-based summary built from the parsed data."""
        dated = [e.dt for e in self.events if getattr(e, 'dt', None)]
        sources = sorted(set(e.log_source for e in self.events))
        iocs = self._extract_iocs()
        ext = ", ".join(iocs['External IPs (attacker / C2)']) or 'unknown source'
        assets = ", ".join(a['host'] for a in self._extract_assets()[:4]) or 'unknown'
        n_crit = sum(1 for a in self.alerts if str(a.get('severity', '')).lower() == 'critical')
        n_high = sum(1 for a in self.alerts if str(a.get('severity', '')).lower() == 'high')

        when = ""
        if dated:
            start, end = min(dated), max(dated)
            span = (f"between {start.strftime('%Y-%m-%d %H:%M')} and "
                    f"{end.strftime('%Y-%m-%d %H:%M UTC')}")
            if (end - start).days >= 1:
                span += f" (a {(end - start).days}-day dwell time)"
            when = span

        return (
            f"{self._derive_classification()} detected across {len(self.events)} events "
            f"from {len(sources)} log sources ({', '.join(sources)}) {when}. "
            f"The activity originated from {ext} and affected {assets}. "
            f"Overall severity is assessed as {self.overall_severity.upper()} "
            f"(threat level {self.threat_level}/10), comprising {n_crit} critical and "
            f"{n_high} high-severity alerts. The incident remains under investigation."
        )

    def to_json(self) -> str:
        """Convert to comprehensive JSON string (untruncated)."""
        return json.dumps(self.to_dict(), indent=2)

    def save_json(self, filepath: str):
        """Save as JSON file."""
        with open(filepath, 'w') as f:
            f.write(self.to_json())
        print(f"Report saved: {filepath}")

    def save_txt(self, filepath: str):
        """Save as TXT file (full version with all information)."""
        with open(filepath, 'w') as f:
            f.write(self.to_markdown(full=True))
        print(f"Report saved: {filepath}")

    def save_both(self, base_filename: str):
        """Save both JSON and TXT versions (both with full information)."""
        json_file = base_filename if base_filename.endswith('.json') else base_filename.replace('.txt', '.json')
        txt_file = base_filename if base_filename.endswith('.txt') else base_filename.replace('.json', '.txt')

        print(f"Saving comprehensive reports...")
        self.save_json(json_file)
        self.save_txt(txt_file)
        print(f"\nBoth formats saved with FULL information:")
        print(f"  JSON: {json_file}")
        print(f"  TXT:  {txt_file}")

    # ------------------------------------------------------------------ #
    # HTML report (black & white base, color reserved for severity signal)
    # ------------------------------------------------------------------ #

    # All functional color lives here. Swap these for greys to go monochrome.
    _SEV_COLORS = {
        'critical': '#b00020',  # red
        'high':     '#d35400',  # orange
        'medium':   '#b8860b',  # amber
        'low':      '#2e7d32',  # green
        'unknown':  '#555555',  # grey
    }

    def _sev(self, severity: str) -> str:
        """Normalize a severity string to a known key."""
        s = (severity or 'unknown').lower()
        return s if s in self._SEV_COLORS else 'unknown'

    def _esc(self, text) -> str:
        """HTML-escape any value (logs contain <, &, quotes, ../, etc.)."""
        return html_lib.escape(str(text if text is not None else ''))

    def _css(self) -> str:
        """Embedded stylesheet: black-and-white base, color only for severity."""
        sev_rules = "\n".join(
            f"        .sev-{k} {{ color: #fff; background: {v}; }}"
            for k, v in self._SEV_COLORS.items()
        )
        return f"""
    <style>
        :root {{ --ink: #111; --paper: #fff; --muted: #666; --hair: #e2e2e2; --soft: #f7f7f7; }}
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
            color: var(--ink); background: #e9e9ec; margin: 0; padding: 2rem;
            line-height: 1.55; -webkit-print-color-adjust: exact; print-color-adjust: exact;
        }}
        .page {{
            max-width: 960px; margin: 0 auto; background: var(--paper);
            box-shadow: 0 1px 5px rgba(0,0,0,.18);
        }}
        .classification {{
            background: var(--ink); color: #fff; text-align: center; font-size: .68rem;
            letter-spacing: .2em; text-transform: uppercase; padding: .4rem;
        }}
        header.report-head {{ background: var(--ink); color: #fff; padding: 1.75rem 2.25rem; }}
        header.report-head h1 {{ margin: 0 0 .3rem; font-size: 1.55rem; letter-spacing: .01em; }}
        header.report-head .sub {{ color: #b9b9b9; font-size: .78rem; text-transform: uppercase;
                                    letter-spacing: .14em; }}
        .meta {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: .3rem 2.5rem;
                 margin-top: 1.1rem; font-size: .8rem; color: #ddd; }}
        .meta span.k {{ color: #8c8c8c; display: inline-block; min-width: 6.5rem; }}
        .content {{ padding: 1.5rem 2.25rem 2.5rem; counter-reset: sec; }}

        /* executive dashboard */
        .dashboard {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1px; background: var(--hair); border: 1px solid var(--hair); margin: .5rem 0 1rem;
        }}
        .stat {{ background: var(--paper); padding: .9rem 1.1rem; }}
        .stat .label {{ font-size: .66rem; text-transform: uppercase; letter-spacing: .09em;
                        color: var(--muted); margin-bottom: .4rem; }}
        .stat .value {{ font-size: 1.7rem; font-weight: 700; line-height: 1; }}
        .stat .value small {{ font-size: .85rem; color: var(--muted); font-weight: 600; }}
        .sevbreak {{ margin-top: .55rem; display: flex; flex-wrap: wrap; gap: .25rem .7rem;
                     font-size: .7rem; color: var(--muted); }}
        .sevbreak span {{ white-space: nowrap; }}
        .dot {{ display: inline-block; width: .6rem; height: .6rem; border-radius: 50%;
                vertical-align: middle; margin-right: .25rem; }}

        h2.section {{
            counter-increment: sec; font-size: 1.02rem; text-transform: uppercase;
            letter-spacing: .06em; border-bottom: 2px solid var(--ink); padding-bottom: .35rem;
            margin: 2.25rem 0 1rem;
        }}
        h2.section::before {{ content: counter(sec) ".\\00a0\\00a0"; color: var(--muted); }}
        p.body {{ margin: 0 0 1rem; text-align: justify; }}
        .badge {{
            display: inline-block; font-size: .72rem; font-weight: 700; letter-spacing: .05em;
            padding: .12rem .5rem; border-radius: 3px; text-transform: uppercase;
            vertical-align: middle;
        }}
        .badge.lg {{ font-size: 1rem; padding: .25rem .7rem; }}
{sev_rules}
        table {{ width: 100%; border-collapse: collapse; font-size: .84rem; }}
        thead th {{ position: sticky; top: 0; background: var(--ink); color: #fff; }}
        th, td {{ text-align: left; padding: .45rem .6rem; border-bottom: 1px solid var(--hair);
                  vertical-align: top; }}
        th {{ text-transform: uppercase; font-size: .7rem; letter-spacing: .05em; }}
        tbody tr:nth-child(even) {{ background: var(--soft); }}
        table.ioc td.ioc-cat {{ font-weight: 600; white-space: nowrap;
                                width: 230px; vertical-align: top; }}
        table.ioc td.mono {{ line-height: 1.7; }}
        td.mono, .mono {{ font-family: "SF Mono", Consolas, monospace; font-size: .8rem; }}
        .alert {{ border: 1px solid var(--hair); border-left: 5px solid var(--ink);
                  padding: .75rem 1rem; margin: 0 0 .7rem; background: var(--paper); }}
        .alert .top {{ display: flex; align-items: center; gap: .6rem; margin-bottom: .4rem; }}
        .alert .id {{ font-weight: 700; font-family: "SF Mono", Consolas, monospace; }}
        .alert .count {{ color: var(--muted); font-size: .78rem; margin-left: auto; }}
        .alert .summary {{ font-size: .9rem; }}
        .alert .src {{ color: var(--muted); font-size: .76rem; margin-top: .4rem; }}
        .alert .src b {{ color: var(--ink); }}
        .tech {{ border: 1px solid var(--hair); border-top: 3px solid var(--ink);
                 padding: .75rem 1rem; margin: 0 0 .7rem; }}
        .tech .hd {{ font-weight: 700; margin-bottom: .4rem; font-size: .95rem; }}
        .tech .tid {{ font-family: "SF Mono", Consolas, monospace; }}
        .tech .tags {{ margin-bottom: .4rem; }}
        .chip {{ display: inline-block; font-size: .68rem; letter-spacing: .03em;
                 padding: .1rem .55rem; border: 1px solid var(--ink); border-radius: 99px;
                 margin-right: .35rem; }}
        .chip.muted {{ border-color: var(--hair); color: var(--muted); }}
        .chip.ok {{ border-color: #2e7d32; color: #2e7d32; }}
        .chip.warn {{ border-color: #b00020; color: #b00020; }}
        .tech .reason {{ font-size: .85rem; color: #333; }}
        .tech .reason b {{ color: var(--ink); }}
        .meter {{ height: 12px; background: #eee; border: 1px solid var(--ink);
                  border-radius: 2px; overflow: hidden; margin-top: .5rem; }}
        .meter > span {{ display: block; height: 100%; }}
        ol.actions {{ margin: 0; padding-left: 1.25rem; }}
        ol.actions li {{ margin-bottom: .7rem; }}
        ol.rich {{ margin: .35rem 0 1rem; padding-left: 1.4rem; }}
        ol.rich li {{ margin-bottom: .55rem; text-align: justify; }}
        footer.report-foot {{ border-top: 2px solid var(--ink); padding: .9rem 2.25rem;
                              color: var(--muted); font-size: .78rem; text-align: center; }}

        @media print {{
            body {{ background: #fff; padding: 0; }}
            .page {{ box-shadow: none; max-width: none; }}
            thead th {{ position: static; }}
            .alert, .tech, tr, .stat {{ break-inside: avoid; }}
            h2.section {{ break-after: avoid; }}
        }}
    </style>"""

    def _wrap_paragraphs(self, text: str) -> str:
        """Turn a block of text into escaped <p> paragraphs."""
        text = (text or '').strip()
        if not text:
            return '<p class="body"><em>No data returned.</em></p>'
        chunks = [c.strip() for c in text.split('\n\n') if c.strip()] or [text]
        return "\n".join(f'<p class="body">{self._esc(c)}</p>' for c in chunks)

    def _parse_rich_tokens(self, text: str) -> list:
        """Parse loose LLM prose into a flat token stream.

        Handles the list styles models actually emit, run together in one blob:
        numbered ("1. ... 2. ..."), bullet ("* ..." / "• ..."), colon lead-ins,
        and labelled sections ("Alert-001: ..."). Produces tokens:
        {'kind': 'p'|'li', 'text': str, 'header': bool, 'restart': bool}.
        """
        text = (text or '').strip()
        if not text:
            return []

        # Collapse horizontal whitespace but keep newlines as soft boundaries.
        text = re.sub(r'[ \t]+', ' ', text)

        # Put each labelled section / list item on its own line.
        # 1) "Label-001:" headers (after sentence punctuation or at the start)
        text = re.sub(r'(?:(?<=[.:!?])\s+|^)([A-Z][A-Za-z]{1,15}[-\s]?\d{1,4}\s*:)',
                      r'\n\1', text)
        # 2) numbered items ("1. ", "12. ")
        text = re.sub(r'(?:(?<=[.:!?])\s+|^)(\d{1,2}\.\s+)', r'\n\1', text)
        # 3) bullet items ("* ", "• ")
        text = re.sub(r'\s+([*•]\s+)', r'\n\1', text)

        tokens = []
        for raw in text.split('\n'):
            ln = raw.strip()
            if not ln:
                continue
            m_num = re.match(r'^(\d{1,2})\.\s+(.*)$', ln)
            m_bul = re.match(r'^[*•]\s+(.*)$', ln)
            if m_num:
                tokens.append({'kind': 'li', 'text': m_num.group(2).strip(),
                               'header': False, 'restart': m_num.group(1) == '1'})
            elif m_bul:
                tokens.append({'kind': 'li', 'text': m_bul.group(1).strip(),
                               'header': False, 'restart': False})
            else:
                is_header = bool(re.match(r'^[A-Z][A-Za-z]{1,15}[-\s]?\d{1,4}\s*:', ln))
                tokens.append({'kind': 'p', 'text': ln,
                               'header': is_header, 'restart': False})

        # Peel a trailing "Sentence. Lead-in:" off list items so an embedded
        # lead-in starts a fresh block instead of hiding inside a bullet.
        final = []
        for t in tokens:
            if t['kind'] == 'li':
                mc = re.match(r'^(.*[.!?])\s+([A-Z][^.!?]{0,80}:)\s*$', t['text'])
                if mc:
                    t['text'] = mc.group(1).strip()
                    final.append(t)
                    final.append({'kind': 'p', 'text': mc.group(2).strip(),
                                  'header': False, 'restart': False})
                    continue
            final.append(t)
        return final

    def _render_tokens(self, tokens: list) -> str:
        """Render a token stream into HTML (grouping items into <ol>)."""
        out = []
        open_list = False
        for i, t in enumerate(tokens):
            if t['kind'] == 'p':
                if open_list:
                    out.append('</ol>')
                    open_list = False
                txt = self._esc(t['text'])
                if t.get('header'):
                    out.append(f'<p class="body"><strong>{txt}</strong></p>')
                else:
                    out.append(f'<p class="body">{txt}</p>')
            else:  # li
                if open_list and t.get('restart') and i != 0:
                    out.append('</ol>')
                    open_list = False
                if not open_list:
                    out.append('<ol class="rich">')
                    open_list = True
                out.append(f'<li>{self._esc(t["text"])}</li>')
        if open_list:
            out.append('</ol>')
        return "\n".join(out)

    def _format_rich_text(self, text: str) -> str:
        """Format LLM prose as a professional, fully point-wise section.

        Inline numbered lists ("1. ... 2. ... 3. ...") become real <ol>
        lists, and colon-terminated lead-ins (e.g. "business impact could be
        severe:") are promoted to their own lines. Everything stays visible.
        """
        tokens = self._parse_rich_tokens(text)
        if not tokens:
            return '<p class="body"><em>No data returned.</em></p>'
        return self._render_tokens(tokens)

    def to_html(self) -> str:
        """Render the full incident report as a self-contained HTML document."""
        d = self.to_dict()
        sev = self._sev(d['severity'])
        tl = int(d['threat_level']) if str(d['threat_level']).isdigit() else 5
        tl_color = self._SEV_COLORS[
            'critical' if tl >= 8 else 'high' if tl >= 6 else 'medium' if tl >= 3 else 'low'
        ]

        # Readable timestamp: "2026-06-02T15:16:57.97Z" -> "2026-06-02 15:16:57 UTC"
        ts = str(d['timestamp'])
        ts_display = ts.replace('T', ' ').split('.')[0] + ' UTC' if 'T' in ts else ts

        # Dashboard stats.
        n_events = len(d['timeline'])
        n_alerts = len(d['alerts'])
        n_tech = len([t for t in d['mitre_techniques'] if isinstance(t, dict)])
        sev_counts = {}
        for a in d['alerts']:
            k = self._sev(a.get('severity', 'unknown'))
            sev_counts[k] = sev_counts.get(k, 0) + 1
        order = ['critical', 'high', 'medium', 'low', 'unknown']
        sevbreak = "".join(
            f'<span><span class="dot" style="background:{self._SEV_COLORS[k]}"></span>'
            f'{sev_counts[k]} {k}</span>'
            for k in order if sev_counts.get(k)
        ) or '<span>None</span>'

        parts = []
        parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Incident Report {self._esc(d['incident_id'])}</title>
{self._css()}
</head>
<body>
<div class="page">

  <div class="classification">Confidential &middot; SOC Internal</div>

  <header class="report-head">
    <h1>Incident Report &mdash; {self._esc(d['incident_id'])}</h1>
    <div class="sub">AI SOC CoPilot Analysis</div>
    <div class="meta">
      <div><span class="k">Report ID</span> <span class="mono">{self._esc(d['incident_id'])}</span></div>
      <div><span class="k">Classification</span> {self._esc(d['classification'])}</div>
      <div><span class="k">Status</span> {self._esc(d['status'])}</div>
      <div><span class="k">Detected</span> <span class="mono">{self._esc(d['detected'])}</span></div>
      <div><span class="k">Generated</span> <span class="mono">{self._esc(ts_display)}</span></div>
    </div>
  </header>

  <div class="content">

    <div class="dashboard">
      <div class="stat">
        <div class="label">Threat Level</div>
        <div class="value">{tl}<small>/10</small></div>
        <div class="meter"><span style="width:{tl*10}%; background:{tl_color};"></span></div>
      </div>
      <div class="stat">
        <div class="label">Overall Severity</div>
        <div class="value"><span class="badge lg sev-{sev}">{self._esc(d['severity'])}</span></div>
      </div>
      <div class="stat">
        <div class="label">Events Analyzed</div>
        <div class="value">{n_events}</div>
      </div>
      <div class="stat">
        <div class="label">Security Alerts</div>
        <div class="value">{n_alerts}</div>
        <div class="sevbreak">{sevbreak}</div>
      </div>
      <div class="stat">
        <div class="label">MITRE Techniques</div>
        <div class="value">{n_tech}</div>
      </div>
    </div>""")

        # 1. Incident Overview
        parts.append('  <h2 class="section">Incident Overview</h2>')
        parts.append(self._format_rich_text(d['overview']))

        # 2. Event Timeline
        parts.append('  <h2 class="section">Event Timeline</h2>')
        rows = "\n".join(
            f"      <tr><td class='mono'>{self._esc(e['time'][:19])}</td>"
            f"<td>{self._esc(e['source'])}</td>"
            f"<td class='mono'>{self._esc(e['type'])}</td>"
            f"<td>{self._esc(e['description'])}</td></tr>"
            for e in d['timeline']
        )
        parts.append(
            "  <table>\n"
            "    <thead><tr><th>Timestamp</th><th>Source</th><th>Event Type</th><th>Description</th></tr></thead>\n"
            f"    <tbody>\n{rows}\n    </tbody>\n  </table>"
        )

        # 3. Indicators of Compromise
        parts.append('  <h2 class="section">Indicators of Compromise (IOCs)</h2>')
        ioc_rows = ""
        for cat, vals in d['iocs'].items():
            if not vals:
                continue
            cells = "<br>".join(self._esc(v) for v in vals)
            ioc_rows += (f"      <tr><td class='ioc-cat'>{self._esc(cat)}</td>"
                         f"<td class='mono'>{cells}</td></tr>\n")
        if ioc_rows:
            parts.append(
                "  <table class='ioc'>\n"
                "    <thead><tr><th>Type</th><th>Indicator(s)</th></tr></thead>\n"
                f"    <tbody>\n{ioc_rows}    </tbody>\n  </table>"
            )
        else:
            parts.append('<p class="body"><em>No indicators extracted.</em></p>')

        # 4. Affected Assets / Scope
        parts.append('  <h2 class="section">Affected Assets / Scope</h2>')
        asset_rows = ""
        for a in d['assets']:
            asev = self._sev(a['severity'])
            asset_rows += (f"      <tr><td class='mono'>{self._esc(a['host'])}</td>"
                           f"<td>{a['events']}</td>"
                           f"<td><span class='badge sev-{asev}'>{self._esc(a['severity'])}</span></td></tr>\n")
        if asset_rows:
            parts.append(
                "  <table>\n"
                "    <thead><tr><th>Asset</th><th>Events Involved</th><th>Max Severity</th></tr></thead>\n"
                f"    <tbody>\n{asset_rows}    </tbody>\n  </table>"
            )
        else:
            parts.append('<p class="body"><em>No internal assets identified.</em></p>')

        # 5. MITRE ATT&CK Mapping
        parts.append('  <h2 class="section">MITRE ATT&amp;CK Mapping</h2>')
        techs = d['mitre_techniques']
        if not techs:
            parts.append('<p class="body"><em>No techniques identified.</em></p>')
        for t in techs:
            if not isinstance(t, dict):
                continue
            verified = t.get('verified', False)
            # Only flag the problem case; verified is the expected default.
            status_chip = ('' if verified else
                           '<span class="chip warn">&#9888; unverified ID</span>')
            parts.append(f"""  <div class="tech">
    <div class="hd"><span class="tid">[{self._esc(t.get('id', '?'))}]</span> {self._esc(t.get('name', 'Unknown'))}</div>
    <div class="tags">
      <span class="chip">{self._esc(t.get('tactic', 'N/A'))}</span>
      <span class="chip muted">Confidence: {self._esc(t.get('confidence', 'N/A'))}</span>
      {status_chip}
    </div>
    <div class="reason"><b>Reasoning:</b> {self._esc(t.get('reasoning', 'N/A'))}</div>
  </div>""")

        # 6. Impact / Threat Assessment
        parts.append('  <h2 class="section">Impact / Threat Assessment</h2>')
        parts.append(self._format_rich_text(d['threat_assessment']))

        # 7. Recommendations
        parts.append('  <h2 class="section">Recommendations</h2>')
        if d['actions']:
            items = "\n".join(f"    <li>{self._esc(a)}</li>" for a in d['actions'])
            parts.append(f'  <ol class="actions">\n{items}\n  </ol>')
        else:
            parts.append('<p class="body"><em>No actions returned.</em></p>')

        parts.append("""  </div><!-- /content -->
  <footer class="report-foot">End of Report &middot; Generated by AI SOC CoPilot</footer>
</div>
</body>
</html>""")

        return "\n".join(parts)

    def save_html(self, filepath: str):
        """Save the report as a self-contained HTML file."""
        with open(filepath, 'w') as f:
            f.write(self.to_html())
        print(f"Report saved: {filepath}")

    def to_markdown(self, full: bool = True) -> str:
        """Generate professional incident report.

        Args:
            full: If True, include all information. If False, truncate for console display.
        """
        if full:
            return self._to_markdown_full()
        else:
            return self._to_markdown_summary()

    def _to_markdown_summary(self) -> str:
        """Generate summary version for console (truncated)."""
        data = self.to_dict()
        lines = []

        # Header
        lines.append("")
        lines.append("╔" + "═" * 78 + "╗")
        lines.append("║" + f"INCIDENT REPORT: {self.incident_id}".center(78) + "║")
        lines.append("║" + f"AI SOC CoPilot Analysis".center(78) + "║")
        lines.append("╚" + "═" * 78 + "╝")
        lines.append("")

        # Report Metadata
        lines.append(f"  Report ID:      {self.incident_id}")
        lines.append(f"  Report Date:    {self.timestamp}")
        lines.append(f"  Severity:       {self.overall_severity.upper()}")
        lines.append(f"  Threat Level:   {self.threat_level} / 10")
        lines.append("")
        lines.append("─" * 80)
        lines.append("")

        # OVERVIEW (Summary - Continuous paragraph)
        lines.append("INCIDENT OVERVIEW")
        lines.append("")
        overview_text = self._clean_text(data['overview'])
        overview_text = self._truncate_text(overview_text, max_words=100)
        words = overview_text.split()
        current_line = ""
        for word in words:
            if len(current_line) + len(word) + 1 > 76:
                if current_line:
                    lines.append("  " + current_line)
                current_line = word
            else:
                current_line += " " + word if current_line else word
        if current_line:
            lines.append("  " + current_line)
        lines.append("")
        lines.append("─" * 80)
        lines.append("")

        # EVENT TIMELINE
        lines.append("EVENT TIMELINE")
        lines.append("")
        lines.append("  " + "─" * 76)
        lines.append(f"  {'Timestamp':<26} {'Source':<18} {'Event Type':<20}")
        lines.append("  " + "─" * 76)

        for event in data['timeline'][:10]:  # Show first 10 only in summary
            timestamp = event['time'][:19]
            source = event['source']
            event_type = event['type']
            description = event['description']

            lines.append(f"  {timestamp:<26} {source:<18} {event_type:<20}")
            desc_words = description.split()[:15]  # Truncate description
            lines.append(f"  {'':26} └─ {' '.join(desc_words)}...")

        if len(data['timeline']) > 10:
            lines.append(f"  {'':26} └─ ... ({len(data['timeline']) - 10} more events)")

        lines.append("  " + "─" * 76)
        lines.append("")

        # ALERTS (Truncated)
        lines.append("SECURITY ALERTS")
        lines.append("")
        for alert in data['alerts'][:5]:  # Show first 5 only
            lines.append(f"  [{alert.get('id', 'Unknown')}]")
            lines.append(f"    Severity:  {alert.get('severity', 'unknown').upper()}")
            lines.append(f"    Events:    {alert.get('event_count', 0)}")
            summary = self._clean_text(alert.get('summary', 'N/A'))
            summary = self._truncate_text(summary, max_words=25)
            lines.append(f"    Summary:   {summary}")
            lines.append("")

        if len(data['alerts']) > 5:
            lines.append(f"  ... ({len(data['alerts']) - 5} more alerts)")
            lines.append("")

        lines.append("─" * 80)
        lines.append("")

        # MITRE ATT&CK (Truncated)
        lines.append("MITRE ATT&CK TECHNIQUES")
        lines.append("")
        for tech in data['mitre_techniques'][:3]:  # Show first 3 only
            if isinstance(tech, dict):
                marker = "" if tech.get('verified') else "  (unverified ID)"
                lines.append(f"  [{tech.get('id', '?')}] {tech.get('name', 'Unknown')}{marker}")
                lines.append(f"    Tactic:      {tech.get('tactic', 'N/A')}")
                lines.append(f"    Confidence:  {tech.get('confidence', 'N/A')}")
                reasoning = self._clean_text(tech.get('reasoning', 'N/A'))
                reasoning = self._truncate_text(reasoning, max_words=20)
                lines.append(f"    Reasoning:   {reasoning}")
                lines.append("")

        if len(data['mitre_techniques']) > 3:
            lines.append(f"  ... ({len(data['mitre_techniques']) - 3} more techniques)")
            lines.append("")

        lines.append("─" * 80)
        lines.append("")

        # THREAT ASSESSMENT (Summary - Continuous)
        lines.append("THREAT ASSESSMENT")
        lines.append("")
        assessment = self._clean_text(data['threat_assessment'])
        assessment = self._truncate_text(assessment, max_words=80)
        words = assessment.split()
        current_line = ""
        for word in words:
            if len(current_line) + len(word) + 1 > 76:
                if current_line:
                    lines.append("  " + current_line)
                current_line = word
            else:
                current_line += " " + word if current_line else word
        if current_line:
            lines.append("  " + current_line)
        lines.append("")
        lines.append("─" * 80)
        lines.append("")

        # RECOMMENDED ACTIONS
        lines.append("RECOMMENDED ACTIONS")
        lines.append("")
        for i, action in enumerate(data['actions'][:5], 1):
            lines.append(f"  {i}. {action}")
        lines.append("")
        lines.append("╔" + "═" * 78 + "╗")
        lines.append("║" + "View full report in accompanying JSON/TXT files".center(78) + "║")
        lines.append("╚" + "═" * 78 + "╝")
        lines.append("")

        return "\n".join(lines)

    def _to_markdown_full(self) -> str:
        """Generate FULL professional incident report with ALL information (for files)."""
        data = self.to_dict()

        lines = []

        # Header
        lines.append("")
        lines.append("╔" + "═" * 78 + "╗")
        lines.append("║" + f"INCIDENT REPORT: {self.incident_id}".center(78) + "║")
        lines.append("║" + f"AI SOC CoPilot Analysis".center(78) + "║")
        lines.append("╚" + "═" * 78 + "╝")
        lines.append("")

        # Report Metadata
        lines.append(f"  Report ID:      {self.incident_id}")
        lines.append(f"  Report Date:    {self.timestamp}")
        lines.append(f"  Severity:       {self.overall_severity.upper()}")
        lines.append(f"  Threat Level:   {self.threat_level} / 10")
        lines.append("")
        lines.append("─" * 80)
        lines.append("")

        # OVERVIEW (FULL - COMPLETE PARAGRAPH)
        lines.append("INCIDENT OVERVIEW")
        lines.append("")
        overview_text = data['overview']

        # Format as continuous paragraph without truncation
        words = overview_text.split()
        current_line = ""
        for word in words:
            if len(current_line) + len(word) + 1 > 76:
                if current_line:
                    lines.append("  " + current_line)
                current_line = word
            else:
                current_line += " " + word if current_line else word
        if current_line:
            lines.append("  " + current_line)

        lines.append("")
        lines.append("─" * 80)
        lines.append("")

        # EVENT TIMELINE (FULL - ALL EVENTS)
        lines.append("EVENT TIMELINE")
        lines.append("")
        lines.append("  " + "─" * 76)
        lines.append(f"  {'Timestamp':<26} {'Source':<18} {'Event Type':<20}")
        lines.append("  " + "─" * 76)

        for event in data['timeline']:
            timestamp = event['time'][:19]
            source = event['source']
            event_type = event['type']
            description = event['description']

            lines.append(f"  {timestamp:<26} {source:<18} {event_type:<20}")

            # Word wrap description without truncation
            desc_lines = []
            words = description.split()
            current_line = ""
            for word in words:
                if len(current_line) + len(word) + 1 > 70:
                    if current_line:
                        desc_lines.append(current_line)
                    current_line = word
                else:
                    current_line += " " + word if current_line else word
            if current_line:
                desc_lines.append(current_line)

            for desc_line in desc_lines:
                lines.append(f"  {'':26} └─ {desc_line}")

        lines.append("  " + "─" * 76)
        lines.append("")

        # ALERTS (FULL - ALL ALERTS, NO TRUNCATION)
        lines.append("SECURITY ALERTS")
        lines.append("")
        for alert in data['alerts']:
            lines.append(f"  [{alert.get('id', 'Unknown')}]")
            lines.append(f"    Severity:  {alert.get('severity', 'unknown').upper()}")
            lines.append(f"    Events:    {alert.get('event_count', 0)}")
            summary = alert.get('summary', 'N/A')
            lines.append(f"    Summary:   {summary}")
            lines.append(f"    Sources:   {', '.join(alert.get('sources', []))}")
            lines.append("")
        lines.append("─" * 80)
        lines.append("")

        # MITRE ATT&CK (FULL - ALL TECHNIQUES, NO TRUNCATION)
        lines.append("MITRE ATT&CK TECHNIQUES")
        lines.append("")
        for tech in data['mitre_techniques']:
            if isinstance(tech, dict):
                marker = "" if tech.get('verified') else "  (unverified ID)"
                lines.append(f"  [{tech.get('id', '?')}] {tech.get('name', 'Unknown')}{marker}")
                lines.append(f"    Tactic:      {tech.get('tactic', 'N/A')}")
                lines.append(f"    Confidence:  {tech.get('confidence', 'N/A')}")
                reasoning = tech.get('reasoning', 'N/A')
                lines.append(f"    Reasoning:   {reasoning}")
                lines.append("")
        lines.append("─" * 80)
        lines.append("")

        # THREAT ASSESSMENT (FULL - COMPLETE PARAGRAPH)
        lines.append("THREAT ASSESSMENT")
        lines.append("")
        assessment = data['threat_assessment']

        # Format as continuous paragraph without truncation
        words = assessment.split()
        current_line = ""
        for word in words:
            if len(current_line) + len(word) + 1 > 76:
                if current_line:
                    lines.append("  " + current_line)
                current_line = word
            else:
                current_line += " " + word if current_line else word
        if current_line:
            lines.append("  " + current_line)

        lines.append("")
        lines.append("─" * 80)
        lines.append("")

        # RECOMMENDED ACTIONS (FULL - BETTER FORMATTED)
        lines.append("RECOMMENDED ACTIONS")
        lines.append("")

        for i, action in enumerate(data['actions'], 1):
            # Clean up the action text
            action_clean = action.strip().rstrip('-').rstrip()
            lines.append(f"  {i}. {action_clean}")

        lines.append("")
        lines.append("╔" + "═" * 78 + "╗")
        lines.append("║" + "End of Report".center(78) + "║")
        lines.append("╚" + "═" * 78 + "╝")
        lines.append("")

        return "\n".join(lines)

    def save_markdown(self, filepath: str):
        """Save as Markdown file."""
        with open(filepath, 'w') as f:
            f.write(self.to_markdown())
        print(f"Report saved: {filepath}")

    def _extract_actions(self) -> List[str]:
        """Extract immediate actions from prioritized actions."""
        actions_text = self.analysis.get('prioritized_actions', '')
        if not actions_text:
            return []

        actions = []
        for line in actions_text.split('\n'):
            line = line.strip()
            if line and (line[0].isdigit() or line.startswith('-')):
                # Clean up the line - remove numbering
                action = line.lstrip('0123456789.-) ').strip()

                # Handle multiple formats
                # Format 1: "Action - [Why] - [When]"
                if ' - [Why' in action or ' - [When' in action:
                    action = action.split(' - [Why')[0].split(' - [When')[0].strip()
                # Format 2: "Action: details"
                elif action.endswith(':'):
                    action = action.rstrip(':').strip()
                # Format 3: "Action [Why: ...] [When: ...]"
                else:
                    action = action.split('[Why')[0].split('[When')[0].strip()

                if action and len(action) > 5:
                    actions.append(action)

        return actions[:5]  # Top 5 actions

    def _truncate_text(self, text: str, max_words: int = 50) -> str:
        """Truncate text to maximum number of words."""
        words = text.split()
        if len(words) > max_words:
            return ' '.join(words[:max_words]) + '...'
        return text

    def _clean_text(self, text: str) -> str:
        """Clean up verbose LLM output."""
        # Remove excessive whitespace and newlines
        text = ' '.join(text.split())
        # Remove numbered lists formatting if exists
        text = text.replace('1. ', '').replace('2. ', '').replace('3. ', '')
        text = text.replace('4. ', '').replace('5. ', '').replace('6. ', '')
        # Remove asterisks and bullets
        text = text.replace('*', '').replace('•', '')
        return text.strip()
