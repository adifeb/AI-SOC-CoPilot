"""Attack-path / entity graph construction.

Turns the flat, correlated event stream into an *investigation* view: the
kill-chain stages that actually occurred (in order), the entities involved
(attacker infrastructure, compromised assets, abused accounts), and the
specific events (EVT refs) that evidence each stage. This is fully
deterministic — built from event types and indicators, not the LLM — so it is
reliable regardless of model quality.

Produces, e.g.:

    203.0.113.45 (external)
      -> Reconnaissance        EVT-0001..
      -> Initial Access        SQL injection / path traversal
      -> Execution             webshell on 10.0.0.55
      -> Credential Access     SSH brute-force, MFA tampering
      -> Privilege Escalation  rogue admin account svc_backup
      -> Lateral Movement      WEBSRV-01 -> DC1
      -> Command & Control     beacon to 198.51.100.200
      -> Exfiltration          /etc/shadow -> 198.51.100.200
      -> Impact                shadow-copy deletion, log clearing
"""

from __future__ import annotations

import re
from typing import List

# Kill-chain stages in canonical order.
STAGE_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Credential Access",
    "Privilege Escalation",
    "Lateral Movement",
    "Command & Control",
    "Exfiltration",
    "Impact",
]


def _is_internal_ip(ip: str) -> bool:
    if ip.startswith(("10.", "192.168.", "127.")):
        return True
    if ip.startswith("172."):
        try:
            return 16 <= int(ip.split(".")[1]) <= 31
        except (ValueError, IndexError):
            return False
    return False


def _looks_like_ip(s: str) -> bool:
    return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", s))


def _stage_for(event) -> str | None:
    """Map a single event to a kill-chain stage (or None)."""
    t = (event.event_type or "").lower()
    d = (event.description or "").lower()

    if t in ("sql_injection", "path_traversal"):
        return "Initial Access"
    if t == "webshell_access" or "shell.php" in d:
        return "Execution"
    if t in ("brute_force_attempt", "authentication_failure", "successful_login",
             "identity_login", "cloud_login", "cloud_credential_access", "mfa_tampering"):
        return "Credential Access"
    if t in ("privilege_escalation", "identity_privilege_grant",
             "eventid-4720", "eventid-4732", "eventid-4672"):
        return "Privilege Escalation"
    if t in ("eventid-4625", "eventid-4624", "remote_connection", "network_connection"):
        return "Lateral Movement"
    if t in ("eventid-4688", "defender_execution") or "powershell" in d:
        return "Execution"
    if t == "c2_beacon":
        return "Command & Control"
    if t in ("data_exfiltration", "data_transfer", "cloud_exfiltration"):
        return "Exfiltration"
    if t in ("eventid-1102", "defender_impact") or "vssadmin" in d or "shadow" in d:
        return "Impact"
    if t in ("normal_request", "authorization_failure"):
        return "Reconnaissance"
    return None


def build_attack_graph(events: List) -> dict:
    """Build the entity graph + ordered attack path from the events."""
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
    stages: dict = {}
    attacker, c2, compromised, accounts = set(), set(), set(), set()

    for e in events:
        stage = _stage_for(e)
        # Entities ---------------------------------------------------------
        src = e.source
        if _looks_like_ip(src) and not _is_internal_ip(src):
            if stage in ("Reconnaissance", "Initial Access", "Credential Access"):
                attacker.add(src)
        elif src and not _looks_like_ip(src):
            compromised.add(src)
        elif _looks_like_ip(src) and _is_internal_ip(src):
            compromised.add(src)

        # External IPs referenced in C2 / exfil descriptions = C2 infra.
        if stage in ("Command & Control", "Exfiltration"):
            for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", e.description):
                if not _is_internal_ip(ip):
                    c2.add(ip)

        _ACCT_STOP = {"type", "iamuser", "group", "user", "administrators", "for"}
        for pat in (r"Username=([A-Za-z][\w._-]+)", r"net user ([A-Za-z][\w._-]+)",
                    r"by user \"?([A-Za-z][\w._-]+)", r"target=([A-Za-z][\w._@.-]+)"):
            for acct in re.findall(pat, e.description):
                acct = acct.split("@")[0]
                if len(acct) >= 3 and acct.lower() not in _ACCT_STOP:
                    accounts.add(acct)
        for known in ("svc_backup", "www-data"):
            if known in e.description:
                accounts.add(known)

        # Stage aggregation ------------------------------------------------
        if stage is None:
            continue
        s = stages.setdefault(stage, {"stage": stage, "refs": [], "sources": set(),
                                      "targets": set(), "severity": "low", "detail": ""})
        s["refs"].append(getattr(e, "ref", ""))
        s["sources"].add(src)
        if sev_rank.get(e.severity, 0) > sev_rank.get(s["severity"], 0):
            s["severity"] = e.severity
            s["detail"] = e.description[:120]
        elif not s["detail"]:
            s["detail"] = e.description[:120]

    ordered = []
    for name in STAGE_ORDER:
        if name in stages:
            st = stages[name]
            st["sources"] = sorted(x for x in st["sources"] if x)
            ordered.append(st)

    return {
        "entities": {
            "attacker": sorted(attacker),
            "c2": sorted(c2),
            "compromised": sorted(compromised),
            "accounts": sorted(accounts),
        },
        "stages": ordered,
    }
