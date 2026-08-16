"""Attacker profiling -- sessions, classification and TTP mapping.

Every event a decoy emits carries a source address. This module folds the
event stream back into per-attacker sessions and answers three questions:

1. *What did this source do?* -- :class:`AttackerProfile` collects the
   services touched, commands issued, credentials attempted and timeline.
2. *What kind of attacker is it?* -- :func:`classify` applies heuristics
   (scanner / brute-forcer / opportunist / exfiltrator / canary-tripper).
3. *Which techniques does the behaviour map to?* -- :func:`map_ttps`
   translates observed sequences into simplified MITRE ATT&CK technique
   ids (T1110 Brute Force, T1046 Network Service Discovery, ...).

Everything is pure computation over event dicts, so it runs against the
live :class:`EventBuffer`, a log file, or a replay stream.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable

#: Seconds of silence that split one source's activity into two sessions.
SESSION_GAP = 300.0

#: Classification thresholds.
BRUTE_FORCE_ATTEMPTS = 3
SCANNER_SERVICE_SPREAD = 3

#: Simplified MITRE ATT&CK mapping: (technique id, name, trigger events).
TTP_RULES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("T1046", "Network Service Discovery",
     ("banner", "connect", "query", "greeting")),
    ("T1110.001", "Brute Force: Password Guessing",
     ("login_attempt", "auth_attempt", "plaintext_password")),
    ("T1078", "Valid Accounts",
     ("login_success",)),
    ("T1003", "OS Credential Dumping",
     ("credential_capture", "file_download")),
    ("T1105", "Ingress Tool Transfer",
     ("download_request", "malware_staging")),
    ("T1059", "Command and Scripting Interpreter",
     ("command",)),
    ("T1048", "Exfiltration Over Alternative Protocol",
     ("message_accepted", "open_relay_abuse")),
    ("T1583.004", "Acquire Infrastructure: Server",
     ("dangerous_command",)),
)


@dataclass
class AttackerProfile:
    """Everything one source IP did across all decoys."""

    ip: str
    first_seen: str = ""
    last_seen: str = ""
    events: int = 0
    services: Counter = field(default_factory=Counter)
    event_types: Counter = field(default_factory=Counter)
    usernames: Counter = field(default_factory=Counter)
    commands: list[str] = field(default_factory=list)
    sessions: int = 1
    max_severity: int = 0
    canary_hits: int = 0

    def observe(self, event: dict[str, Any]) -> None:
        """Fold one event into the profile."""
        from ..core.logger import severity_rank
        ts = str(event.get("ts", ""))
        if not self.first_seen or ts < self.first_seen:
            self.first_seen = ts
        if ts > self.last_seen:
            self.last_seen = ts
        self.events += 1
        self.services[str(event.get("service", "?"))] += 1
        etype = str(event.get("event", "?"))
        self.event_types[etype] += 1
        self.max_severity = max(self.max_severity,
                                severity_rank(str(event.get("severity", "info"))))
        user = event.get("user")
        if isinstance(user, str) and user:
            self.usernames[user] += 1
        if etype == "command" and isinstance(event.get("data"), str):
            if len(self.commands) < 200:
                self.commands.append(event["data"][:120])
        if etype == "canary_hit":
            self.canary_hits += 1

    @property
    def login_attempts(self) -> int:
        return (self.event_types.get("login_attempt", 0) +
                self.event_types.get("auth_attempt", 0) +
                self.event_types.get("plaintext_password", 0))

    @property
    def login_successes(self) -> int:
        return self.event_types.get("login_success", 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "events": self.events,
            "services": dict(self.services),
            "event_types": dict(self.event_types),
            "usernames": dict(self.usernames.most_common(10)),
            "login_attempts": self.login_attempts,
            "login_successes": self.login_successes,
            "canary_hits": self.canary_hits,
            "classification": classify(self),
            "ttps": map_ttps(self),
        }


def classify(profile: AttackerProfile) -> str:
    """Heuristic attacker classification.

    Categories, in priority order:

    * ``canary-tripper`` -- touched a canary token (highest fidelity signal)
    * ``exfiltrator`` -- abused the SMTP relay or downloaded files
    * ``brute-forcer`` -- many credential attempts
    * ``scanner`` -- touched many services with shallow interaction
    * ``opportunist`` -- everything else (single service, few events)
    """
    if profile.canary_hits > 0:
        return "canary-tripper"
    exfil = (profile.event_types.get("open_relay_abuse", 0) +
             profile.event_types.get("message_accepted", 0) +
             profile.event_types.get("file_download", 0) +
             profile.event_types.get("download_request", 0))
    if exfil >= 2:
        return "exfiltrator"
    if profile.login_attempts >= BRUTE_FORCE_ATTEMPTS:
        return "brute-forcer"
    if len(profile.services) >= SCANNER_SERVICE_SPREAD:
        return "scanner"
    return "opportunist"


def map_ttps(profile: AttackerProfile) -> list[dict[str, str]]:
    """Map observed event types to simplified MITRE ATT&CK techniques.

    A rule fires when any of its trigger events appears in the profile.
    Returns ``[{"id", "name"}]`` in rule order (stable for reports).
    """
    seen = set(profile.event_types)
    out = []
    for tech_id, name, triggers in TTP_RULES:
        if any(t in seen for t in triggers):
            out.append({"id": tech_id, "name": name})
    return out


#: src values that mark operational events (decoy lifecycle) rather than
#: attacker traffic; the tracker must not profile them.
NON_ATTACKER_SOURCES = {"-", "?", ""}


def source_ip(event: dict[str, Any]) -> str:
    """Extract the bare source IP from an event's ``src`` field."""
    return str(event.get("src", "?")).split(":")[0]


class AttackerTracker:
    """Folds an event stream into per-IP profiles with session splitting.

    Feed events in chronological order via :meth:`observe` (or bulk via
    :meth:`observe_all`). Sessions are approximated by counting gaps of
    more than ``session_gap`` seconds between consecutive events from the
    same IP (using the ``ts`` strings, which sort chronologically).
    """

    def __init__(self, session_gap: float = SESSION_GAP):
        self.session_gap = session_gap
        self.profiles: dict[str, AttackerProfile] = {}
        self._last_ts: dict[str, str] = {}

    def observe(self, event: dict[str, Any]) -> AttackerProfile | None:
        """Fold one event into its source profile.

        Returns the profile, or None for operational events (decoy
        lifecycle) whose src is a placeholder rather than an address.
        """
        raw_src = str(event.get("src", "?"))
        if raw_src in NON_ATTACKER_SOURCES:
            return None
        ip = source_ip(event)
        profile = self.profiles.get(ip)
        if profile is None:
            profile = AttackerProfile(ip=ip)
            self.profiles[ip] = profile
        else:
            prev = self._last_ts.get(ip, "")
            if prev and _seconds_between(prev, str(event.get("ts", ""))) > self.session_gap:
                profile.sessions += 1
        profile.observe(event)
        self._last_ts[ip] = str(event.get("ts", ""))
        return profile

    def observe_all(self, events: Iterable[dict[str, Any]]) -> int:
        """Fold many events; returns the number actually profiled
        (operational events with placeholder sources are skipped)."""
        count = 0
        for event in events:
            if self.observe(event) is not None:
                count += 1
        return count

    def top(self, n: int = 10) -> list[AttackerProfile]:
        """The ``n`` most active profiles, most events first."""
        return sorted(self.profiles.values(),
                      key=lambda p: p.events, reverse=True)[:n]

    def classified(self) -> dict[str, list[str]]:
        """IPs grouped by classification."""
        groups: dict[str, list[str]] = {}
        for ip, profile in self.profiles.items():
            groups.setdefault(classify(profile), []).append(ip)
        return groups

    def report(self) -> dict[str, Any]:
        """Full tracker report (profiles keyed by IP)."""
        return {
            "attackers": len(self.profiles),
            "by_classification": {k: len(v) for k, v in self.classified().items()},
            "profiles": {ip: p.to_dict() for ip, p in self.profiles.items()},
        }


def _seconds_between(ts_a: str, ts_b: str) -> float:
    """Seconds between two ``YYYY-mm-dd HH:MM:SS`` strings (0 on failure)."""
    import time as _time
    fmt = "%Y-%m-%d %H:%M:%S"
    try:
        a = _time.mktime(_time.strptime(ts_a, fmt))
        b = _time.mktime(_time.strptime(ts_b, fmt))
    except ValueError:
        return 0.0
    return abs(b - a)
