"""Deception score -- rate how convincing the deployment is.

A honeypot that *looks* like a honeypot is worthless: attackers fingerprint
decoys the same way they fingerprint real services. This module grades a
deployment the way an adversary would, producing a 0-100 score with a
per-check breakdown and concrete penalty reasons.

Checks fall into three families:

* Consistency -- do all protocol surfaces tell the same OS/version/
  hostname story? (SSH banner says Ubuntu while HTTP says IIS is an
  instant tell.)
* Plausibility -- are the advertised versions recent and real, do
  banners avoid honeypot-ish words, does the fake roster look like a
  real org?
* Behaviour -- are response delays human-plausible (a tarpit set to 10s
  per response screams), do banners carry the identity where real
  servers put it?

The scorer runs against a Persona plus optional observed banners, so it
can grade both the configuration and what a scanner would actually see.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..core.persona import Persona

#: Words that instantly reveal a decoy to anyone reading a banner.
REVEALING_WORDS = ("honeypot", "decoy", "fake", "trap", "simulation",
                   "cowrie", "dionaea", "conpot", "honeyd")

#: Version strings considered believable per surface, with the oldest
#: plausible release year for context in reports.
VERSION_EXPECTATIONS = {
    "ssh": (("OpenSSH_7", "OpenSSH_8", "OpenSSH_9"), 2018),
    "http": (("nginx/1.2", "nginx/1.3", "Apache/2.4", "Apache/2.5",
              "Microsoft-IIS/10"), 2017),
    "ftp": (("vsftpd 3", "ProFTPD 1.3", "Pure-FTPd"), 2015),
    "smtp": (("Postfix", "Exim 4.9", "Sendmail 8.1", "Microsoft ESMTP"), 2015),
    "redis": (("6.", "7.", "8."), 2020),
    "mysql": (("5.7", "8.0", "8.4", "10."), 2017),
    "telnet": (("busybox 1.3", "busybox 1.2"), 2015),
}

#: Cross-surface OS agreement matrix: which HTTP servers fit which OS stories.
HTTP_SERVER_BY_OS = {
    "Ubuntu": ("nginx", "Apache"),
    "Debian": ("nginx", "Apache"),
    "CentOS": ("Apache", "nginx"),
}


@dataclass
class CheckResult:
    """One graded check: full marks, earned marks, and the reason."""

    name: str
    weight: int
    earned: int
    reason: str = ""

    @property
    def passed(self) -> bool:
        return self.earned >= self.weight

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "weight": self.weight,
                "earned": self.earned, "passed": self.passed,
                "reason": self.reason}


@dataclass
class DeceptionReport:
    """Full grading result for one deployment."""

    score: int
    grade: str
    checks: list[CheckResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "grade": self.grade,
            "checks": [c.to_dict() for c in self.checks],
        }

    def render(self) -> str:
        """Human-readable multi-line summary."""
        lines = [f"Deception score: {self.score}/100 (grade {self.grade})"]
        for check in self.checks:
            mark = "PASS" if check.passed else "FAIL"
            lines.append(f"  [{mark}] {check.name}: "
                         f"{check.earned}/{check.weight}  {check.reason}")
        return "\n".join(lines)


def grade_label(score: int) -> str:
    """Letter grade for a 0-100 score."""
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def check_revealing_words(persona: Persona) -> CheckResult:
    """No banner may contain words that name the deception."""
    fingerprints = persona.fingerprint()
    hits = []
    for surface, value in fingerprints.items():
        lowered = value.lower()
        for word in REVEALING_WORDS:
            if word in lowered:
                hits.append(f"{surface}:{word}")
    if hits:
        return CheckResult("no_revealing_words", 20, 0,
                           "revealing words: " + ", ".join(sorted(hits)))
    return CheckResult("no_revealing_words", 20, 20, "banners are clean")


def check_version_plausibility(persona: Persona) -> CheckResult:
    """Every advertised version must be from a believable recent line."""
    problems = []
    for surface, (prefixes, _year) in VERSION_EXPECTATIONS.items():
        version = persona.versions.get(surface, "")
        if not version:
            continue
        if not any(version.startswith(p) for p in prefixes):
            problems.append(f"{surface}={version}")
    if problems:
        return CheckResult("version_plausibility", 20,
                           max(0, 20 - 7 * len(problems)),
                           "implausible: " + ", ".join(problems))
    return CheckResult("version_plausibility", 20, 20,
                       "all versions from believable lines")


def check_os_consistency(persona: Persona) -> CheckResult:
    """The HTTP Server header must fit the OS the other surfaces claim."""
    http_header = persona.http_server_header()
    allowed = HTTP_SERVER_BY_OS.get(persona.os, ())
    if allowed and not any(http_header.startswith(a) for a in allowed):
        return CheckResult("os_consistency", 20, 0,
                           f"{persona.os} story but HTTP says {http_header}")
    return CheckResult("os_consistency", 20, 20,
                       f"{persona.os} story agrees with HTTP header")


def check_identity_consistency(persona: Persona) -> CheckResult:
    """Hostname/FQDN must appear where real servers put them."""
    problems = []
    if persona.hostname not in persona.ftp_banner():
        problems.append("ftp banner lacks hostname")
    if persona.fqdn not in persona.smtp_banner():
        problems.append("smtp banner lacks fqdn")
    if "." not in persona.domain:
        problems.append("domain has no dot")
    if problems:
        return CheckResult("identity_consistency", 20,
                           max(0, 20 - 7 * len(problems)),
                           "; ".join(problems))
    return CheckResult("identity_consistency", 20, 20,
                       "hostname and fqdn used consistently")


def check_roster_realism(persona: Persona) -> CheckResult:
    """The fake user roster must look like a real org, not admin/admin."""
    problems = []
    if len(persona.users) < 2:
        problems.append("only one account")
    names = persona.usernames()
    if len(set(names)) != len(names):
        problems.append("duplicate usernames")
    for user in persona.users:
        if user.password == user.username:
            problems.append(f"{user.username} uses username as password")
        if len(user.password) < 4:
            problems.append(f"{user.username} password too short")
    if problems:
        return CheckResult("roster_realism", 10,
                           max(0, 10 - 4 * len(problems)),
                           "; ".join(problems))
    return CheckResult("roster_realism", 10, 10, "roster looks organic")


def check_timing_plausibility(tarpit_delays: dict[str, float]) -> CheckResult:
    """Configured tarpit delays must stay inside human-plausible bounds.

    0-1.5s reads as a busy or congested server; beyond 3s per response a
    scanner flags the host as a tarpit and moves on.
    """
    suspicious = {svc: d for svc, d in tarpit_delays.items() if d > 3.0}
    if suspicious:
        worst = max(suspicious.values())
        return CheckResult("timing_plausibility", 10, 0,
                           f"delays up to {worst:.1f}s scream tarpit")
    earned = 10 if all(d <= 1.5 for d in tarpit_delays.values()) else 6
    reason = ("delays read as normal congestion" if earned == 10
              else "delays noticeable but tolerable")
    return CheckResult("timing_plausibility", 10, earned, reason)


def score_deployment(persona: Persona,
                     tarpit_delays: dict[str, float] | None = None,
                     observed_banners: dict[str, str] | None = None) -> DeceptionReport:
    """Grade a deployment 0-100.

    tarpit_delays maps service -> configured base delay (defaults to
    zero). observed_banners optionally maps service -> banner text
    actually seen on the wire; when present, an extra check grades
    those and the score is rescaled over the larger weight total.
    """
    checks = [
        check_revealing_words(persona),
        check_version_plausibility(persona),
        check_os_consistency(persona),
        check_identity_consistency(persona),
        check_roster_realism(persona),
        check_timing_plausibility(tarpit_delays or {}),
    ]
    if observed_banners:
        hits = []
        for surface, banner in observed_banners.items():
            lowered = banner.lower()
            for word in REVEALING_WORDS:
                if word in lowered:
                    hits.append(f"{surface}:{word}")
        earned = 0 if hits else 10
        reason = ("observed banners reveal deception: " + ", ".join(hits)
                  if hits else "observed banners are clean")
        checks.append(CheckResult("observed_banners", 10, earned, reason))
    total_weight = sum(c.weight for c in checks)
    raw = sum(c.earned for c in checks)
    score = round(raw * 100 / total_weight)
    return DeceptionReport(score=score, grade=grade_label(score), checks=checks)
