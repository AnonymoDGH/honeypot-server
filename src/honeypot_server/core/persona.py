"""Persona engine -- one seeded fake identity shared by every decoy.

A convincing honeypot deployment must not contradict itself: if the SSH
banner claims Ubuntu while the HTTP Server header claims IIS and the FTP
welcome says vsftpd, any attacker with two minutes notices. The persona
engine generates one coherent fake machine -- hostname, domain, OS story,
software versions and a roster of fake users -- from a single integer seed,
and every protocol module renders its banners from that same persona.

The same seed always produces the same identity, so a deployment can be
restarted without changing its fingerprints, and tests stay deterministic.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field

#: Name fragments used to assemble plausible hostnames.
HOST_PREFIXES = (
    "web", "mail", "db", "app", "file", "backup", "intranet", "portal",
    "crm", "erp", "hr", "finance", "dev", "staging", "proxy", "cache",
)

#: Plausible second-level domains for the fake organisation.
DOMAIN_WORDS = (
    "acme", "northwind", "globex", "initech", "umbra", "vertex",
    "bluepeak", "ironwood", "silverline", "redstone", "oakhurst",
    "lakeside", "meridian", "pinnacle", "harborview",
)

DOMAIN_TLDS = ("local", "internal", "corp", "lan", "net", "com")

#: Fake account roster material. Roles drive which services mention them.
FIRST_NAMES = ("james", "maria", "david", "sarah", "chen", "olga",
               "luis", "anna", "peter", "fatima", "john", "kate")
LAST_NAMES = ("smith", "garcia", "lee", "novak", "kumar", "silva",
              "brown", "muller", "tanaka", "wilson", "rossi", "khan")

SERVICE_ROLES = ("admin", "deploy", "backup", "monitor", "webmaster",
                 "dba", "support", "auditor")

#: OS stories with matching version strings for each protocol surface.
OS_STORIES = (
    {
        "os": "Ubuntu",
        "os_version": "22.04",
        "kernel": "5.15.0-91-generic",
        "ssh": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        "http": "nginx/1.24.0",
        "ftp": "vsftpd 3.0.5",
        "smtp": "Postfix",
        "telnet": "busybox 1.35.0",
        "redis": "7.0.12",
        "mysql": "8.0.35-0ubuntu0.22.04.1",
    },
    {
        "os": "Debian",
        "os_version": "12",
        "kernel": "6.1.0-17-amd64",
        "ssh": "OpenSSH_9.2p1 Debian-2+deb12u1",
        "http": "Apache/2.4.57 (Debian)",
        "ftp": "ProFTPD 1.3.8",
        "smtp": "Exim 4.96",
        "telnet": "busybox 1.36.1",
        "redis": "7.2.3",
        "mysql": "10.11.4-MariaDB-1~deb12u1",
    },
    {
        "os": "CentOS",
        "os_version": "7.9",
        "kernel": "3.10.0-1160.el7.x86_64",
        "ssh": "OpenSSH_7.4",
        "http": "Apache/2.4.6 (CentOS)",
        "ftp": "vsftpd 3.0.2",
        "smtp": "Postfix",
        "telnet": "busybox 1.30.1",
        "redis": "6.2.14",
        "mysql": "5.7.44",
    },
)


@dataclass
class FakeUser:
    """One fake account the decoys pretend exists.

    ``password`` is only ever used to *validate* attempts in-memory; when an
    attempt is logged it is hashed first (see core.logger.hash_credential).
    """

    username: str
    password: str
    role: str
    home: str = ""
    shell: str = "/bin/bash"
    uid: int = 1000

    def matches(self, username: str, password: str) -> bool:
        """Case-sensitive credential comparison against this persona."""
        return self.username == username and self.password == password


@dataclass
class Persona:
    """A complete, self-consistent fake machine identity.

    Build one with :meth:`generate` (seeded) or :meth:`default` and pass it
    to every decoy so all banners, fake files and account rosters agree.
    """

    seed: int
    hostname: str
    domain: str
    fqdn: str
    os: str
    os_version: str
    kernel: str
    versions: dict[str, str]
    users: list[FakeUser] = field(default_factory=list)
    org_name: str = ""
    admin_email: str = ""
    ip_story: str = "10.20.30.40"

    # -- banner rendering ---------------------------------------------------
    def ssh_banner(self) -> str:
        """SSH identification string the decoy sends first."""
        return f"SSH-2.0-{self.versions['ssh']}"

    def ftp_banner(self) -> str:
        """FTP 220 greeting."""
        return f"220 {self.hostname} FTP service ({self.versions['ftp']}) ready."

    def smtp_banner(self) -> str:
        """SMTP 220 greeting."""
        return f"220 {self.fqdn} ESMTP {self.versions['smtp']}"

    def http_server_header(self) -> str:
        """Value for the HTTP Server response header."""
        return self.versions["http"]

    def telnet_banner(self) -> str:
        """Telnet login preamble."""
        return (f"{self.hostname} login: ")

    def redis_info_line(self, key: str) -> str:
        """Fake redis INFO values consistent with the persona."""
        table = {
            "redis_version": self.versions["redis"],
            "os": f"{self.os} {self.os_version}",
            "run_id": hashlib.sha1(self.fqdn.encode()).hexdigest()[:40],
            "executable": "/usr/bin/redis-server",
            "config_file": "/etc/redis/redis.conf",
        }
        return table.get(key, "")

    def mysql_version(self) -> str:
        """Version string embedded in the MySQL handshake greeting."""
        return self.versions["mysql"]

    # -- roster helpers ------------------------------------------------------
    def usernames(self) -> list[str]:
        """All fake usernames, in roster order."""
        return [u.username for u in self.users]

    def find_user(self, username: str) -> FakeUser | None:
        """Look up a fake account by exact username."""
        for u in self.users:
            if u.username == username:
                return u
        return None

    def admin(self) -> FakeUser:
        """The privileged fake account (first user with role admin)."""
        for u in self.users:
            if u.role == "admin":
                return u
        return self.users[0]

    def fingerprint(self) -> dict[str, str]:
        """Flat dict of every surface banner, for deception scoring."""
        return {
            "hostname": self.hostname,
            "fqdn": self.fqdn,
            "os": f"{self.os} {self.os_version}",
            "ssh": self.ssh_banner(),
            "ftp": self.ftp_banner(),
            "smtp": self.smtp_banner(),
            "http": self.http_server_header(),
            "telnet": self.versions["telnet"],
            "redis": self.versions["redis"],
            "mysql": self.mysql_version(),
        }

    # -- construction ---------------------------------------------------------
    @classmethod
    def generate(cls, seed: int = 0, user_count: int = 6) -> "Persona":
        """Deterministically build a persona from an integer seed.

        The same seed always yields the same hostname, OS story and user
        roster. ``user_count`` is clamped to 1..12.
        """
        rng = random.Random(seed)
        story = rng.choice(OS_STORIES)
        hostname = f"{rng.choice(HOST_PREFIXES)}-{rng.randint(1, 99):02d}"
        word = rng.choice(DOMAIN_WORDS)
        domain = f"{word}.{rng.choice(DOMAIN_TLDS)}"
        fqdn = f"{hostname}.{domain}"
        org = word.capitalize() + " " + rng.choice(
            ("Systems", "Logistics", "Holdings", "Labs", "Group"))
        users: list[FakeUser] = []
        seen: set[str] = set()
        roles = list(SERVICE_ROLES)
        rng.shuffle(roles)
        count = max(1, min(12, user_count))
        for i in range(count):
            first = rng.choice(FIRST_NAMES)
            last = rng.choice(LAST_NAMES)
            base = f"{first}.{last}"
            username = base
            n = 1
            while username in seen:
                username = f"{base}{n}"
                n += 1
            seen.add(username)
            role = "admin" if i == 0 else roles[i % len(roles)]
            password = _fake_password(rng, username)
            users.append(FakeUser(
                username=username, password=password, role=role,
                home=f"/home/{username}", uid=1000 + i))
        admin_email = f"admin@{domain}"
        ip_story = ".".join(str(rng.randint(2, 250)) for _ in range(4))
        return cls(seed=seed, hostname=hostname, domain=domain, fqdn=fqdn,
                   os=story["os"], os_version=story["os_version"],
                   kernel=story["kernel"],
                   versions={k: v for k, v in story.items()
                             if k not in ("os", "os_version", "kernel")},
                   users=users, org_name=org, admin_email=admin_email,
                   ip_story=ip_story)

    @classmethod
    def default(cls) -> "Persona":
        """The canonical seed-0 persona used when none is configured."""
        return cls.generate(0)


def _fake_password(rng: random.Random, username: str) -> str:
    """Assemble a plausible-looking weak password for a fake account.

    These mimic the credential patterns brute-force dictionaries target
    (name + year, word + digits) so a decoy login success feels real.
    """
    patterns = (
        lambda: f"{username}{rng.randint(2015, 2026)}",
        lambda: f"{rng.choice(('qwerty', 'letmein', 'welcome', 'changeme'))}!{rng.randint(1, 99)}",
        lambda: f"{rng.choice(FIRST_NAMES)}{rng.choice(LAST_NAMES)}{rng.randint(1, 999)}",
        lambda: f"{username}_{rng.choice(('prod', 'dev', 'test', 'temp'))}",
    )
    return rng.choice(patterns)()


def persona_from_seed(seed: int | str | None) -> Persona:
    """Normalise a CLI/config seed value into a Persona.

    ``None`` gives the default persona; strings are hashed so operators can
    pass memorable seeds like "acme-dc1" instead of integers.
    """
    if seed is None:
        return Persona.default()
    if isinstance(seed, str):
        seed = int(hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8], 16)
    return Persona.generate(int(seed))
