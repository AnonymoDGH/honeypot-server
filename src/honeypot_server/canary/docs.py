"""Canary document generator -- bait files with embedded tripwires.

Generates the files attackers love to steal, each seeded with canary
tokens from a CanaryTokenFactory:

* fake "password list" text files (the classic credential dump bait);
* CSV exports pretending to be user databases or VPN rosters;
* fake shell history and config files with embedded API keys;
* fake AWS credential files (~/.aws/credentials shape).

Every document embeds at least one unique token, so when a decoy serves
the file (FTP RETR, HTTP GET) or the token later appears anywhere in
attacker traffic, the registry raises a critical canary_hit. Documents
are deterministic per seed, which keeps replanted files stable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..core.persona import Persona
from .tokens import CanaryToken, CanaryTokenFactory


@dataclass
class CanaryDocument:
    """One generated bait file."""

    filename: str
    content: str
    tokens: list[CanaryToken]

    def to_dict(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "content": self.content,
            "tokens": [t.to_dict() for t in self.tokens],
        }


class DocumentGenerator:
    """Builds bait documents for one persona using one token factory."""

    def __init__(self, persona: Persona, factory: CanaryTokenFactory):
        self.persona = persona
        self.factory = factory

    # -- individual documents ---------------------------------------------------
    def password_list(self, rows: int = 8) -> CanaryDocument:
        """Fake recovered-credentials text file.

        Mixes the persona's fake accounts (their passwords are already
        decoy bait) with a planted AWS key id and an API token. The file
        header pretends to be a pentest artefact, which is exactly what
        credential-hunting tools grep for.
        """
        tokens = [self.factory.aws_key(note="planted in password list"),
                  self.factory.api_token(note="planted in password list")]
        lines = [
            "# recovered_credentials.txt -- internal pentest 2024-Q3",
            "# format: username:password:source",
        ]
        users = self.persona.users[:max(1, min(rows, len(self.persona.users)))]
        for user in users:
            lines.append(f"{user.username}:{user.password}:{self.persona.domain}")
        lines.append(f"aws-deploy:{tokens[0].value}:aws-console")
        lines.append(f"ci-bot:{tokens[1].value}:ci-variables")
        return CanaryDocument(
            filename="recovered_credentials.txt",
            content="\n".join(lines) + "\n", tokens=tokens)

    def vpn_roster_csv(self) -> CanaryDocument:
        """Fake VPN user export with a bearer JWT in the token column."""
        token = self.factory.jwt(subject="vpn-export",
                                 note="planted in VPN roster")
        lines = ["username,email,group,otp_token"]
        for user in self.persona.users[:5]:
            email = f"{user.username}@{self.persona.domain}"
            lines.append(f"{user.username},{email},{user.role},")
        lines.append(f"svc-vpn,vpn@{self.persona.domain},service,{token.value}")
        return CanaryDocument(filename="vpn_users.csv",
                              content="\n".join(lines) + "\n",
                              tokens=[token])

    def aws_credentials_file(self) -> CanaryDocument:
        """Fake ~/.aws/credentials with a full planted key pair."""
        token = self.factory.aws_key(note="planted in aws credentials file")
        content = (
            "[default]\n"
            f"aws_access_key_id = {token.value}\n"
            f"aws_secret_access_key = {token.meta['secret_access_key']}\n"
            "region = us-east-1\n"
            "\n"
            "[backup]\n"
            f"aws_access_key_id = {token.value}\n"
            f"aws_secret_access_key = {token.meta['secret_access_key']}\n"
        )
        return CanaryDocument(filename="aws_credentials", content=content,
                              tokens=[token])

    def shell_history(self) -> CanaryDocument:
        """Fake .bash_history with a token-bearing curl command."""
        token = self.factory.api_token(prefix="sk-live-",
                                       note="planted in shell history")
        p = self.persona
        lines = [
            "cd /var/www",
            "systemctl status nginx",
            f"curl -H 'Authorization: Bearer {token.value}' "
            f"https://api.{p.domain}/v1/status",
            f"ssh {p.admin().username}@db.{p.domain}",
            "tail -f /var/log/syslog",
            f"pg_dump appdb > /backups/db-dump.sql",
        ]
        return CanaryDocument(filename=".bash_history",
                              content="\n".join(lines) + "\n",
                              tokens=[token])

    def deploy_config(self) -> CanaryDocument:
        """Fake deploy.env with a GitHub PAT and a canary URL."""
        gh = self.factory.github_token(note="planted in deploy config")
        url_token = self.factory.url(path_hint="webhook",
                                     note="planted in deploy config")
        content = (
            "# deploy.env -- do not commit\n"
            f"GITHUB_TOKEN={gh.value}\n"
            f"DEPLOY_HOOK={url_token.meta['url']}\n"
            f"APP_HOST={self.persona.fqdn}\n"
            "APP_ENV=production\n"
        )
        return CanaryDocument(filename="deploy.env", content=content,
                              tokens=[gh, url_token])

    # -- bulk ------------------------------------------------------------------
    def full_set(self) -> list[CanaryDocument]:
        """Every bait document this generator knows how to make."""
        return [self.password_list(), self.vpn_roster_csv(),
                self.aws_credentials_file(), self.shell_history(),
                self.deploy_config()]


def plant_documents(generator: DocumentGenerator, registry: Any,
                    tree: Any | None = None) -> list[CanaryDocument]:
    """Generate the full document set, register tokens, optionally plant.

    When tree is given (a FakeFTPTree or any object with inject(path,
    content)), each document is also injected under /internal so the FTP
    decoy serves it. Returns the generated documents.
    """
    docs = generator.full_set()
    for doc in docs:
        for token in doc.tokens:
            registry.register(token.value, kind="doc", id=token.id,
                              note=token.note, file=doc.filename)
    if tree is not None:
        for doc in docs:
            tree.inject(f"/internal/{doc.filename}", doc.content)
    return docs
