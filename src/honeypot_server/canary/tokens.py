"""Canary token generator -- tripwires that phone home when touched.

A canary token is a piece of plausible-looking secret that has exactly one
job: to be *used* by an attacker. Nothing legitimate ever touches it, so
the moment a decoy sees the value, the event is unambiguous evidence of
real malicious activity -- and gets escalated to critical severity.

This module generates three families of tokens, all deterministic under a
seed so a deployment can regenerate its tokens after a restart:

* AWS-style access key ids (AKIA...) with a matching fake secret;
* API tokens in common shapes (sk-live-..., ghp_..., bearer JWTs);
* canary URLs -- unique links planted in fake pages and documents; a GET
  for one means someone is reading the bait.

Tokens register themselves into the protocol CanaryRegistry (see
protocols.base) so every decoy watches for them automatically.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import random
import string
from dataclasses import dataclass, field
from typing import Any

#: Alphabet used for token bodies (unambiguous, URL-safe).
TOKEN_ALPHABET = string.ascii_uppercase + string.digits

#: Alphabet for lowercase secret material.
SECRET_ALPHABET = string.ascii_letters + string.digits


def _token_body(rng: random.Random, length: int,
                alphabet: str = TOKEN_ALPHABET) -> str:
    return "".join(rng.choice(alphabet) for _ in range(length))


@dataclass
class CanaryToken:
    """One planted tripwire."""

    id: str
    kind: str
    value: str
    note: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "value": self.value,
                "note": self.note, "meta": self.meta}


class CanaryTokenFactory:
    """Deterministic generator and registry-loader for canary tokens.

    Build one with a seed, call the generators you need, then attach()
    the results to a CanaryRegistry. The same seed always yields the
    same token values, which is how a restarted deployment keeps its
    planted documents valid.
    """

    def __init__(self, seed: int | str = 0, domain: str = "canary.internal"):
        if isinstance(seed, str):
            seed = int(hashlib.sha256(seed.encode()).hexdigest()[:8], 16)
        self.seed = int(seed)
        self.rng = random.Random(self.seed)
        self.domain = domain
        self.tokens: list[CanaryToken] = []

    # -- generators -----------------------------------------------------------
    def _next_id(self, kind: str) -> str:
        digest = hashlib.sha256(
            f"{self.seed}:{kind}:{len(self.tokens)}".encode()).hexdigest()
        return f"{kind}-{digest[:10]}"

    def aws_key(self, note: str = "") -> CanaryToken:
        """Fake AWS access key id + secret access key pair.

        The id follows the real AKIA + 16 uppercase/digit shape; the secret
        follows the 40-char base64-ish shape. Both are unique per seed.
        """
        key_id = "AKIA" + _token_body(self.rng, 16)
        secret = _token_body(self.rng, 40, SECRET_ALPHABET)
        token = CanaryToken(
            id=self._next_id("aws"), kind="aws",
            value=key_id, note=note or "fake AWS access key id",
            meta={"secret_access_key": secret})
        self.tokens.append(token)
        return token

    def api_token(self, prefix: str = "sk-live-", length: int = 28,
                  note: str = "") -> CanaryToken:
        """Generic API token with a recognisable vendor prefix."""
        value = prefix + _token_body(self.rng, length, SECRET_ALPHABET)
        token = CanaryToken(
            id=self._next_id("api"), kind="api", value=value,
            note=note or f"fake API token ({prefix.rstrip('-')})")
        self.tokens.append(token)
        return token

    def github_token(self, note: str = "") -> CanaryToken:
        """GitHub personal-access-token shaped value (ghp_ + 36)."""
        return self.api_token(prefix="ghp_", length=36,
                              note=note or "fake GitHub PAT")

    def jwt(self, subject: str = "svc-backup", note: str = "") -> CanaryToken:
        """A structurally valid (HS256-shaped) fake bearer JWT.

        Header and payload are real base64url JSON; the signature is an
        HMAC over them with a per-seed key, so the token even survives
        naive format validation -- but the signature key is fake, so no
        real service would accept it.
        """
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({
            "sub": subject, "iss": self.domain, "role": "admin",
            "seed": self.seed}).encode()).rstrip(b"=").decode()
        signing_input = f"{header}.{payload}".encode()
        key = hashlib.sha256(f"jwt:{self.seed}".encode()).digest()
        signature = base64.urlsafe_b64encode(
            hmac.new(key, signing_input, hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        value = f"{header}.{payload}.{signature}"
        token = CanaryToken(
            id=self._next_id("jwt"), kind="jwt", value=value,
            note=note or f"fake bearer JWT for {subject}")
        self.tokens.append(token)
        return token

    def url(self, path_hint: str = "invoice", note: str = "") -> CanaryToken:
        """Unique canary URL: https://<domain>/<hint>/<unique-id>.

        Plant it in fake pages, emails or documents; a request for the
        path means the bait was read. The unique id is the watched value.
        """
        uid = _token_body(self.rng, 12).lower()
        path = f"/{path_hint}/{uid}"
        token = CanaryToken(
            id=self._next_id("url"), kind="url", value=uid,
            note=note or f"canary URL {path}",
            meta={"url": f"https://{self.domain}{path}", "path": path})
        self.tokens.append(token)
        return token

    # -- bulk + registry --------------------------------------------------------
    def standard_set(self) -> list[CanaryToken]:
        """The default planting: one of each family plus an extra URL."""
        return [self.aws_key(), self.api_token(), self.github_token(),
                self.jwt(), self.url(), self.url(path_hint="reset")]

    def attach(self, registry: Any) -> int:
        """Register every generated token into a CanaryRegistry.

        Returns the number registered. Works with any object exposing
        register(value, kind=..., **meta).
        """
        count = 0
        for token in self.tokens:
            registry.register(token.value, kind=token.kind, id=token.id,
                              note=token.note, **token.meta)
            count += 1
        return count

    def export(self) -> list[dict[str, Any]]:
        """All generated tokens as JSON-ready dicts."""
        return [t.to_dict() for t in self.tokens]

    def save(self, path: str) -> None:
        """Persist the token list (for replanting after restart)."""
        from pathlib import Path
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(self.export(), indent=2), encoding="utf-8")


def load_tokens(path: str) -> list[CanaryToken]:
    """Read tokens written by CanaryTokenFactory.save()."""
    from pathlib import Path
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [CanaryToken(id=t["id"], kind=t["kind"], value=t["value"],
                        note=t.get("note", ""), meta=t.get("meta", {}))
            for t in data]


def verify_jwt_shape(token_value: str) -> bool:
    """Structural check used by tests/reports: 3 dot-separated b64url parts."""
    parts = token_value.split(".")
    if len(parts) != 3:
        return False
    for part in parts:
        if not part:
            return False
        padded = part + "=" * (-len(part) % 4)
        try:
            base64.urlsafe_b64decode(padded)
        except Exception:
            return False
    return True
