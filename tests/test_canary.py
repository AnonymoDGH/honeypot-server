"""Tests for canary token generation and registry attachment."""

import json

from honeypot_server.canary.tokens import (
    CanaryToken,
    CanaryTokenFactory,
    load_tokens,
    verify_jwt_shape,
)
from honeypot_server.protocols.base import CanaryRegistry


class TestFactoryDeterminism:
    def test_same_seed_same_tokens(self):
        a = CanaryTokenFactory(seed=42)
        b = CanaryTokenFactory(seed=42)
        assert a.aws_key().value == b.aws_key().value
        assert a.url().value == b.url().value

    def test_different_seeds_differ(self):
        a = CanaryTokenFactory(seed=1).aws_key().value
        b = CanaryTokenFactory(seed=2).aws_key().value
        assert a != b

    def test_string_seed_stable(self):
        a = CanaryTokenFactory(seed="dc1").api_token().value
        b = CanaryTokenFactory(seed="dc1").api_token().value
        assert a == b


class TestAwsKey:
    def test_shape(self):
        token = CanaryTokenFactory(seed=3).aws_key()
        assert token.value.startswith("AKIA")
        assert len(token.value) == 20
        assert token.value[4:].isalnum() and token.value[4:].isupper()
        secret = token.meta["secret_access_key"]
        assert len(secret) == 40

    def test_kind_and_id(self):
        token = CanaryTokenFactory(seed=4).aws_key()
        assert token.kind == "aws"
        assert token.id.startswith("aws-")


class TestApiTokens:
    def test_generic_prefix(self):
        token = CanaryTokenFactory(seed=5).api_token(prefix="sk-live-", length=28)
        assert token.value.startswith("sk-live-")
        assert len(token.value) == len("sk-live-") + 28

    def test_github_shape(self):
        token = CanaryTokenFactory(seed=6).github_token()
        assert token.value.startswith("ghp_")
        assert len(token.value) == 4 + 36


class TestJwt:
    def test_structure(self):
        token = CanaryTokenFactory(seed=7).jwt(subject="svc-backup")
        assert verify_jwt_shape(token.value)
        parts = token.value.split(".")
        import base64
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        assert header["alg"] == "HS256"
        assert payload["sub"] == "svc-backup"
        assert payload["role"] == "admin"

    def test_verify_rejects_garbage(self):
        assert not verify_jwt_shape("not.a.jwt!")
        assert not verify_jwt_shape("onlyonepart")
        assert not verify_jwt_shape("a.b")


class TestUrl:
    def test_shape(self):
        factory = CanaryTokenFactory(seed=8, domain="bait.example")
        token = factory.url(path_hint="invoice")
        assert token.kind == "url"
        assert token.meta["url"].startswith("https://bait.example/invoice/")
        assert token.meta["path"].endswith(token.value)
        assert len(token.value) == 12

    def test_unique_ids(self):
        factory = CanaryTokenFactory(seed=9)
        values = {factory.url().value for _ in range(20)}
        assert len(values) == 20


class TestStandardSetAndRegistry:
    def test_standard_set_families(self):
        factory = CanaryTokenFactory(seed=10)
        tokens = factory.standard_set()
        kinds = [t.kind for t in tokens]
        assert kinds.count("aws") == 1
        assert kinds.count("jwt") == 1
        assert kinds.count("url") == 2
        assert len(tokens) == 6

    def test_attach_registers_all(self):
        factory = CanaryTokenFactory(seed=11)
        factory.standard_set()
        registry = CanaryRegistry()
        assert factory.attach(registry) == 6
        assert len(registry) == 6
        for token in factory.tokens:
            assert token.value in registry

    def test_scan_finds_planted_token(self):
        factory = CanaryTokenFactory(seed=12)
        token = factory.aws_key()
        registry = CanaryRegistry()
        factory.attach(registry)
        hits = registry.scan(f"config: aws_key={token.value}")
        assert len(hits) == 1
        assert hits[0]["kind"] == "aws"
        assert hits[0]["id"] == token.id

    def test_export_and_save_load_roundtrip(self, tmp_path):
        factory = CanaryTokenFactory(seed=13)
        factory.standard_set()
        path = tmp_path / "tokens.json"
        factory.save(str(path))
        loaded = load_tokens(str(path))
        assert len(loaded) == 6
        assert loaded[0].value == factory.tokens[0].value
        assert loaded[0].kind == factory.tokens[0].kind
        # file is valid JSON
        json.loads(path.read_text(encoding="utf-8"))

    def test_token_to_dict(self):
        token = CanaryToken(id="x-1", kind="api", value="v", note="n",
                            meta={"a": 1})
        d = token.to_dict()
        assert d == {"id": "x-1", "kind": "api", "value": "v", "note": "n",
                     "meta": {"a": 1}}
