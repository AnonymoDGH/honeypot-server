"""Tests for canary document generation and planting."""

from honeypot_server.canary.docs import (
    CanaryDocument,
    DocumentGenerator,
    plant_documents,
)
from honeypot_server.canary.tokens import CanaryTokenFactory, verify_jwt_shape
from honeypot_server.core.persona import Persona
from honeypot_server.protocols.base import CanaryRegistry
from honeypot_server.protocols.ftp import FakeFTPTree

PERSONA = Persona.generate(91)


def _gen(seed=20):
    factory = CanaryTokenFactory(seed=seed, domain=PERSONA.domain)
    return DocumentGenerator(PERSONA, factory), factory


class TestPasswordList:
    def test_contains_persona_users_and_tokens(self):
        gen, factory = _gen()
        doc = gen.password_list()
        assert doc.filename == "recovered_credentials.txt"
        user = PERSONA.users[0]
        assert f"{user.username}:{user.password}" in doc.content
        assert len(doc.tokens) == 2
        for token in doc.tokens:
            assert token.value in doc.content

    def test_row_count_clamped(self):
        gen, _ = _gen()
        doc = gen.password_list(rows=2)
        data_rows = [l for l in doc.content.splitlines()
                     if l and not l.startswith("#")]
        # 2 persona users + 2 token rows
        assert len(data_rows) == 4


class TestVpnRoster:
    def test_csv_shape_and_jwt(self):
        gen, _ = _gen()
        doc = gen.vpn_roster_csv()
        lines = doc.content.strip().splitlines()
        assert lines[0] == "username,email,group,otp_token"
        jwt_row = lines[-1]
        jwt_value = jwt_row.split(",")[-1]
        assert verify_jwt_shape(jwt_value)
        assert doc.tokens[0].value == jwt_value


class TestAwsCredentials:
    def test_credentials_file_shape(self):
        gen, _ = _gen()
        doc = gen.aws_credentials_file()
        token = doc.tokens[0]
        assert "[default]" in doc.content
        assert f"aws_access_key_id = {token.value}" in doc.content
        assert token.meta["secret_access_key"] in doc.content


class TestShellHistory:
    def test_history_embeds_bearer_token(self):
        gen, _ = _gen()
        doc = gen.shell_history()
        token = doc.tokens[0]
        assert f"Bearer {token.value}" in doc.content
        assert PERSONA.domain in doc.content


class TestDeployConfig:
    def test_two_token_kinds(self):
        gen, _ = _gen()
        doc = gen.deploy_config()
        kinds = {t.kind for t in doc.tokens}
        assert kinds == {"api", "url"}
        assert "GITHUB_TOKEN=ghp_" in doc.content
        assert "DEPLOY_HOOK=https://" in doc.content


class TestFullSetAndPlanting:
    def test_full_set_covers_five_documents(self):
        gen, _ = _gen()
        docs = gen.full_set()
        names = {d.filename for d in docs}
        assert names == {"recovered_credentials.txt", "vpn_users.csv",
                         "aws_credentials", ".bash_history", "deploy.env"}

    def test_plant_registers_tokens(self):
        gen, _ = _gen()
        registry = CanaryRegistry()
        docs = plant_documents(gen, registry)
        total_tokens = sum(len(d.tokens) for d in docs)
        assert len(registry) == total_tokens
        # scanning attacker traffic with a planted value raises a hit
        value = docs[0].tokens[0].value
        hits = registry.scan(f"curl -d key={value}")
        assert hits and hits[0]["kind"] == "doc"

    def test_plant_into_ftp_tree(self):
        gen, _ = _gen()
        tree = FakeFTPTree(PERSONA)
        registry = CanaryRegistry()
        docs = plant_documents(gen, registry, tree=tree)
        for doc in docs:
            assert tree.is_file(f"/internal/{doc.filename}")
        listing = [n for _, n in tree.list_dir("/internal")]
        assert "recovered_credentials.txt" in listing

    def test_documents_deterministic_per_seed(self):
        gen_a, _ = _gen(seed=77)
        gen_b, _ = _gen(seed=77)
        doc_a = gen_a.password_list()
        doc_b = gen_b.password_list()
        assert doc_a.content == doc_b.content

    def test_document_to_dict(self):
        gen, _ = _gen()
        doc = gen.password_list()
        d = doc.to_dict()
        assert d["filename"] == doc.filename
        assert len(d["tokens"]) == len(doc.tokens)
        assert d["content"] == doc.content
