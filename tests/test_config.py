"""Tests for deployment configuration loading and validation."""

import json

import pytest

from honeypot_server.core.config import (
    ConfigError,
    DeploymentConfig,
    default_config_dict,
    from_dict,
    from_file,
)


class TestFromDict:
    def test_defaults(self):
        cfg = from_dict({})
        assert cfg.host == "0.0.0.0"
        assert cfg.services == {}
        assert cfg.log is None
        assert cfg.tarpit_enabled is False

    def test_full_config(self):
        cfg = from_dict({
            "host": "127.0.0.1",
            "log": "trap.jsonl",
            "rotate": True,
            "persona": "acme-dc1",
            "services": {"http": 8080, "ftp": 0},
            "tarpit": {"enabled": True, "base": 0.4, "jitter": 0.1},
            "canary": {"enabled": True, "seed": 9},
        })
        assert cfg.host == "127.0.0.1"
        assert cfg.log == "trap.jsonl" and cfg.rotate
        assert cfg.persona == "acme-dc1"
        assert cfg.services == {"http": 8080, "ftp": 0}
        assert cfg.tarpit_enabled and cfg.tarpit_base == 0.4
        assert cfg.canary_enabled and cfg.canary_seed == 9

    def test_unknown_service_rejected(self):
        with pytest.raises(ConfigError, match="unknown service"):
            from_dict({"services": {"gopher": 70}})

    def test_bad_port_rejected(self):
        with pytest.raises(ConfigError, match="port"):
            from_dict({"services": {"http": -1}})
        with pytest.raises(ConfigError, match="port"):
            from_dict({"services": {"http": "eighty"}})

    def test_bool_port_rejected(self):
        with pytest.raises(ConfigError):
            from_dict({"services": {"http": True}})

    def test_type_errors(self):
        with pytest.raises(ConfigError, match="host"):
            from_dict({"host": 123})
        with pytest.raises(ConfigError, match="rotate"):
            from_dict({"rotate": "yes"})
        with pytest.raises(ConfigError, match="tarpit"):
            from_dict({"tarpit": "on"})
        with pytest.raises(ConfigError, match="tarpit.base"):
            from_dict({"tarpit": {"base": "fast"}})
        with pytest.raises(ConfigError, match="canary"):
            from_dict({"canary": [1, 2]})

    def test_root_must_be_object(self):
        with pytest.raises(ConfigError, match="root"):
            from_dict([1, 2, 3])


class TestFromFile:
    def test_roundtrip(self, tmp_path):
        path = tmp_path / "deploy.json"
        path.write_text(json.dumps({
            "host": "127.0.0.1",
            "services": {"redis": 6379},
        }), encoding="utf-8")
        cfg = from_file(path)
        assert cfg.services == {"redis": 6379}

    def test_invalid_json(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(ConfigError, match="invalid JSON"):
            from_file(path)


class TestBuild:
    def test_build_tarpit(self):
        cfg = from_dict({"tarpit": {"enabled": True, "base": 0.3,
                                    "jitter": 0.0}})
        tarpit = cfg.build_tarpit()
        assert tarpit.delay_for("http") == 0.3

    def test_build_tarpit_disabled(self):
        cfg = from_dict({"tarpit": {"base": 0.3}})
        assert cfg.build_tarpit().delay_for("http") == 0.0

    def test_build_persona_from_string_seed(self):
        cfg = from_dict({"persona": "acme-dc1"})
        persona = cfg.build_persona()
        assert persona.fqdn  # resolved to a real persona

    def test_build_manager_registers_services(self, tmp_path):
        cfg = from_dict({
            "host": "127.0.0.1",
            "log": str(tmp_path / "m.jsonl"),
            "services": {"http": 0, "ftp": 0},
        })
        manager = cfg.build_manager()
        assert set(manager.records) == {"http", "ftp"}
        assert not any(r.running for r in manager.records.values())

    def test_to_dict_roundtrip(self):
        original = {
            "host": "10.0.0.1",
            "log": "x.jsonl",
            "rotate": True,
            "persona": 42,
            "services": {"ssh": 2222},
            "tarpit": {"enabled": True, "base": 0.5, "jitter": 0.2},
            "canary": {"enabled": False, "seed": None},
        }
        cfg = from_dict(original)
        assert cfg.to_dict() == original


class TestDefaultConfig:
    def test_default_is_valid(self):
        cfg = from_dict(default_config_dict())
        assert set(cfg.services) == {"http", "ftp", "ssh", "smtp"}

    def test_deployment_config_dataclass_defaults(self):
        cfg = DeploymentConfig()
        assert cfg.service_names() == []
        assert cfg.ports() == {}
