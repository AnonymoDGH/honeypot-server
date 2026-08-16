"""Deployment configuration -- describe a whole fleet in one JSON file.

Command-line flags are fine for a quick decoy, but a real deployment has
many knobs: which services, which ports, which persona seed, whether the
tarpit is armed, which canary tokens are planted, log rotation limits.
This module defines the JSON schema for all of it and converts a config
into a ready-to-start HoneypotManager.

Schema (every key optional):

    {
      "host": "0.0.0.0",
      "log": "trap.jsonl",
      "rotate": true,
      "persona": "acme-dc1",
      "services": {"http": 8080, "ftp": 2121, "ssh": 2222},
      "tarpit": {"enabled": true, "base": 0.4, "jitter": 0.2},
      "canary": {"enabled": true, "seed": 7}
    }

"services" maps service name -> port (0 for ephemeral). Unknown services
or malformed shapes raise ConfigError with a precise message instead of
failing later at bind time.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..protocols import known_services
from .persona import Persona, persona_from_seed
from .server import HoneypotManager
from .tarpit import Tarpit


class ConfigError(ValueError):
    """Raised when a deployment config is malformed."""


@dataclass
class DeploymentConfig:
    """Validated description of one honeypot deployment."""

    host: str = "0.0.0.0"
    log: str | None = None
    rotate: bool = False
    persona: str | int | None = None
    services: dict[str, int] = field(default_factory=dict)
    tarpit_enabled: bool = False
    tarpit_base: float = 0.0
    tarpit_jitter: float = 0.0
    canary_enabled: bool = False
    canary_seed: str | int | None = None

    def service_names(self) -> list[str]:
        return list(self.services)

    def ports(self) -> dict[str, int]:
        return dict(self.services)

    def build_tarpit(self) -> Tarpit:
        """The Tarpit this config describes."""
        tarpit = Tarpit()
        if self.tarpit_enabled:
            tarpit.enable(base=self.tarpit_base, jitter=self.tarpit_jitter)
        return tarpit

    def build_persona(self) -> Persona:
        """The Persona this config describes."""
        return persona_from_seed(self.persona)

    def build_manager(self) -> HoneypotManager:
        """Create (but do not start) the manager for this config."""
        manager = HoneypotManager(
            self.log, host=self.host, persona=self.build_persona(),
            tarpit=self.build_tarpit(), rotate=self.rotate)
        manager.add_many(self.service_names(), self.ports())
        return manager

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready round-trip representation."""
        return {
            "host": self.host,
            "log": self.log,
            "rotate": self.rotate,
            "persona": self.persona,
            "services": dict(self.services),
            "tarpit": {"enabled": self.tarpit_enabled,
                       "base": self.tarpit_base,
                       "jitter": self.tarpit_jitter},
            "canary": {"enabled": self.canary_enabled,
                       "seed": self.canary_seed},
        }


def _require_type(value: Any, types: tuple, key: str) -> None:
    if not isinstance(value, types):
        names = "/".join(t.__name__ for t in types)
        raise ConfigError(f"'{key}' must be {names}, got {type(value).__name__}")


def from_dict(data: dict[str, Any]) -> DeploymentConfig:
    """Validate and build a DeploymentConfig from a plain dict."""
    if not isinstance(data, dict):
        raise ConfigError("config root must be an object")
    cfg = DeploymentConfig()

    if "host" in data:
        _require_type(data["host"], (str,), "host")
        cfg.host = data["host"]
    if "log" in data and data["log"] is not None:
        _require_type(data["log"], (str,), "log")
        cfg.log = data["log"]
    if "rotate" in data:
        _require_type(data["rotate"], (bool,), "rotate")
        cfg.rotate = data["rotate"]
    if "persona" in data and data["persona"] is not None:
        _require_type(data["persona"], (str, int), "persona")
        cfg.persona = data["persona"]

    services = data.get("services", {})
    _require_type(services, (dict,), "services")
    known = set(known_services())
    for name, port in services.items():
        if name not in known:
            raise ConfigError(f"unknown service '{name}' "
                              f"(known: {', '.join(sorted(known))})")
        if not isinstance(port, int) or isinstance(port, bool) or port < 0:
            raise ConfigError(f"port for '{name}' must be an integer >= 0")
        cfg.services[name] = port

    tarpit = data.get("tarpit", {})
    _require_type(tarpit, (dict,), "tarpit")
    if "enabled" in tarpit:
        _require_type(tarpit["enabled"], (bool,), "tarpit.enabled")
        cfg.tarpit_enabled = tarpit["enabled"]
    if "base" in tarpit:
        _require_type(tarpit["base"], (int, float), "tarpit.base")
        cfg.tarpit_base = float(tarpit["base"])
    if "jitter" in tarpit:
        _require_type(tarpit["jitter"], (int, float), "tarpit.jitter")
        cfg.tarpit_jitter = float(tarpit["jitter"])

    canary = data.get("canary", {})
    _require_type(canary, (dict,), "canary")
    if "enabled" in canary:
        _require_type(canary["enabled"], (bool,), "canary.enabled")
        cfg.canary_enabled = canary["enabled"]
    if "seed" in canary and canary["seed"] is not None:
        _require_type(canary["seed"], (str, int), "canary.seed")
        cfg.canary_seed = canary["seed"]

    return cfg


def from_file(path: str | Path) -> DeploymentConfig:
    """Load and validate a deployment config from a JSON file."""
    text = Path(path).read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON in {path}: {exc}") from exc
    return from_dict(data)


def default_config_dict() -> dict[str, Any]:
    """A sensible starter config as a dict (for --write-default)."""
    return DeploymentConfig(
        services={"http": 80, "ftp": 21, "ssh": 22, "smtp": 25},
    ).to_dict()
