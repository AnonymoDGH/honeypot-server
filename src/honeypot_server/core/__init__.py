"""Core infrastructure for the honeypot platform.

Houses the event logger, the server lifecycle manager, the persona engine
and the tarpit pacing helpers. Protocol decoys in ``honeypot_server.protocols``
build on these pieces; intelligence modules in ``honeypot_server.intel``
consume the JSONL events they emit.
"""

from __future__ import annotations

from .persona import FakeUser, Persona, persona_from_seed
from .server import DecoyRecord, HoneypotManager, PortRegistry
from .tarpit import Tarpit, TarpitConfig, get_tarpit, set_tarpit
from .logger import (
    EventBuffer,
    Logger,
    RotatingJSONLWriter,
    hash_credential,
    iter_log_paths,
    make_event,
    read_events,
    redact,
)

__all__ = [
    "EventBuffer",
    "FakeUser",
    "Persona",
    "DecoyRecord",
    "HoneypotManager",
    "PortRegistry",
    "persona_from_seed",
    "Tarpit",
    "TarpitConfig",
    "get_tarpit",
    "set_tarpit",
    "Logger",
    "RotatingJSONLWriter",
    "hash_credential",
    "iter_log_paths",
    "make_event",
    "read_events",
    "redact",
]
