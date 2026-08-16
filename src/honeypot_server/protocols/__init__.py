"""Protocol decoy registry.

Maps service names to their handler classes and transport kind so the
lifecycle manager (core.server) and the CLI can start any decoy by name
without importing each module individually.
"""

from __future__ import annotations

from .base import CanaryRegistry, ProtocolHandler, UDPProtocolHandler, build_server
from .dns import DNSHandler
from .ftp import FTPHandler
from .http import HTTPHandler
from .mysql import MySQLHandler
from .redis import RedisHandler
from .smtp import SMTPHandler
from .ssh import SSHHandler
from .telnet import TelnetHandler

#: service name -> (handler class, transport).
PROTOCOLS: dict[str, tuple[type, str]] = {
    "http": (HTTPHandler, "tcp"),
    "ftp": (FTPHandler, "tcp"),
    "ssh": (SSHHandler, "tcp"),
    "smtp": (SMTPHandler, "tcp"),
    "dns": (DNSHandler, "udp"),
    "telnet": (TelnetHandler, "tcp"),
    "redis": (RedisHandler, "tcp"),
    "mysql": (MySQLHandler, "tcp"),
}


def known_services() -> list[str]:
    """All service names this build can run."""
    return list(PROTOCOLS)


def handler_for(service: str) -> type:
    """Handler class for ``service`` (KeyError when unknown)."""
    return PROTOCOLS[service][0]


def transport_for(service: str) -> str:
    """Transport kind ("tcp"/"udp") for ``service``."""
    return PROTOCOLS[service][1]


__all__ = [
    "PROTOCOLS", "known_services", "handler_for", "transport_for",
    "build_server", "CanaryRegistry", "ProtocolHandler", "UDPProtocolHandler",
    "HTTPHandler", "FTPHandler", "SSHHandler", "SMTPHandler", "DNSHandler",
    "TelnetHandler", "RedisHandler", "MySQLHandler",
]
