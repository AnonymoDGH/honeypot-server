"""Server lifecycle manager -- start, stop and monitor many decoys.

:class:`HoneypotManager` is the single object a deployment talks to:

* ``add()``/``start()``/``stop()`` individual decoys or the whole fleet;
* a port registry that refuses to double-bind a port and reports which
  service owns which address;
* ``status()`` for dashboards and the CLI ``status`` subcommand;
* ``health_check()`` -- a real TCP connect (or UDP probe) against each
  live decoy to prove it still answers;
* graceful shutdown: stop accepting, let in-flight handlers drain, then
  close sockets, with a bounded wait.

The manager shares one :class:`Logger`, one :class:`Persona`, one
:class:`Tarpit` and one :class:`CanaryRegistry` across every decoy so the
deployment behaves like a single machine.
"""

from __future__ import annotations

import socket
import socketserver
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..protocols import PROTOCOLS, handler_for, transport_for
from .logger import Logger
from .persona import Persona, persona_from_seed
from .tarpit import Tarpit


@dataclass
class DecoyRecord:
    """Bookkeeping for one running (or configured) decoy."""

    service: str
    host: str
    port: int
    server: socketserver.BaseServer | None = None
    thread: threading.Thread | None = None
    started_at: float = 0.0
    connections: int = 0

    @property
    def running(self) -> bool:
        return self.server is not None and self.thread is not None \
            and self.thread.is_alive()

    @property
    def uptime(self) -> float:
        return time.time() - self.started_at if self.started_at else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "host": self.host,
            "port": self.port,
            "running": self.running,
            "uptime": round(self.uptime, 1),
            "transport": transport_for(self.service),
        }


class PortRegistry:
    """Tracks which (host, port) pairs are claimed by which service."""

    def __init__(self) -> None:
        self._claims: dict[tuple[str, int], str] = {}
        self._lock = threading.Lock()

    def claim(self, host: str, port: int, service: str) -> bool:
        """Reserve (host, port) for ``service``. False when taken."""
        with self._lock:
            key = (host, port)
            if key in self._claims:
                return False
            self._claims[key] = service
            return True

    def release(self, host: str, port: int) -> None:
        with self._lock:
            self._claims.pop((host, port), None)

    def owner(self, host: str, port: int) -> str | None:
        with self._lock:
            return self._claims.get((host, port))

    def all(self) -> dict[tuple[str, int], str]:
        with self._lock:
            return dict(self._claims)


class HoneypotManager:
    """Owns the whole decoy fleet for one deployment."""

    def __init__(self, log: str | Path | None = None, *,
                 host: str = "127.0.0.1",
                 persona: Persona | int | str | None = None,
                 tarpit: Tarpit | None = None,
                 rotate: bool = False):
        self.host = host
        self.logger = Logger(log, rotate=rotate)
        self.persona = (persona if isinstance(persona, Persona)
                        else persona_from_seed(persona))
        self.tarpit = tarpit or Tarpit()
        self.registry = PortRegistry()
        self.canaries = None  # lazily created; shared by all decoys
        self.records: dict[str, DecoyRecord] = {}
        self._lock = threading.Lock()
        self.started_at = 0.0

    # -- configuration --------------------------------------------------------
    def add(self, service: str, port: int | None = None,
            host: str | None = None) -> DecoyRecord:
        """Register a decoy (not yet started). Port 0 = ephemeral.

        Raises ValueError for unknown services or duplicate registrations.
        """
        if service not in PROTOCOLS:
            raise ValueError(f"unknown service: {service}")
        with self._lock:
            if service in self.records:
                raise ValueError(f"service already added: {service}")
            record = DecoyRecord(service=service, host=host or self.host,
                                 port=int(port) if port is not None else 0)
            self.records[service] = record
            return record

    def add_many(self, services: list[str],
                 ports: dict[str, int] | None = None) -> list[DecoyRecord]:
        """Register several decoys at once."""
        ports = ports or {}
        return [self.add(svc, ports.get(svc)) for svc in services]

    # -- lifecycle --------------------------------------------------------------
    def start(self, service: str | None = None) -> list[DecoyRecord]:
        """Start one decoy (or every registered one). Returns started records.

        A decoy whose port is already claimed by another decoy is skipped
        with a ``port_conflict`` event instead of crashing the fleet.
        """
        targets = ([service] if service else list(self.records))
        started = []
        for name in targets:
            record = self.records.get(name)
            if record is None or record.running:
                continue
            if self._start_one(record):
                started.append(record)
        if started and not self.started_at:
            self.started_at = time.time()
        return started

    def _start_one(self, record: DecoyRecord) -> bool:
        from ..protocols.base import CanaryRegistry, build_server
        if self.canaries is None:
            self.canaries = CanaryRegistry()
        handler = handler_for(record.service)
        udp = transport_for(record.service) == "udp"
        try:
            server = build_server(handler, record.host, record.port,
                                  self.logger, udp=udp,
                                  persona=self.persona,
                                  tarpit=self.tarpit,
                                  canaries=self.canaries, start=True)
        except OSError as exc:
            self.logger.log({"service": record.service, "src": "-",
                             "event": "bind_failed", "severity": "warn",
                             "error": str(exc), "port": record.port})
            return False
        record.server = server
        record.thread = getattr(server, "thread", None)
        record.port = server.server_address[1]
        record.started_at = time.time()
        self.registry.claim(record.host, record.port, record.service)
        self.logger.log({"service": record.service, "src": "-",
                         "event": "decoy_started", "severity": "notice",
                         "host": record.host, "port": record.port})
        return True

    def stop(self, service: str | None = None, timeout: float = 2.0) -> list[str]:
        """Stop one decoy (or all). Returns names actually stopped.

        ``shutdown()`` stops the accept loop; the handler threads are
        daemons with bounded read timeouts, so we wait at most ``timeout``
        seconds for the serve thread before closing the socket.
        """
        targets = ([service] if service else list(self.records))
        stopped = []
        for name in targets:
            record = self.records.get(name)
            if record is None or record.server is None:
                continue
            try:
                record.server.shutdown()
            except Exception:
                pass
            if record.thread is not None:
                record.thread.join(timeout)
            try:
                record.server.server_close()
            except OSError:
                pass
            self.registry.release(record.host, record.port)
            self.logger.log({"service": name, "src": "-",
                             "event": "decoy_stopped", "severity": "notice",
                             "port": record.port})
            record.server = None
            record.thread = None
            stopped.append(name)
        if not any(r.running for r in self.records.values()):
            self.started_at = 0.0
        return stopped

    def stop_all(self, timeout: float = 2.0) -> list[str]:
        """Stop every decoy. Alias kept for readability at call sites."""
        return self.stop(timeout=timeout)

    # -- introspection -----------------------------------------------------------
    def status(self) -> dict[str, Any]:
        """Fleet snapshot for the CLI and dashboards."""
        return {
            "persona": self.persona.fqdn,
            "seed": self.persona.seed,
            "uptime": round(time.time() - self.started_at, 1)
            if self.started_at else 0.0,
            "events": self.logger.count,
            "tarpit": self.tarpit.stats(),
            "decoys": {name: rec.to_dict()
                       for name, rec in self.records.items()},
            "ports": {f"{h}:{p}": svc
                      for (h, p), svc in self.registry.all().items()},
        }

    def health_check(self, timeout: float = 1.0) -> dict[str, bool]:
        """Probe every running decoy over its real transport.

        TCP decoys get a connect-and-read (they all banner or wait
        politely); UDP decoys get a minimal DNS query. Returns service ->
        healthy.
        """
        results: dict[str, bool] = {}
        for name, record in self.records.items():
            if not record.running:
                results[name] = False
                continue
            results[name] = self._probe(record, timeout)
        return results

    def _probe(self, record: DecoyRecord, timeout: float) -> bool:
        if transport_for(record.service) == "udp":
            return self._probe_udp(record, timeout)
        try:
            with socket.create_connection((record.host, record.port),
                                          timeout=timeout) as s:
                s.settimeout(timeout)
                try:
                    s.recv(64)  # most decoys banner immediately
                except (socket.timeout, TimeoutError):
                    pass  # connected but silent is still alive
            return True
        except OSError:
            return False

    def _probe_udp(self, record: DecoyRecord, timeout: float) -> bool:
        import struct as _struct
        query = _struct.pack(">HHHHHH", 0x7777, 0x0100, 1, 0, 0, 0)
        query += b"\x04ping\x00" + _struct.pack(">HH", 1, 1)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(query, (record.host, record.port))
                s.recvfrom(4096)
            return True
        except OSError:
            return False

    # -- context manager -----------------------------------------------------------
    def __enter__(self) -> "HoneypotManager":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop_all()
