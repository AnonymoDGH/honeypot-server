"""Shared scaffolding for every protocol decoy.

Each decoy in :mod:`honeypot_server.protocols` is a socketserver handler
built on :class:`ProtocolHandler`, which provides:

* a per-connection session id and source address string;
  
* ``emit()`` -- structured event logging through the canonical schema
  (core.logger.make_event), with optional canary-token scanning;

* safe socket I/O helpers (``send``, ``recv_line``, ``recv_bytes``) that
  swallow client disconnects instead of raising into socketserver;

* tarpit hooks so every protocol paces itself through the same policy.

The module also exposes :func:`build_server`, the factory every runner
(the legacy ``run_server`` and the new lifecycle manager) uses to attach a
logger, persona, tarpit and canary registry to a socketserver instance.
"""

from __future__ import annotations

import socket
import socketserver
import threading
import uuid
from typing import Any

from ..core.logger import Logger, make_event
from ..core.persona import Persona
from ..core.tarpit import Tarpit, get_tarpit

#: Per-connection read timeout. Attackers that go silent should not pin a
#: decoy thread forever; real clients retransmit or reconnect.
DEFAULT_TIMEOUT = 8.0

#: Largest single read/line we will accept before dropping a connection.
MAX_LINE = 8192


class CanaryRegistry:
    """Lookup table of canary token values the decoys watch for.

    The canary package (honeypot_server.canary.tokens) produces tokens;
    when any protocol sees a registered value inside attacker-supplied
    data it raises a critical event. Values are matched as substrings of
    the decoded payload, case-sensitively.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def register(self, value: str, kind: str = "generic", **meta: Any) -> None:
        """Watch for ``value``; ``kind`` and ``meta`` ride the alert event."""
        with self._lock:
            self._tokens[value] = {"kind": kind, **meta}

    def unregister(self, value: str) -> bool:
        with self._lock:
            return self._tokens.pop(value, None) is not None

    def scan(self, text: str) -> list[dict[str, Any]]:
        """Return metadata dicts for every registered token found in text."""
        if not text:
            return []
        hits = []
        with self._lock:
            for value, meta in self._tokens.items():
                if value and value in text:
                    hits.append({"token": value, **meta})
        return hits

    def items(self) -> list[tuple[str, dict[str, Any]]]:
        """Snapshot of (value, metadata) pairs for iteration."""
        with self._lock:
            return [(v, dict(m)) for v, m in self._tokens.items()]

    def __len__(self) -> int:
        with self._lock:
            return len(self._tokens)

    def __contains__(self, value: str) -> bool:
        with self._lock:
            return value in self._tokens


class ProtocolHandler(socketserver.BaseRequestHandler):
    """Base class for all TCP decoy handlers.

    Subclasses set ``service`` and implement :meth:`handle`. The server
    object is expected to carry ``logger``, ``persona``, ``tarpit`` and
    ``canaries`` attributes (see :func:`build_server`); missing attributes
    fall back to safe defaults so handlers also work under the legacy
    ``run_server`` wiring.
    """

    service: str = "tcp"
    timeout: float = DEFAULT_TIMEOUT

    # -- lifecycle -----------------------------------------------------------
    def setup(self) -> None:
        self.session_id = uuid.uuid4().hex[:10]
        self.src = f"{self.client_address[0]}:{self.client_address[1]}"
        self.ip = self.client_address[0]
        self.closed = False
        try:
            self.request.settimeout(self.timeout)
        except OSError:
            pass

    # -- context accessors ---------------------------------------------------
    @property
    def logger(self) -> Logger:
        return self.server.logger  # type: ignore[attr-defined]

    @property
    def persona(self) -> Persona:
        return getattr(self.server, "persona", None) or Persona.default()

    @property
    def tarpit(self) -> Tarpit:
        return getattr(self.server, "tarpit", None) or get_tarpit()

    @property
    def canaries(self) -> CanaryRegistry:
        registry = getattr(self.server, "canaries", None)
        if registry is None:
            registry = CanaryRegistry()
            self.server.canaries = registry  # type: ignore[attr-defined]
        return registry

    # -- logging ---------------------------------------------------------------
    def emit(self, event: str, *, severity: str = "info",
             data: str | None = None, **fields: Any) -> dict[str, Any]:
        """Log one structured event for this session.

        Every event carries the session id and service. If ``data`` (or any
        string field) contains a registered canary token, an additional
        critical ``canary_hit`` event is emitted and the original event is
        tagged with ``canary=True``.
        """
        entry = make_event(self.service, self.src, event, severity=severity,
                           data=data, session=self.session_id, **fields)
        haystacks = [v for v in [data, *[
            f for f in fields.values() if isinstance(f, str)]] if v]
        hits = []
        for hay in haystacks:
            hits.extend(self.canaries.scan(hay))
        if hits:
            entry["canary"] = True
            self.logger.log(entry)
            for hit in hits:
                alert = make_event(self.service, self.src, "canary_hit",
                                   severity="critical",
                                   session=self.session_id,
                                   canary_kind=hit.get("kind", "generic"),
                                   canary_id=hit.get("id", ""),
                                   canary_note=hit.get("note", ""))
                self.logger.log(alert)
            return entry
        return self.logger.log(entry)

    def scan_canaries(self, text: str) -> list[dict[str, Any]]:
        """Scan raw text for canary tokens WITHOUT storing the text.

        Credential paths mask or hash secrets before they reach emit(),
        which would hide a planted token from the scanner. This method
        closes that gap: it checks the raw value, raises the critical
        canary_hit events, and returns the hits -- but the secret itself
        never lands in the log.
        """
        hits = self.canaries.scan(text)
        for hit in hits:
            self.logger.log(make_event(
                self.service, self.src, "canary_hit", severity="critical",
                session=self.session_id,
                canary_kind=hit.get("kind", "generic"),
                canary_id=hit.get("id", ""),
                canary_note=hit.get("note", "")))
        return hits

    # -- socket I/O -----------------------------------------------------------
    def send(self, payload: bytes) -> bool:
        """Send all of ``payload``; False when the peer went away."""
        if not payload or self.closed:
            return False
        try:
            self.request.sendall(payload)
            return True
        except OSError:
            self.closed = True
            return False

    def send_text(self, text: str) -> bool:
        """UTF-8 convenience wrapper around :meth:`send`."""
        return self.send(text.encode("utf-8", "replace"))

    def recv_bytes(self, size: int = 4096) -> bytes:
        """One read; empty bytes on timeout, disconnect or error."""
        try:
            return self.request.recv(size)
        except (socket.timeout, TimeoutError, OSError):
            return b""

    def recv_line(self, limit: int = MAX_LINE,
                  terminators: tuple[bytes, ...] = (b"\r\n", b"\n")) -> bytes | None:
        """Read until a line terminator; None on EOF/timeout.

        Returns the line *without* the terminator. Lines longer than
        ``limit`` are truncated to it (the remainder stays in the stream,
        which is fine for a decoy).
        """
        buf = bytearray()
        while len(buf) < limit:
            chunk = self.recv_bytes(1)
            if not chunk:
                return bytes(buf) if buf else None
            buf.extend(chunk)
            for term in terminators:
                if buf.endswith(term):
                    return bytes(buf[: -len(term)])
        return bytes(buf)

    def pause(self) -> float:
        """Apply this service's tarpit delay. Returns seconds waited."""
        return self.tarpit.wait(self.service)


class UDPProtocolHandler(socketserver.BaseRequestHandler):
    """Base class for datagram decoys (DNS). Mirrors ProtocolHandler."""

    service: str = "udp"

    def setup(self) -> None:
        self.session_id = uuid.uuid4().hex[:10]
        self.src = f"{self.client_address[0]}:{self.client_address[1]}"
        self.ip = self.client_address[0]

    @property
    def logger(self) -> Logger:
        return self.server.logger  # type: ignore[attr-defined]

    @property
    def persona(self) -> Persona:
        return getattr(self.server, "persona", None) or Persona.default()

    @property
    def canaries(self) -> CanaryRegistry:
        registry = getattr(self.server, "canaries", None)
        if registry is None:
            registry = CanaryRegistry()
            self.server.canaries = registry  # type: ignore[attr-defined]
        return registry

    def emit(self, event: str, *, severity: str = "info",
             data: str | None = None, **fields: Any) -> dict[str, Any]:
        """Structured event logging for datagram sessions."""
        entry = make_event(self.service, self.src, event, severity=severity,
                           data=data, session=self.session_id, **fields)
        hits = self.canaries.scan(data or "")
        if hits:
            entry["canary"] = True
            self.logger.log(entry)
            for hit in hits:
                self.logger.log(make_event(
                    self.service, self.src, "canary_hit", severity="critical",
                    session=self.session_id,
                    canary_kind=hit.get("kind", "generic"),
                    canary_id=hit.get("id", "")))
            return entry
        return self.logger.log(entry)

    def reply(self, payload: bytes) -> bool:
        """Answer the datagram peer; False on send failure."""
        data, sock = self.request
        try:
            sock.sendto(payload, self.client_address)
            return True
        except OSError:
            return False


def build_server(handler_cls: type, host: str, port: int, logger: Logger, *,
                 udp: bool = False, persona: Persona | None = None,
                 tarpit: Tarpit | None = None,
                 canaries: CanaryRegistry | None = None,
                 stop: threading.Event | None = None,
                 start: bool = False) -> socketserver.BaseServer:
    """Create (and optionally start) a threaded socketserver for a decoy.

    Attaches ``logger``, ``persona``, ``tarpit``, ``canaries`` and
    ``stop_event`` so handlers see one consistent context regardless of
    which runner started them.
    """
    if udp:
        server: socketserver.BaseServer = socketserver.ThreadingUDPServer(
            (host, port), handler_cls)
    else:
        server = socketserver.ThreadingTCPServer((host, port), handler_cls)
    server.daemon_threads = True
    server.allow_reuse_address = True
    server.logger = logger
    server.persona = persona or Persona.default()
    server.tarpit = tarpit or get_tarpit()
    server.canaries = canaries if canaries is not None else CanaryRegistry()
    server.stop_event = stop or threading.Event()
    if start:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        server.thread = thread  # type: ignore[attr-defined]
    return server
