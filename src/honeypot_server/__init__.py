"""Honeypot Server — fake services that log everyone who knocks.

Spin up convincing-looking decoys (HTTP, FTP, SSH, SMTP, DNS, telnet,
redis, mysql) and record every handshake, banner grab, and probe into a
JSONL log. On top of the decoys sits a deception layer: a persona engine
that keeps every protocol telling one consistent fake-identity story, a
tar pit that slows attackers down, canary tokens that scream when
touched, attacker profiling with simplified MITRE ATT&CK mapping, IOC
feeds, dashboards, session replay, and a 0-100 deception score.

Defensive tooling for your own network. Pure standard library.
"""

from __future__ import annotations

import socket
import socketserver
import threading
from pathlib import Path

from .core.logger import Logger, make_event, hash_credential
from .core.persona import Persona, persona_from_seed
from .core.tarpit import Tarpit, TarpitConfig
from .core.server import HoneypotManager
from .core.config import DeploymentConfig, from_dict as config_from_dict
from .protocols import PROTOCOLS, handler_for, known_services
from .protocols.base import CanaryRegistry, build_server
from .intel.attacker import AttackerTracker, classify, map_ttps
from .intel.deception import score_deployment
from .canary.tokens import CanaryTokenFactory

DEFAULT_PORTS = {
    "http": 80,
    "ftp": 21,
    "ssh": 22,
    "smtp": 25,
    "dns": 53,
}

BANNERS = {
    "http": b"HTTP/1.1 404 Not Found\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n",
    "ftp": b"220 honeypot FTP server ready.\r\n",
    "ssh": b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    "smtp": b"220 mail.example.com ESMTP Postfix\r\n",
}

FAKE_PAGES = {
    "http": (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 198\r\n\r\n"
        b"<html><head><title>Intranet</title></head><body>"
        b"<h1>Internal Portal</h1><p>Login required.</p>"
        b"<form><input name='user'><input type='password' name='pass'>"
        b"<button>Sign in</button></form></body></html>"
    ),
}


class ServiceHandler(socketserver.BaseRequestHandler):
    """Speaks just enough of a protocol to look real, logs everything."""

    service = "tcp"

    def handle(self) -> None:
        logger: Logger = self.server.logger
        sock = self.request
        addr = f"{self.client_address[0]}:{self.client_address[1]}"
        sock.settimeout(8)

        banner = BANNERS.get(self.service)
        if banner:
            self._send(banner)
            logger.log({"service": self.service, "src": addr, "event": "banner"})

        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            except OSError:
                break
            if not data:
                break
            text = data.decode("utf-8", "replace").strip()
            logger.log({"service": self.service, "src": addr, "event": "data", "data": text[:400]})
            reply = self._reply(text)
            if reply:
                self._send(reply)

    def _send(self, payload: bytes) -> None:
        try:
            self.request.sendall(payload)
        except OSError:
            pass

    def _reply(self, text: str) -> bytes | None:
        if self.service == "http":
            if text.lower().startswith(("get ", "post ", "head ")):
                return FAKE_PAGES["http"]
            return None
        if self.service == "ftp":
            if text.upper().startswith(("USER", "PASS")):
                return b"530 Login incorrect.\r\n"
            return b"500 Unknown command.\r\n"
        if self.service == "smtp":
            if text.upper().startswith(("EHLO", "HELO")):
                return b"250 mail.example.com\r\n"
            if text.upper().startswith(("AUTH", "MAIL", "RCPT")):
                return b"502 Not implemented.\r\n"
            return b"500 Command unrecognized.\r\n"
        return None


class HTTPServiceHandler(ServiceHandler):
    service = "http"


class FTPServiceHandler(ServiceHandler):
    service = "ftp"


class SSHServiceHandler(ServiceHandler):
    service = "ssh"


class SMTPServiceHandler(ServiceHandler):
    service = "smtp"


class DNSServiceHandler(socketserver.BaseRequestHandler):
    """UDP DNS decoy — logs the query name, answers nothing."""

    def handle(self) -> None:
        data, sock = self.request
        addr = f"{self.client_address[0]}:{self.client_address[1]}"
        if len(data) >= 13:
            i = 12
            labels = []
            while i < len(data) and data[i] != 0:
                n = data[i]
                labels.append(data[i + 1:i + 1 + n].decode("ascii", "replace"))
                i += 1 + n
            self.server.logger.log({
                "service": "dns", "src": addr, "event": "query",
                "data": ".".join(labels),
            })


HANDLERS = {
    "http": HTTPServiceHandler,
    "ftp": FTPServiceHandler,
    "ssh": SSHServiceHandler,
    "smtp": SMTPServiceHandler,
    "dns": DNSServiceHandler,
}


def run_server(service: str, host: str, port: int, logger: Logger,
               stop: threading.Event):
    """Start a single decoy service. Returns the server object."""
    handler = HANDLERS[service]

    if service == "dns":
        server = socketserver.ThreadingUDPServer((host, port), handler)
    else:
        server = socketserver.ThreadingTCPServer((host, port), handler)
    server.logger = logger
    server.stop_event = stop

    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def run(services: list[str], host: str, ports: dict[str, int] | None = None,
        log: str | Path | None = None, stop: threading.Event | None = None) -> list:
    """Start all requested services. Returns the server objects."""
    ports = ports or {}
    logger = Logger(log)
    stop = stop or threading.Event()
    servers = []
    for svc in services:
        port = ports.get(svc, DEFAULT_PORTS[svc])
        s = run_server(svc, host, port, logger, stop)
        servers.append(s)
        print(f"[+] {svc} decoy on {host}:{port}"
              + (f"  -> {log}" if log else "  (console)"))
    return servers


__all__ = [
    # legacy 0.1.0 API (kept stable)
    "DEFAULT_PORTS", "BANNERS", "FAKE_PAGES", "HANDLERS",
    "Logger", "make_event", "hash_credential",
    "run_server", "run",
    # 0.2.0 platform API
    "Persona", "persona_from_seed",
    "Tarpit", "TarpitConfig",
    "HoneypotManager",
    "DeploymentConfig", "config_from_dict",
    "PROTOCOLS", "handler_for", "known_services",
    "CanaryRegistry", "build_server",
    "AttackerTracker", "classify", "map_ttps",
    "score_deployment",
    "CanaryTokenFactory",
]