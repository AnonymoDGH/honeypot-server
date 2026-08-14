"""Honeypot Server — fake services that log everyone who knocks.

Spin up convincing-looking decoys (HTTP, FTP, SSH, SMTP, DNS) and record
every handshake, banner grab, and probe into a JSONL log. Perfect for
watching what rattles around your network — or for the scene where the
villain trips a decoy and everyone knows he was there.

Pure standard library.
"""

from __future__ import annotations

import json
import socket
import socketserver
import threading
import time
from pathlib import Path

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


class Logger:
    """Thread-safe JSONL logger."""

    def __init__(self, path: str | Path | None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()

    def log(self, entry: dict) -> None:
        entry["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
        line = json.dumps(entry, ensure_ascii=False)
        if self.path:
            with self._lock:
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
        else:
            print(f"  [{entry['service']}] {entry.get('src', '?')}: {line}")


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


__all__ = ["DEFAULT_PORTS", "HANDLERS", "Logger", "run_server", "run"]
