"""HTTP decoy -- request parsing, virtual filesystem, credential capture.

Unlike the original banner-only decoy, this handler parses real HTTP/1.x
requests (method, path, version, headers, body) and serves a virtual
filesystem of fake pages: an intranet login, a fake admin panel, robots.txt
bait and a 404 maze that leads scanners in circles.

Deception details:

* POSTed form bodies are parsed; fields that look like credentials are
  logged as SHA-256 digests only (never plaintext).
* every response carries the persona's Server header so fingerprints
  agree across protocols;
* unknown paths fall into a deterministic 404 maze whose links point at
  other fake paths, wasting crawler time.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, unquote, urlparse

from ..core.logger import hash_credential
from ..core.persona import Persona
from .base import ProtocolHandler

#: Header/body separator for HTTP/1.x.
CRLF = b"\r\n"

#: Form field names that indicate a credential attempt (lowercased).
CREDENTIAL_FIELDS = {
    "user", "username", "login", "email", "account", "usr", "uid",
    "pass", "password", "passwd", "pwd", "secret", "pin",
}

#: Common scanner paths worth an explicit "interesting" fake page.
BAIT_PATHS = ("/admin", "/wp-login.php", "/phpmyadmin", "/.env",
              "/config.php", "/backup.sql", "/api/v1/token")


@dataclass
class HTTPRequest:
    """A parsed HTTP request."""

    method: str = ""
    path: str = "/"
    version: str = "HTTP/1.1"
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    raw: bytes = b""
    error: str | None = None

    @property
    def clean_path(self) -> str:
        """Path without query string, decoded once."""
        return unquote(urlparse(self.path).path) or "/"

    def header(self, name: str, default: str = "") -> str:
        """Case-insensitive header lookup."""
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return default

    def form(self) -> dict[str, str]:
        """Parse an urlencoded form body into a dict (last value wins)."""
        if not self.body:
            return {}
        try:
            text = self.body.decode("utf-8", "replace")
        except Exception:
            return {}
        return dict(parse_qsl(text, keep_blank_values=True))


def parse_request(raw: bytes) -> HTTPRequest:
    """Parse raw request bytes into an :class:`HTTPRequest`.

    Tolerant of malformed input: a bad request line sets ``error`` instead
    of raising, so the handler can answer 400 like a real server.
    """
    req = HTTPRequest(raw=raw)
    head, _, body = raw.partition(CRLF + CRLF)
    lines = head.split(CRLF)
    if not lines or not lines[0]:
        req.error = "empty request"
        return req
    parts = lines[0].decode("utf-8", "replace").split(" ")
    if len(parts) != 3 or not parts[2].upper().startswith("HTTP/"):
        req.error = f"bad request line: {lines[0][:80]!r}"
        return req
    req.method = parts[0].upper()
    req.path = parts[1]
    req.version = parts[2].upper()
    for line in lines[1:]:
        text = line.decode("utf-8", "replace")
        name, sep, value = text.partition(":")
        if sep:
            req.headers[name.strip()] = value.strip()
    req.body = body
    return req


class VirtualFS:
    """The fake site a persona serves: pages keyed by path.

    Built from the persona so hostnames and branding agree with every
    other decoy. ``render()`` returns (status, content_type, body).
    """

    def __init__(self, persona: Persona):
        self.persona = persona
        self.pages: dict[str, tuple[int, str, str]] = {}
        self._build()

    def _page(self, title: str, body_html: str) -> str:
        return (f"<html><head><title>{title}</title></head>"
                f"<body>{body_html}</body></html>")

    def _login_form(self, action: str, title: str) -> str:
        return self._page(title, (
            f"<h1>{self.persona.org_name} \u2014 {title}</h1>"
            "<p>Authorized personnel only.</p>"
            f'<form method="POST" action="{action}">'
            '<input name="user" placeholder="Username">'
            '<input type="password" name="pass" placeholder="Password">'
            "<button>Sign in</button></form>"))

    def _build(self) -> None:
        p = self.persona
        self.pages["/"] = (200, "text/html", self._page(
            f"{p.hostname} intranet",
            f"<h1>{p.org_name} Internal Portal</h1>"
            "<p>Welcome. Choose a service:</p><ul>"
            '<li><a href="/login">Staff login</a></li>'
            '<li><a href="/admin">Admin console</a></li>'
            '<li><a href="/status">System status</a></li></ul>'))
        self.pages["/login"] = (200, "text/html",
                                self._login_form("/login", "Staff Login"))
        self.pages["/admin"] = (200, "text/html",
                                self._login_form("/admin", "Admin Console"))
        self.pages["/status"] = (200, "text/plain", (
            f"host: {p.fqdn}\nos: {p.os} {p.os_version}\n"
            f"kernel: {p.kernel}\nuptime: 42 days\nload: 0.08 0.03 0.01\n"))
        self.pages["/robots.txt"] = (200, "text/plain", (
            "User-agent: *\nDisallow: /admin\nDisallow: /backup\n"
            "Disallow: /internal\n"))
        self.pages["/.env"] = (200, "text/plain", (
            "APP_KEY=base64:fakefakefakefakefakefakefakefake\n"
            f"DB_HOST={p.ip_story}\nDB_PASSWORD=changeme123\n"
            "AWS_SECRET_ACCESS_KEY=AKIAFAKEFAKEFAKEFAKE\n"))
        self.pages["/backup.sql"] = (200, "application/octet-stream", (
            "-- MySQL dump (truncated)\nCREATE TABLE users (id INT, name TEXT);\n"
            "INSERT INTO users VALUES (1, 'admin');\n"))

    def render(self, path: str) -> tuple[int, str, str]:
        """Serve ``path`` or fall into the 404 maze."""
        if path in self.pages:
            return self.pages[path]
        if path in BAIT_PATHS:
            return (200, "text/html",
                    self._login_form(path, "Restricted Area"))
        return maze_page(path)


def maze_page(path: str) -> tuple[int, str, str]:
    """Deterministic 404 maze: the links depend on the requested path.

    A crawler following "helpful" links walks a cycle of fake paths, each
    of which 404s with more links. Deterministic so repeated scans see a
    stable site.
    """
    digest = hashlib.sha1(path.encode("utf-8", "replace")).hexdigest()
    seed = int(digest[:8], 16)
    words = ("archive", "internal", "legacy", "tmp", "old", "draft",
             "mirror", "cache", "export", "reports")
    links = []
    for i in range(3):
        word = words[(seed + i * 7) % len(words)]
        num = (seed >> (i * 4)) % 900 + 100
        links.append(f'<li><a href="/{word}/{num}">{word}-{num}</a></li>')
    body = ("<h1>404 Not Found</h1><p>The page you requested is gone.</p>"
            "<p>You might be looking for:</p><ul>" + "".join(links) + "</ul>")
    return (404, "text/html",
            f"<html><head><title>404 Not Found</title></head>"
            f"<body>{body}</body></html>")


def extract_credentials(form: dict[str, str]) -> dict[str, str]:
    """Pull credential-looking fields out of a form, hashed.

    Returns a dict with ``user`` (plaintext -- usernames are low-sensitivity
    and needed for attack profiling) and ``pass_sha256`` (digest only).
    Empty result when nothing credential-like was submitted.
    """
    user = ""
    secret = ""
    for name, value in form.items():
        lowered = name.lower()
        if lowered in CREDENTIAL_FIELDS:
            if "pass" in lowered or "secret" in lowered or "pin" in lowered:
                secret = value
            elif not user:
                user = value
    if not user and not secret:
        return {}
    out: dict[str, str] = {}
    if user:
        out["user"] = user
    if secret:
        out["pass_sha256"] = hash_credential(secret)
    return out


class HTTPHandler(ProtocolHandler):
    """Full HTTP decoy: parse, serve the virtual FS, capture credentials."""

    service = "http"

    def handle(self) -> None:
        self.fs = VirtualFS(self.persona)
        self.emit("connect")
        while not self.closed:
            raw = self._read_request()
            if raw is None:
                break
            req = parse_request(raw)
            self._respond(req)
            if req.header("Connection", "keep-alive").lower() == "close":
                break
            if req.version == "HTTP/1.0":
                break

    def _read_request(self) -> bytes | None:
        """Read headers plus any Content-Length body. None on EOF/timeout."""
        buf = bytearray()
        while CRLF + CRLF not in buf:
            chunk = self.recv_bytes(1024)
            if not chunk:
                return bytes(buf) if buf else None
            buf.extend(chunk)
            if len(buf) > 65536:
                break
        head, _, rest = bytes(buf).partition(CRLF + CRLF)
        length = 0
        for line in head.split(CRLF)[1:]:
            name, sep, value = line.decode("utf-8", "replace").partition(":")
            if sep and name.strip().lower() == "content-length":
                try:
                    length = min(int(value.strip()), 65536)
                except ValueError:
                    length = 0
        body = bytearray(rest)
        while len(body) < length:
            chunk = self.recv_bytes(min(4096, length - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        return head + CRLF + CRLF + bytes(body)

    def _respond(self, req: HTTPRequest) -> None:
        self.emit("request", data=f"{req.method} {req.path} {req.version}",
                  method=req.method, path=req.clean_path,
                  headers=dict(req.headers))
        if req.error:
            self._send_response(400, "text/plain", "400 Bad Request\n", req)
            return
        if req.method == "POST":
            self._capture(req)
        status, ctype, body = self.fs.render(req.clean_path)
        if req.method == "HEAD":
            body = ""
        self.pause()
        self._send_response(status, ctype, body, req)

    def _capture(self, req: HTTPRequest) -> None:
        creds = extract_credentials(req.form())
        if creds:
            self.emit("credential_capture", severity="alert",
                      path=req.clean_path, **creds)

    def _send_response(self, status: int, ctype: str, body: str,
                       req: HTTPRequest) -> None:
        reasons = {200: "OK", 400: "Bad Request", 404: "Not Found"}
        reason = reasons.get(status, "OK")
        payload = body.encode("utf-8", "replace")
        lines = [f"HTTP/1.1 {status} {reason}",
                 f"Server: {self.persona.http_server_header()}",
                 f"Content-Type: {ctype}; charset=utf-8",
                 f"Content-Length: {len(payload)}",
                 "Connection: close"]
        head = "\r\n".join(lines) + "\r\n\r\n"
        self.send(head.encode("utf-8") + payload)
        self.closed = True  # Connection: close ends keep-alive loops
