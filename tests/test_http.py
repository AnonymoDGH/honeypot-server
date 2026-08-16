"""Tests for the HTTP decoy: parsing, virtual FS, maze, credential capture."""

import json
import socket
import time

from honeypot_server.core.logger import Logger, hash_credential
from honeypot_server.core.persona import Persona
from honeypot_server.protocols.base import build_server
from honeypot_server.protocols.http import (
    HTTPHandler,
    HTTPRequest,
    VirtualFS,
    extract_credentials,
    maze_page,
    parse_request,
)


def _start(tmp_path, persona=None):
    logger = Logger(tmp_path / "http.jsonl")
    server = build_server(HTTPHandler, "127.0.0.1", 0, logger,
                          persona=persona or Persona.generate(1), start=True)
    port = server.server_address[1]
    return server, logger, port


def _get(port, request: bytes, timeout=3.0) -> bytes:
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.sendall(request)
        chunks = []
        while True:
            try:
                data = s.recv(4096)
            except (socket.timeout, TimeoutError):
                break
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)
    finally:
        s.close()


def _wait_for(log, needle, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if log.exists() and needle in log.read_text(encoding="utf-8"):
            return True
        time.sleep(0.05)
    return False


class TestParseRequest:
    def test_basic_get(self):
        raw = b"GET /admin?p=1 HTTP/1.1\r\nHost: x\r\nUser-Agent: t\r\n\r\n"
        req = parse_request(raw)
        assert req.method == "GET" and req.version == "HTTP/1.1"
        assert req.path == "/admin?p=1" and req.clean_path == "/admin"
        assert req.header("host") == "x"
        assert req.header("USER-AGENT") == "t"
        assert req.error is None

    def test_post_body(self):
        raw = (b"POST /login HTTP/1.1\r\nContent-Length: 15\r\n\r\n"
               b"user=a&pass=b%21c")
        req = parse_request(raw)
        assert req.method == "POST"
        assert req.form() == {"user": "a", "pass": "b!c"}

    def test_bad_request_line(self):
        req = parse_request(b"GARBAGE\r\n\r\n")
        assert req.error

    def test_empty_request(self):
        assert parse_request(b"").error

    def test_header_default(self):
        req = HTTPRequest()
        assert req.header("Missing", "dflt") == "dflt"


class TestVirtualFS:
    def setup_method(self):
        self.fs = VirtualFS(Persona.generate(2))

    def test_root_page(self):
        status, ctype, body = self.fs.render("/")
        assert status == 200 and ctype == "text/html"
        assert "Internal Portal" in body

    def test_login_and_admin_forms(self):
        for path in ("/login", "/admin"):
            status, _, body = self.fs.render(path)
            assert status == 200
            assert 'name="user"' in body and 'type="password"' in body

    def test_status_page_matches_persona(self):
        p = self.fs.persona
        _, _, body = self.fs.render("/status")
        assert p.fqdn in body and p.kernel in body

    def test_robots_disallows_admin(self):
        _, _, body = self.fs.render("/robots.txt")
        assert "Disallow: /admin" in body

    def test_env_bait(self):
        status, _, body = self.fs.render("/.env")
        assert status == 200 and "AWS_SECRET_ACCESS_KEY" in body

    def test_unknown_path_hits_maze(self):
        status, _, body = self.fs.render("/definitely/not/here")
        assert status == 404 and "404 Not Found" in body
        assert "<a href=" in body

    def test_maze_is_deterministic_and_varies(self):
        a1 = maze_page("/x")[2]
        a2 = maze_page("/x")[2]
        assert a1 == a2
        assert maze_page("/x")[2] != maze_page("/y")[2]


class TestExtractCredentials:
    def test_user_and_password(self):
        out = extract_credentials({"user": "admin", "pass": "hunter2"})
        assert out["user"] == "admin"
        assert out["pass_sha256"] == hash_credential("hunter2")
        assert "hunter2" not in json.dumps(out)

    def test_various_field_names(self):
        out = extract_credentials({"Email": "a@b.c", "PASSWORD": "x"})
        assert out["user"] == "a@b.c" and "pass_sha256" in out

    def test_non_credential_form(self):
        assert extract_credentials({"q": "search", "page": "2"}) == {}

    def test_password_only(self):
        out = extract_credentials({"pin": "1234"})
        assert "user" not in out and out["pass_sha256"]


class TestLiveServer:
    def test_get_served_with_persona_header(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            resp = _get(port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            assert resp.startswith(b"HTTP/1.1 200 OK")
            assert server.persona.http_server_header().encode() in resp
            assert b"Internal Portal" in resp
            assert _wait_for(logger.path, "\"event\": \"request\"") or \
                _wait_for(logger.path, "\"request\"")
        finally:
            server.shutdown(); server.server_close()

    def test_404_maze_served(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            resp = _get(port, b"GET /nope HTTP/1.1\r\nHost: x\r\n\r\n")
            assert resp.startswith(b"HTTP/1.1 404")
            assert b"404 Not Found" in resp
        finally:
            server.shutdown(); server.server_close()

    def test_post_credentials_captured_hashed(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            body = b"user=admin&pass=hunter2"
            req = (b"POST /login HTTP/1.1\r\nHost: x\r\n"
                   b"Content-Type: application/x-www-form-urlencoded\r\n"
                   b"Content-Length: " + str(len(body)).encode() +
                   b"\r\n\r\n" + body)
            resp = _get(port, req)
            assert resp.startswith(b"HTTP/1.1 200")
            assert _wait_for(logger.path, "credential_capture")
            text = logger.path.read_text(encoding="utf-8")
            assert hash_credential("hunter2") in text
            assert "hunter2" not in text.replace(hash_credential("hunter2"), "")
        finally:
            server.shutdown(); server.server_close()

    def test_bad_request_gets_400(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            resp = _get(port, b"NOT A REQUEST\r\n\r\n")
            assert resp.startswith(b"HTTP/1.1 400")
        finally:
            server.shutdown(); server.server_close()

    def test_head_returns_no_body(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            resp = _get(port, b"HEAD / HTTP/1.1\r\nHost: x\r\n\r\n")
            head, _, body = resp.partition(b"\r\n\r\n")
            assert resp.startswith(b"HTTP/1.1 200")
            assert body == b""
            assert b"Content-Length: 0" in head
        finally:
            server.shutdown(); server.server_close()
