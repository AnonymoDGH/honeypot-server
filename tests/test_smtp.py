"""Tests for the SMTP decoy state machine and open-relay bait."""

import base64
import socket
import time

from honeypot_server.core.logger import Logger, hash_credential
from honeypot_server.core.persona import Persona
from honeypot_server.protocols.base import build_server
from honeypot_server.protocols.smtp import SMTPHandler, parse_address

PERSONA = Persona.generate(41)


def _start(tmp_path):
    logger = Logger(tmp_path / "smtp.jsonl")
    server = build_server(SMTPHandler, "127.0.0.1", 0, logger,
                          persona=PERSONA, start=True)
    return server, logger, server.server_address[1]


class SMTPClient:
    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=3)
        self.buf = b""

    def readline(self) -> str:
        while b"\r\n" not in self.buf:
            data = self.sock.recv(4096)
            if not data:
                raise EOFError
            self.buf += data
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line.decode()

    def read_reply(self) -> list[str]:
        """Read a (possibly multiline) SMTP reply."""
        lines = []
        while True:
            line = self.readline()
            lines.append(line)
            if len(line) >= 4 and line[3] == " ":
                return lines
            if len(line) < 4:
                return lines

    def cmd(self, text: str) -> list[str]:
        self.sock.sendall(text.encode() + b"\r\n")
        return self.read_reply()

    def close(self):
        self.sock.close()


def _wait_for(log, needle, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if log.exists() and needle in log.read_text(encoding="utf-8"):
            return True
        time.sleep(0.05)
    return False


class TestParseAddress:
    def test_angle_form(self):
        assert parse_address("<a@b.c>") == "a@b.c"
        assert parse_address("<x@y.z> SIZE=100") == "x@y.z"

    def test_bare_form(self):
        assert parse_address("a@b.c") == "a@b.c"
        assert parse_address("a@b.c SIZE=5") == "a@b.c"

    def test_unterminated_angle(self):
        assert parse_address("<oops") == "oops"


class TestSMTPSession:
    def test_banner_and_ehlo(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = SMTPClient(port)
            banner = c.readline()
            assert banner.startswith("220") and PERSONA.fqdn in banner
            lines = c.cmd("EHLO evil.example")
            assert lines[0].startswith("250-")
            assert any("AUTH PLAIN LOGIN" in l for l in lines)
            c.close()
        finally:
            server.shutdown(); server.server_close()

    def test_full_relay_transaction(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = SMTPClient(port)
            c.readline()
            c.cmd("EHLO spammer.example")
            assert c.cmd("MAIL FROM:<boss@victim.com>")[-1].startswith("250")
            assert c.cmd("RCPT TO:<mark@remote.net>")[-1].startswith("250")
            assert c.cmd("DATA")[-1].startswith("354")
            c.sock.sendall(b"Subject: hi\r\n\r\nBuy now!\r\n.\r\n")
            reply = c.read_reply()
            assert reply[-1].startswith("250") and "queued" in reply[-1]
            c.close()
            assert _wait_for(logger.path, "message_accepted")
            assert _wait_for(logger.path, "\"relay_attempt\": true")
            assert _wait_for(logger.path, "open_relay_abuse")
            text = logger.path.read_text(encoding="utf-8")
            assert "boss@victim.com" in text and "mark@remote.net" in text
        finally:
            server.shutdown(); server.server_close()

    def test_local_recipient_not_flagged_as_relay(self, tmp_path):
        server, logger, port = _start(tmp_path)
        local = f"someone@{PERSONA.domain}"
        try:
            c = SMTPClient(port)
            c.readline()
            c.cmd("EHLO local")
            c.cmd("MAIL FROM:<a@b.c>")
            c.cmd(f"RCPT TO:<{local}>")
            c.cmd("DATA")
            c.sock.sendall(b"hello\r\n.\r\n")
            c.read_reply()
            c.close()
            assert _wait_for(logger.path, "message_accepted")
            assert _wait_for(logger.path, "\"relay_attempt\": false")
        finally:
            server.shutdown(); server.server_close()

    def test_state_machine_ordering(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = SMTPClient(port)
            c.readline()
            assert c.cmd("MAIL FROM:<x@y>")[-1].startswith("503")  # no EHLO
            c.cmd("EHLO t")
            assert c.cmd("RCPT TO:<x@y>")[-1].startswith("503")  # no MAIL
            assert c.cmd("DATA")[-1].startswith("503")  # no RCPT
            c.cmd("MAIL FROM:<x@y>")
            assert c.cmd("DATA")[-1].startswith("503")  # still no RCPT
            c.close()
        finally:
            server.shutdown(); server.server_close()

    def test_auth_plain_inline(self, tmp_path):
        server, logger, port = _start(tmp_path)
        blob = base64.b64encode(b"\0admin\0hunter2").decode()
        try:
            c = SMTPClient(port)
            c.readline()
            c.cmd("EHLO t")
            reply = c.cmd(f"AUTH PLAIN {blob}")
            assert reply[-1].startswith("535")
            c.close()
            assert _wait_for(logger.path, "auth_attempt")
            assert _wait_for(logger.path, hash_credential("hunter2"))
        finally:
            server.shutdown(); server.server_close()

    def test_auth_login_two_step(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = SMTPClient(port)
            c.readline()
            c.cmd("EHLO t")
            assert c.cmd("AUTH LOGIN")[0].startswith("334")
            user = base64.b64encode(b"deploy").decode()
            pw = base64.b64encode(b"s3cret!").decode()
            assert c.cmd(user)[0].startswith("334")
            assert c.cmd(pw)[-1].startswith("535")
            c.close()
            assert _wait_for(logger.path, "\"user\": \"deploy\"")
            assert _wait_for(logger.path, hash_credential("s3cret!"))
        finally:
            server.shutdown(); server.server_close()

    def test_vrfy_and_misc(self, tmp_path):
        server, logger, port = _start(tmp_path)
        name = PERSONA.usernames()[0]
        try:
            c = SMTPClient(port)
            c.readline()
            reply = c.cmd(f"VRFY {name}")
            assert reply[-1].startswith("250") and name in reply[-1]
            assert c.cmd("VRFY ghost")[-1].startswith("252")
            assert c.cmd("NOOP")[-1].startswith("250")
            assert c.cmd("BOGUS")[-1].startswith("502")
            assert c.cmd("QUIT")[-1].startswith("221")
            c.close()
        finally:
            server.shutdown(); server.server_close()

    def test_dot_stuffing_unstuffed(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = SMTPClient(port)
            c.readline()
            c.cmd("EHLO t")
            c.cmd("MAIL FROM:<a@b.c>")
            c.cmd("RCPT TO:<d@e.f>")
            c.cmd("DATA")
            c.sock.sendall(b"..hidden dot line\r\n.\r\n")
            c.read_reply()
            c.close()
            assert _wait_for(logger.path, "message_accepted")
        finally:
            server.shutdown(); server.server_close()
