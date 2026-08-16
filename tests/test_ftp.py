"""Tests for the FTP decoy state machine and fake tree."""

import socket
import time

from honeypot_server.core.logger import Logger, hash_credential
from honeypot_server.core.persona import Persona
from honeypot_server.protocols.base import CanaryRegistry, build_server
from honeypot_server.protocols.ftp import FTPHandler, FakeFTPTree

PERSONA = Persona.generate(21)


def _start(tmp_path, canaries=None):
    logger = Logger(tmp_path / "ftp.jsonl")
    server = build_server(FTPHandler, "127.0.0.1", 0, logger,
                          persona=PERSONA, canaries=canaries, start=True)
    return server, logger, server.server_address[1]


class FTPClient:
    """Tiny line-oriented FTP client for tests."""

    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=3)
        self.buf = b""

    def readline(self) -> str:
        while b"\r\n" not in self.buf:
            data = self.sock.recv(4096)
            if not data:
                raise EOFError("server closed")
            self.buf += data
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line.decode("utf-8", "replace")

    def read_until(self, code: str) -> list[str]:
        """Read lines until one starts with ``code`` (inclusive)."""
        lines = []
        while True:
            line = self.readline()
            lines.append(line)
            if line.startswith(code) and not line[3:4] == "-":
                return lines

    def cmd(self, text: str, code: str) -> list[str]:
        self.sock.sendall(text.encode() + b"\r\n")
        return self.read_until(code)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def _wait_for(log, needle, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if log.exists() and needle in log.read_text(encoding="utf-8"):
            return True
        time.sleep(0.05)
    return False


class TestFakeFTPTree:
    def setup_method(self):
        self.tree = FakeFTPTree(PERSONA)

    def test_root_listing(self):
        names = [n for _, n in self.tree.list_dir("/")]
        assert names == ["pub", "incoming", "internal", "backups"]

    def test_resolve_relative_and_parent(self):
        assert self.tree.resolve("/", "pub") == "/pub"
        assert self.tree.resolve("/pub", "../internal") == "/internal"
        assert self.tree.resolve("/pub", "/backups") == "/backups"
        assert self.tree.resolve("/internal", ".") == "/internal"
        assert self.tree.resolve("/", "..") == "/"

    def test_ls_lines_format(self):
        lines = self.tree.ls_lines("/internal")
        assert any(l.startswith("d") or l.startswith("-") for l in lines)
        assert any("credentials.txt" in l for l in lines)

    def test_inject_file(self):
        self.tree.inject("/internal/canary.txt", "bait")
        assert self.tree.is_file("/internal/canary.txt")
        assert "canary.txt" in [n for _, n in self.tree.list_dir("/internal")]


class TestFTPSession:
    def test_banner_and_unknown_user_flow(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = FTPClient(port)
            banner = c.readline()
            assert banner.startswith("220") and PERSONA.hostname in banner
            lines = c.cmd("USER ghost", "331")
            assert lines[-1].startswith("331")
            lines = c.cmd("PASS whatever", "530")
            assert lines[-1].startswith("530")
            c.close()
            assert _wait_for(logger.path, "login_attempt")
            text = logger.path.read_text(encoding="utf-8")
            assert hash_credential("whatever") in text
            assert "whatever" not in text.replace(hash_credential("whatever"), "")
        finally:
            server.shutdown(); server.server_close()

    def test_successful_login_with_persona_password(self, tmp_path):
        server, logger, port = _start(tmp_path)
        user = PERSONA.users[1]
        try:
            c = FTPClient(port)
            c.readline()
            c.cmd(f"USER {user.username}", "331")
            lines = c.cmd(f"PASS {user.password}", "230")
            assert lines[-1].startswith("230")
            c.close()
            assert _wait_for(logger.path, "login_success")
        finally:
            server.shutdown(); server.server_close()

    def test_navigation_and_listing(self, tmp_path):
        server, logger, port = _start(tmp_path)
        user = PERSONA.admin()
        try:
            c = FTPClient(port)
            c.readline()
            c.cmd(f"USER {user.username}", "331")
            c.cmd(f"PASS {user.password}", "230")
            assert c.cmd("PWD", "257")[-1].startswith('257 "/"')
            assert c.cmd("CWD internal", "250")[-1].startswith("250")
            assert c.cmd("PWD", "257")[-1].startswith('257 "/internal"')
            lines = c.cmd("LIST", "226")
            assert any("credentials.txt" in l for l in lines)
            assert c.cmd("CWD /nope", "550")[-1].startswith("550")
            assert c.cmd("CDUP", "250")[-1].startswith("250")
            c.close()
        finally:
            server.shutdown(); server.server_close()

    def test_retr_serves_fake_file(self, tmp_path):
        server, logger, port = _start(tmp_path)
        user = PERSONA.admin()
        try:
            c = FTPClient(port)
            c.readline()
            c.cmd(f"USER {user.username}", "331")
            c.cmd(f"PASS {user.password}", "230")
            c.cmd("CWD pub", "250")
            lines = c.cmd("RETR readme.txt", "226")
            assert lines[0].startswith("150")
            assert any(PERSONA.fqdn in l for l in lines)
            assert c.cmd("RETR ghost.txt", "550")[-1].startswith("550")
            c.close()
            assert _wait_for(logger.path, "file_download")
        finally:
            server.shutdown(); server.server_close()

    def test_commands_require_auth(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = FTPClient(port)
            c.readline()
            assert c.cmd("LIST", "530")[-1].startswith("530")
            assert c.cmd("PASS early", "503")[-1].startswith("503")
            c.close()
        finally:
            server.shutdown(); server.server_close()

    def test_misc_commands(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = FTPClient(port)
            c.readline()
            assert c.cmd("SYST", "215")[-1].startswith("215")
            assert PERSONA.os in c.cmd("SYST", "215")[-1]
            assert c.cmd("FEAT", "211")[-1].startswith("211")
            assert c.cmd("TYPE I", "200")[-1].startswith("200")
            assert c.cmd("PASV", "227")[-1].startswith("227")
            assert c.cmd("NOPE", "502")[-1].startswith("502")
            assert c.cmd("QUIT", "221")[-1].startswith("221")
            c.close()
        finally:
            server.shutdown(); server.server_close()

    def test_brute_force_flag_after_three_failures(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = FTPClient(port)
            c.readline()
            for i in range(3):
                c.cmd("USER admin", "331")
                c.cmd(f"PASS wrong{i}", "530")
            c.close()
            assert _wait_for(logger.path, "brute_force_suspected")
        finally:
            server.shutdown(); server.server_close()

    def test_credentials_file_embeds_doc_canaries(self, tmp_path):
        canaries = CanaryRegistry()
        canaries.register("CANARY-XYZ-123", kind="doc", id="doc1")
        server, logger, port = _start(tmp_path, canaries=canaries)
        user = PERSONA.admin()
        try:
            c = FTPClient(port)
            c.readline()
            c.cmd(f"USER {user.username}", "331")
            c.cmd(f"PASS {user.password}", "230")
            c.cmd("CWD internal", "250")
            lines = c.cmd("RETR credentials.txt", "226")
            assert any("CANARY-XYZ-123" in l for l in lines)
            c.close()
        finally:
            server.shutdown(); server.server_close()
