"""Tests for the legacy banner handlers kept for backward compatibility.

The original 0.1.0 API (run/run_server/HANDLERS and the simple
ServiceHandler family) must keep working exactly as before: these tests
pin that behaviour down independently of the new protocol modules.
"""

import socket
import threading
import time

from honeypot_server import (
    BANNERS,
    DEFAULT_PORTS,
    FAKE_PAGES,
    HANDLERS,
    Logger,
    run,
    run_server,
)


def _free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _wait_for(log, needle, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if log.exists() and needle in log.read_text(encoding="utf-8"):
            return True
        time.sleep(0.05)
    return False


class TestLegacyConstants:
    def test_default_ports(self):
        assert DEFAULT_PORTS == {"http": 80, "ftp": 21, "ssh": 22,
                                 "smtp": 25, "dns": 53}

    def test_banners_present_for_tcp_services(self):
        assert set(BANNERS) == {"http", "ftp", "ssh", "smtp"}
        for banner in BANNERS.values():
            assert banner.endswith(b"\r\n")

    def test_handlers_registered(self):
        assert set(HANDLERS) == {"http", "ftp", "ssh", "smtp", "dns"}

    def test_fake_page_shape(self):
        page = FAKE_PAGES["http"]
        assert page.startswith(b"HTTP/1.1 200 OK")
        assert b"Content-Length" in page


class TestLegacyRun:
    def test_run_returns_servers_and_serves(self, tmp_path):
        log = tmp_path / "legacy.jsonl"
        stop = threading.Event()
        port = _free_port()
        servers = run(["http"], "127.0.0.1", {"http": port}, log, stop)
        try:
            assert len(servers) == 1
            time.sleep(0.2)
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            s.settimeout(3)
            banner = b""
            while b"\r\n\r\n" not in banner:  # drain the 404 banner fully
                chunk = s.recv(4096)
                if not chunk:
                    break
                banner += chunk
            assert banner.startswith(b"HTTP/1.1 404")
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            body = s.recv(4096)
            s.close()
            assert b"HTTP/1.1 200 OK" in body
            assert _wait_for(log, "GET /")
        finally:
            for srv in servers:
                srv.shutdown()
                srv.server_close()

    def test_run_server_direct(self, tmp_path):
        log = tmp_path / "direct.jsonl"
        stop = threading.Event()
        logger = Logger(log)
        port = _free_port()
        server = run_server("ftp", "127.0.0.1", port, logger, stop)
        try:
            time.sleep(0.2)
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            banner = s.recv(64)
            s.sendall(b"USER root\r\n")
            s.settimeout(3)
            reply = s.recv(64)
            s.close()
            assert banner.startswith(b"220")
            assert reply.startswith(b"530")
            assert _wait_for(log, "USER root")
        finally:
            server.shutdown()
            server.server_close()

    def test_ssh_legacy_banner_only(self, tmp_path):
        log = tmp_path / "ssh.jsonl"
        stop = threading.Event()
        port = _free_port()
        servers = run(["ssh"], "127.0.0.1", {"ssh": port}, log, stop)
        try:
            time.sleep(0.2)
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            banner = s.recv(128)
            s.close()
            assert banner.startswith(b"SSH-2.0-OpenSSH")
            assert _wait_for(log, "banner")
        finally:
            for srv in servers:
                srv.shutdown()
                srv.server_close()

    def test_dns_legacy_logs_query(self, tmp_path):
        log = tmp_path / "dns.jsonl"
        stop = threading.Event()
        port = _free_port()
        servers = run(["dns"], "127.0.0.1", {"dns": port}, log, stop)
        try:
            time.sleep(0.2)
            import struct
            query = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
            query += b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.sendto(query, ("127.0.0.1", port))
            try:
                s.recvfrom(4096)
            except (socket.timeout, TimeoutError):
                pass  # legacy handler answers nothing
            s.close()
            assert _wait_for(log, "example.com")
        finally:
            for srv in servers:
                srv.shutdown()
                srv.server_close()

    def test_smtp_legacy_replies(self, tmp_path):
        log = tmp_path / "smtp.jsonl"
        stop = threading.Event()
        port = _free_port()
        servers = run(["smtp"], "127.0.0.1", {"smtp": port}, log, stop)
        try:
            time.sleep(0.2)
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            banner = s.recv(128)
            s.sendall(b"EHLO test\r\n")
            s.settimeout(3)
            reply = s.recv(128)
            s.close()
            assert banner.startswith(b"220")
            assert reply.startswith(b"250")
        finally:
            for srv in servers:
                srv.shutdown()
                srv.server_close()
