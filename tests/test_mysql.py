"""Tests for the MySQL decoy: packet framing, greeting, auth parsing."""

import socket
import struct
import time

from honeypot_server.core.logger import Logger
from honeypot_server.core.persona import Persona
from honeypot_server.protocols.base import build_server
from honeypot_server.protocols.mysql import (
    CLIENT_CONNECT_WITH_DB,
    CLIENT_PROTOCOL_41,
    CLIENT_SECURE_CONNECTION,
    ER_ACCESS_DENIED,
    MySQLHandler,
    build_access_denied,
    build_greeting,
    packet,
    parse_handshake_response,
    read_packet,
)

PERSONA = Persona.generate(81)


def _start(tmp_path):
    logger = Logger(tmp_path / "mysql.jsonl")
    server = build_server(MySQLHandler, "127.0.0.1", 0, logger,
                          persona=PERSONA, start=True)
    return server, logger, server.server_address[1]


def _handshake_response(username: str, auth: bytes = bytes(20),
                        database: str = "") -> bytes:
    caps = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION
    if database:
        caps |= CLIENT_CONNECT_WITH_DB
    payload = struct.pack("<II", caps, 16 * 1024 * 1024)
    payload += bytes([33]) + b"\x00" * 23
    payload += username.encode() + b"\x00"
    payload += bytes([len(auth)]) + auth
    if database:
        payload += database.encode() + b"\x00"
    return payload


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _wait_for(log, needle, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if log.exists() and needle in log.read_text(encoding="utf-8"):
            return True
        time.sleep(0.05)
    return False


class TestFraming:
    def test_packet_roundtrip(self):
        framed = packet(b"hello", 3)
        assert framed[:3] == b"\x05\x00\x00" and framed[3] == 3
        stream = bytearray(framed)
        def recv(n):
            out = bytes(stream[:n])
            del stream[:n]
            return out
        seq, payload = read_packet(recv)
        assert seq == 3 and payload == b"hello"

    def test_read_packet_eof(self):
        assert read_packet(lambda n: b"") is None
        assert read_packet(lambda n: b"\x00\x00") is None

    def test_greeting_structure(self):
        framed = build_greeting(PERSONA, 4242, bytes(range(20)))
        payload = framed[4:]
        assert payload[0] == 0x0A  # protocol version 10
        version = payload[1:payload.find(b"\x00", 1)].decode()
        assert version == PERSONA.mysql_version()
        thread_id = struct.unpack("<I", payload[payload.find(b"\x00", 1) + 1:
                                                payload.find(b"\x00", 1) + 5])[0]
        assert thread_id == 4242

    def test_greeting_salt_validation(self):
        import pytest
        with pytest.raises(ValueError):
            build_greeting(PERSONA, 1, b"short")

    def test_access_denied_packet(self):
        framed = build_access_denied("root", 2)
        payload = framed[4:]
        assert payload[0] == 0xFF
        assert struct.unpack("<H", payload[1:3])[0] == ER_ACCESS_DENIED
        assert b"root" in payload and b"28000" in payload


class TestParseHandshakeResponse:
    def test_basic(self):
        payload = _handshake_response("root", bytes(range(20)), "appdb")
        parsed = parse_handshake_response(payload)
        assert parsed is not None
        assert parsed["username"] == "root"
        assert parsed["auth_response"] == bytes(range(20))
        assert parsed["database"] == "appdb"

    def test_no_database(self):
        parsed = parse_handshake_response(_handshake_response("admin"))
        assert parsed["username"] == "admin" and parsed["database"] == ""

    def test_too_short(self):
        assert parse_handshake_response(b"\x00" * 10) is None

    def test_missing_nul(self):
        payload = struct.pack("<II", CLIENT_PROTOCOL_41, 100)
        payload += bytes([33]) + b"\x00" * 23 + b"noname"
        assert parse_handshake_response(payload) is None


class TestLiveMySQL:
    def test_greeting_sent_on_connect(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            head = _recv_exact(s, 4)
            length = head[0] | (head[1] << 8) | (head[2] << 16)
            payload = _recv_exact(s, length)
            assert payload[0] == 0x0A
            assert PERSONA.mysql_version().encode() in payload
            s.close()
            assert _wait_for(logger.path, "greeting")
        finally:
            server.shutdown(); server.server_close()

    def test_auth_attempt_logged_and_denied(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            head = _recv_exact(s, 4)
            _recv_exact(s, head[0] | (head[1] << 8) | (head[2] << 16))
            s.sendall(packet(_handshake_response("root", b"\x11" * 20), 1))
            head = _recv_exact(s, 4)
            payload = _recv_exact(s, head[0] | (head[1] << 8) | (head[2] << 16))
            assert payload[0] == 0xFF
            assert struct.unpack("<H", payload[1:3])[0] == ER_ACCESS_DENIED
            s.close()
            assert _wait_for(logger.path, "\"user\": \"root\"")
            assert _wait_for(logger.path, "auth_sha256")
        finally:
            server.shutdown(); server.server_close()

    def test_brute_force_flag(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            head = _recv_exact(s, 4)
            _recv_exact(s, head[0] | (head[1] << 8) | (head[2] << 16))
            for i in range(3):
                s.sendall(packet(_handshake_response(f"user{i}"), 1))
                head = _recv_exact(s, 4)
                _recv_exact(s, head[0] | (head[1] << 8) | (head[2] << 16))
            s.close()
            assert _wait_for(logger.path, "brute_force_suspected")
        finally:
            server.shutdown(); server.server_close()

    def test_garbage_handshake_logged(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            head = _recv_exact(s, 4)
            _recv_exact(s, head[0] | (head[1] << 8) | (head[2] << 16))
            s.sendall(packet(b"\x02\x03garbage", 1))
            s.close()
            assert _wait_for(logger.path, "handshake_malformed")
        finally:
            server.shutdown(); server.server_close()
