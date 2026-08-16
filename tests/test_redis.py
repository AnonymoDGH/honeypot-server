"""Tests for the Redis decoy: RESP codec, commands, danger flags."""

import socket
import time

from honeypot_server.core.logger import Logger, hash_credential
from honeypot_server.core.persona import Persona
from honeypot_server.protocols.base import CanaryRegistry, build_server
from honeypot_server.protocols.redis import (
    FAKE_KEYS,
    RedisHandler,
    encode_array,
    encode_bulk,
    encode_error,
    encode_int,
    encode_simple,
    parse_resp_array,
)

PERSONA = Persona.generate(71)


def _start(tmp_path, canaries=None):
    logger = Logger(tmp_path / "redis.jsonl")
    server = build_server(RedisHandler, "127.0.0.1", 0, logger,
                          persona=PERSONA, canaries=canaries, start=True)
    return server, logger, server.server_address[1]


class RedisClient:
    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=3)
        self.buf = b""

    def send_cmd(self, *parts: str):
        out = f"*{len(parts)}\r\n".encode()
        for p in parts:
            raw = p.encode()
            out += b"$" + str(len(raw)).encode() + b"\r\n" + raw + b"\r\n"
        self.sock.sendall(out)

    def send_raw(self, data: bytes):
        self.sock.sendall(data)

    def read_reply(self) -> bytes:
        """Read one complete RESP reply (simple/bulk/error/int/array)."""
        self.sock.settimeout(3)
        while True:
            if self.buf[:1] in (b"+", b"-", b":"):
                if b"\r\n" in self.buf:
                    line, self.buf = self.buf.split(b"\r\n", 1)
                    return line
            elif self.buf[:1] == b"$":
                nl = self.buf.find(b"\r\n")
                if nl != -1:
                    length = int(self.buf[1:nl])
                    if length == -1:
                        self.buf = self.buf[nl + 2:]
                        return b"$-1"
                    end = nl + 2 + length + 2
                    if len(self.buf) >= end:
                        payload = self.buf[nl + 2:nl + 2 + length]
                        self.buf = self.buf[end:]
                        return payload
            elif self.buf[:1] == b"*":
                nl = self.buf.find(b"\r\n")
                if nl != -1 and b"\r\n" in self.buf[nl + 2:]:
                    # good enough for flat arrays of short bulks
                    count = int(self.buf[1:nl])
                    offset = nl + 2
                    items = []
                    ok = True
                    for _ in range(count):
                        if offset >= len(self.buf) or self.buf[offset:offset+1] != b"$":
                            ok = False
                            break
                        nl2 = self.buf.find(b"\r\n", offset)
                        if nl2 == -1:
                            ok = False
                            break
                        length = int(self.buf[offset + 1:nl2])
                        end = nl2 + 2 + length + 2
                        if end > len(self.buf):
                            ok = False
                            break
                        items.append(self.buf[nl2 + 2:nl2 + 2 + length])
                        offset = end
                    if ok:
                        self.buf = self.buf[offset:]
                        return b"|" .join(items) if items else b"*empty"
            data = self.sock.recv(4096)
            if not data:
                raise EOFError
            self.buf += data

    def close(self):
        self.sock.close()


def _wait_for(log, needle, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if log.exists() and needle in log.read_text(encoding="utf-8"):
            return True
        time.sleep(0.05)
    return False


class TestRespCodec:
    def test_encoders(self):
        assert encode_simple("OK") == b"+OK\r\n"
        assert encode_error("ERR x") == b"-ERR x\r\n"
        assert encode_int(7) == b":7\r\n"
        assert encode_bulk("hi") == b"$2\r\nhi\r\n"
        assert encode_bulk(None) == b"$-1\r\n"
        assert encode_array(["a", "b"]) == (
            b"*2\r\n$1\r\na\r\n$1\r\nb\r\n")

    def test_parse_resp_array(self):
        raw = b"*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n"
        assert parse_resp_array(raw) == ["GET", "mykey"]

    def test_parse_resp_array_incomplete(self):
        assert parse_resp_array(b"*2\r\n$3\r\nGET\r\n") is None
        assert parse_resp_array(b"not resp") is None
        assert parse_resp_array(b"*x\r\n") is None

    def test_parse_resp_array_bounds(self):
        assert parse_resp_array(b"*999\r\n") is None


class TestRedisSession:
    def test_ping_pong(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = RedisClient(port)
            c.send_cmd("PING")
            assert c.read_reply() == b"+PONG"
            c.send_cmd("PING", "hello")
            assert c.read_reply() == b"hello"
            c.close()
            assert _wait_for(logger.path, "\"command\": \"PING\"")
        finally:
            server.shutdown(); server.server_close()

    def test_inline_command(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = RedisClient(port)
            c.send_raw(b"PING\r\n")
            assert c.read_reply() == b"+PONG"
            c.close()
        finally:
            server.shutdown(); server.server_close()

    def test_info_report_matches_persona(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = RedisClient(port)
            c.send_cmd("INFO")
            report = c.read_reply().decode()
            assert f"redis_version:{PERSONA.versions['redis']}" in report
            assert PERSONA.os in report
            assert "connected_clients" in report
            c.close()
        finally:
            server.shutdown(); server.server_close()

    def test_auth_failure_logged_hashed(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = RedisClient(port)
            c.send_cmd("AUTH", "guessme")
            reply = c.read_reply()
            assert reply.startswith(b"-WRONGPASS")
            c.close()
            assert _wait_for(logger.path, hash_credential("guessme"))
            text = logger.path.read_text(encoding="utf-8")
            assert "guessme" not in text.replace(hash_credential("guessme"), "")
        finally:
            server.shutdown(); server.server_close()

    def test_keys_and_get_bait(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = RedisClient(port)
            c.send_cmd("KEYS", "*")
            keys = c.read_reply().decode().split("|")
            assert set(keys) == set(FAKE_KEYS)
            c.send_cmd("GET", "secret:api_key")
            assert c.read_reply().decode() == FAKE_KEYS["secret:api_key"]
            c.send_cmd("GET", "missing")
            assert c.read_reply() == b"$-1"
            c.send_cmd("EXISTS", "cache:users")
            assert c.read_reply() == b":1"
            c.close()
            assert _wait_for(logger.path, "key_read")
        finally:
            server.shutdown(); server.server_close()

    def test_config_get(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = RedisClient(port)
            c.send_cmd("CONFIG", "GET", "dir")
            reply = c.read_reply().decode()
            assert "dir" in reply and "/var/lib/redis" in reply
            c.close()
        finally:
            server.shutdown(); server.server_close()

    def test_dangerous_commands_flagged(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = RedisClient(port)
            c.send_cmd("CONFIG", "SET", "dir", "/tmp")
            assert c.read_reply() == b"+OK"
            c.send_cmd("SLAVEOF", "1.2.3.4", "6379")
            assert c.read_reply() == b"+OK"
            c.send_cmd("EVAL", "return 1", "0")
            c.read_reply()  # unknown command error
            c.close()
            assert _wait_for(logger.path, "dangerous_command")
            assert _wait_for(logger.path, "replication hijack")
        finally:
            server.shutdown(); server.server_close()

    def test_unknown_command_error(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = RedisClient(port)
            c.send_cmd("FLY")
            reply = c.read_reply()
            assert reply.startswith(b"-ERR unknown command")
            c.close()
        finally:
            server.shutdown(); server.server_close()

    def test_scan_and_dbsize(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            c = RedisClient(port)
            c.send_cmd("DBSIZE")
            assert c.read_reply() == f":{len(FAKE_KEYS)}".encode()
            c.send_cmd("SCAN", "0")
            # SCAN replies with a nested array; read raw bytes instead.
            c.sock.settimeout(3)
            raw = b""
            while b"queue:emails" not in raw:
                data = c.sock.recv(4096)
                if not data:
                    break
                raw += data
            reply = raw.decode()
            assert "session:admin" in reply and reply.startswith("*2")
            c.close()
        finally:
            server.shutdown(); server.server_close()
