"""Tests for the SSH decoy: KEXINIT parsing, fingerprinting, capture."""

import socket
import struct
import time

from honeypot_server.core.logger import Logger, hash_credential
from honeypot_server.core.persona import Persona
from honeypot_server.protocols.base import build_server
from honeypot_server.protocols.ssh import (
    MSG_KEXDH_INIT,
    MSG_KEXINIT,
    SSHHandler,
    build_kexinit,
    fingerprint_client,
    parse_kexinit,
    read_packet,
    wrap_packet,
)

PERSONA = Persona.generate(31)


def _start(tmp_path):
    logger = Logger(tmp_path / "ssh.jsonl")
    server = build_server(SSHHandler, "127.0.0.1", 0, logger,
                          persona=PERSONA, start=True)
    return server, logger, server.server_address[1]


def _wait_for(log, needle, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if log.exists() and needle in log.read_text(encoding="utf-8"):
            return True
        time.sleep(0.05)
    return False


def _client_kexinit_payload(kex: list[str], ciphers: list[str]) -> bytes:
    """Build a client SSH_MSG_KEXINIT payload with chosen lists."""
    payload = bytes([MSG_KEXINIT]) + bytes(16)  # cookie
    lists = [kex, ["ssh-ed25519"], ciphers, ciphers,
             ["hmac-sha2-256"], ["hmac-sha2-256"],
             ["none"], ["none"], [], []]
    for lst in lists:
        raw = ",".join(lst).encode()
        payload += struct.pack(">I", len(raw)) + raw
    payload += bytes([0]) + struct.pack(">I", 0)
    return payload


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _drain_until(sock, fragment: bytes, timeout=3.0):
    """Read from the socket until ``fragment`` appears (Windows-safe close)."""
    sock.settimeout(timeout)
    buf = b""
    while fragment not in buf:
        try:
            data = sock.recv(4096)
        except (socket.timeout, TimeoutError):
            return buf
        if not data:
            return buf
        buf += data
    return buf


def _recv_packet(sock):
    head = _recv_exact(sock, 4)
    if head is None:
        return None
    (length,) = struct.unpack(">I", head)
    body = _recv_exact(sock, length)
    if body is None:
        return None
    padding = body[0]
    return body[1:length - padding]


OPENSSH_KEX = ["sntrup761x25519-sha512@openssh.com", "curve25519-sha256",
               "ecdh-sha2-nistp256", "diffie-hellman-group16-sha512"]
OPENSSH_CIPHERS = ["chacha20-poly1305@openssh.com", "aes128-ctr",
                   "aes256-ctr", "aes128-gcm@openssh.com"]
NMAP_KEX = ["diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group14-sha1"]
NMAP_CIPHERS = ["aes128-cbc", "3des-cbc", "blowfish-cbc", "cast128-cbc"]


class TestFingerprint:
    def test_openssh(self):
        assert fingerprint_client(OPENSSH_KEX, OPENSSH_CIPHERS) == "openssh"

    def test_nmap(self):
        assert fingerprint_client(NMAP_KEX, NMAP_CIPHERS) == "nmap"

    def test_unknown(self):
        assert fingerprint_client(["weird-kex"], ["weird-cipher"]) == "unknown"

    def test_empty_lists(self):
        assert fingerprint_client([], []) == "unknown"


class TestParseKexinit:
    def test_roundtrip(self):
        payload = _client_kexinit_payload(OPENSSH_KEX, OPENSSH_CIPHERS)
        parsed = parse_kexinit(payload)
        assert parsed is not None
        assert parsed["kex_algorithms"] == OPENSSH_KEX
        assert parsed["encryption_algorithms_client_to_server"] == OPENSSH_CIPHERS
        assert len(parsed["cookie"]) == 32  # hex of 16 bytes

    def test_truncated(self):
        payload = _client_kexinit_payload(OPENSSH_KEX, OPENSSH_CIPHERS)
        assert parse_kexinit(payload[:20]) is None

    def test_wrong_type(self):
        assert parse_kexinit(bytes([99]) + bytes(30)) is None

    def test_lying_length(self):
        payload = bytes([MSG_KEXINIT]) + bytes(16) + struct.pack(">I", 999)
        assert parse_kexinit(payload) is None


class TestPacketFraming:
    def test_wrap_and_read_roundtrip(self):
        payload = b"\x14" + b"hello world"
        packet = wrap_packet(payload)
        (length,) = struct.unpack(">I", packet[:4])
        assert length == len(packet) - 4
        # read_packet via a fake recv over the bytes
        stream = bytearray(packet)
        def recv(n):
            out = bytes(stream[:n])
            del stream[:n]
            return out
        assert read_packet(recv) == payload

    def test_read_packet_eof(self):
        assert read_packet(lambda n: b"") is None
        assert read_packet(lambda n: b"\x00\x00") is None

    def test_build_kexinit_is_parseable(self):
        packet = build_kexinit(PERSONA, bytes(16))
        stream = bytearray(packet)
        def recv(n):
            out = bytes(stream[:n])
            del stream[:n]
            return out
        payload = read_packet(recv)
        parsed = parse_kexinit(payload)
        assert parsed is not None
        assert parsed["kex_algorithms"]  # non-empty
        assert parsed["compression_algorithms_client_to_server"] == ["none"]


class TestLiveSSH:
    def test_banner_matches_persona(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            line = s.recv(256).decode().strip()
            assert line == PERSONA.ssh_banner()
            s.close()
        finally:
            server.shutdown(); server.server_close()

    def test_full_kex_exchange_and_fingerprint(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            s.recv(256)  # banner
            s.sendall(b"SSH-2.0-OpenSSH_9.2\r\n")
            s.sendall(wrap_packet(
                _client_kexinit_payload(OPENSSH_KEX, OPENSSH_CIPHERS)))
            server_payload = _recv_packet(s)
            assert server_payload is not None
            assert server_payload[0] == MSG_KEXINIT
            # send KEXDH_INIT with a fake 32-byte e
            e = bytes(range(32))
            dh = bytes([MSG_KEXDH_INIT]) + struct.pack(">I", len(e)) + e
            s.sendall(wrap_packet(dh))
            disc = _recv_packet(s)
            assert disc is not None and disc[0] == 1  # SSH_MSG_DISCONNECT
            s.close()
            assert _wait_for(logger.path, "\"client_guess\": \"openssh\"")
            assert _wait_for(logger.path, "kexdh_init")
        finally:
            server.shutdown(); server.server_close()

    def test_nmap_style_client_fingerprinted(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            s.recv(256)
            s.sendall(b"SSH-2.0-Nmap\r\n")
            s.sendall(wrap_packet(
                _client_kexinit_payload(NMAP_KEX, NMAP_CIPHERS)))
            _recv_packet(s)  # server kexinit
            s.close()
            assert _wait_for(logger.path, "\"client_guess\": \"nmap\"")
        finally:
            server.shutdown(); server.server_close()

    def test_garbage_kexinit_logged(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            s.recv(256)
            s.sendall(b"SSH-2.0-broken\r\n")
            s.sendall(wrap_packet(bytes([MSG_KEXINIT]) + b"junk"))
            s.close()
            assert _wait_for(logger.path, "kexinit_malformed")
        finally:
            server.shutdown(); server.server_close()

    def test_plaintext_credential_capture(self, tmp_path):
        server, logger, port = _start(tmp_path)
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            s.recv(256)  # banner
            s.sendall(b"USER admin\r\n")
            _drain_until(s, b"Password: ")  # read prompt before replying
            s.sendall(b"PASS supersecret\r\n")
            _drain_until(s, b"command not found")
            s.close()
            assert _wait_for(logger.path, "plaintext_user")
            assert _wait_for(logger.path, hash_credential("supersecret"))
            text = logger.path.read_text(encoding="utf-8")
            assert "supersecret" not in text.replace(
                hash_credential("supersecret"), "")
        finally:
            server.shutdown(); server.server_close()
