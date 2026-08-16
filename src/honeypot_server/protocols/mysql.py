"""MySQL decoy -- handshake greeting packet and auth attempt logging.

MySQL brute-force tools expect a real server greeting before they send
credentials. This decoy speaks the opening of the MySQL client/server
protocol (the "Initial Handshake Packet", protocol version 10) with the
persona's version string, then parses the client's HandshakeResponse41
to recover the attempted username and the scrambled auth response.

The scrambled response is logged as a SHA-256 digest (it is not the raw
password, but it is still attacker-specific evidence), and the attempt is
answered with the genuine-looking ``ER_ACCESS_DENIED_ERROR`` (1045) so
tools retry -- each retry is another logged attempt.
"""

from __future__ import annotations

import hashlib
import struct

from ..core.persona import Persona
from .base import ProtocolHandler

#: Protocol constants (MySQL client/server protocol, protocol 10).
PROTOCOL_VERSION = 0x0A
CHARSET_UTF8 = 33
SERVER_STATUS_AUTOCOMMIT = 0x0002

#: Capability flags we advertise (subset relevant to handshake parsing).
CLIENT_LONG_PASSWORD = 0x00000001
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_PLUGIN_AUTH = 0x00080000
CLIENT_CONNECT_WITH_DB = 0x00000008

CAPABILITIES = (CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 |
                CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH |
                CLIENT_CONNECT_WITH_DB)

#: Error packet for refused logins.
ER_ACCESS_DENIED = 1045

#: Auth plugin every modern client understands.
AUTH_PLUGIN = "mysql_native_password"


def packet(payload: bytes, seq: int) -> bytes:
    """Wrap a payload in MySQL packet framing (3-byte length + seq)."""
    return struct.pack("<I", len(payload))[:3] + bytes([seq & 0xFF]) + payload


def read_packet(recv) -> tuple[int, bytes] | None:
    """Read one MySQL packet via ``recv(n)``. Returns (seq, payload)."""
    head = recv(4)
    if head is None or len(head) < 4:
        return None
    length = head[0] | (head[1] << 8) | (head[2] << 16)
    if length == 0 or length > 16 * 1024 * 1024:
        return None
    payload = recv(length)
    if payload is None or len(payload) < length:
        return None
    return head[3], payload


def build_greeting(persona: Persona, thread_id: int, salt: bytes) -> bytes:
    """Build the server Initial Handshake Packet (protocol 10).

    ``salt`` must be 20 bytes; it is split 8/12 across the two
    auth-plugin-data fields exactly like a real server.
    """
    if len(salt) != 20:
        raise ValueError("salt must be 20 bytes")
    version = persona.mysql_version().encode("ascii", "replace") + b"\x00"
    payload = bytearray()
    payload.append(PROTOCOL_VERSION)
    payload.extend(version)
    payload.extend(struct.pack("<I", thread_id))
    payload.extend(salt[:8])            # auth-plugin-data-part-1
    payload.append(0)                   # filler
    payload.extend(struct.pack("<H", CAPABILITIES & 0xFFFF))
    payload.append(CHARSET_UTF8)
    payload.extend(struct.pack("<H", SERVER_STATUS_AUTOCOMMIT))
    payload.extend(struct.pack("<H", (CAPABILITIES >> 16) & 0xFFFF))
    payload.append(21)                  # length of auth plugin data
    payload.extend(b"\x00" * 10)        # reserved
    payload.extend(salt[8:] + b"\x00")  # auth-plugin-data-part-2
    payload.extend(AUTH_PLUGIN.encode() + b"\x00")
    return packet(bytes(payload), seq=0)


def parse_handshake_response(payload: bytes) -> dict | None:
    """Parse a HandshakeResponse41 payload.

    Returns a dict with ``capabilities``, ``username``, ``auth_response``
    (raw scrambled bytes) and optional ``database``; None when the packet
    is too short or malformed to attribute.
    """
    if len(payload) < 32:
        return None
    caps, max_packet = struct.unpack("<II", payload[:8])
    charset = payload[8]
    offset = 9 + 23  # skip 23 reserved zero bytes
    end = payload.find(b"\x00", offset)
    if end == -1:
        return None
    username = payload[offset:end].decode("utf-8", "replace")
    offset = end + 1
    auth = b""
    if caps & CLIENT_SECURE_CONNECTION:
        if offset >= len(payload):
            return None
        auth_len = payload[offset]
        offset += 1
        auth = payload[offset:offset + auth_len]
        offset += auth_len
    else:
        end = payload.find(b"\x00", offset)
        if end != -1:
            auth = payload[offset:end]
            offset = end + 1
    database = ""
    if caps & CLIENT_CONNECT_WITH_DB and offset < len(payload):
        end = payload.find(b"\x00", offset)
        if end != -1:
            database = payload[offset:end].decode("utf-8", "replace")
    return {
        "capabilities": caps,
        "max_packet": max_packet,
        "charset": charset,
        "username": username,
        "auth_response": auth,
        "database": database,
    }


def build_access_denied(username: str, seq: int) -> bytes:
    """ER_ACCESS_DENIED_ERROR packet, matching real server wording."""
    message = (f"Access denied for user '{username}'@'%' "
               "(using password: YES)")
    payload = (b"\xff" + struct.pack("<H", ER_ACCESS_DENIED) +
               b"#" + b"28000" + message.encode("utf-8"))
    return packet(payload, seq)


def build_ok(seq: int) -> bytes:
    """Minimal OK packet (used to acknowledge COM_QUIT)."""
    return packet(b"\x07\x00\x00\x02\x00\x00\x00", seq)


class MySQLHandler(ProtocolHandler):
    """MySQL decoy: greet, parse the auth attempt, deny, repeat."""

    service = "mysql"
    timeout = 6.0

    def handle(self) -> None:
        self.emit("connect")
        salt = hashlib.sha256(self.session_id.encode()).digest()[:20]
        thread_id = int(self.session_id[:6], 16) % 90000 + 100
        self.send(build_greeting(self.persona, thread_id, salt))
        self.emit("greeting", severity="notice",
                  version=self.persona.mysql_version(),
                  thread_id=thread_id)
        attempts = 0
        while not self.closed and attempts < 8:
            read = read_packet(self._recv_exact)
            if read is None:
                break
            seq, payload = read
            if not payload:
                break
            if payload[0] == 0x01:  # COM_QUIT
                self.emit("quit")
                break
            if payload[0] == 0x0E:  # COM_PING (pre-auth scanners)
                self.emit("ping_before_auth", severity="notice")
                self.send(build_access_denied("scanner", seq + 1))
                break
            parsed = parse_handshake_response(payload)
            if parsed is None:
                self.emit("handshake_malformed", severity="notice",
                          data=payload[:64].hex())
                break
            attempts += 1
            auth_digest = hashlib.sha256(parsed["auth_response"]).hexdigest()
            self.emit("auth_attempt", severity="alert",
                      user=parsed["username"],
                      auth_sha256=auth_digest,
                      database=parsed["database"],
                      capabilities=parsed["capabilities"])
            self.pause()
            self.send(build_access_denied(parsed["username"], seq + 1))
        if attempts >= 3:
            self.emit("brute_force_suspected", severity="warn",
                      attempts=attempts)

    def _recv_exact(self, n: int) -> bytes | None:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.recv_bytes(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)
