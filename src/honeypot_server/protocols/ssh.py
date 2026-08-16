"""SSH decoy -- banner exchange, KEXINIT parsing, client fingerprinting.

A low-interaction decoy cannot complete real SSH cryptography with the
standard library, but it can go much further than a banner:

* exchange identification strings and parse the client's binary
  SSH_MSG_KEXINIT packet, extracting every algorithm name-list;
* fingerprint the client software from those lists (OpenSSH, PuTTY,
  Paramiko, libssh, Nmap...) -- scanners have distinctive stacks;
* answer with a persona-consistent KEXINIT of our own, log the
  client's Diffie-Hellman public value when it arrives, then bow out
  with a polite SSH_MSG_DISCONNECT;
* fall back to plaintext capture when a lazy tool skips the protocol
  entirely (USER/PASS-style lines are logged with hashed secrets).
"""

from __future__ import annotations

import struct
from typing import Any

from ..core.logger import hash_credential
from ..core.persona import Persona
from .base import ProtocolHandler

#: SSH protocol message numbers we care about.
MSG_DISCONNECT = 1
MSG_KEXINIT = 20
MSG_KEXDH_INIT = 30

#: The ten name-lists inside KEXINIT, in wire order (RFC 4253 sec. 7.1).
KEXINIT_FIELDS = (
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_algorithms_client_to_server",
    "encryption_algorithms_server_to_client",
    "mac_algorithms_client_to_server",
    "mac_algorithms_server_to_client",
    "compression_algorithms_client_to_server",
    "compression_algorithms_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
)

#: Client fingerprints: (marker kex algorithms, marker ciphers) -> guess.
#: Order matters; the first rule whose markers all appear wins.
FINGERPRINT_RULES: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("nmap",
     ("diffie-hellman-group-exchange-sha256",),
     ("aes128-cbc", "3des-cbc", "blowfish-cbc", "cast128-cbc")),
    ("putty",
     ("ecdh-sha2-nistp256", "rsa2048-sha2-256"),
     ("aes256-ctr", "aes256-cbc")),
    ("paramiko",
     ("ecdh-sha2-nistp256", "diffie-hellman-group-exchange-sha256"),
     ("aes128-ctr", "aes256-ctr")),
    ("libssh",
     ("curve25519-sha256", "ecdh-sha2-nistp256",
      "diffie-hellman-group18-sha512"),
     ("chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com")),
    ("openssh",
     ("sntrup761x25519-sha512@openssh.com", "curve25519-sha256"),
     ("chacha20-poly1305@openssh.com", "aes128-ctr")),
)


def fingerprint_client(kex: list[str], ciphers: list[str]) -> str:
    """Guess the client software from its KEXINIT algorithm lists.

    Returns one of the rule names ("openssh", "putty", "paramiko",
    "libssh", "nmap") or "unknown". Matching is by subset: every marker
    in a rule must appear in the client's lists.
    """
    kex_set, cipher_set = set(kex), set(ciphers)
    for name, kex_markers, cipher_markers in FINGERPRINT_RULES:
        if all(m in kex_set for m in kex_markers) and all(
                m in cipher_set for m in cipher_markers):
            return name
    return "unknown"


def parse_kexinit(payload: bytes) -> dict[str, Any] | None:
    """Parse an SSH_MSG_KEXINIT payload into cookie + name-lists.

    ``payload`` starts with the message-type byte. Returns None when the
    buffer is malformed or truncated (scanners love sending junk).
    """
    if len(payload) < 17 or payload[0] != MSG_KEXINIT:
        return None
    cookie = payload[1:17]
    offset = 17
    result: dict[str, Any] = {"cookie": cookie.hex()}
    for field in KEXINIT_FIELDS:
        if offset + 4 > len(payload):
            return None
        (length,) = struct.unpack(">I", payload[offset:offset + 4])
        offset += 4
        if offset + length > len(payload):
            return None
        raw = payload[offset:offset + length].decode("ascii", "replace")
        offset += length
        result[field] = [x for x in raw.split(",") if x]
    return result


def build_kexinit(persona: Persona, cookie: bytes) -> bytes:
    """Build our (fake but well-formed) KEXINIT packet, ready to send.

    The algorithm lists mirror the persona's SSH story so fingerprints
    stay consistent with the identification banner.
    """
    openssh = "OpenSSH" in persona.versions.get("ssh", "")
    kex = ("curve25519-sha256,ecdh-sha2-nistp256,"
           "diffie-hellman-group16-sha512,diffie-hellman-group14-sha256")
    if openssh:
        kex = "sntrup761x25519-sha512@openssh.com," + kex
    host_key = "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519"
    ciphers = ("chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr,"
               "aes128-gcm@openssh.com")
    macs = "umac-64-etm@openssh.com,hmac-sha2-256,hmac-sha2-512"
    payload = bytes([MSG_KEXINIT]) + cookie
    for value in (kex, host_key, ciphers, ciphers, macs, macs,
                  "none", "none", "", ""):
        payload += struct.pack(">I", len(value)) + value.encode("ascii")
    payload += bytes([0]) + struct.pack(">I", 0)  # first_kex_follows, 0
    return wrap_packet(payload)


def wrap_packet(payload: bytes) -> bytes:
    """Wrap a payload in SSH binary packet framing (no encryption)."""
    block = 8
    pad_len = block - ((5 + len(payload)) % block)
    if pad_len < 4:
        pad_len += block
    packet_len = 1 + len(payload) + pad_len
    return struct.pack(">IB", packet_len, pad_len) + payload + b"\0" * pad_len


def read_packet(recv) -> bytes | None:
    """Read one SSH packet using ``recv(n)``; None on EOF/short read."""
    head = recv(4)
    if head is None or len(head) < 4:
        return None
    (length,) = struct.unpack(">I", head)
    if length <= 0 or length > 65536:
        return None
    body = recv(length)
    if body is None or len(body) < length:
        return None
    padding = body[0]
    return body[1:length - padding]


class SSHHandler(ProtocolHandler):
    """SSH decoy session: ident exchange, KEXINIT, fingerprint, capture."""

    service = "ssh"

    def handle(self) -> None:
        self.emit("connect")
        banner = self.persona.ssh_banner()
        self.send_text(banner + "\r\n")
        self.emit("banner", data=banner)
        ident = self.recv_line()
        if ident is None:
            return
        client_ident = ident.decode("utf-8", "replace").strip()
        self.emit("identification", data=client_ident)
        if not client_ident.startswith("SSH-"):
            self._plaintext_session(client_ident)
            return
        self._binary_session()

    # -- binary protocol ------------------------------------------------------
    def _recv_exact(self, n: int) -> bytes | None:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.recv_bytes(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def _binary_session(self) -> None:
        packet = read_packet(self._recv_exact)
        if packet is None:
            self.emit("kex_truncated", severity="notice")
            return
        if not packet or packet[0] != MSG_KEXINIT:
            self.emit("unexpected_packet", severity="notice",
                      msg_type=packet[0] if packet else -1)
            return
        parsed = parse_kexinit(packet)
        if parsed is None:
            self.emit("kexinit_malformed", severity="notice")
            return
        client = fingerprint_client(parsed["kex_algorithms"],
                                    parsed["encryption_algorithms_client_to_server"])
        self.emit("kexinit", severity="notice", client_guess=client,
                  kex_algorithms=parsed["kex_algorithms"],
                  ciphers=parsed["encryption_algorithms_client_to_server"],
                  host_keys=parsed["server_host_key_algorithms"])
        cookie = bytes(range(16))  # deterministic: fine for a decoy
        self.send(build_kexinit(self.persona, cookie))
        self.pause()
        # Expect KEXDH_INIT next; log the client's DH public value.
        nxt = read_packet(self._recv_exact)
        if nxt and nxt[0] == MSG_KEXDH_INIT:
            e_len = struct.unpack(">I", nxt[1:5])[0] if len(nxt) >= 5 else 0
            e_hex = nxt[5:5 + e_len].hex()[:64]
            self.emit("kexdh_init", severity="notice", e=e_hex)
        self._disconnect("Protocol error: no matching key exchange method")

    def _disconnect(self, reason: str) -> None:
        payload = struct.pack(">BI", MSG_DISCONNECT, 3)  # 3 = key exchange
        payload += struct.pack(">I", len(reason)) + reason.encode()
        payload += struct.pack(">I", 0)  # language tag
        self.send(wrap_packet(payload))
        self.closed = True

    # -- plaintext fallback -----------------------------------------------------
    def _plaintext_session(self, first_line: str) -> None:
        """Tools that speak before handshaking: capture what they say.

        Lazy scanners and misconfigured scripts sometimes send credentials
        or shell commands in the clear. We play along with a fake shell
        prompt for a few lines, hashing anything password-like.
        """
        self._capture_line(first_line)
        self.send_text("Password: ")
        for _ in range(4):
            line = self.recv_line()
            if line is None:
                break
            text = line.decode("utf-8", "replace").strip()
            if not text:
                continue
            self._capture_line(text)
            self.send_text("-bash: command not found\n")

    def _capture_line(self, text: str) -> None:
        lowered = text.lower()
        if lowered.startswith(("user ", "login ", "user:")):
            _, _, value = text.partition(" ")
            if ":" in lowered[:6]:
                _, _, value = text.partition(":")
            self.emit("plaintext_user", severity="alert", user=value.strip())
        elif lowered.startswith(("pass", "password")):
            _, _, value = text.partition(" ")
            if ":" in lowered[:10]:
                _, _, value = text.partition(":")
            self.scan_canaries(value.strip())  # raw check before hashing
            self.emit("plaintext_password", severity="alert",
                      pass_sha256=hash_credential(value.strip()))
        else:
            self.emit("plaintext_data", data=text[:200])
