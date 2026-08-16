"""Redis decoy -- RESP parsing, fake INFO, command logging.

Exposed Redis is a top malware target (ransomware, Mirai variants). This
decoy speaks RESP well enough for scanners and attack tools:

* PING, ECHO, TIME, DBSIZE, CONFIG GET answer believably;
* INFO returns a full fake server report rendered from the persona
  (version, OS, run id, fake memory stats);
* AUTH always fails after logging the attempted password (hashed);
* KEYS/SCAN return a few tempting fake key names; GET on them returns
  bait values (including canary tokens when registered);
* CONFIG SET / SLAVEOF / DEBUG -- the classic RCE staging commands --
  are accepted and flagged critical.

Both inline commands ("PING\r\n") and RESP arrays ("*1\r\n$4\r\nPING")
are parsed, since real tools use both.
"""

from __future__ import annotations

import time

from ..core.logger import hash_credential
from ..core.persona import Persona
from .base import ProtocolHandler

#: Fake keys the decoy pretends to hold, with bait values.
FAKE_KEYS = {
    "session:admin": "eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoic3VwZXIifQ==",
    "cache:users": "128",
    "queue:emails": "3",
    "secret:api_key": "sk-live-FAKEFAKEFAKEFAKEFAKEFAKE",
}

#: Commands attackers use to stage persistence or exfiltration.
DANGEROUS_COMMANDS = {
    "config": "configuration tampering",
    "slaveof": "replication hijack attempt",
    "replicaof": "replication hijack attempt",
    "debug": "debug interface abuse",
    "module": "module load attempt",
    "eval": "lua script execution attempt",
    "bgsave": "persistence staging",
    "save": "persistence staging",
}


def encode_simple(value: str) -> bytes:
    """RESP simple string."""
    return f"+{value}\r\n".encode()


def encode_error(value: str) -> bytes:
    """RESP error."""
    return f"-{value}\r\n".encode()


def encode_bulk(value: str | None) -> bytes:
    """RESP bulk string (None -> null bulk)."""
    if value is None:
        return b"$-1\r\n"
    raw = value.encode("utf-8", "replace")
    return b"$" + str(len(raw)).encode() + b"\r\n" + raw + b"\r\n"


def encode_array(items: list[str]) -> bytes:
    """RESP array of bulk strings."""
    out = b"*" + str(len(items)).encode() + b"\r\n"
    for item in items:
        out += encode_bulk(item)
    return out


def encode_int(value: int) -> bytes:
    """RESP integer."""
    return f":{value}\r\n".encode()


def parse_resp_array(data: bytes) -> list[str] | None:
    """Parse one complete RESP array of bulk strings from ``data``.

    Returns None when the buffer is not (yet) a complete array; callers
    treat that as "read more". Only flat arrays of bulk strings are
    supported, which covers every Redis command.
    """
    if not data.startswith(b"*"):
        return None
    lines = data.split(b"\r\n")
    try:
        count = int(lines[0][1:])
    except ValueError:
        return None
    if count < 0 or count > 128:
        return None
    items: list[str] = []
    i = 1
    for _ in range(count):
        if i >= len(lines) or not lines[i].startswith(b"$"):
            return None
        try:
            length = int(lines[i][1:])
        except ValueError:
            return None
        i += 1
        if i >= len(lines):
            return None
        items.append(lines[i][:length].decode("utf-8", "replace"))
        i += 1
    return items


class RedisHandler(ProtocolHandler):
    """Redis decoy session."""

    service = "redis"
    timeout = 6.0

    def handle(self) -> None:
        self.authed = False
        self.emit("connect")
        buf = b""
        while not self.closed:
            chunk = self.recv_bytes(4096)
            if not chunk:
                break
            buf += chunk
            while buf:
                command, rest = self._take_command(buf)
                if command is None:
                    break
                buf = rest
                self.pause()
                self._dispatch(command)

    def _take_command(self, buf: bytes) -> tuple[list[str] | None, bytes]:
        """Extract one command (RESP or inline) from the front of buf."""
        if buf.startswith(b"*"):
            end = self._array_end(buf)
            if end is None:
                return None, buf
            parsed = parse_resp_array(buf[:end])
            return parsed, buf[end:]
        if b"\r\n" in buf:
            line, rest = buf.split(b"\r\n", 1)
            text = line.decode("utf-8", "replace").strip()
            return (text.split() if text else []), rest
        if b"\n" in buf:
            line, rest = buf.split(b"\n", 1)
            text = line.decode("utf-8", "replace").strip()
            return (text.split() if text else []), rest
        return None, buf

    def _array_end(self, buf: bytes) -> int | None:
        """Byte offset just past the first complete RESP array, else None."""
        lines = buf.split(b"\r\n")
        try:
            count = int(lines[0][1:])
        except (ValueError, IndexError):
            return None
        offset = len(lines[0]) + 2
        for _ in range(count):
            if offset >= len(buf) or buf[offset:offset + 1] != b"$":
                return None
            nl = buf.find(b"\r\n", offset)
            if nl == -1:
                return None
            try:
                length = int(buf[offset + 1:nl])
            except ValueError:
                return None
            offset = nl + 2 + length + 2
            if offset > len(buf):
                return None
        return offset

    # -- dispatch -----------------------------------------------------------
    def _dispatch(self, command: list[str]) -> None:
        if not command:
            return
        name = command[0].upper()
        args = command[1:]
        if name == "AUTH":
            self.emit("command", data="AUTH ****", command=name)
        else:
            self.emit("command", data=" ".join(command)[:400], command=name,
                      args=args[:8])
        if name in {c.upper() for c in DANGEROUS_COMMANDS}:
            self.emit("dangerous_command", severity="critical",
                      command=name,
                      reason=DANGEROUS_COMMANDS[name.lower()])
        method = getattr(self, f"cmd_{name.lower()}", None)
        if method is None:
            self.send(encode_error(
                f"ERR unknown command '{command[0]}'"))
            return
        method(args)

    # -- commands -----------------------------------------------------------
    def cmd_ping(self, args: list[str]) -> None:
        if args:
            self.send(encode_bulk(args[0]))
        else:
            self.send(encode_simple("PONG"))

    def cmd_echo(self, args: list[str]) -> None:
        self.send(encode_bulk(args[0] if args else ""))

    def cmd_auth(self, args: list[str]) -> None:
        secret = args[-1] if args else ""
        self.scan_canaries(secret)  # raw check before the value is hashed
        self.emit("auth_attempt", severity="alert",
                  pass_sha256=hash_credential(secret))
        self.send(encode_error("WRONGPASS invalid username-password pair"))

    def cmd_info(self, args: list[str]) -> None:
        self.send(encode_bulk(self._info_report()))

    def _info_report(self) -> str:
        p = self.persona
        lines = [
            "# Server",
            f"redis_version:{p.versions['redis']}",
            "redis_mode:standalone",
            f"os:{p.os} {p.os_version}",
            f"arch_bits:64",
            f"run_id:{p.redis_info_line('run_id')}",
            "tcp_port:6379",
            f"uptime_in_seconds:{86400 * 12}",
            f"executable:{p.redis_info_line('executable')}",
            f"config_file:{p.redis_info_line('config_file')}",
            "# Clients",
            "connected_clients:2",
            "# Memory",
            "used_memory:1048576",
            "used_memory_human:1.00M",
            "maxmemory:268435456",
            "# Keyspace",
            "db0:keys=4,expires=0,avg_ttl=0",
        ]
        return "\r\n".join(lines) + "\r\n"

    def cmd_time(self, args: list[str]) -> None:
        now = int(time.time())
        self.send(encode_array([str(now), "000000"]))

    def cmd_dbsize(self, args: list[str]) -> None:
        self.send(encode_int(len(FAKE_KEYS)))

    def cmd_keys(self, args: list[str]) -> None:
        self.send(encode_array(list(FAKE_KEYS)))

    def cmd_scan(self, args: list[str]) -> None:
        body = encode_bulk("0") + encode_array(list(FAKE_KEYS))
        self.send(b"*2\r\n" + body)

    def cmd_get(self, args: list[str]) -> None:
        key = args[0] if args else ""
        value = FAKE_KEYS.get(key)
        if value is None:
            for token_value, meta in self.canaries.items():
                if meta.get("kind") == "redis" and key == meta.get("key"):
                    value = meta.get("value", token_value)
        self.emit("key_read", severity="notice", key=key)
        self.send(encode_bulk(value))

    def cmd_exists(self, args: list[str]) -> None:
        key = args[0] if args else ""
        self.send(encode_int(1 if key in FAKE_KEYS else 0))

    def cmd_config(self, args: list[str]) -> None:
        sub = args[0].upper() if args else ""
        if sub == "GET" and len(args) >= 2:
            param = args[1].lower()
            table = {
                "dir": "/var/lib/redis",
                "dbfilename": "dump.rdb",
                "requirepass": "",
                "bind": "0.0.0.0",
            }
            if param in table:
                self.send(encode_array([param, table[param]]))
            else:
                self.send(encode_array([]))
        else:
            self.send(encode_simple("OK"))

    def cmd_slaveof(self, args: list[str]) -> None:
        self.send(encode_simple("OK"))

    def cmd_replicaof(self, args: list[str]) -> None:
        self.cmd_slaveof(args)

    def cmd_save(self, args: list[str]) -> None:
        self.send(encode_simple("OK"))

    def cmd_bgsave(self, args: list[str]) -> None:
        self.send(encode_simple("Background saving started"))

    def cmd_quit(self, args: list[str]) -> None:
        self.send(encode_simple("OK"))
        self.closed = True
