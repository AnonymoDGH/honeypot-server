"""Telnet decoy -- fake login plus a canned busybox-style shell.

Telnet is where IoT botnets recruit. This decoy:

* performs minimal IAC negotiation (WILL ECHO, WILL SGA, DONT LINEMODE)
  so clients that insist on option handshakes do not bail out;
* presents the persona's login prompt and accepts any username with
  any password after one "Login incorrect" -- then lets them in, which
  is exactly what a default-credential device would do;
* serves a fake busybox shell: ls, cat, whoami, uname, ifconfig, wget,
  cd, echo, busybox -- canned output seeded from the persona, so the
  machine the bot "compromised" matches every other decoy surface;
* logs every command; download attempts (wget/curl/tftp) are flagged as
  malware staging.
"""

from __future__ import annotations

from ..core.logger import hash_credential
from ..core.persona import Persona
from .base import ProtocolHandler

#: Telnet protocol bytes.
IAC = 255
WILL = 251
WONT = 252
DO = 253
DONT = 254
SB = 250
SE = 240

#: Telnet options we negotiate.
OPT_ECHO = 1
OPT_SGA = 3
OPT_LINEMODE = 34

#: Commands that indicate malware staging / lateral movement.
STAGING_COMMANDS = ("wget", "curl", "tftp", "scp", "nc", "netcat")


def strip_iac(data: bytes) -> tuple[bytes, list[tuple[int, int]]]:
    """Separate telnet IAC sequences from printable input.

    Returns (clean_text_bytes, negotiations) where negotiations is a list
    of (verb, option) pairs seen in the stream. Sub-negotiations are
    skipped whole. Doubled IAC (escaped 0xFF literal) becomes one 0xFF.
    """
    clean = bytearray()
    negotiations: list[tuple[int, int]] = []
    i = 0
    while i < len(data):
        b = data[i]
        if b != IAC:
            clean.append(b)
            i += 1
            continue
        if i + 1 >= len(data):
            break
        verb = data[i + 1]
        if verb == IAC:
            clean.append(IAC)
            i += 2
        elif verb in (WILL, WONT, DO, DONT):
            if i + 2 < len(data):
                negotiations.append((verb, data[i + 2]))
            i += 3
        elif verb == SB:
            end = data.find(bytes([IAC, SE]), i)
            i = len(data) if end == -1 else end + 2
        else:
            i += 2
    return bytes(clean), negotiations


class TelnetHandler(ProtocolHandler):
    """Telnet decoy: negotiate, fake login, canned busybox shell."""

    service = "telnet"

    def handle(self) -> None:
        self.persona_ctx = self.persona
        self.username = ""
        self.commands: list[str] = []
        self.emit("connect")
        self._negotiate()
        if not self._login():
            return
        self._shell()
        if self.commands:
            self.emit("session_summary", severity="notice",
                      commands=list(self.commands))

    # -- negotiation -----------------------------------------------------------
    def _negotiate(self) -> None:
        self.send(bytes([
            IAC, WILL, OPT_ECHO,
            IAC, WILL, OPT_SGA,
            IAC, DONT, OPT_LINEMODE,
        ]))

    def _read_line(self) -> str | None:
        """Read one line, stripping any IAC sequences that arrive inline."""
        line = self.recv_line()
        if line is None:
            return None
        clean, negotiations = strip_iac(line)
        for verb, option in negotiations:
            self.emit("iac", severity="debug", verb=verb, option=option)
            # Refuse anything we did not offer; agree to their DO-ECHO.
            if verb == DO and option in (OPT_ECHO, OPT_SGA):
                continue
            if verb in (DO, WILL):
                reply_verb = WONT if verb == DO else DONT
                self.send(bytes([IAC, reply_verb, option]))
        return clean.decode("utf-8", "replace").strip()

    # -- login ------------------------------------------------------------------
    def _login(self) -> bool:
        p = self.persona_ctx
        for attempt in range(3):
            self.send_text(f"{p.hostname} login: ")
            user = self._read_line()
            if user is None:
                return False
            self.send_text("Password: ")
            password = self._read_line()
            if password is None:
                return False
            known = p.find_user(user)
            success = bool(known and known.password == password)
            self.scan_canaries(password)  # raw check before hashing
            self.emit("login_attempt", severity="alert", user=user,
                      pass_sha256=hash_credential(password), success=success)
            # Default-credential bait: any non-empty pair gets in.
            if user and password:
                self.username = user
                self.emit("login_success", severity="critical", user=user)
                self.send_text("\r\nWelcome to the application server.\r\n\r\n")
                return True
            self.send_text("Login incorrect\r\n")
        self.send_text("Too many login failures.\r\n")
        return False

    # -- shell ------------------------------------------------------------------
    def _shell(self) -> None:
        while not self.closed:
            self.send_text(f"{self.username}@{self.persona_ctx.hostname}:~$ ")
            line = self._read_line()
            if line is None:
                break
            if not line:
                continue
            self.pause()
            self._run(line)

    def _run(self, line: str) -> None:
        parts = line.split()
        cmd = parts[0].lower()
        self.commands.append(line[:200])
        severity = "warn" if cmd in STAGING_COMMANDS else "info"
        self.emit("command", data=line[:400], command=cmd, severity=severity)
        if cmd in STAGING_COMMANDS:
            self.emit("malware_staging", severity="critical", data=line[:400])
        handler = getattr(self, f"sh_{cmd}", None)
        if handler is None:
            self.send_text(f"-ash: {cmd}: not found\r\n")
            return
        handler(parts[1:])

    # -- canned commands -----------------------------------------------------------
    def sh_whoami(self, args: list[str]) -> None:
        self.send_text(self.username + "\r\n")

    def sh_id(self, args: list[str]) -> None:
        self.send_text(f"uid=0({self.username}) gid=0(root)\r\n")

    def sh_uname(self, args: list[str]) -> None:
        p = self.persona_ctx
        if "-a" in args:
            self.send_text(
                f"Linux {p.hostname} {p.kernel} #1 SMP {p.os} armv7l\r\n")
        else:
            self.send_text("Linux\r\n")

    def sh_ls(self, args: list[str]) -> None:
        self.send_text("busybox  firmware.bin  config  tmp  update.sh\r\n")

    def sh_pwd(self, args: list[str]) -> None:
        self.send_text("/root\r\n")

    def sh_cat(self, args: list[str]) -> None:
        target = args[0] if args else ""
        if target.endswith("config") or target == "/etc/passwd":
            lines = ["root:x:0:0:root:/root:/bin/ash"]
            for u in self.persona_ctx.users[:4]:
                lines.append(f"{u.username}:x:{u.uid}:100::/home/{u.username}:/bin/sh")
            self.send_text("\r\n".join(lines) + "\r\n")
        elif target:
            self.send_text(f"cat: {target}: No such file or directory\r\n")

    def sh_ifconfig(self, args: list[str]) -> None:
        ip = self.persona_ctx.ip_story
        self.send_text(
            f"eth0      Link encap:Ethernet  HWaddr 00:0C:29:FA:KE:01\r\n"
            f"          inet addr:{ip}  Bcast:255.255.255.0  Mask:255.255.255.0\r\n"
            "          UP BROADCAST RUNNING MULTICAST  MTU:1500\r\n")

    def sh_ps(self, args: list[str]) -> None:
        self.send_text("PID   USER     COMMAND\r\n"
                       "    1 root     /sbin/init\r\n"
                       "  142 root     /usr/sbin/telnetd\r\n"
                       f"  301 {self.username:<8} -ash\r\n")

    def sh_wget(self, args: list[str]) -> None:
        url = args[-1] if args else ""
        self.emit("download_request", severity="critical", url=url)
        self.send_text(f"Connecting to {url or 'host'}... connected.\r\n"
                       "HTTP request sent, awaiting response... 200 OK\r\n"
                       "Length: 48128 (47K) [application/octet-stream]\r\n"
                       "Saving to: 'download'\r\n\r\n"
                       "100%[===================>] 48,128      12.1K/s\r\n")

    def sh_curl(self, args: list[str]) -> None:
        self.sh_wget(args)

    def sh_echo(self, args: list[str]) -> None:
        self.send_text(" ".join(args) + "\r\n")

    def sh_cd(self, args: list[str]) -> None:
        pass  # always succeeds, silently

    def sh_busybox(self, args: list[str]) -> None:
        self.send_text("BusyBox v1.35.0 (2023-04-11) multi-call binary.\r\n"
                       "Usage: busybox [function [arguments]...]\r\n")

    def sh_exit(self, args: list[str]) -> None:
        self.closed = True
