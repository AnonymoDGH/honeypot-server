"""SMTP decoy -- EHLO/MAIL/RCPT/DATA state machine with open-relay bait.

Spammers probe for open relays within minutes of a new IP appearing. This
decoy behaves like a misconfigured mail server: it advertises a generous
EHLO, accepts *any* sender and *any* recipient (including remote domains,
the classic relay test), and captures the full DATA payload. Every
accepted message is logged with its envelope and a SHA-256 digest of the
body so operators can deduplicate spam runs without storing floods.

AUTH is offered but always fails after one challenge -- capturing the
attempted credentials (hashed) on the way.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from ..core.logger import hash_credential
from ..core.persona import Persona
from .base import ProtocolHandler

#: Session states.
S_GREETED = "greeted"
S_HELO = "helo"          # EHLO/HELO done, ready for MAIL
S_MAIL = "mail"          # MAIL FROM seen, ready for RCPT
S_RCPT = "rcpt"          # at least one RCPT TO seen, ready for DATA
S_DATA = "data"          # reading message body until <CRLF>.<CRLF>
S_AUTH_PLAIN = "auth_plain"   # waiting for base64 credentials
S_AUTH_LOGIN_USER = "auth_login_user"
S_AUTH_LOGIN_PASS = "auth_login_pass"

#: Largest message body we will buffer (2 MiB) before cutting it off.
MAX_BODY = 2 * 1024 * 1024


@dataclass
class Envelope:
    """The SMTP transaction in progress."""

    helo: str = ""
    mail_from: str = ""
    rcpt_to: list[str] = field(default_factory=list)
    body: str = ""

    def reset(self) -> None:
        self.mail_from = ""
        self.rcpt_to = []
        self.body = ""


def parse_address(arg: str) -> str:
    """Extract the address from a MAIL FROM/RCPT TO argument.

    Handles both ``<addr>`` and bare ``addr`` forms plus ESMTP params
    (``SIZE=...`` etc.) after the address.
    """
    text = arg.strip()
    if text.startswith("<"):
        end = text.find(">")
        return text[1:end] if end != -1 else text[1:]
    return text.split(" ")[0].strip()


class SMTPHandler(ProtocolHandler):
    """SMTP state machine with open-relay bait."""

    service = "smtp"

    def handle(self) -> None:
        self.state = S_GREETED
        self.env = Envelope()
        self.messages = 0
        self.emit("connect")
        banner = self.persona.smtp_banner()
        self.send_text(banner + "\r\n")
        self.emit("banner", data=banner)
        while not self.closed:
            line = self.recv_line()
            if line is None:
                break
            text = line.decode("utf-8", "replace")
            if self.state == S_DATA:
                self._data_line(text)
                continue
            if self.handle_auth_states(text):
                continue
            stripped = text.strip()
            if not stripped:
                continue
            self.pause()
            self._dispatch(stripped)

    # -- dispatch -----------------------------------------------------------
    def _dispatch(self, text: str) -> None:
        cmd, _, arg = text.partition(" ")
        cmd = cmd.upper()
        arg = arg.strip()
        if cmd in ("AUTH",):
            self.emit("command", data=text[:200], command=cmd)
        else:
            self.emit("command", data=text[:400], command=cmd, arg=arg[:200])
        method = getattr(self, f"cmd_{cmd.lower()}", None)
        if method is None:
            self.send_text("502 5.5.2 Command not recognized.\r\n")
            return
        method(arg)

    # -- handshake ------------------------------------------------------------
    def cmd_ehlo(self, arg: str) -> None:
        self.env.reset()
        self.env.helo = arg or "?"
        self.state = S_HELO
        fqdn = self.persona.fqdn
        self.send_text(f"250-{fqdn}\r\n"
                       "250-PIPELINING\r\n"
                       "250-SIZE 52428800\r\n"
                       "250-8BITMIME\r\n"
                       "250-AUTH PLAIN LOGIN\r\n"
                       "250 HELP\r\n")

    def cmd_helo(self, arg: str) -> None:
        self.env.reset()
        self.env.helo = arg or "?"
        self.state = S_HELO
        self.send_text(f"250 {self.persona.fqdn}\r\n")

    # -- envelope ---------------------------------------------------------------
    def cmd_mail(self, arg: str) -> None:
        if self.state not in (S_HELO, S_RCPT):
            self.send_text("503 5.5.1 Error: send EHLO/HELO first.\r\n")
            return
        if not arg.upper().startswith("FROM:"):
            self.send_text("501 5.5.4 Syntax: MAIL FROM:<address>.\r\n")
            return
        self.env.reset()
        self.env.mail_from = parse_address(arg[5:])
        self.state = S_MAIL
        self.send_text("250 2.1.0 Ok\r\n")

    def cmd_rcpt(self, arg: str) -> None:
        if self.state not in (S_MAIL, S_RCPT):
            self.send_text("503 5.5.1 Error: need MAIL command.\r\n")
            return
        if not arg.upper().startswith("TO:"):
            self.send_text("501 5.5.4 Syntax: RCPT TO:<address>.\r\n")
            return
        addr = parse_address(arg[3:])
        self.env.rcpt_to.append(addr)
        self.state = S_RCPT
        # Open-relay bait: accept every recipient, even remote domains.
        self.send_text("250 2.1.5 Ok\r\n")

    def cmd_data(self, arg: str) -> None:
        if self.state != S_RCPT:
            self.send_text("503 5.5.1 Error: need RCPT command.\r\n")
            return
        self.state = S_DATA
        self.send_text("354 End data with <CR><LF>.<CR><LF>.\r\n")

    def _data_line(self, text: str) -> None:
        if text.rstrip("\r") == ".":
            self._finish_message()
            return
        if len(self.env.body) < MAX_BODY:
            # Undo dot-stuffing like a real MTA.
            if text.startswith(".."):
                text = text[1:]
            self.env.body += text.rstrip("\r\n") + "\n"

    def _finish_message(self) -> None:
        self.messages += 1
        body_digest = hash_credential(self.env.body)
        remote = any("@" in r and not r.endswith(self.persona.domain)
                     for r in self.env.rcpt_to)
        self.emit("message_accepted", severity="alert",
                  mail_from=self.env.mail_from,
                  rcpt_to=list(self.env.rcpt_to),
                  body_sha256=body_digest,
                  bytes=len(self.env.body),
                  relay_attempt=remote)
        if remote:
            self.emit("open_relay_abuse", severity="critical",
                      mail_from=self.env.mail_from,
                      rcpt_to=list(self.env.rcpt_to))
        self.send_text("250 2.0.0 Ok: queued as %08X\r\n" % (self.messages * 7919))
        self.env.reset()
        self.state = S_HELO

    # -- auth bait ---------------------------------------------------------------
    def cmd_auth(self, arg: str) -> None:
        mech = arg.split(" ")[0].upper() if arg else ""
        if mech == "PLAIN":
            rest = arg[5:].strip()
            if rest:
                self._auth_plain(rest)
            else:
                self.state = S_AUTH_PLAIN
                self.send_text("334 \r\n")
        elif mech == "LOGIN":
            self.state = S_AUTH_LOGIN_USER
            self.send_text("334 VXNlcm5hbWU6\r\n")  # "Username:"
        else:
            self.send_text("504 5.5.4 Mechanism not supported.\r\n")

    def _auth_plain(self, blob: str) -> None:
        try:
            decoded = base64.b64decode(blob).decode("utf-8", "replace")
            parts = decoded.split("\0")
            user = parts[-2] if len(parts) >= 2 else ""
            secret = parts[-1] if parts else ""
        except Exception:
            user, secret = "", ""
        self.scan_canaries(secret)  # raw check before hashing
        self.emit("auth_attempt", severity="alert", user=user,
                  pass_sha256=hash_credential(secret), mechanism="PLAIN")
        self.state = S_HELO
        self.send_text("535 5.7.8 Authentication credentials invalid.\r\n")

    def _auth_login_step(self, text: str) -> None:
        try:
            decoded = base64.b64decode(text.strip()).decode("utf-8", "replace")
        except Exception:
            decoded = text
        if self.state == S_AUTH_LOGIN_USER:
            self._login_user = decoded
            self.state = S_AUTH_LOGIN_PASS
            self.send_text("334 UGFzc3dvcmQ6\r\n")  # "Password:"
        else:
            self.scan_canaries(decoded)  # raw check before hashing
            self.emit("auth_attempt", severity="alert",
                      user=getattr(self, "_login_user", ""),
                      pass_sha256=hash_credential(decoded),
                      mechanism="LOGIN")
            self.state = S_HELO
            self.send_text("535 5.7.8 Authentication credentials invalid.\r\n")

    # -- misc ------------------------------------------------------------------
    def cmd_rset(self, arg: str) -> None:
        self.env.reset()
        if self.state not in (S_GREETED,):
            self.state = S_HELO
        self.send_text("250 2.0.0 Ok\r\n")

    def cmd_noop(self, arg: str) -> None:
        self.send_text("250 2.0.0 Ok\r\n")

    def cmd_vrfy(self, arg: str) -> None:
        # Pretend every persona user exists: bait for address harvesting.
        name = arg.split("@")[0].strip()
        if self.persona.find_user(name):
            self.send_text(f"250 {name} <{name}@{self.persona.domain}>\r\n")
        else:
            self.send_text(f"252 2.1.5 Cannot VRFY user.\r\n")

    def cmd_quit(self, arg: str) -> None:
        self.send_text("221 2.0.0 Bye\r\n")
        self.closed = True

    def handle_auth_states(self, text: str) -> bool:
        """Route a line to AUTH state handling when inside AUTH. True if handled."""
        if self.state == S_AUTH_PLAIN:
            self._auth_plain(text.strip())
            return True
        if self.state in (S_AUTH_LOGIN_USER, S_AUTH_LOGIN_PASS):
            self._auth_login_step(text)
            return True
        return False
