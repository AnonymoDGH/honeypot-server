"""FTP decoy -- full state machine over a fake directory tree.

The handler walks attackers through a believable FTP session:

* USER/PASS against the persona's fake roster. Unknown users get the
  classic two-stage "give me a password" dance; wrong passwords get 530.
  A correct persona password actually logs the attacker in -- the most
  convincing deception is one that occasionally succeeds.
* CWD/PWD/LS over a virtual directory tree seeded per persona.
* RETR streams small fake files (config snippets, password lists that
  embed canary tokens when a registry is attached).
* Every command is logged; credential attempts are hashed before storage.

Only the control connection is honoured: PORT/PASV answer politely but
never open a data socket, which is exactly how a misbehaving real server
looks to a scanner.
"""

from __future__ import annotations

from typing import Any

from ..core.logger import hash_credential
from ..core.persona import Persona
from .base import ProtocolHandler

#: States of the FTP control session.
STATE_GREETED = "greeted"      # banner sent, waiting for USER
STATE_USER = "user"            # USER seen, waiting for PASS
STATE_AUTHED = "authed"        # logged in


class FakeFTPTree:
    """A virtual FTP directory tree derived from the persona.

    Directories map to dicts of children; files map to their content.
    Paths are absolute ("/...") and normalised by :meth:`resolve`.
    """

    def __init__(self, persona: Persona):
        self.persona = persona
        self.dirs: dict[str, list[str]] = {}
        self.files: dict[str, str] = {}
        self._build()

    def _build(self) -> None:
        p = self.persona
        self.dirs["/"] = ["pub", "incoming", "internal", "backups"]
        self.dirs["/pub"] = ["readme.txt", "site-plan.pdf"]
        self.dirs["/incoming"] = []
        self.dirs["/internal"] = ["staff.csv", "credentials.txt", "deploy.sh"]
        self.dirs["/backups"] = ["db-dump.sql", "www.tar.gz"]
        self.files["/pub/readme.txt"] = (
            f"Welcome to {p.fqdn}.\n"
            "This server holds internal releases. Do not index.\n")
        self.files["/pub/site-plan.pdf"] = "%PDF-1.4 fake\n"
        staff_rows = ["username,role,office"]
        for u in p.users:
            staff_rows.append(f"{u.username},{u.role},hq")
        self.files["/internal/staff.csv"] = "\n".join(staff_rows) + "\n"
        cred_rows = ["# recovered credentials -- rotate these"]
        for u in p.users[:3]:
            cred_rows.append(f"{u.username}:{u.password}")
        self.files["/internal/credentials.txt"] = "\n".join(cred_rows) + "\n"
        self.files["/internal/deploy.sh"] = (
            "#!/bin/sh\nrsync -a /var/www/ backup@10.0.0.9:/srv/www/\n")
        self.files["/backups/db-dump.sql"] = (
            "-- dump of appdb\nCREATE TABLE sessions (id INT);\n")
        self.files["/backups/www.tar.gz"] = "\x1f\x8b fake gzip stream\n"

    def inject(self, path: str, content: str, directory: str = "/internal") -> None:
        """Plant an extra bait file (e.g. a canary document) into the tree."""
        self.files[path] = content
        name = path.rsplit("/", 1)[-1]
        parent = path.rsplit("/", 1)[0] or "/"
        listing = self.dirs.setdefault(parent, [])
        if name not in listing:
            listing.append(name)

    def resolve(self, cwd: str, target: str) -> str:
        """Resolve ``target`` (absolute or relative) against ``cwd``."""
        if not target:
            return cwd
        if target.startswith("/"):
            parts = target.strip("/").split("/")
            base: list[str] = []
        else:
            parts = target.split("/")
            base = [x for x in cwd.strip("/").split("/") if x]
        for part in parts:
            if part in ("", "."):
                continue
            if part == "..":
                if base:
                    base.pop()
            else:
                base.append(part)
        return "/" + "/".join(base)

    def is_dir(self, path: str) -> bool:
        return path in self.dirs

    def is_file(self, path: str) -> bool:
        return path in self.files

    def list_dir(self, path: str) -> list[tuple[str, str]]:
        """(kind, name) pairs for a directory: kind is "d" or "-"."""
        entries = []
        for name in self.dirs.get(path, []):
            child = self.resolve(path, name)
            kind = "d" if child in self.dirs else "-"
            entries.append((kind, name))
        return entries

    def ls_lines(self, path: str) -> list[str]:
        """Unix-style LIST output for ``path``."""
        lines = []
        for kind, name in self.list_dir(path):
            if kind == "d":
                lines.append(f"drwxr-xr-x  2 ftp ftp  4096 Jan 12 09:14 {name}")
            else:
                size = len(self.files.get(self.resolve(path, name), ""))
                lines.append(f"-rw-r--r--  1 ftp ftp {size:>5} Jan 12 09:14 {name}")
        return lines


class FTPHandler(ProtocolHandler):
    """FTP control-connection state machine."""

    service = "ftp"

    def handle(self) -> None:
        self.tree = FakeFTPTree(self.persona)
        self.state = STATE_GREETED
        self.pending_user = ""
        self.username = ""
        self.cwd = "/"
        self.attempts = 0
        self.emit("connect")
        self.send_text(self.persona.ftp_banner() + "\r\n")
        self.emit("banner", data=self.persona.ftp_banner())
        while not self.closed:
            line = self.recv_line()
            if line is None:
                break
            text = line.decode("utf-8", "replace").strip()
            if not text:
                continue
            self.pause()
            self._dispatch(text)
        if self.attempts >= 3:
            self.emit("brute_force_suspected", severity="warn",
                      attempts=self.attempts, user=self.username or self.pending_user)

    # -- dispatch -----------------------------------------------------------
    def _dispatch(self, text: str) -> None:
        cmd, _, arg = text.partition(" ")
        cmd = cmd.upper()
        arg = arg.strip()
        # Log everything; hash PASS values before they touch the log.
        if cmd == "PASS":
            self.emit("command", data="PASS ****", command="PASS")
        else:
            self.emit("command", data=text, command=cmd, arg=arg)
        method = getattr(self, f"cmd_{cmd.lower()}", None)
        if method is None:
            self.send_text("502 Command not implemented.\r\n")
            return
        method(arg)

    # -- auth ----------------------------------------------------------------
    def cmd_user(self, arg: str) -> None:
        self.pending_user = arg
        self.state = STATE_USER
        if self.persona.find_user(arg):
            self.send_text(f"331 Password required for {arg}.\r\n")
        else:
            # Same reply for unknown users: do not leak which names exist.
            self.send_text(f"331 Password required for {arg}.\r\n")

    def cmd_pass(self, arg: str) -> None:
        if self.state != STATE_USER:
            self.send_text("503 Login with USER first.\r\n")
            return
        self.attempts += 1
        user = self.persona.find_user(self.pending_user)
        self.scan_canaries(arg)  # raw check before the value is hashed
        digest = hash_credential(arg)
        success = bool(user and user.password == arg)
        self.emit("login_attempt", severity="alert", user=self.pending_user,
                  pass_sha256=digest, success=success)
        if success:
            self.state = STATE_AUTHED
            self.username = self.pending_user
            self.send_text(f"230 User {self.username} logged in.\r\n")
            self.emit("login_success", severity="critical", user=self.username)
        else:
            self.state = STATE_GREETED
            self.send_text("530 Login incorrect.\r\n")

    # -- navigation -----------------------------------------------------------
    def _require_auth(self) -> bool:
        if self.state != STATE_AUTHED:
            self.send_text("530 Please login with USER and PASS.\r\n")
            return False
        return True

    def cmd_pwd(self, arg: str) -> None:
        if not self._require_auth():
            return
        self.send_text(f'257 "{self.cwd}" is the current directory.\r\n')

    def cmd_cwd(self, arg: str) -> None:
        if not self._require_auth():
            return
        target = self.tree.resolve(self.cwd, arg)
        if self.tree.is_dir(target):
            self.cwd = target
            self.send_text(f"250 Directory changed to {target}.\r\n")
        else:
            self.send_text(f"550 {arg}: No such file or directory.\r\n")

    def cmd_cdup(self, arg: str) -> None:
        self.cmd_cwd("..")

    def cmd_type(self, arg: str) -> None:
        self.send_text(f"200 Type set to {arg or 'A'}.\r\n")

    def cmd_syst(self, arg: str) -> None:
        self.send_text(f"215 UNIX Type: L8 ({self.persona.os})\r\n")

    def cmd_feat(self, arg: str) -> None:
        self.send_text("211-Features:\r\n UTF8\r\n SIZE\r\n211 End\r\n")

    # -- listing / transfer ---------------------------------------------------
    def cmd_list(self, arg: str) -> None:
        if not self._require_auth():
            return
        target = self.tree.resolve(self.cwd, arg) if arg else self.cwd
        if not self.tree.is_dir(target):
            self.send_text(f"550 {arg or self.cwd}: Not a directory.\r\n")
            return
        # Real FTP wants a data connection; we inline the listing, which
        # many clients tolerate and every scanner parses happily.
        lines = self.tree.ls_lines(target)
        self.send_text("150 Opening data connection.\r\n")
        for line in lines:
            self.send_text(line + "\r\n")
        self.send_text("226 Transfer complete.\r\n")

    def cmd_retr(self, arg: str) -> None:
        if not self._require_auth():
            return
        target = self.tree.resolve(self.cwd, arg)
        if not self.tree.is_file(target):
            self.send_text(f"550 {arg}: No such file.\r\n")
            return
        content = self.tree.files[target]
        if target.endswith("credentials.txt"):
            # Embed registered document canaries so a leaked copy phones home.
            for value, meta in self.canaries.items():
                if meta.get("kind") == "doc":
                    content += f"svc-canary:{value}\n"
        self.emit("file_download", severity="notice", path=target)
        self.send_text(f"150 Opening data connection for {arg}.\r\n")
        # Inline the data on the control channel with CRLF endings so the
        # closing 226 always starts on its own line.
        data = content.replace("\r\n", "\n").replace("\n", "\r\n")
        if not data.endswith("\r\n"):
            data += "\r\n"
        self.send_text(data)
        self.send_text("226 Transfer complete.\r\n")

    def cmd_size(self, arg: str) -> None:
        if not self._require_auth():
            return
        target = self.tree.resolve(self.cwd, arg)
        if self.tree.is_file(target):
            self.send_text(f"213 {len(self.tree.files[target])}\r\n")
        else:
            self.send_text(f"550 {arg}: No such file.\r\n")

    def cmd_pasv(self, arg: str) -> None:
        # Advertise a data port we never open: looks like a flaky server.
        self.send_text("227 Entering Passive Mode (127,0,0,1,4,1).\r\n")

    def cmd_port(self, arg: str) -> None:
        self.send_text("200 PORT command successful.\r\n")

    def cmd_quit(self, arg: str) -> None:
        self.send_text("221 Goodbye.\r\n")
        self.closed = True
