"""Tests for the server lifecycle manager and port registry."""

import socket
import time

import pytest

from honeypot_server.core.persona import Persona
from honeypot_server.core.server import (
    DecoyRecord,
    HoneypotManager,
    PortRegistry,
)


def _free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


class TestPortRegistry:
    def test_claim_and_release(self):
        reg = PortRegistry()
        assert reg.claim("127.0.0.1", 81, "http")
        assert not reg.claim("127.0.0.1", 81, "ftp")  # taken
        assert reg.owner("127.0.0.1", 81) == "http"
        reg.release("127.0.0.1", 81)
        assert reg.owner("127.0.0.1", 81) is None
        assert reg.claim("127.0.0.1", 81, "ftp")

    def test_all_snapshot(self):
        reg = PortRegistry()
        reg.claim("h", 1, "a")
        reg.claim("h", 2, "b")
        assert reg.all() == {("h", 1): "a", ("h", 2): "b"}


class TestDecoyRecord:
    def test_not_running_initially(self):
        rec = DecoyRecord(service="http", host="h", port=1)
        assert not rec.running and rec.uptime == 0.0
        d = rec.to_dict()
        assert d["service"] == "http" and d["running"] is False
        assert d["transport"] == "tcp"


class TestManagerLifecycle:
    def test_add_unknown_service_raises(self, tmp_path):
        mgr = HoneypotManager(tmp_path / "m.jsonl")
        with pytest.raises(ValueError):
            mgr.add("gopher")

    def test_add_duplicate_raises(self, tmp_path):
        mgr = HoneypotManager(tmp_path / "m.jsonl")
        mgr.add("http")
        with pytest.raises(ValueError):
            mgr.add("http")

    def test_start_stop_roundtrip(self, tmp_path):
        mgr = HoneypotManager(tmp_path / "m.jsonl", persona=Persona.generate(3))
        mgr.add("http", _free_port())
        mgr.add("ftp", _free_port())
        started = mgr.start()
        try:
            assert {r.service for r in started} == {"http", "ftp"}
            assert all(r.running for r in started)
            status = mgr.status()
            assert status["decoys"]["http"]["running"] is True
            assert len(status["ports"]) == 2
            assert status["persona"] == Persona.generate(3).fqdn
        finally:
            stopped = mgr.stop_all()
        assert set(stopped) == {"http", "ftp"}
        assert not any(r.running for r in mgr.records.values())

    def test_ephemeral_port_assigned(self, tmp_path):
        mgr = HoneypotManager(tmp_path / "m.jsonl")
        mgr.add("redis", 0)
        mgr.start("redis")
        try:
            assert mgr.records["redis"].port > 0
        finally:
            mgr.stop_all()

    def test_decoy_actually_serves(self, tmp_path):
        mgr = HoneypotManager(tmp_path / "m.jsonl", persona=Persona.generate(4))
        mgr.add("ftp", _free_port())
        mgr.start("ftp")
        try:
            port = mgr.records["ftp"].port
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            banner = s.recv(128)
            s.close()
            assert banner.startswith(b"220")
        finally:
            mgr.stop_all()

    def test_bind_conflict_reported_not_fatal(self, tmp_path):
        busy = socket.socket()
        busy.bind(("127.0.0.1", 0))
        busy.listen(1)
        port = busy.getsockname()[1]
        mgr = HoneypotManager(tmp_path / "m.jsonl")
        mgr.add("http", port)
        started = mgr.start("http")
        try:
            assert started == []
            assert not mgr.records["http"].running
            text = (tmp_path / "m.jsonl").read_text(encoding="utf-8")
            assert "bind_failed" in text
        finally:
            mgr.stop_all()
            busy.close()

    def test_health_check(self, tmp_path):
        mgr = HoneypotManager(tmp_path / "m.jsonl")
        mgr.add("http", _free_port())
        mgr.add("dns", _free_port())
        mgr.add("ftp", _free_port())
        mgr.start()
        try:
            health = mgr.health_check(timeout=1.0)
            assert health == {"http": True, "dns": True, "ftp": True}
        finally:
            mgr.stop_all()
        health = mgr.health_check()
        assert all(v is False for v in health.values())

    def test_context_manager(self, tmp_path):
        with HoneypotManager(tmp_path / "m.jsonl") as mgr:
            mgr.add("telnet", _free_port())
            mgr.start("telnet")
            assert mgr.records["telnet"].running
        assert not mgr.records["telnet"].running

    def test_shared_persona_across_decoys(self, tmp_path):
        mgr = HoneypotManager(tmp_path / "m.jsonl", persona="acme-dc1")
        mgr.add("http", _free_port())
        mgr.add("ssh", _free_port())
        mgr.start()
        try:
            http_port = mgr.records["http"].port
            ssh_port = mgr.records["ssh"].port
            s = socket.create_connection(("127.0.0.1", ssh_port), timeout=3)
            ssh_banner = s.recv(256).decode().strip()
            s.close()
            s = socket.create_connection(("127.0.0.1", http_port), timeout=3)
            s.sendall(b"GET /status HTTP/1.1\r\nHost: x\r\n\r\n")
            body = b""
            s.settimeout(3)
            while True:
                try:
                    chunk = s.recv(4096)
                except (socket.timeout, TimeoutError):
                    break
                if not chunk:
                    break
                body += chunk
            s.close()
            # both surfaces agree with the persona story
            assert ssh_banner == mgr.persona.ssh_banner()
            assert mgr.persona.fqdn.encode() in body
        finally:
            mgr.stop_all()

    def test_add_many_and_status_events(self, tmp_path):
        mgr = HoneypotManager(tmp_path / "m.jsonl")
        records = mgr.add_many(["http", "ftp"], {"http": _free_port()})
        assert [r.service for r in records] == ["http", "ftp"]
        mgr.start()
        try:
            assert mgr.status()["events"] >= 2  # decoy_started events
        finally:
            mgr.stop_all()
