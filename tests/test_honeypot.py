import json
import socket
import threading
import time

from honeypot_server import Logger, run


def test_logger_writes_jsonl(tmp_path):
    log = tmp_path / "trap.jsonl"
    logger = Logger(log)
    logger.log({"service": "http", "src": "1.2.3.4", "event": "data", "data": "GET /"})
    lines = log.read_text(encoding="utf-8").strip().splitlines()
    entry = json.loads(lines[0])
    assert entry["service"] == "http"
    assert entry["src"] == "1.2.3.4"
    assert "ts" in entry


def _wait_for(log, needle, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if log.exists() and needle in log.read_text(encoding="utf-8"):
            return True
        time.sleep(0.1)
    return False


def test_http_decoy_logs_intrusion(tmp_path):
    log = tmp_path / "trap.jsonl"
    stop = threading.Event()

    # bind a free port first, then reuse it
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    servers = run(["http"], "127.0.0.1", {"http": port}, log, stop)
    try:
        time.sleep(0.3)
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        s.recv(64)  # wait for the banner, then attack
        s.sendall(b"GET /admin HTTP/1.1\r\nHost: x\r\n\r\n")
        # A real client awaits the response; closing instantly on Windows
        # can RST the connection and eat the in-flight data.
        s.settimeout(3)
        s.recv(1024)
        s.close()
        assert _wait_for(log, "GET /admin")
    finally:
        for srv in servers:
            srv.shutdown()
            srv.server_close()


def test_ftp_banner(tmp_path):
    log = tmp_path / "ftp.jsonl"
    stop = threading.Event()
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    servers = run(["ftp"], "127.0.0.1", {"ftp": port}, log, stop)
    try:
        time.sleep(0.3)
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        banner = s.recv(64)
        s.sendall(b"USER admin\r\n")
        s.close()
        assert banner.startswith(b"220")
        assert _wait_for(log, "USER admin")
    finally:
        for srv in servers:
            srv.shutdown()
            srv.server_close()
