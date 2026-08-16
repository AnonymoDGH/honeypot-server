"""Tests for the structured logger, rotation and enrichment helpers."""

import hashlib
import json
import threading

from honeypot_server import Logger
from honeypot_server.core.logger import (
    EventBuffer,
    RotatingJSONLWriter,
    hash_credential,
    iter_log_paths,
    make_event,
    read_events,
    redact,
    severity_rank,
)


def test_logger_writes_jsonl_with_schema(tmp_path):
    log = tmp_path / "trap.jsonl"
    logger = Logger(log)
    logger.log({"service": "http", "src": "1.2.3.4", "event": "data", "data": "GET /"})
    entry = json.loads(log.read_text(encoding="utf-8").strip())
    assert entry["service"] == "http"
    assert entry["src"] == "1.2.3.4"
    assert "ts" in entry and "id" in entry
    assert entry["severity"] == "info"


def test_logger_preserves_caller_severity(tmp_path):
    logger = Logger(tmp_path / "x.jsonl")
    logger.log({"service": "ssh", "src": "a", "event": "login", "severity": "alert"})
    assert logger.tail(1)[0]["severity"] == "alert"


def test_logger_console_mode_counts(capsys):
    logger = Logger(None)
    logger.log({"service": "ftp", "src": "9.9.9.9", "event": "banner"})
    out = capsys.readouterr().out
    assert "ftp" in out and "9.9.9.9" in out
    assert logger.count == 1


def test_logger_enrich_hook(tmp_path):
    logger = Logger(tmp_path / "e.jsonl",
                    enrich=lambda e: {**e, "persona": "web-01"})
    logger.log({"service": "http", "src": "s", "event": "hit"})
    assert logger.tail(1)[0]["persona"] == "web-01"


def test_logger_enrich_hook_errors_are_swallowed(tmp_path):
    def boom(entry):
        raise RuntimeError("nope")
    logger = Logger(tmp_path / "e2.jsonl", enrich=boom)
    stored = logger.log({"service": "http", "src": "s", "event": "hit"})
    assert stored["event"] == "hit"


def test_logger_stats(tmp_path):
    logger = Logger(tmp_path / "s.jsonl")
    logger.log({"service": "http", "src": "1.1.1.1:5", "event": "a"})
    logger.log({"service": "ftp", "src": "1.1.1.1:6", "event": "b"})
    stats = logger.stats()
    assert stats["events"] == 2
    assert stats["by_service"] == {"http": 1, "ftp": 1}
    assert stats["by_source"] == {"1.1.1.1": 2}


def test_make_event_schema():
    e = make_event("redis", "10.0.0.2:443", "command", severity="warn",
                   data="INFO", command="INFO")
    assert e["service"] == "redis" and e["event"] == "command"
    assert e["severity"] == "warn" and e["command"] == "INFO"
    assert len(e["id"]) == 12


def test_make_event_unknown_severity_downgrades():
    assert make_event("x", "y", "z", severity="bogus")["severity"] == "info"


def test_severity_rank_ordering():
    assert severity_rank("debug") < severity_rank("info") < severity_rank("alert")
    assert severity_rank("critical") == 5
    assert severity_rank("mystery") == 1


def test_hash_credential_is_sha256():
    assert hash_credential("hunter2") == hashlib.sha256(b"hunter2").hexdigest()
    assert hash_credential("a") != hash_credential("b")


def test_redact_hashes_sensitive_fields():
    entry = {"service": "ftp", "user": "admin", "password": "hunter2",
             "Token": "abc"}
    out = redact(entry)
    assert out["user"] == "admin"
    assert out["password"].startswith("sha256:")
    assert "hunter2" not in json.dumps(out)
    assert out["Token"].startswith("sha256:")
    # original untouched
    assert entry["password"] == "hunter2"


def test_redact_non_string_values():
    out = redact({"secret": {"a": 1}})
    assert out["secret"].startswith("sha256:")


def test_rotating_writer_rotates_on_size(tmp_path):
    path = tmp_path / "rot.jsonl"
    w = RotatingJSONLWriter(path, max_bytes=100, max_files=3)
    for i in range(30):
        w.write_event({"i": i, "pad": "x" * 40})
    archives = [p for p in tmp_path.iterdir() if p.name != "rot.jsonl"]
    assert len(archives) == 3  # max_files honoured
    assert w.rotations >= 3
    assert path.exists()


def test_rotating_writer_manual_rotate_and_paths(tmp_path):
    path = tmp_path / "m.jsonl"
    w = RotatingJSONLWriter(path, max_bytes=10_000, max_files=2)
    w.write_line("one")
    target = w.rotate()
    assert target == path.with_name("m.jsonl.1")
    w.write_line("two")
    names = [p.name for p in w.paths()]
    assert names == ["m.jsonl", "m.jsonl.1"]
    assert w.total_bytes() > 0


def test_rotating_writer_empty_rotate_is_noop(tmp_path):
    w = RotatingJSONLWriter(tmp_path / "empty.jsonl")
    assert w.rotate() is None


def test_read_events_chronological_across_rotation(tmp_path):
    path = tmp_path / "c.jsonl"
    w = RotatingJSONLWriter(path, max_bytes=200, max_files=8)
    for i in range(20):
        w.write_event({"seq": i, "pad": "y" * 30})
    seqs = [e["seq"] for e in read_events(path)]
    assert seqs == sorted(seqs)
    assert len(seqs) == 20


def test_read_events_skips_malformed(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text('{"a": 1}\nnot json\n\n{"a": 2}\n', encoding="utf-8")
    assert [e["a"] for e in read_events(path)] == [1, 2]


def test_iter_log_paths(tmp_path):
    path = tmp_path / "i.jsonl"
    path.write_text("{}", encoding="utf-8")
    (tmp_path / "i.jsonl.1").write_text("{}", encoding="utf-8")
    names = [p.name for p in iter_log_paths(path)]
    assert names == ["i.jsonl", "i.jsonl.1"]


def test_event_buffer_ring_and_queries():
    buf = EventBuffer(maxlen=5)
    for i in range(8):
        buf.append({"service": "http" if i % 2 else "ftp",
                    "src": f"10.0.0.{i}:1", "ts": f"2026-01-01 00:00:0{i}"})
    assert len(buf) == 5
    recent = buf.recent(2)
    assert recent[0]["ts"].endswith("7") and recent[1]["ts"].endswith("6")
    assert buf.by_service() == {"http": 3, "ftp": 2}
    assert sum(buf.by_source().values()) == 5
    assert len(buf.since("2026-01-01 00:00:05")) == 2


def test_logger_thread_safety(tmp_path):
    log = tmp_path / "t.jsonl"
    logger = Logger(log)
    def worker(n):
        for i in range(25):
            logger.log({"service": "http", "src": f"w{n}", "event": "hit", "i": i})
    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads: t.start()
    for t in threads: t.join()
    lines = log.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 100
    for line in lines:
        json.loads(line)  # every line is valid JSON


def test_logger_context_manager(tmp_path):
    with Logger(tmp_path / "ctx.jsonl") as logger:
        logger.log({"service": "dns", "src": "q", "event": "query"})
    assert logger.enrich is None
