"""Tests for session recording, replay and log diffing."""

import json

from honeypot_server.core.logger import Logger, make_event
from honeypot_server.intel.replay import (
    SessionRecorder,
    diff_logs,
    load_recording,
    replay_session,
    session_key,
)


def ev(service, src, event, ts="2026-04-01 12:00:00", **fields):
    e = make_event(service, src, event, **fields)
    e["ts"] = ts
    return e


class TestSessionKey:
    def test_groups_by_ip_and_service(self):
        a = ev("http", "1.2.3.4:10", "request")
        b = ev("http", "1.2.3.4:99", "request")
        c = ev("ftp", "1.2.3.4:10", "command")
        assert session_key(a) == session_key(b)
        assert session_key(a) != session_key(c)


class TestSessionRecorder:
    def test_records_ordered_events(self):
        rec = SessionRecorder()
        rec.observe(ev("ftp", "9.9.9.9:1", "connect", ts="2026-04-01 12:00:00"))
        rec.observe(ev("ftp", "9.9.9.9:1", "command", ts="2026-04-01 12:00:05",
                       data="USER admin"))
        rec.observe(ev("ftp", "9.9.9.9:1", "command", ts="2026-04-01 12:00:09",
                       data="PASS x"))
        records = rec.export()
        assert len(records) == 1
        r = records[0]
        assert r["service"] == "ftp" and r["src"] == "9.9.9.9:1"
        assert [e["event"] for e in r["events"]] == ["connect", "command", "command"]
        assert r["delays"] == [5.0, 4.0]
        assert r["started"] == "2026-04-01 12:00:00"
        assert r["ended"] == "2026-04-01 12:00:09"

    def test_separate_sessions_per_source(self):
        rec = SessionRecorder()
        rec.observe(ev("http", "1.1.1.1:1", "request"))
        rec.observe(ev("http", "2.2.2.2:1", "request"))
        assert len(rec.export()) == 2

    def test_max_events_cap(self):
        rec = SessionRecorder(max_events=3)
        for i in range(10):
            rec.observe(ev("http", "3.3.3.3:1", "request",
                           ts=f"2026-04-01 12:00:{i:02d}"))
        assert len(rec.export()[0]["events"]) == 3
        assert len(rec.export()[0]["delays"]) == 9  # delays still tracked

    def test_export_single_key(self):
        rec = SessionRecorder()
        rec.observe(ev("http", "4.4.4.4:1", "request"))
        rec.observe(ev("ftp", "5.5.5.5:1", "command"))
        one = rec.export("4.4.4.4/http")
        assert len(one) == 1 and one[0]["service"] == "http"
        assert rec.export("missing/x") == []

    def test_save_and_load_roundtrip(self, tmp_path):
        rec = SessionRecorder()
        rec.observe(ev("ssh", "6.6.6.6:1", "banner", ts="2026-04-01 12:00:00"))
        rec.observe(ev("ssh", "6.6.6.6:1", "kexinit", ts="2026-04-01 12:00:02"))
        path = rec.save(tmp_path / "rec.json")
        loaded = load_recording(path)
        assert len(loaded) == 1
        assert loaded[0]["events"][1]["event"] == "kexinit"
        # file is valid JSON
        json.loads(path.read_text(encoding="utf-8"))

    def test_observe_all_count(self):
        rec = SessionRecorder()
        events = [ev("http", "7.7.7.7:1", "request") for _ in range(4)]
        assert rec.observe_all(events) == 4


class TestReplay:
    def _record(self):
        rec = SessionRecorder()
        rec.observe(ev("ftp", "8.8.8.8:1", "connect", ts="2026-04-01 12:00:00"))
        rec.observe(ev("ftp", "8.8.8.8:1", "command", ts="2026-04-01 12:00:03",
                       data="USER admin"))
        rec.observe(ev("ftp", "8.8.8.8:1", "command", ts="2026-04-01 12:00:07",
                       data="PASS pw"))
        return rec.export()[0]

    def test_replay_feeds_sink_in_order(self):
        seen = []
        n = replay_session(self._record(), seen.append)
        assert n == 3
        assert [e["event"] for e in seen] == ["connect", "command", "command"]
        assert all(e["replay"] is True for e in seen)
        assert all(e["replay_src"] == "8.8.8.8:1" for e in seen)

    def test_replay_speed_scales_delays(self):
        slept = []
        replay_session(self._record(), lambda e: None, speed=2.0,
                       sleep=slept.append)
        assert slept == [6.0, 8.0]  # (3s, 4s) * 2

    def test_replay_speed_zero_no_sleep(self):
        slept = []
        replay_session(self._record(), lambda e: None, speed=0.0,
                       sleep=slept.append)
        assert slept == []

    def test_replay_into_logger(self, tmp_path):
        logger = Logger(tmp_path / "replayed.jsonl")
        replay_session(self._record(), logger.log)
        text = (tmp_path / "replayed.jsonl").read_text(encoding="utf-8")
        assert text.count('"replay": true') == 3

    def test_replay_empty_record(self):
        assert replay_session({"events": [], "delays": []}, lambda e: None) == 0


class TestDiffLogs:
    def test_diff_detects_differences(self):
        a = [ev("http", "1.1.1.1:1", "request"),
             ev("ftp", "1.1.1.1:2", "command")]
        b = [ev("http", "1.1.1.1:9", "request"),
             ev("ssh", "2.2.2.2:1", "banner")]
        result = diff_logs(a, b)
        assert result["common"] == 1  # http|request|1.1.1.1
        assert "ftp|command|1.1.1.1" in result["only_a"]
        assert "ssh|banner|2.2.2.2" in result["only_b"]
        assert result["total_a"] == 2 and result["total_b"] == 2

    def test_identical_streams(self):
        a = [ev("http", "1.1.1.1:1", "request")]
        b = [ev("http", "1.1.1.1:77", "request", ts="2027-01-01 00:00:00")]
        result = diff_logs(a, b)
        assert result["only_a"] == [] and result["only_b"] == []
        assert result["common"] == 1

    def test_diff_accepts_paths(self, tmp_path):
        log_a = tmp_path / "a.jsonl"
        log_b = tmp_path / "b.jsonl"
        la, lb = Logger(log_a), Logger(log_b)
        la.log(ev("http", "1.1.1.1:1", "request"))
        lb.log(ev("http", "1.1.1.1:1", "request"))
        lb.log(ev("dns", "3.3.3.3:1", "query"))
        result = diff_logs(log_a, log_b)
        assert result["only_b"] == ["dns|query|3.3.3.3"]

    def test_diff_empty_sides(self):
        result = diff_logs([], [])
        assert result == {"only_a": [], "only_b": [], "common": 0,
                          "total_a": 0, "total_b": 0}
