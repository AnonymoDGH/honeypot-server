"""Tests for the CLI: subcommands and legacy flag compatibility."""

import json
import socket
import threading
import time

import pytest

import honeypot_server.cli as cli
from honeypot_server.cli import build_parser, main
from honeypot_server.core.logger import Logger, make_event


def _free_port() -> int:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _seed_log(path, n=6):
    logger = Logger(path)
    for i in range(n):
        e = make_event("ftp", f"203.0.113.{i % 2}:1", "login_attempt",
                       severity="alert", user="admin")
        e["ts"] = f"2026-05-01 08:00:0{i}"
        logger.log(e)
    e = make_event("http", "198.51.100.9:2", "request")
    e["ts"] = "2026-05-01 08:01:00"
    logger.log(e)


class TestParser:
    def test_all_subcommands_registered(self):
        parser = build_parser()
        # parse each subcommand with its required args
        args = parser.parse_args(["status", "--log", "x.jsonl"])
        assert args.command == "status"
        args = parser.parse_args(["diff", "a.jsonl", "b.jsonl"])
        assert args.command == "diff" and args.log_a == "a.jsonl"
        args = parser.parse_args(["canary", "tokens"])
        assert args.what == "tokens"
        args = parser.parse_args(["score", "--seed", "3"])
        assert args.seed == "3"

    def test_run_flags(self):
        parser = build_parser()
        args = parser.parse_args(["run", "--services", "http,ftp",
                                  "--host", "127.0.0.1",
                                  "--ports", "http=8080",
                                  "--tarpit", "0.5", "--rotate", "--canary"])
        assert args.services == "http,ftp"
        assert args.tarpit == "0.5"
        assert args.rotate and args.canary


class TestLegacyCompat:
    def test_legacy_flags_style_routes_to_run(self, tmp_path, capsys):
        port = _free_port()
        log = tmp_path / "legacy.jsonl"
        stop = threading.Event()
        cli.RUN_STOP_HOOK = stop
        result = {}

        def runner():
            result["rc"] = main(["--services", "http", "--host", "127.0.0.1",
                                 "--ports", f"http={port}", "--log", str(log)])

        t = threading.Thread(target=runner)
        t.start()
        time.sleep(0.6)
        # the decoy must actually answer
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        s.settimeout(3)
        s.recv(256)
        s.close()
        stop.set()
        t.join(timeout=5)
        cli.RUN_STOP_HOOK = None
        assert result["rc"] == 0
        out = capsys.readouterr().out
        assert "http decoy on" in out
        assert log.exists()

    def test_unknown_service_exits(self, capsys):
        with pytest.raises(SystemExit):
            main(["--services", "gopher"])
        assert "Unknown service" in capsys.readouterr().out


class TestStatus:
    def test_status_output(self, tmp_path, capsys):
        log = tmp_path / "s.jsonl"
        _seed_log(log)
        assert main(["status", "--log", str(log)]) == 0
        out = capsys.readouterr().out
        assert "events:  7" in out
        assert "ftp" in out and "203.0.113.0" in out

    def test_status_missing_log_exits(self, tmp_path):
        with pytest.raises(SystemExit):
            main(["status", "--log", str(tmp_path / "nope.jsonl")])


class TestReport:
    def test_terminal_report(self, tmp_path, capsys):
        log = tmp_path / "r.jsonl"
        _seed_log(log)
        assert main(["report", "--log", str(log), "--no-color"]) == 0
        out = capsys.readouterr().out
        assert "HONEYPOT DASHBOARD" in out

    def test_html_report_written(self, tmp_path, capsys):
        log = tmp_path / "r.jsonl"
        _seed_log(log)
        out_html = tmp_path / "report.html"
        assert main(["report", "--log", str(log), "--html", str(out_html)]) == 0
        page = out_html.read_text(encoding="utf-8")
        assert page.startswith("<!DOCTYPE html>")
        assert "Top attackers" in page


class TestBlocklist:
    def test_export_feeds(self, tmp_path, capsys):
        log = tmp_path / "b.jsonl"
        _seed_log(log)
        outdir = tmp_path / "feeds"
        assert main(["blocklist", "--log", str(log), "--out", str(outdir)]) == 0
        assert (outdir / "blocklist.txt").exists()
        assert (outdir / "stix-bundle.json").exists()
        assert (outdir / "fail2ban.log").exists()
        text = (outdir / "blocklist.txt").read_text(encoding="utf-8")
        assert "203.0.113.0" in text


class TestCanary:
    def test_tokens_to_stdout(self, capsys):
        assert main(["canary", "tokens", "--seed", "5"]) == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert len(data) == 6
        assert any(t["kind"] == "aws" for t in data)

    def test_tokens_to_file(self, tmp_path, capsys):
        out_json = tmp_path / "tokens.json"
        assert main(["canary", "tokens", "--seed", "5",
                     "--out", str(out_json)]) == 0
        assert out_json.exists()

    def test_docs_written(self, tmp_path, capsys):
        outdir = tmp_path / "bait"
        assert main(["canary", "docs", "--seed", "5",
                     "--out", str(outdir)]) == 0
        assert (outdir / "recovered_credentials.txt").exists()
        assert (outdir / "tokens.json").exists()


class TestReplay:
    def test_record_then_replay(self, tmp_path, capsys):
        log = tmp_path / "src.jsonl"
        _seed_log(log)
        rec = tmp_path / "sessions.json"
        assert main(["replay", "--log", str(log), "--record", str(rec)]) == 0
        assert rec.exists()
        out = capsys.readouterr().out
        assert "recorded" in out
        replayed = tmp_path / "replayed.jsonl"
        assert main(["replay", "--recording", str(rec),
                     "--log", str(replayed)]) == 0
        text = replayed.read_text(encoding="utf-8")
        assert '"replay": true' in text

    def test_replay_requires_target(self, capsys):
        assert main(["replay"]) == 1


class TestDiff:
    def test_diff_two_logs(self, tmp_path, capsys):
        log_a = tmp_path / "a.jsonl"
        log_b = tmp_path / "b.jsonl"
        _seed_log(log_a)
        _seed_log(log_b)
        extra = make_event("dns", "9.9.9.9:1", "query")
        Logger(log_b).log(extra)
        assert main(["diff", str(log_a), str(log_b)]) == 0
        out = capsys.readouterr().out
        assert "dns|query|9.9.9.9" in out


class TestScore:
    def test_score_output(self, capsys):
        assert main(["score", "--seed", "7"]) == 0
        out = capsys.readouterr().out
        assert "Deception score:" in out
        assert "persona:" in out

    def test_score_with_tarpit_penalty(self, capsys):
        main(["score", "--seed", "7", "--tarpit", "9"])
        out = capsys.readouterr().out
        assert "scream tarpit" in out
