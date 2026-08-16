"""Tests for IOC export feeds: blocklist, STIX bundle, fail2ban lines."""

import json

from honeypot_server.core.logger import Logger, make_event
from honeypot_server.intel.feeds import (
    BLOCK_WORTHY_EVENTS,
    build_blocklist,
    build_fail2ban_lines,
    build_stix_bundle,
    collect_blockable,
    export_feeds,
)


def sample_events():
    events = []
    for i in range(4):
        e = make_event("ftp", "203.0.113.7:1000", "login_attempt",
                       severity="alert", user=f"admin{i}")
        e["ts"] = f"2026-02-01 10:00:0{i}"
        events.append(e)
    e = make_event("http", "198.51.100.9:2000", "credential_capture",
                   severity="alert", user="root")
    e["ts"] = "2026-02-01 10:01:00"
    events.append(e)
    # benign noise that must not appear in feeds
    e = make_event("http", "192.0.2.1:3000", "request")
    e["ts"] = "2026-02-01 10:02:00"
    events.append(e)
    # loopback must never be blocked
    e = make_event("ftp", "127.0.0.1:4000", "login_attempt", severity="alert")
    e["ts"] = "2026-02-01 10:03:00"
    events.append(e)
    return events


class TestCollectBlockable:
    def test_qualifying_ips(self):
        out = collect_blockable(sample_events())
        assert set(out) == {"203.0.113.7", "198.51.100.9"}
        assert out["203.0.113.7"]["events"] == 4
        assert "login_attempt" in out["203.0.113.7"]["reasons"]
        assert out["203.0.113.7"]["last_ts"] == "2026-02-01 10:00:03"

    def test_allowlist_excludes(self):
        out = collect_blockable(sample_events(), allowlist={"203.0.113.7"})
        assert set(out) == {"198.51.100.9"}

    def test_min_severity_filter(self):
        out = collect_blockable(sample_events(), min_severity="critical")
        assert out == {}

    def test_accepts_log_path(self, tmp_path):
        log = tmp_path / "f.jsonl"
        logger = Logger(log)
        for e in sample_events():
            logger.log(dict(e))
        out = collect_blockable(log)
        assert "203.0.113.7" in out


class TestBlocklist:
    def test_plain_ips_sorted(self):
        text = build_blocklist(sample_events(), header=False)
        lines = text.strip().splitlines()
        assert lines == ["198.51.100.9", "203.0.113.7"]

    def test_header(self):
        text = build_blocklist(sample_events())
        assert text.startswith("# honeypot-server blocklist: 2")

    def test_empty_stream(self):
        assert build_blocklist([]) == ""


class TestStixBundle:
    def test_bundle_shape(self):
        bundle = build_stix_bundle(sample_events())
        assert bundle["type"] == "bundle"
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        notes = [o for o in bundle["objects"] if o["type"] == "note"]
        assert len(indicators) == 2 and len(notes) == 2
        patterns = {i["pattern"] for i in indicators}
        assert "[ipv4-addr:value = '203.0.113.7']" in patterns

    def test_note_carries_classification_and_ttps(self):
        bundle = build_stix_bundle(sample_events())
        notes = [o for o in bundle["objects"] if o["type"] == "note"]
        brute = [n for n in notes if "203-0-113-7" in n["object_refs"][0]]
        assert brute and "brute-forcer" in brute[0]["content"]
        assert "T1110.001" in brute[0]["ttps"]

    def test_deterministic_ids(self):
        b1 = build_stix_bundle(sample_events())
        b2 = build_stix_bundle(sample_events())
        ids1 = sorted(o["id"] for o in b1["objects"])
        ids2 = sorted(o["id"] for o in b2["objects"])
        assert ids1 == ids2

    def test_serializable(self):
        json.dumps(build_stix_bundle(sample_events()))


class TestFail2ban:
    def test_line_format(self):
        text = build_fail2ban_lines(sample_events())
        lines = text.strip().splitlines()
        assert len(lines) == 5  # 4 ftp + 1 http, loopback skipped
        assert all("[INFO]" in l for l in lines)
        assert any("[203.0.113.7]" in l and "login_attempt" in l for l in lines)
        assert not any("127.0.0.1" in l for l in lines)

    def test_custom_jail_name(self):
        text = build_fail2ban_lines(sample_events(), jail="decoy")
        assert "decoy[1]:" in text

    def test_empty(self):
        assert build_fail2ban_lines([]) == ""


class TestExportFeeds:
    def test_writes_all_three(self, tmp_path):
        paths = export_feeds(sample_events(), tmp_path / "feeds")
        assert set(paths) == {"blocklist", "stix", "fail2ban"}
        for p in paths.values():
            assert p.exists() and p.stat().st_size > 0
        bundle = json.loads(paths["stix"].read_text(encoding="utf-8"))
        assert bundle["type"] == "bundle"
        assert "203.0.113.7" in paths["blocklist"].read_text(encoding="utf-8")

    def test_generator_input_materialised_once(self, tmp_path):
        def gen():
            yield from sample_events()
        paths = export_feeds(gen(), tmp_path / "feeds2")
        text = paths["blocklist"].read_text(encoding="utf-8")
        assert "203.0.113.7" in text  # generator not exhausted early


def test_block_worthy_events_cover_services():
    assert "login_attempt" in BLOCK_WORTHY_EVENTS
    assert "canary_hit" in BLOCK_WORTHY_EVENTS
    assert "request" not in BLOCK_WORTHY_EVENTS
