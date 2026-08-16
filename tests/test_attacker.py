"""Tests for attacker profiling, classification and TTP mapping."""

from honeypot_server.core.logger import make_event
from honeypot_server.intel.attacker import (
    AttackerProfile,
    AttackerTracker,
    _seconds_between,
    classify,
    map_ttps,
    source_ip,
)


def ev(service, src, event, ts="2026-01-01 00:00:00", **fields):
    e = make_event(service, src, event, **fields)
    e["ts"] = ts
    return e


class TestAttackerProfile:
    def test_observe_accumulates(self):
        p = AttackerProfile(ip="1.2.3.4")
        p.observe(ev("http", "1.2.3.4:1", "request", ts="2026-01-01 00:00:01"))
        p.observe(ev("ftp", "1.2.3.4:2", "login_attempt", user="admin",
                     ts="2026-01-01 00:00:05"))
        p.observe(ev("ftp", "1.2.3.4:2", "command", data="USER admin",
                     ts="2026-01-01 00:00:06"))
        assert p.events == 3
        assert p.services == {"http": 1, "ftp": 2}
        assert p.first_seen.endswith("01") and p.last_seen.endswith("06")
        assert p.usernames["admin"] == 1
        assert p.commands == ["USER admin"]
        assert p.login_attempts == 1

    def test_severity_tracking(self):
        p = AttackerProfile(ip="x")
        p.observe(ev("http", "x:1", "request", severity="info"))
        p.observe(ev("http", "x:1", "credential_capture", severity="alert"))
        assert p.max_severity == 4

    def test_canary_hits_counted(self):
        p = AttackerProfile(ip="x")
        p.observe(ev("http", "x:1", "canary_hit", severity="critical"))
        assert p.canary_hits == 1


class TestClassify:
    def _profile(self, **event_counts):
        p = AttackerProfile(ip="9.9.9.9")
        for name, count in event_counts.items():
            p.event_types[name] = count
            if name == "canary_hit":
                p.canary_hits += count
        return p

    def test_canary_tripper_wins(self):
        p = self._profile(canary_hit=1, login_attempt=99)
        assert classify(p) == "canary-tripper"

    def test_brute_forcer(self):
        p = self._profile(login_attempt=5)
        assert classify(p) == "brute-forcer"

    def test_exfiltrator(self):
        p = self._profile(message_accepted=1, file_download=1)
        assert classify(p) == "exfiltrator"

    def test_scanner(self):
        p = self._profile(banner=4)
        p.services.update({"http": 1, "ftp": 1, "ssh": 1})
        assert classify(p) == "scanner"

    def test_opportunist_default(self):
        p = self._profile(request=2)
        assert classify(p) == "opportunist"


class TestMapTtps:
    def test_brute_force_maps_to_t1110(self):
        p = AttackerProfile(ip="x")
        p.event_types["login_attempt"] = 3
        ids = [t["id"] for t in map_ttps(p)]
        assert "T1110.001" in ids

    def test_discovery_and_command(self):
        p = AttackerProfile(ip="x")
        p.event_types["banner"] = 1
        p.event_types["command"] = 2
        ids = [t["id"] for t in map_ttps(p)]
        assert "T1046" in ids and "T1059" in ids

    def test_valid_accounts(self):
        p = AttackerProfile(ip="x")
        p.event_types["login_success"] = 1
        assert any(t["id"] == "T1078" for t in map_ttps(p))

    def test_empty_profile_no_ttps(self):
        assert map_ttps(AttackerProfile(ip="x")) == []

    def test_stable_order(self):
        p = AttackerProfile(ip="x")
        p.event_types.update({"command": 1, "banner": 1})
        first = [t["id"] for t in map_ttps(p)]
        assert first == [t["id"] for t in map_ttps(p)]
        assert first.index("T1046") < first.index("T1059")


class TestTracker:
    def test_profiles_per_ip(self):
        tracker = AttackerTracker()
        tracker.observe(ev("http", "1.1.1.1:5", "request"))
        tracker.observe(ev("ftp", "2.2.2.2:6", "login_attempt"))
        tracker.observe(ev("http", "1.1.1.1:7", "request"))
        assert set(tracker.profiles) == {"1.1.1.1", "2.2.2.2"}
        assert tracker.profiles["1.1.1.1"].events == 2

    def test_session_split_on_gap(self):
        tracker = AttackerTracker(session_gap=60)
        tracker.observe(ev("http", "1.1.1.1:5", "request",
                           ts="2026-01-01 00:00:00"))
        tracker.observe(ev("http", "1.1.1.1:6", "request",
                           ts="2026-01-01 00:00:30"))
        tracker.observe(ev("http", "1.1.1.1:7", "request",
                           ts="2026-01-01 00:10:00"))
        assert tracker.profiles["1.1.1.1"].sessions == 2

    def test_top_ordering(self):
        tracker = AttackerTracker()
        for i in range(3):
            tracker.observe(ev("http", "1.1.1.1:1", "request"))
        tracker.observe(ev("http", "2.2.2.2:1", "request"))
        top = tracker.top(2)
        assert top[0].ip == "1.1.1.1" and top[0].events == 3

    def test_classified_groups(self):
        tracker = AttackerTracker()
        for i in range(4):
            tracker.observe(ev("ftp", f"3.3.3.3:{i}", "login_attempt"))
        tracker.observe(ev("http", "4.4.4.4:1", "request"))
        groups = tracker.classified()
        assert "3.3.3.3" in groups["brute-forcer"]
        assert "4.4.4.4" in groups["opportunist"]

    def test_report_shape(self):
        tracker = AttackerTracker()
        tracker.observe(ev("http", "5.5.5.5:1", "request"))
        report = tracker.report()
        assert report["attackers"] == 1
        assert "5.5.5.5" in report["profiles"]
        assert report["profiles"]["5.5.5.5"]["classification"] == "opportunist"
        assert isinstance(report["by_classification"], dict)

    def test_observe_all_returns_count(self):
        tracker = AttackerTracker()
        events = [ev("http", "6.6.6.6:1", "request") for _ in range(5)]
        assert tracker.observe_all(events) == 5


def test_source_ip_strips_port():
    assert source_ip({"src": "10.0.0.1:1234"}) == "10.0.0.1"
    assert source_ip({}) == "?"


def test_seconds_between():
    assert _seconds_between("2026-01-01 00:00:00", "2026-01-01 00:01:00") == 60
    assert _seconds_between("bad", "2026-01-01 00:01:00") == 0.0
