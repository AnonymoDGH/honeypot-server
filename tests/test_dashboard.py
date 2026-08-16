"""Tests for the terminal dashboard and HTML report renderers."""

from honeypot_server.core.logger import make_event
from honeypot_server.intel.dashboard import (
    _bar,
    _svg_bar_chart,
    render_html_report,
    render_terminal,
    summarize,
)
from collections import Counter


def sample_events():
    events = []
    for i in range(5):
        e = make_event("http", f"203.0.113.{i}:1", "request")
        e["ts"] = f"2026-03-01 09:00:0{i}"
        events.append(e)
    for i in range(3):
        e = make_event("ftp", "198.51.100.4:2", "login_attempt",
                       severity="alert", user="admin")
        e["ts"] = f"2026-03-01 09:01:0{i}"
        events.append(e)
    e = make_event("ssh", "198.51.100.4:3", "canary_hit", severity="critical")
    e["ts"] = "2026-03-01 09:02:00"
    events.append(e)
    return events


class TestSummarize:
    def test_counts(self):
        data = summarize(sample_events())
        assert data["total"] == 9
        assert data["services"] == {"http": 5, "ftp": 3, "ssh": 1}
        assert data["severities"]["alert"] == 3
        assert data["severities"]["critical"] == 1
        assert len(data["sources"]) == 6
        assert data["first_ts"] == "2026-03-01 09:00:00"
        assert data["last_ts"] == "2026-03-01 09:02:00"

    def test_empty_stream(self):
        data = summarize([])
        assert data["total"] == 0
        assert data["first_ts"] == "" and data["last_ts"] == ""

    def test_tracker_attached(self):
        data = summarize(sample_events())
        assert "198.51.100.4" in data["tracker"].profiles


class TestTerminal:
    def test_render_contains_sections(self):
        out = render_terminal(sample_events(), color=False)
        assert "HONEYPOT DASHBOARD" in out
        assert "Services" in out and "Top sources" in out
        assert "http" in out and "ftp" in out
        assert "198.51.100.4" in out
        assert "canary-tripper" in out  # classification tag shown

    def test_color_mode_has_ansi(self):
        out = render_terminal(sample_events(), color=True)
        assert "\033[1m" in out and "\033[0m" in out

    def test_empty_events(self):
        out = render_terminal([], color=False)
        assert "events: 0" in out

    def test_bar_scaling(self):
        line = _bar("http", 10, 10, width=10)
        assert "10" in line and line.count("\u2588") == 10
        line = _bar("ftp", 5, 10, width=10)
        assert line.count("\u2588") == 5 and line.count("\u2591") == 5
        assert _bar("x", 0, 0, width=4).count("\u2588") == 0


class TestSvg:
    def test_chart_has_rects_and_labels(self):
        svg = _svg_bar_chart(Counter({"http": 5, "ftp": 3}))
        assert svg.startswith("<svg") and svg.endswith("</svg>")
        assert svg.count("<rect") == 2
        assert "http" in svg and "ftp" in svg

    def test_empty_counter(self):
        svg = _svg_bar_chart(Counter())
        assert svg.startswith("<svg")

    def test_labels_escaped(self):
        svg = _svg_bar_chart(Counter({"<script>": 1}))
        assert "<script>" not in svg
        assert "&lt;script&gt;" in svg


class TestHtmlReport:
    def test_report_structure(self):
        page = render_html_report(sample_events(), title="Trap Report")
        assert page.startswith("<!DOCTYPE html>")
        assert "<title>Trap Report</title>" in page
        assert "Events by service" in page
        assert "Events by severity" in page
        assert "Top attackers" in page
        assert "<svg" in page

    def test_attacker_table_rows(self):
        page = render_html_report(sample_events())
        assert "198.51.100.4" in page
        assert "canary-tripper" in page

    def test_title_escaped(self):
        page = render_html_report([], title="<evil> & co")
        assert "<evil>" not in page
        assert "&lt;evil&gt;" in page

    def test_empty_report_still_valid(self):
        page = render_html_report([])
        assert page.count("<html") == 1 and page.endswith("</html>")
