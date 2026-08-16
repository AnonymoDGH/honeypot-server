"""Dashboards -- ANSI terminal view and static HTML report with SVG.

Two renderers over the same event data:

* render_terminal -- a pure-stdlib ANSI screen: totals, top sources,
  per-service histogram and severity counts. Designed for the CLI
  report command and watch loops.
* render_html_report -- a self-contained HTML page (no external assets)
  with inline SVG charts: a service bar chart, a severity distribution
  chart and an attacker table with classifications.

Both take plain event dicts so they work on live buffers, log files and
replay streams alike.
"""

from __future__ import annotations

import html
import time
from collections import Counter
from typing import Any, Iterable

from .attacker import AttackerTracker, classify

#: ANSI helpers (only used by the terminal renderer).
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
COLORS = {
    "debug": "\033[90m", "info": "\033[37m", "notice": "\033[36m",
    "warn": "\033[33m", "alert": "\033[35m", "critical": "\033[31m",
}

#: Bar palette for the SVG charts.
SVG_COLORS = ["#e6a23c", "#67c23a", "#409eff", "#f56c6c", "#909399",
              "#b88230", "#5cb87a", "#9b59b6"]

#: Block characters for text bars (full / empty).
BLOCK_FULL = "\u2588"
BLOCK_EMPTY = "\u2591"


def summarize(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate an event stream into dashboard-ready numbers."""
    events = list(events)
    services: Counter = Counter()
    severities: Counter = Counter()
    sources: Counter = Counter()
    event_types: Counter = Counter()
    first_ts = ""
    last_ts = ""
    for e in events:
        services[str(e.get("service", "?"))] += 1
        severities[str(e.get("severity", "info"))] += 1
        sources[str(e.get("src", "?")).split(":")[0]] += 1
        event_types[str(e.get("event", "?"))] += 1
        ts = str(e.get("ts", ""))
        if ts:
            first_ts = ts if not first_ts or ts < first_ts else first_ts
            last_ts = ts if ts > last_ts else last_ts
    tracker = AttackerTracker()
    tracker.observe_all(events)
    return {
        "total": len(events),
        "services": services,
        "severities": severities,
        "sources": sources,
        "event_types": event_types,
        "first_ts": first_ts,
        "last_ts": last_ts,
        "tracker": tracker,
    }


def _bar(label: str, value: int, max_value: int, width: int = 24) -> str:
    """One text bar: label, filled block, count."""
    filled = int(width * value / max_value) if max_value else 0
    bar = BLOCK_FULL * filled + BLOCK_EMPTY * (width - filled)
    return f"{label:<10} {bar} {value}"


def render_terminal(events: Iterable[dict[str, Any]], *, color: bool = True,
                    width: int = 60) -> str:
    """Render the ANSI terminal dashboard as one string."""
    data = summarize(events)
    lines: list[str] = []
    title = "HONEYPOT DASHBOARD"
    lines.append(f"{BOLD}{title.center(width)}{RESET}" if color
                 else title.center(width))
    lines.append("-" * width)
    total = data["total"]
    n_sources = len(data["sources"])
    span = ""
    if data["first_ts"]:
        span = f"{data['first_ts']}  ->  {data['last_ts']}"
    lines.append(f"events: {total}   sources: {n_sources}   {span}")
    lines.append("")
    lines.append(f"{BOLD}Services{RESET}" if color else "Services")
    max_svc = max(data["services"].values(), default=0)
    for svc, count in data["services"].most_common():
        lines.append("  " + _bar(svc, count, max_svc))
    lines.append("")
    lines.append(f"{BOLD}Top sources{RESET}" if color else "Top sources")
    for ip, count in data["sources"].most_common(5):
        profile = data["tracker"].profiles.get(ip)
        tag = classify(profile) if profile else "?"
        lines.append(f"  {ip:<16} {count:>5} events  [{tag}]")
    lines.append("")
    lines.append(f"{BOLD}Severity{RESET}" if color else "Severity")
    for sev in ("critical", "alert", "warn", "notice", "info", "debug"):
        count = data["severities"].get(sev, 0)
        if count:
            prefix = COLORS.get(sev, "") if color else ""
            suffix = RESET if color else ""
            lines.append(f"  {prefix}{sev:<9}{suffix}{count}")
    lines.append("-" * width)
    return "\n".join(lines)


def _svg_bar_chart(counter: Counter, *, height: int = 180,
                   bar_width: int = 46, gap: int = 14) -> str:
    """Inline SVG bar chart for a Counter (labels below bars)."""
    items = counter.most_common()
    if not items:
        return '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"></svg>'
    max_value = max(v for _, v in items)
    chart_w = len(items) * (bar_width + gap) + gap
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{chart_w}" '
        f'height="{height + 40}" role="img" aria-label="bar chart">'
    ]
    for i, (label, value) in enumerate(items):
        bar_h = int(height * value / max_value) if max_value else 0
        x = gap + i * (bar_width + gap)
        y = height - bar_h
        fill = SVG_COLORS[i % len(SVG_COLORS)]
        parts.append(f'<rect x="{x}" y="{y}" width="{bar_width}" '
                     f'height="{bar_h}" fill="{fill}" rx="3"/>')
        parts.append(f'<text x="{x + bar_width // 2}" y="{y - 4}" '
                     f'text-anchor="middle" font-size="11">{value}</text>')
        parts.append(f'<text x="{x + bar_width // 2}" y="{height + 16}" '
                     f'text-anchor="middle" font-size="11">'
                     + html.escape(str(label)) + "</text>")
    parts.append("</svg>")
    return "".join(parts)


def render_html_report(events: Iterable[dict[str, Any]], *,
                       title: str = "Honeypot Report") -> str:
    """Render a self-contained HTML report with embedded SVG charts."""
    data = summarize(events)
    svc_svg = _svg_bar_chart(data["services"])
    sev_svg = _svg_bar_chart(data["severities"])
    rows = []
    for profile in data["tracker"].top(20):
        rows.append(
            "<tr>"
            f"<td>{html.escape(profile.ip)}</td>"
            f"<td>{profile.events}</td>"
            f"<td>{len(profile.services)}</td>"
            f"<td>{profile.login_attempts}</td>"
            f"<td>{html.escape(classify(profile))}</td>"
            "</tr>")
    generated = time.strftime("%Y-%m-%d %H:%M:%S")
    total = data["total"]
    n_sources = len(data["sources"])
    first = data["first_ts"] or "-"
    last = data["last_ts"] or "-"
    head = (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        f"<title>{html.escape(title)}</title>"
        "<style>"
        "body { font-family: system-ui, sans-serif; margin: 2rem;"
        "       background: #faf7f0; }"
        "h1 { color: #8a5a00; }"
        "section { background: #fff; border: 1px solid #e8e0d0;"
        "          border-radius: 8px; padding: 1rem 1.5rem;"
        "          margin-bottom: 1.5rem; }"
        "table { border-collapse: collapse; width: 100%; }"
        "th, td { text-align: left; padding: 4px 10px;"
        "         border-bottom: 1px solid #eee; }"
        ".meta { color: #777; font-size: 0.9rem; }"
        "</style></head><body>"
    )
    meta = (f'<p class="meta">generated {generated} &middot; {total} events'
            f" &middot; {n_sources} sources &middot; window {first}"
            f" &rarr; {last}</p>")
    table = ("<table><tr><th>IP</th><th>events</th><th>services</th>"
             "<th>logins</th><th>class</th></tr>" + "".join(rows) + "</table>")
    return (head
            + f"<h1>&#127855; {html.escape(title)}</h1>"
            + meta
            + f"<section><h2>Events by service</h2>{svc_svg}</section>"
            + f"<section><h2>Events by severity</h2>{sev_svg}</section>"
            + f"<section><h2>Top attackers</h2>{table}</section>"
            + '<p class="meta">honeypot-server &middot; defensive deception,'
            + " own network only</p></body></html>")
