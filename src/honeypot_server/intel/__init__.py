"""Intelligence layer -- turn honeypot events into attacker insight.

Modules here consume the JSONL event stream produced by the decoys and
produce profiles, IOC feeds, dashboards, reports and replays.
"""

from __future__ import annotations

from .attacker import (
    AttackerProfile,
    AttackerTracker,
    classify,
    map_ttps,
    source_ip,
)

__all__ = [
    "AttackerProfile",
    "AttackerTracker",
    "classify",
    "map_ttps",
    "source_ip",
]
