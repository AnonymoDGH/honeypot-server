"""IOC export feeds -- blocklists, STIX-like bundles, fail2ban lines.

The point of a honeypot is to produce intelligence other tools can act
on. This module renders the event log (or an in-memory event list) into
three consumable formats:

* :func:`build_blocklist` -- plain attacker IPs, one per line, ready for
  iptables/nftables/ACL ingestion;
* :func:`build_stix_bundle` -- a STIX 2.1-shaped JSON bundle with
  ``indicator`` objects per attacker IP plus ``note`` objects carrying
  the classification and TTP mapping;
* :func:`build_fail2ban_lines` -- log lines in the format fail2ban's
  default regexes already understand, so a honeypot can drive real
  banning without a custom filter.

All three are pure functions over event dicts: feed them a live buffer,
a parsed log file, or a replay stream.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Iterable

from ..core.logger import read_events, severity_rank
from .attacker import AttackerTracker, classify, map_ttps

#: Event types that mark an IP as hostile enough to block.
BLOCK_WORTHY_EVENTS = {
    "login_attempt", "auth_attempt", "credential_capture",
    "plaintext_password", "login_success", "canary_hit",
    "dangerous_command", "malware_staging", "open_relay_abuse",
    "message_accepted", "download_request",
}

#: Never block these (loopback/test sources would lock out operators).
BLOCKLIST_ALLOWLIST = {"127.0.0.1", "::1", "0.0.0.0"}


def _iter_source(events: Iterable[dict[str, Any]] | str | Path):
    """Normalise the input: an event iterable or a log path."""
    if isinstance(events, (str, Path)):
        return read_events(events)
    return events


def collect_blockable(events: Iterable[dict[str, Any]] | str | Path, *,
                      min_severity: str = "info",
                      allowlist: set[str] | None = None) -> dict[str, dict[str, Any]]:
    """Fold events into per-IP block candidates.

    An IP qualifies when it triggers at least one block-worthy event at or
    above ``min_severity``. Returns ip -> {"events", "reasons", "last_ts"}.
    """
    floor = severity_rank(min_severity)
    skip = BLOCKLIST_ALLOWLIST | (allowlist or set())
    out: dict[str, dict[str, Any]] = {}
    for event in _iter_source(events):
        etype = str(event.get("event", ""))
        if etype not in BLOCK_WORTHY_EVENTS:
            continue
        if severity_rank(str(event.get("severity", "info"))) < floor:
            continue
        ip = str(event.get("src", "")).split(":")[0]
        if not ip or ip in skip:
            continue
        entry = out.setdefault(ip, {"events": 0, "reasons": set(), "last_ts": ""})
        entry["events"] += 1
        entry["reasons"].add(etype)
        ts = str(event.get("ts", ""))
        if ts > entry["last_ts"]:
            entry["last_ts"] = ts
    return out


def build_blocklist(events: Iterable[dict[str, Any]] | str | Path, *,
                    min_severity: str = "info",
                    allowlist: set[str] | None = None,
                    header: bool = True) -> str:
    """Render the plain-IP blocklist (one IP per line, sorted).

    With ``header`` the file starts with a ``#`` comment naming the
    generator and count, which most firewall loaders ignore safely.
    """
    candidates = collect_blockable(events, min_severity=min_severity,
                                   allowlist=allowlist)
    ips = sorted(candidates)
    if not ips:
        return ""
    lines = []
    if header:
        lines.append(f"# honeypot-server blocklist: {len(ips)} attackers")
    lines.extend(ips)
    return "\n".join(lines) + "\n"


def build_stix_bundle(events: Iterable[dict[str, Any]] | str | Path, *,
                      min_severity: str = "info",
                      allowlist: set[str] | None = None,
                      created_by: str = "honeypot-server") -> dict[str, Any]:
    """Build a STIX 2.1-shaped bundle from the event stream.

    One ``indicator`` per blockable IP (pattern: ``[ipv4-addr:value = ...]``),
    one ``note`` per attacker carrying classification + TTP ids. The bundle
    is deterministic for a fixed event stream (ids derive from the IP).
    """
    materialised = list(_iter_source(events))
    candidates = collect_blockable(materialised, min_severity=min_severity,
                                   allowlist=allowlist)
    tracker = AttackerTracker()
    tracker.observe_all(materialised)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    objects: list[dict[str, Any]] = []
    for ip in sorted(candidates):
        info = candidates[ip]
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{ip.replace('.', '-')}",
            "created": now,
            "modified": now,
            "name": f"Honeypot-captured attacker {ip}",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": info["last_ts"] or now,
            "indicator_types": ["malicious-activity"],
            "labels": sorted(info["reasons"]),
            "created_by_ref": created_by,
        }
        objects.append(indicator)
        profile = tracker.profiles.get(ip)
        if profile is not None:
            objects.append({
                "type": "note",
                "spec_version": "2.1",
                "id": f"note--{ip.replace('.', '-')}",
                "created": now,
                "content": (f"classification={classify(profile)}; "
                            f"events={profile.events}"),
                "object_refs": [indicator["id"]],
                "ttps": [t["id"] for t in map_ttps(profile)],
            })
    return {
        "type": "bundle",
        "id": "bundle--honeypot-server",
        "objects": objects,
    }


def build_fail2ban_lines(events: Iterable[dict[str, Any]] | str | Path, *,
                         jail: str = "honeypot") -> str:
    """Render fail2ban-compatible log lines for block-worthy events.

    Format mirrors the classic ``<time> <jail>[<pid>]: [INFO] [<ip>] ...``
    shape that fail2ban's common regexes parse; one line per qualifying
    event, in input order.
    """
    lines = []
    for event in _iter_source(events):
        etype = str(event.get("event", ""))
        if etype not in BLOCK_WORTHY_EVENTS:
            continue
        ip = str(event.get("src", "")).split(":")[0]
        if not ip or ip in BLOCKLIST_ALLOWLIST:
            continue
        ts = str(event.get("ts", ""))
        service = str(event.get("service", "?"))
        lines.append(
            f"{ts} {jail}[1]: [INFO] [{ip}] {service} {etype} blocked")
    return "\n".join(lines) + ("\n" if lines else "")


def export_feeds(events: Iterable[dict[str, Any]] | str | Path,
                 outdir: str | Path, *, min_severity: str = "info",
                 allowlist: set[str] | None = None) -> dict[str, Path]:
    """Write all three feeds into ``outdir``. Returns name -> path.

    The event source is materialised once so multiple passes see the same
    data (a generator would be exhausted by the first pass).
    """
    materialised = list(_iter_source(events))
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {
        "blocklist": out / "blocklist.txt",
        "stix": out / "stix-bundle.json",
        "fail2ban": out / "fail2ban.log",
    }
    paths["blocklist"].write_text(
        build_blocklist(materialised, min_severity=min_severity,
                        allowlist=allowlist), encoding="utf-8")
    bundle = build_stix_bundle(materialised, min_severity=min_severity,
                               allowlist=allowlist)
    paths["stix"].write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    paths["fail2ban"].write_text(
        build_fail2ban_lines(materialised), encoding="utf-8")
    return paths
