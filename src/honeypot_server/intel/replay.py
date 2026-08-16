"""Session replay and log diffing.

Two capabilities built on the JSONL event stream:

* **Replay** -- SessionRecorder captures live sessions (every event a
  single source generates, in order, with inter-event delays) into a
  compact JSON document; replay_session plays one back through any sink
  (a logger, a queue, a test collector), optionally scaled in time.
  Recording what an attacker actually did, in order, is the rawest form
  of intel -- and replaying it into a sandbox lets you watch the
  intrusion again without re-exposing anything.

* **Diff** -- diff_logs compares two log files and reports which events
  (by service/event/src fingerprint) appear only in one of them. Useful
  for "did the new decoy version change what we capture?" and for
  regression-testing deployments against a golden log.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable, Iterable

from ..core.logger import read_events

#: Default cap on events stored per recorded session.
MAX_SESSION_EVENTS = 500


def session_key(event: dict[str, Any]) -> str:
    """Grouping key for sessions: source IP plus service.

    A "session" here is one source talking to one decoy; cross-service
    correlation belongs to the attacker profiler.
    """
    ip = str(event.get("src", "?")).split(":")[0]
    return ip + "/" + str(event.get("service", "?"))


class SessionRecorder:
    """Records per-source sessions from a live event stream.

    Feed events chronologically via observe(). Each (ip, service) pair
    gets its own session record holding the ordered events and the
    delays between them (seconds, from the ts strings).
    """

    def __init__(self, max_events: int = MAX_SESSION_EVENTS):
        self.max_events = max_events
        self.sessions: dict[str, dict[str, Any]] = {}
        self._last_ts: dict[str, str] = {}

    def observe(self, event: dict[str, Any]) -> dict[str, Any]:
        """Fold one event into its session record. Returns the record."""
        key = session_key(event)
        record = self.sessions.get(key)
        if record is None:
            record = {
                "key": key,
                "src": str(event.get("src", "?")),
                "service": str(event.get("service", "?")),
                "started": str(event.get("ts", "")),
                "events": [],
                "delays": [],
            }
            self.sessions[key] = record
        else:
            prev = self._last_ts.get(key, "")
            record["delays"].append(_seconds_between(prev, str(event.get("ts", ""))))
        if len(record["events"]) < self.max_events:
            record["events"].append(_compact_event(event))
        self._last_ts[key] = str(event.get("ts", ""))
        record["ended"] = str(event.get("ts", ""))
        return record

    def observe_all(self, events: Iterable[dict[str, Any]]) -> int:
        """Fold many events; returns the number observed."""
        count = 0
        for event in events:
            self.observe(event)
            count += 1
        return count

    def export(self, key: str | None = None) -> list[dict[str, Any]]:
        """Session records (all, or one by key) as JSON-ready dicts."""
        if key is not None:
            record = self.sessions.get(key)
            return [record] if record else []
        return list(self.sessions.values())

    def save(self, path: str | Path, key: str | None = None) -> Path:
        """Write the recording(s) to a JSON file. Returns the path."""
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(self.export(key), indent=2),
                       encoding="utf-8")
        return out


def load_recording(path: str | Path) -> list[dict[str, Any]]:
    """Read a session recording written by SessionRecorder.save()."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        return [data]
    return data


def _compact_event(event: dict[str, Any]) -> dict[str, Any]:
    """Trim an event to the fields replay needs (keeps it small)."""
    return {
        "ts": str(event.get("ts", "")),
        "service": str(event.get("service", "?")),
        "event": str(event.get("event", "?")),
        "severity": str(event.get("severity", "info")),
        "data": event.get("data"),
    }


def replay_session(record: dict[str, Any],
                   sink: Callable[[dict[str, Any]], None], *,
                   speed: float = 0.0,
                   sleep: Callable[[float], None] = time.sleep) -> int:
    """Play one recorded session back through sink().

    Each replayed event is the stored compact event plus replay=True and
    the original replay_src. speed scales the recorded inter-event
    delays (0 = no waiting, 1 = real time, 2 = twice as slow). Returns
    the number of events replayed.
    """
    events = record.get("events", [])
    delays = record.get("delays", [])
    for i, event in enumerate(events):
        if speed > 0 and i > 0 and i - 1 < len(delays):
            wait = delays[i - 1] * speed
            if wait > 0:
                sleep(wait)
        replayed = dict(event)
        replayed["replay"] = True
        replayed["replay_src"] = record.get("src", "?")
        sink(replayed)
    return len(events)


def diff_logs(events_a: Iterable[dict[str, Any]] | str | Path,
              events_b: Iterable[dict[str, Any]] | str | Path) -> dict[str, Any]:
    """Compare two event streams by (service, event, src-ip) fingerprints.

    Returns a dict with only_a, only_b (sorted fingerprint lists),
    common count and per-side totals. Fingerprints deliberately drop
    timestamps and payloads so the diff measures behaviour coverage,
    not byte equality.
    """
    def fingerprints(events: Iterable[dict[str, Any]] | str | Path) -> set[str]:
        if isinstance(events, (str, Path)):
            events = read_events(events)
        out = set()
        for e in events:
            ip = str(e.get("src", "?")).split(":")[0]
            out.add(str(e.get("service", "?")) + "|" + str(e.get("event", "?")) + "|" + ip)
        return out

    set_a = fingerprints(events_a)
    set_b = fingerprints(events_b)
    return {
        "only_a": sorted(set_a - set_b),
        "only_b": sorted(set_b - set_a),
        "common": len(set_a & set_b),
        "total_a": len(set_a),
        "total_b": len(set_b),
    }


def _seconds_between(ts_a: str, ts_b: str) -> float:
    """Seconds between two ts strings (0 on parse failure)."""
    fmt = "%Y-%m-%d %H:%M:%S"
    try:
        a = time.mktime(time.strptime(ts_a, fmt))
        b = time.mktime(time.strptime(ts_b, fmt))
    except ValueError:
        return 0.0
    return max(0.0, b - a)
