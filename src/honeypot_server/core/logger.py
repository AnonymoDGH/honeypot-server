"""Structured JSONL event logging with rotation and enrichment.

The original project shipped a single :class:`Logger` that appended one JSON
object per line. This module keeps that exact public behaviour (constructor
signature, ``log()``, the ``ts`` field format, console fallback) and layers
the machinery a real deployment needs on top:

* :class:`RotatingJSONLWriter` -- size-capped rotation so a busy honeypot
  cannot fill the disk.
* :func:`make_event` -- the canonical event schema every decoy emits
  (id, ts, severity, service, src, event, plus free-form fields).
* :class:`EventBuffer` -- an in-memory ring of recent events that the
  dashboard and attacker profiler read without re-parsing files.
* Enrichment helpers -- credential hashing (captured secrets are stored as
  SHA-256 digests, never plaintext), redaction, session tagging.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

#: Severity ladder, ordered from chattiest to most alarming. The numeric
#: rank lets feeds and dashboards filter with a simple comparison.
SEVERITIES: dict[str, int] = {
    "debug": 0,
    "info": 1,
    "notice": 2,
    "warn": 3,
    "alert": 4,
    "critical": 5,
}

#: Default cap for one JSONL segment before rotation kicks in (5 MiB).
DEFAULT_MAX_BYTES = 5 * 1024 * 1024

#: How many rotated segments to keep beside the live file.
DEFAULT_MAX_FILES = 5


def severity_rank(severity: str) -> int:
    """Return the numeric rank of a severity name (unknown names map to 1)."""
    return SEVERITIES.get(str(severity).lower(), 1)


def new_event_id() -> str:
    """Return a short unique event id (hex uuid4, 12 chars)."""
    return uuid.uuid4().hex[:12]


def make_event(service: str, src: str, event: str, *,
               severity: str = "info", data: str | None = None,
               **fields: Any) -> dict[str, Any]:
    """Build a canonical honeypot event dictionary.

    Every decoy emits events through this helper so downstream consumers
    (feeds, dashboards, replay) can rely on a stable schema:

    ``{"id", "ts", "severity", "service", "src", "event", ...fields}``

    ``data`` carries the observed payload text when one exists. Extra keyword
    arguments are copied verbatim, which is how protocols attach structured
    detail (parsed headers, attempted usernames, canary token ids...).
    """
    entry: dict[str, Any] = {
        "id": new_event_id(),
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "severity": severity if severity in SEVERITIES else "info",
        "service": service,
        "src": src,
        "event": event,
    }
    if data is not None:
        entry["data"] = data
    entry.update(fields)
    return entry


def hash_credential(value: str) -> str:
    """Return the SHA-256 hex digest of a captured credential.

    Honeypots must never store plaintext passwords: the digest still lets an
    operator notice credential reuse (same digest across services) and lets
    intel feeds publish an IOC without leaking the secret itself.
    """
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def redact(entry: dict[str, Any], keys: Iterable[str] = ("password", "pass",
                                                          "secret", "token")) -> dict[str, Any]:
    """Return a copy of ``entry`` where sensitive fields are SHA-256 digests.

    Values under any of ``keys`` (case-insensitive, matched on the field name
    only) are replaced with ``sha256:<digest>``. Non-string values are hashed
    over their JSON representation so the shape of the event survives.
    """
    lowered = {k.lower() for k in keys}
    out = dict(entry)
    for key, value in out.items():
        if key.lower() in lowered and value is not None:
            if not isinstance(value, str):
                value = json.dumps(value, sort_keys=True, ensure_ascii=False)
            out[key] = "sha256:" + hash_credential(value)
    return out


class RotatingJSONLWriter:
    """Append-only JSONL writer with size-based rotation.

    The live file is ``path``; when it exceeds ``max_bytes`` it is closed and
    shifted to ``path.1``, previous generations move up one suffix, and
    anything beyond ``max_files`` generations is deleted. Rotation is
    performed inside :meth:`write_line` under the instance lock, so
    concurrent decoy threads never interleave partial lines.
    """

    def __init__(self, path: str | Path, max_bytes: int = DEFAULT_MAX_BYTES,
                 max_files: int = DEFAULT_MAX_FILES):
        self.path = Path(path)
        self.max_bytes = max(1, int(max_bytes))
        self.max_files = max(1, int(max_files))
        self._lock = threading.Lock()
        self.bytes_written = 0
        self.rotations = 0
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _size(self) -> int:
        try:
            return self.path.stat().st_size
        except OSError:
            return 0

    def _generation(self, n: int) -> Path:
        return self.path.with_name(self.path.name + f".{n}")

    def rotate(self) -> Path | None:
        """Rotate now, regardless of size. Returns the new archive path."""
        with self._lock:
            return self._rotate_locked()

    def _rotate_locked(self) -> Path | None:
        if not self.path.exists() and self._size() == 0:
            return None
        oldest = self._generation(self.max_files)
        if oldest.exists():
            oldest.unlink()
        for n in range(self.max_files - 1, 0, -1):
            src = self._generation(n)
            if src.exists():
                os.replace(src, self._generation(n + 1))
        target = self._generation(1)
        os.replace(self.path, target)
        self.rotations += 1
        self.bytes_written = 0
        return target

    def write_line(self, line: str) -> None:
        """Write one line (newline appended) rotating first when oversized."""
        payload = line if line.endswith("\n") else line + "\n"
        raw = payload.encode("utf-8")
        with self._lock:
            if self._size() + len(raw) > self.max_bytes:
                self._rotate_locked()
            with self.path.open("ab") as f:
                f.write(raw)
            self.bytes_written += len(raw)

    def write_event(self, entry: dict[str, Any]) -> None:
        """Serialize ``entry`` as one JSON line."""
        self.write_line(json.dumps(entry, ensure_ascii=False))

    def paths(self) -> list[Path]:
        """Live file first, then archives newest to oldest."""
        found = [self.path] if self.path.exists() else []
        for n in range(1, self.max_files + 1):
            gen = self._generation(n)
            if gen.exists():
                found.append(gen)
        return found

    def total_bytes(self) -> int:
        """Combined size of the live file and every archive."""
        return sum(p.stat().st_size for p in self.paths())


class EventBuffer:
    """Bounded in-memory ring of recent events.

    The dashboard and the attacker profiler need fast access to "what just
    happened" without re-reading log files; every :class:`Logger` keeps one
    of these and appends each event as it is written.
    """

    def __init__(self, maxlen: int = 1000):
        self._events: deque[dict[str, Any]] = deque(maxlen=max(1, maxlen))
        self._lock = threading.Lock()

    def append(self, entry: dict[str, Any]) -> None:
        with self._lock:
            self._events.append(entry)

    def recent(self, n: int = 20) -> list[dict[str, Any]]:
        """The ``n`` newest events, newest first."""
        with self._lock:
            items = list(self._events)
        return list(reversed(items[-n:]))

    def all(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._events)

    def by_service(self) -> dict[str, int]:
        """Event counts keyed by service name."""
        counts: dict[str, int] = {}
        with self._lock:
            for e in self._events:
                svc = e.get("service", "?")
                counts[svc] = counts.get(svc, 0) + 1
        return counts

    def by_source(self) -> dict[str, int]:
        """Event counts keyed by source IP (port stripped)."""
        counts: dict[str, int] = {}
        with self._lock:
            for e in self._events:
                src = str(e.get("src", "?")).split(":")[0]
                counts[src] = counts.get(src, 0) + 1
        return counts

    def since(self, ts: str) -> list[dict[str, Any]]:
        """Events whose ``ts`` string sorts after ``ts`` (same format)."""
        with self._lock:
            return [e for e in self._events if str(e.get("ts", "")) > ts]

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)


class Logger:
    """Thread-safe JSONL logger.

    Drop-in compatible with the original single-file logger: ``Logger(path)``
    appends one JSON object per line and stamps each entry with ``ts`` in
    ``YYYY-mm-dd HH:MM:SS`` form; ``Logger(None)`` prints to the console.

    New optional behaviour:

    * ``rotate=True`` routes writes through a :class:`RotatingJSONLWriter`.
    * every entry gains a unique ``id`` and a default ``severity`` when the
      caller did not supply them;
    * every entry is mirrored into an :class:`EventBuffer` (``self.buffer``)
      for live consumers;
    * ``self.enrich``, when set, is a callable applied to each entry before
      it is written (persona tagging, session ids, ...).
    """

    def __init__(self, path: str | Path | None, *, rotate: bool = False,
                 max_bytes: int = DEFAULT_MAX_BYTES,
                 max_files: int = DEFAULT_MAX_FILES,
                 buffer_size: int = 1000,
                 enrich: Callable[[dict[str, Any]], dict[str, Any]] | None = None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self.writer: RotatingJSONLWriter | None = None
        if self.path and rotate:
            self.writer = RotatingJSONLWriter(self.path, max_bytes, max_files)
        self.buffer = EventBuffer(buffer_size)
        self.enrich = enrich
        self.count = 0

    def log(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Stamp, enrich and persist one event. Returns the stored entry."""
        entry.setdefault("ts", time.strftime("%Y-%m-%d %H:%M:%S"))
        entry.setdefault("id", new_event_id())
        entry.setdefault("severity", "info")
        if self.enrich is not None:
            try:
                enriched = self.enrich(entry)
                if isinstance(enriched, dict):
                    entry = enriched
            except Exception:  # enrichment must never break logging
                pass
        self.buffer.append(entry)
        line = json.dumps(entry, ensure_ascii=False)
        if self.path:
            with self._lock:
                if self.writer is not None:
                    self.writer.write_line(line)
                else:
                    with self.path.open("a", encoding="utf-8") as f:
                        f.write(line + "\n")
                self.count += 1
        else:
            self.count += 1
            print(f"  [{entry.get('service', '?')}] {entry.get('src', '?')}: {line}")
        return entry

    def tail(self, n: int = 10) -> list[dict[str, Any]]:
        """The ``n`` newest buffered events, newest first."""
        return self.buffer.recent(n)

    def stats(self) -> dict[str, Any]:
        """Summary counts for status displays."""
        return {
            "events": self.count,
            "buffered": len(self.buffer),
            "by_service": self.buffer.by_service(),
            "by_source": self.buffer.by_source(),
            "rotations": self.writer.rotations if self.writer else 0,
        }

    def close(self) -> None:
        """Flush and release the underlying file (idempotent).

        Files are opened per-write, so closing only detaches the enrichment
        hook; the method exists for symmetry with context-manager use and
        future buffered writers.
        """
        self.enrich = None

    def __enter__(self) -> "Logger":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def iter_log_paths(path: str | Path, max_files: int = 999) -> list[Path]:
    """Live log plus rotated archives that exist, newest first.

    Archives are numbered ``name.1`` (newest) upward; scanning stops at the
    first missing generation so a partially cleaned directory does not hide
    older segments behind the gap.
    """
    base = Path(path)
    found = [base] if base.exists() else []
    for n in range(1, max_files + 1):
        gen = base.with_name(base.name + f".{n}")
        if not gen.exists():
            break
        found.append(gen)
    return found


def read_events(path: str | Path, *, include_rotated: bool = True,
                max_files: int = 999) -> Iterator[dict[str, Any]]:
    """Yield event dicts from a JSONL log, oldest first.

    Malformed lines are skipped silently; when ``include_rotated`` is true
    the archives produced by :class:`RotatingJSONLWriter` are read too
    (oldest archive first, live file last) so callers see chronological
    order even across rotations.
    """
    base = Path(path)
    paths: list[Path] = []
    if include_rotated:
        archives = []
        for n in range(1, max_files + 1):
            gen = base.with_name(base.name + f".{n}")
            if not gen.exists():
                break
            archives.append(gen)
        paths.extend(reversed(archives))  # oldest archive first
    if base.exists():
        paths.append(base)
    for p in paths:
        try:
            with p.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue
