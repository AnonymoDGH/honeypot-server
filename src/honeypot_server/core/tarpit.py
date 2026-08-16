"""Tar-pit pacing -- deliberately waste an attacker's time.

Every real service answers instantly; a honeypot can do better by answering
*slowly*. A scanner that waits 400 ms per probe burns through its target
list an order of magnitude slower, and an interactive attacker typing into
a fake shell gets the uncanny feeling of a congested link. This module owns
all delay policy so protocols never hard-code sleeps:

* :class:`TarpitConfig` -- per-service base delay, jitter and cap.
* :class:`Tarpit` -- computes delays (deterministic when seeded) and
  performs the actual waiting through an injectable ``sleep`` callable,
  which is how tests run without real pauses.
* :func:`drip` -- slow-drip sender that streams a response in small chunks
  with a pause between each, for maximum time-wasting on bulk replies.

Delays default to zero: tarpitting is an opt-in deception mode.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Callable

#: Hard ceiling for any single delay so a misconfiguration cannot wedge a
#: decoy thread forever.
MAX_SAFE_DELAY = 30.0


@dataclass
class TarpitConfig:
    """Delay policy for one service.

    ``base`` is the mean pause in seconds; ``jitter`` adds up to +/- jitter
    seconds (uniform) so timing does not look mechanical; ``cap`` bounds the
    result. ``enabled=False`` short-circuits everything to zero delay.
    """

    enabled: bool = False
    base: float = 0.0
    jitter: float = 0.0
    cap: float = MAX_SAFE_DELAY

    def clamp(self, value: float) -> float:
        """Bound a computed delay into [0, min(cap, MAX_SAFE_DELAY)]."""
        ceiling = min(self.cap, MAX_SAFE_DELAY)
        return max(0.0, min(value, ceiling))


def default_configs() -> dict[str, TarpitConfig]:
    """Sensible per-service starting points (all disabled by default).

    Interactive protocols get longer base delays than bulk ones: an FTP
    directory listing or a shell prompt is where humans wait anyway.
    """
    return {
        "http": TarpitConfig(False, 0.25, 0.15),
        "ftp": TarpitConfig(False, 0.4, 0.2),
        "ssh": TarpitConfig(False, 0.6, 0.3),
        "smtp": TarpitConfig(False, 0.3, 0.15),
        "dns": TarpitConfig(False, 0.1, 0.05),
        "telnet": TarpitConfig(False, 0.5, 0.25),
        "redis": TarpitConfig(False, 0.2, 0.1),
        "mysql": TarpitConfig(False, 0.35, 0.2),
    }


class Tarpit:
    """Computes and performs protocol delays.

    ``sleep`` is injectable so tests can record calls instead of waiting;
    ``rng`` is injectable so jitter is deterministic under a seed.
    """

    def __init__(self, configs: dict[str, TarpitConfig] | None = None, *,
                 seed: int | None = None,
                 sleep: Callable[[float], None] = time.sleep,
                 rng: random.Random | None = None):
        self.configs = configs if configs is not None else default_configs()
        self.sleep = sleep
        self.rng = rng if rng is not None else random.Random(seed)
        self.total_waited = 0.0
        self.waits = 0

    def config(self, service: str) -> TarpitConfig:
        """Policy for ``service``; unknown services get a disabled config."""
        return self.configs.get(service, TarpitConfig())

    def enable(self, service: str | None = None, base: float | None = None,
               jitter: float | None = None) -> None:
        """Turn tarpitting on for one service (or all when None)."""
        targets = ([service] if service else list(self.configs))
        for name in targets:
            cfg = self.configs.setdefault(name, TarpitConfig())
            cfg.enabled = True
            if base is not None:
                cfg.base = base
            if jitter is not None:
                cfg.jitter = jitter

    def disable(self, service: str | None = None) -> None:
        """Turn tarpitting off for one service (or all when None)."""
        targets = ([service] if service else list(self.configs))
        for name in targets:
            if name in self.configs:
                self.configs[name].enabled = False

    def delay_for(self, service: str) -> float:
        """Compute the next delay for ``service`` without sleeping.

        Deterministic for a seeded rng: base plus uniform(-jitter, jitter),
        clamped to the configured cap. Disabled services return 0.0.
        """
        cfg = self.config(service)
        if not cfg.enabled or cfg.base <= 0:
            return 0.0
        value = cfg.base
        if cfg.jitter > 0:
            value += self.rng.uniform(-cfg.jitter, cfg.jitter)
        return cfg.clamp(value)

    def wait(self, service: str) -> float:
        """Sleep for the service's next delay. Returns seconds waited."""
        delay = self.delay_for(service)
        if delay > 0:
            self.sleep(delay)
            self.total_waited += delay
            self.waits += 1
        return delay

    def drip(self, send: Callable[[bytes], None], payload: bytes,
             service: str, chunk_size: int = 64) -> int:
        """Send ``payload`` in chunks with a tarpit pause between each.

        Returns the number of chunks sent. When tarpitting is disabled for
        the service the whole payload goes out in one chunk.
        """
        cfg = self.config(service)
        if not cfg.enabled or not payload:
            if payload:
                send(payload)
                return 1
            return 0
        chunk_size = max(1, chunk_size)
        chunks = 0
        for i in range(0, len(payload), chunk_size):
            send(payload[i:i + chunk_size])
            chunks += 1
            if i + chunk_size < len(payload):
                self.wait(service)
        return chunks

    def stats(self) -> dict[str, float | int]:
        """Cumulative time-wasting totals, for status displays."""
        return {"waits": self.waits, "total_waited": round(self.total_waited, 3)}


_global: Tarpit | None = None


def get_tarpit() -> Tarpit:
    """Process-wide tarpit (created lazily with default disabled configs)."""
    global _global
    if _global is None:
        _global = Tarpit()
    return _global


def set_tarpit(tarpit: Tarpit | None) -> None:
    """Replace (or clear, with None) the process-wide tarpit."""
    global _global
    _global = tarpit
