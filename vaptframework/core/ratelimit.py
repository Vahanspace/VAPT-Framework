"""Rate limiting and the kill switch — the third guardrail.

Even authorized, in-scope testing must be gentle: a token-bucket limiter caps the request
rate so the framework cannot accidentally behave like a denial-of-service. A file-based
kill switch lets an operator halt all active work immediately by creating a stop file.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass


class TestingHalted(Exception):
    """Raised when the kill switch is engaged."""


class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int | None = None, *, _clock=time.monotonic, _sleep=time.sleep):
        if rate_per_sec <= 0:
            raise ValueError("rate_per_sec must be > 0")
        self.rate = float(rate_per_sec)
        self.capacity = float(burst if burst is not None else max(1.0, rate_per_sec))
        self._tokens = self.capacity
        self._clock = _clock
        self._sleep = _sleep
        self._last = _clock()

    def _refill(self) -> None:
        now = self._clock()
        elapsed = now - self._last
        self._last = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)

    def try_acquire(self, tokens: float = 1.0) -> bool:
        self._refill()
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False

    def acquire(self, tokens: float = 1.0) -> float:
        """Block until ``tokens`` are available; returns the seconds waited."""
        waited = 0.0
        while not self.try_acquire(tokens):
            needed = tokens - self._tokens
            delay = needed / self.rate
            self._sleep(delay)
            waited += delay
        return waited


@dataclass
class KillSwitch:
    stop_file: str

    def engaged(self) -> bool:
        return os.path.exists(self.stop_file)

    def check(self) -> None:
        if self.engaged():
            raise TestingHalted(f"kill switch engaged: {self.stop_file} exists")

    def engage(self, reason: str = "manual stop") -> None:
        os.makedirs(os.path.dirname(self.stop_file) or ".", exist_ok=True)
        with open(self.stop_file, "w", encoding="utf-8") as fh:
            fh.write(reason)

    def clear(self) -> None:
        if os.path.exists(self.stop_file):
            os.remove(self.stop_file)


class Throttle:
    """Convenience wrapper: enforces both the kill switch and the rate limit per request."""

    def __init__(self, bucket: TokenBucket, kill_switch: KillSwitch | None = None):
        self.bucket = bucket
        self.kill_switch = kill_switch

    def gate(self) -> float:
        if self.kill_switch:
            self.kill_switch.check()
        return self.bucket.acquire()
