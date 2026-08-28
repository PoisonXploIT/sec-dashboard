"""Auth hardening for the remote deployment (bunker phase, plan 2.1).

In-memory, no Redis (parity with ratelimit.py):

- truncate_key(): audit-safe rendering of an API key (first 8 chars + "...",
  never the full secret; short keys render only their first 2 chars).
- FailedAuthTracker: per-peer lockout after N failed auth attempts inside a
  window. A success clears the failure counter (and any active lockout, so a
  shared Cloudflare origin is not held hostage by one typo-prone user); the
  cost of that escape is documented in SEGUIMIENTO.md. Injectable clock for
  tests.
"""
import time
from collections import deque


def truncate_key(key: str | None) -> str:
    """Audit-safe rendering of an API key (never the full secret)."""
    if not key:
        return "(none)"
    if len(key) <= 8:
        return key[:2] + "..."
    return key[:8] + "..."


class FailedAuthTracker:
    """Lock a peer out after `max_failures` failed attempts inside `window`.

    is_blocked(peer) -> (blocked, retry_after_seconds). record_failure opens
    the lockout on the Nth hit; record_success clears both counters. Stale
    failure entries expire with the window so a slow drip does not accumulate
    forever. Memory bounded like RateLimiter via a GC sweep.
    """

    def __init__(self, max_failures: int = 5, window: float = 300.0,
                 lockout: float = 900.0, clock=time.monotonic):
        self.max_failures = max_failures
        self.window = window
        self.lockout = lockout
        self._clock = clock
        self._fails: dict[str, deque] = {}
        self._locked_until: dict[str, float] = {}
        self._gc_threshold = 4096

    def is_blocked(self, peer: str) -> tuple[bool, int]:
        until = self._locked_until.get(peer)
        if until is None:
            return False, 0
        now = self._clock()
        if until <= now:
            del self._locked_until[peer]
            return False, 0
        return True, max(1, int(until - now))

    def record_failure(self, peer: str) -> None:
        now = self._clock()
        fails = self._fails.setdefault(peer, deque())
        while fails and fails[0] <= now - self.window:
            fails.popleft()
        fails.append(now)
        if len(fails) >= self.max_failures:
            self._locked_until[peer] = now + self.lockout
        self._maybe_gc()

    def record_success(self, peer: str) -> None:
        """Clear the failure counter; also lifts an active lockout (documented)."""
        self._fails.pop(peer, None)
        self._locked_until.pop(peer, None)

    def _maybe_gc(self):
        if len(self._fails) <= self._gc_threshold:
            return
        now = self._clock()
        stale = [k for k, f in self._fails.items()
                 if not f or f[-1] < now - 2 * self.window]
        for k in stale:
            del self._fails[k]
