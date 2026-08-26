"""In-memory rate limiting for /api endpoints (MVP, no Redis).

Sliding-window limiter keyed by client IP. main.py wires two buckets: a
strict one for the expensive mutation POSTs and a much more permissive
flood guard for GETs. Rejected requests are NOT recorded, so a blocked
burst does not keep extending the ban. The clock is injectable so tests
run on a frozen timeline instead of sleeping.
"""
import time
from collections import deque


class RateLimiter:
    """Sliding-window in-memory rate limiter.

    check(key) returns (allowed, retry_after_seconds). Allowed hits are
    recorded; rejected ones are not. When rejected, retry_after is the
    whole number of seconds until the oldest hit inside the window expires
    (minimum 1).
    """

    def __init__(self, limit: int, window: float = 60.0, clock=time.monotonic):
        self.limit = limit
        self.window = window
        self._clock = clock
        self._hits: dict[str, deque] = {}
        # Memory bound: above this many distinct keys we sweep stale ones.
        self._gc_threshold = 4096

    def check(self, key: str) -> tuple[bool, int]:
        now = self._clock()
        hits = self._hits.get(key)
        if hits is None:
            hits = deque()
            self._hits[key] = hits
        while hits and hits[0] <= now - self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            retry_after = int(hits[0] + self.window - now)
            return False, max(1, retry_after)
        hits.append(now)
        self._maybe_gc()
        return True, 0

    def _maybe_gc(self):
        """Bound memory for unbounded distinct keys (proxy egress IPs, etc.).

        Only runs when the key count exceeds the threshold; stale entries
        are those with no live hit inside a 2x-window. A purged key simply
        gets a fresh window on its next request (acceptable trade-off).
        """
        if len(self._hits) <= self._gc_threshold:
            return
        now = self._clock()
        stale = [k for k, h in self._hits.items()
                 if not h or h[-1] < now - 2 * self.window]
        for k in stale:
            del self._hits[k]
