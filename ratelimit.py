"""In-memory sliding-window rate limiter (single process). Swap for Redis when scaling out."""
import math
import threading
import time
from collections import deque


class SlidingWindowLimiter:
    def __init__(self, max_keys: int = 100_000, clock=time.monotonic):
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()
        self._max_keys = max_keys
        self._clock = clock

    def hit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        """Record a request. Returns (allowed, retry_after_seconds)."""
        now = self._clock()
        with self._lock:
            q = self._hits.get(key)
            if q is None:
                if len(self._hits) >= self._max_keys:
                    self._evict(now, window)
                q = self._hits[key] = deque()
            cutoff = now - window
            while q and q[0] <= cutoff:
                q.popleft()
            if len(q) >= limit:               # rejected hits are NOT recorded
                return False, max(1, math.ceil(q[0] + window - now))
            q.append(now)
            return True, 0

    def _evict(self, now: float, window: int) -> None:
        stale = [k for k, q in self._hits.items() if not q or q[-1] <= now - window]
        for k in stale:
            del self._hits[k]
        if len(self._hits) >= self._max_keys:  # still full: bounded memory beats perfect accounting
            self._hits.pop(next(iter(self._hits)))
