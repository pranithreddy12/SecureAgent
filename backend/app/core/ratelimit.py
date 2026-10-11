"""Failed-login throttling (in-memory, per process).

Tracks failures per (client address, email). After ``max_failures`` within ``window`` seconds the
key is locked until the oldest failure ages out. A successful login clears the key.

ponytail: in-process dict. Behind several workers each has its own counter, so the effective limit
is max_failures x workers; move to Redis/PostgreSQL if the API is ever scaled horizontally.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable


class LoginLimiter:
    def __init__(
        self,
        max_failures: int = 5,
        window: float = 900.0,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 10_000,
    ) -> None:
        self.max_failures = max_failures
        self.window = window
        self._clock = clock
        self._max_keys = max_keys
        self._failures: dict[str, deque[float]] = {}

    def _prune(self, key: str) -> deque[float]:
        q = self._failures.get(key)
        if q is None:
            return deque()
        cutoff = self._clock() - self.window
        while q and q[0] <= cutoff:
            q.popleft()
        if not q:
            self._failures.pop(key, None)
        return q

    def retry_after(self, key: str) -> int:
        """Seconds until another attempt is allowed; 0 if the key is not locked."""
        q = self._prune(key)
        if len(q) < self.max_failures:
            return 0
        return max(1, int(q[0] + self.window - self._clock()) + 1)

    def record_failure(self, key: str) -> None:
        if key not in self._failures and len(self._failures) >= self._max_keys:
            self._failures.pop(next(iter(self._failures)))  # bound memory under spraying
        self._failures.setdefault(key, deque()).append(self._clock())

    def reset(self, key: str) -> None:
        self._failures.pop(key, None)


login_limiter = LoginLimiter()
