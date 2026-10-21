"""Small in-memory request limits for the loopback development API."""

from __future__ import annotations

import math
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping


class RequestLimiter:
    """Limit each route across this process without retaining client identity."""

    def __init__(self, limits: Mapping[str, int], *, window_seconds: int = 60,
                 clock: Callable[[], float] = time.monotonic):
        if window_seconds <= 0 or not limits or any(value <= 0 for value in limits.values()):
            raise ValueError("Request limits and window must be positive")
        self.limits = dict(limits)
        self.window_seconds = window_seconds
        self.clock = clock
        self._events = {route: deque() for route in limits}
        self._lock = threading.Lock()

    def retry_after(self, route: str) -> int:
        """Record an allowed request, or return seconds until a slot opens."""
        now = self.clock()
        with self._lock:
            events = self._events[route]
            while events and now - events[0] >= self.window_seconds:
                events.popleft()
            if len(events) >= self.limits[route]:
                return max(1, math.ceil(self.window_seconds - (now - events[0])))
            events.append(now)
            return 0
