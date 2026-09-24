"""Minimal in-memory TTL cache."""

import time
from typing import Generic, Hashable, TypeVar

V = TypeVar("V")


class TTLCache(Generic[V]):
    def __init__(self, ttl_seconds: float, max_entries: int = 1024) -> None:
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._store: dict[Hashable, tuple[float, V]] = {}

    def get(self, key: Hashable) -> V | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if expires_at <= time.monotonic():
            del self._store[key]
            return None
        return value

    def set(self, key: Hashable, value: V) -> None:
        now = time.monotonic()
        self._store = {k: e for k, e in self._store.items() if e[0] > now}
        while len(self._store) >= self._max_entries:
            del self._store[next(iter(self._store))]
        self._store[key] = (now + self._ttl, value)
