from types import SimpleNamespace

import pytest

from app.services import cache as cache_module
from app.services.cache import TTLCache


@pytest.fixture
def clock(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(cache_module, "time", SimpleNamespace(monotonic=lambda: now[0]))
    return now


def test_miss_returns_none():
    assert TTLCache[str](ttl_seconds=60).get("absent") is None


def test_hit_within_ttl(clock):
    cache = TTLCache[str](ttl_seconds=60)
    cache.set("k", "v")
    clock[0] += 59
    assert cache.get("k") == "v"


def test_entry_expires_after_ttl(clock):
    cache = TTLCache[str](ttl_seconds=60)
    cache.set("k", "v")
    clock[0] += 60
    assert cache.get("k") is None


def test_overwrite_refreshes_ttl(clock):
    cache = TTLCache[str](ttl_seconds=60)
    cache.set("k", "old")
    clock[0] += 50
    cache.set("k", "new")
    clock[0] += 50
    assert cache.get("k") == "new"


def test_oldest_entry_is_evicted_at_capacity(clock):
    cache = TTLCache[int](ttl_seconds=60, max_entries=2)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.set("c", 3)
    assert cache.get("a") is None
    assert (cache.get("b"), cache.get("c")) == (2, 3)
