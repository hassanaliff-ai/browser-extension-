"""Sign-in throttling remains fair, bounded, and safe under concurrency."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from alba_security.request_limits import SignInRateLimit


def test_sliding_window_expires_each_attempt_at_its_own_boundary():
    now = [100.0]
    limiter = SignInRateLimit(max_attempts=2, clock=lambda: now[0])
    assert limiter.retry_after("client") == 0
    now[0] = 120
    assert limiter.retry_after("client") == 0
    now[0] = 150.1
    assert limiter.retry_after("client") == 10
    now[0] = 160
    assert limiter.retry_after("client") == 0
    assert limiter.retry_after("client") == 20
    now[0] = 180
    assert limiter.retry_after("client") == 0


def test_rejected_attempts_do_not_extend_the_lockout():
    now = [100.0]
    limiter = SignInRateLimit(max_attempts=1, clock=lambda: now[0])
    assert limiter.retry_after("client") == 0
    for second in (110, 130, 159.9):
        now[0] = second
        assert limiter.retry_after("client") > 0
    now[0] = 160
    assert limiter.retry_after("client") == 0


def test_client_state_is_independent_and_full_map_does_not_evict_live_limits():
    now = [100.0]
    limiter = SignInRateLimit(max_attempts=1, max_clients=2, clock=lambda: now[0])
    assert limiter.retry_after("client-a") == 0
    assert limiter.retry_after("client-b") == 0
    assert limiter.retry_after("client-c") == 60
    assert limiter.retry_after("client-a") == 60
    assert len(limiter._attempts) == 2
    now[0] = 160
    assert limiter.retry_after("client-c") == 0
    assert len(limiter._attempts) == 1


def test_capacity_retry_waits_until_the_oldest_client_is_fully_expired():
    now = [100.0]
    limiter = SignInRateLimit(max_attempts=3, max_clients=1, clock=lambda: now[0])
    assert limiter.retry_after("client-a") == 0
    now[0] = 130
    assert limiter.retry_after("client-a") == 0
    now[0] = 159
    assert limiter.retry_after("client-b") == 31
    now[0] = 190
    assert limiter.retry_after("client-b") == 0


def test_concurrent_requests_cannot_overrun_the_limit():
    limiter = SignInRateLimit(max_attempts=20, clock=lambda: 100.0)
    with ThreadPoolExecutor(max_workers=16) as workers:
        results = list(workers.map(lambda _: limiter.retry_after("same-client"), range(100)))
    assert results.count(0) == 20
    assert results.count(60) == 80


@pytest.mark.parametrize("options", [
    {"max_attempts": 0}, {"window_seconds": -1}, {"max_clients": 0},
    {"max_attempts": True}, {"window_seconds": 1.5},
])
def test_invalid_configuration_fails_at_startup(options):
    with pytest.raises(ValueError):
        SignInRateLimit(**options)


@pytest.mark.parametrize("client", [None, "", "x" * 257])
def test_invalid_client_identifier_does_not_allocate_state(client):
    limiter = SignInRateLimit()
    with pytest.raises(ValueError):
        limiter.retry_after(client)
    assert len(limiter._attempts) == 0
