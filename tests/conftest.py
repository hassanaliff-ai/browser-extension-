import os
from functools import partial

# Must be set before `main` is imported: it loads settings at import time.
# Forced (not setdefault) so a developer's real key is never used by tests.
os.environ["VT_API_KEY"] = "test-key"
# Never let the legacy test suite write to a developer's configured
# monitoring database, even when their local .env enables the feature.
os.environ["MONITORING_ENABLED"] = "0"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
from app.services.virustotal import VirusTotalClient  # noqa: E402


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def client(monkeypatch):
    """TestClient whose VT client polls fast, so submit-and-poll tests stay quick.

    Each test gets a fresh app lifespan, and therefore a fresh cache.
    """
    monkeypatch.setattr(
        main,
        "VirusTotalClient",
        partial(
            VirusTotalClient,
            poll_initial_delay=0.001,
            poll_max_delay=0.005,
            poll_timeout=0.2,
        ),
    )
    with TestClient(main.app) as test_client:
        yield test_client
