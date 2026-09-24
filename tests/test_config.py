import pytest

from app.config import get_settings


@pytest.fixture(autouse=True)
def fresh_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_loads_key_and_default_ttl(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "abc")
    monkeypatch.delenv("CACHE_TTL_SECONDS", raising=False)
    settings = get_settings()
    assert settings.vt_api_key == "abc"
    assert settings.cache_ttl_seconds == 600


def test_ttl_can_be_overridden(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "abc")
    monkeypatch.setenv("CACHE_TTL_SECONDS", "30")
    assert get_settings().cache_ttl_seconds == 30


def test_empty_key_fails_with_clear_message(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "")
    with pytest.raises(RuntimeError, match="VT_API_KEY is missing or empty"):
        get_settings()
