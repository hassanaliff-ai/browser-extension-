import pytest

from pathlib import Path
import app.config as config
from app.config import Settings, get_settings


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


def test_project_env_is_used_from_another_working_directory(tmp_path, monkeypatch):
    assert Settings.model_config['env_file'] == Path(config.__file__).resolve().parents[1] / '.env'
    project = tmp_path / 'project'
    other = tmp_path / 'evaluation'
    project.mkdir(); other.mkdir()
    (project / '.env').write_text('VT_API_KEY=expected-project-test-key\n')
    (other / '.env').write_text('VT_API_KEY=unrelated-directory-test-key\n')
    monkeypatch.setitem(Settings.model_config, 'env_file', project / '.env')
    monkeypatch.delenv('VT_API_KEY', raising=False)
    monkeypatch.chdir(other)
    assert get_settings().vt_api_key == 'expected-project-test-key'
