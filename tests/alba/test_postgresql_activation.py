"""Windows listener discovery must tolerate an offline API and reject other apps."""
import importlib.util,sys
from pathlib import Path
from types import SimpleNamespace
import pytest


@pytest.fixture
def activation(monkeypatch):
    scripts=Path(__file__).resolve().parents[2]/'scripts'
    monkeypatch.syspath_prepend(str(scripts))
    import primary_api_runtime as module
    monkeypatch.setattr(module.subprocess,'CREATE_NO_WINDOW',0,raising=False)
    return module


def test_offline_api_is_not_an_error(activation,monkeypatch):
    monkeypatch.setattr(activation.subprocess,'run',lambda *a,**kw:SimpleNamespace(stdout=''))
    assert activation.api_process() is None


def test_unrelated_listener_is_never_selected(activation,monkeypatch):
    monkeypatch.setattr(activation.subprocess,'run',lambda *a,**kw:SimpleNamespace(stdout='TCP 127.0.0.1:8001 0.0.0.0:0 LISTENING 123\n'))
    monkeypatch.setattr(activation,'powershell',lambda *a:SimpleNamespace(stdout='{"ProcessId":123,"CommandLine":"unrelated application"}'))
    with pytest.raises(RuntimeError,match='unverified process'):activation.api_process()


def test_recognized_uvicorn_listener_is_selected(activation,monkeypatch):
    monkeypatch.setattr(activation.subprocess,'run',lambda *a,**kw:SimpleNamespace(stdout='TCP 127.0.0.1:8001 0.0.0.0:0 LISTENING 123\n'))
    monkeypatch.setattr(activation,'powershell',lambda *a:SimpleNamespace(stdout='{"ProcessId":123,"CommandLine":"python -m uvicorn prototypes.securescope.backend.primary:create_app --factory --port 8001"}'))
    assert activation.api_process()['ProcessId']==123
