"""Model recovery uses the existing local runtime, never cloud fallback or public networking."""
from pathlib import Path
from unittest.mock import Mock
import start_extsecure as startup


def test_other_model_providers_do_not_launch_local_services(monkeypatch):
    launch=Mock();monkeypatch.setattr(startup,'launch',launch)
    assert startup.ensure_local_ai({'LLM_PROVIDER':'openai'})
    launch.assert_not_called()


def test_existing_local_model_is_reused(monkeypatch):
    monkeypatch.setattr(startup,'reachable',lambda _:True)
    launch=Mock();monkeypatch.setattr(startup,'launch',launch)
    assert startup.ensure_local_ai({'LLM_PROVIDER':'ollama','LOCALAPPDATA':'local-test'})
    launch.assert_not_called()


def test_missing_local_runtime_fails_without_downloading_or_cloud_fallback(tmp_path,monkeypatch):
    monkeypatch.setattr(startup,'reachable',lambda _:False)
    launch=Mock();monkeypatch.setattr(startup,'launch',launch)
    assert not startup.ensure_local_ai({'LLM_PROVIDER':'ollama','LOCALAPPDATA':str(tmp_path)})
    launch.assert_not_called()


def test_stopped_model_recovers_with_private_loopback_settings(tmp_path,monkeypatch):
    runtime=tmp_path/'ExtSecure'/'ollama';runtime.mkdir(parents=True);(runtime/'ollama.exe').write_bytes(b'fixture')
    monkeypatch.setattr(startup,'reachable',lambda _:False)
    wait=Mock(return_value=True);monkeypatch.setattr(startup,'wait_until_ready',wait)
    launch=Mock();monkeypatch.setattr(startup,'launch',launch)
    env={'LLM_PROVIDER':'ollama','LOCALAPPDATA':str(tmp_path),'OLLAMA_HOST':'0.0.0.0:11434'}
    assert startup.ensure_local_ai(env)
    command,used,log=launch.call_args.args
    assert command==[str(runtime/'ollama.exe'),'serve']
    assert used['OLLAMA_HOST']=='127.0.0.1:11434' and used['OLLAMA_NO_CLOUD']=='1'
    assert used['OLLAMA_MODELS']==str(runtime/'models')
    assert env['OLLAMA_HOST']=='0.0.0.0:11434'
    wait.assert_called_once_with('http://127.0.0.1:11434/api/tags')


def test_failed_local_process_start_is_reported_without_breaking_supervision(tmp_path,monkeypatch):
    runtime=tmp_path/'ExtSecure'/'ollama';runtime.mkdir(parents=True);(runtime/'ollama.exe').write_bytes(b'fixture')
    monkeypatch.setattr(startup,'reachable',lambda _:False)
    monkeypatch.setattr(startup,'launch',Mock(side_effect=OSError('test process error')))
    assert not startup.ensure_local_ai({'LLM_PROVIDER':'ollama','LOCALAPPDATA':str(tmp_path)})


def test_scheduler_does_not_depend_on_public_api_startup():
    source=(Path(__file__).resolve().parents[2]/'scripts/run_automatic_report.py').read_text()
    assert 'start_extsecure.main()' not in source
    assert 'start_extsecure.ensure_local_ai' in source
