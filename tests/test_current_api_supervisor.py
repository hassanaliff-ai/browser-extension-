"""The updated worker is checked without touching legacy services."""
import httpx
from unittest.mock import Mock
import pytest
from scripts import current_api_supervisor as current


def test_matching_live_policy_is_ready(monkeypatch):
    response=httpx.Response(200,json={'service':'TestAPI','website_access_policy':current.WEBSITE_ACCESS_POLICY})
    monkeypatch.setattr(current.httpx,'get',lambda *a,**kw:response)
    assert current.ready()


def test_older_or_failed_worker_is_not_ready(monkeypatch):
    for status,data in [(200,{'service':'TestAPI'}),(503,{'service':'TestAPI','website_access_policy':current.WEBSITE_ACCESS_POLICY})]:
        monkeypatch.setattr(current.httpx,'get',lambda *a,_status=status,_data=data,**kw:httpx.Response(_status,json=_data))
        assert not current.ready()


def test_healthy_existing_worker_is_adopted_without_new_process(monkeypatch):
    monkeypatch.setattr(current,'ready',lambda:True)
    launch=Mock();monkeypatch.setattr(current.subprocess,'Popen',launch)
    current.ensure_worker();launch.assert_not_called()


def test_disabled_or_missing_configuration_does_not_run(tmp_path,monkeypatch):
    monkeypatch.setattr(current,'STATE',tmp_path)
    assert not current.enabled()
    (tmp_path/'config.json').write_text('{"enabled":true}')
    assert current.enabled()
    (tmp_path/'config.json').write_text('{"enabled":false}')
    assert not current.enabled()


def test_occupied_unrecognized_port_is_not_terminated(monkeypatch):
    monkeypatch.setattr(current,'ready',lambda:False)
    probe=Mock();probe.__enter__=Mock(return_value=probe);probe.__exit__=Mock(return_value=False)
    probe.bind.side_effect=OSError('Occupied')
    monkeypatch.setattr(current.socket,'socket',lambda *a:probe)
    launch=Mock();monkeypatch.setattr(current.subprocess,'Popen',launch)
    with pytest.raises(OSError):current.ensure_worker()
    launch.assert_not_called()


def test_normal_launcher_uses_selected_updated_worker(tmp_path,monkeypatch):
    import start_extsecure as launcher
    monkeypatch.setattr(launcher,'ROOT',tmp_path)
    monkeypatch.setattr(current,'STATE',tmp_path/'current-api')
    monkeypatch.setattr(launcher,'dotenv_values',lambda _:{'EXTSECURE_ACTIVE_API_PORT':'8769','EXTSECURE_RELEASE_ORIGIN':'https://api.example'})
    monkeypatch.setattr(launcher,'ensure_local_ai',lambda _:True)
    ensure=Mock();launch=Mock()
    monkeypatch.setattr(current,'ensure_worker',ensure);monkeypatch.setattr(launcher,'launch',launch)
    assert launcher.main()==0
    ensure.assert_called_once();launch.assert_called_once()
    assert 'current_api_supervisor.py' in launch.call_args.args[0][1]
