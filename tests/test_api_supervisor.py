"""Recovery policy tests: no real deployment processes or credentials are touched."""
import importlib.util,json,sys
from pathlib import Path
from unittest.mock import Mock
import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('api_supervisor',ROOT/'scripts/api_supervisor.py')
supervisor=importlib.util.module_from_spec(spec);spec.loader.exec_module(supervisor)

def test_bom_config_can_be_disabled(tmp_path,monkeypatch):
    monkeypatch.setattr(supervisor,'STATE',tmp_path)
    (tmp_path/'config.json').write_text('{"enabled":true}',encoding='utf-8-sig')
    assert supervisor.enabled()
    (tmp_path/'config.json').write_text('{"enabled":false}',encoding='utf-8-sig')
    assert not supervisor.enabled()

def test_missing_config_does_not_start_services(tmp_path,monkeypatch):
    monkeypatch.setattr(supervisor,'STATE',tmp_path);assert not supervisor.enabled()

@pytest.fixture
def recovery(tmp_path,monkeypatch):
    import activate_postgresql as api
    import scripts.start_public_api as public
    import scripts.stop_public_api as stop
    monkeypatch.setattr(supervisor,'ROOT',tmp_path);monkeypatch.setattr(supervisor,'STATE',tmp_path)
    directory=tmp_path/'.private/public-api';directory.mkdir(parents=True)
    (directory/'state.json').write_text(json.dumps({'origin':'https://temporary.example','gateway_pid':1,'tunnel_pid':2}))
    mocks={name:Mock() for name in ['start_api','stop_api','api_process','start','stop','publish','checkpoint']}
    for name in ['start_api','stop_api','api_process']:monkeypatch.setattr(api,name,mocks[name])
    monkeypatch.setattr(public,'start',mocks['start']);monkeypatch.setattr(stop,'stop',mocks['stop'])
    monkeypatch.setattr(supervisor,'public_processes_alive',lambda _:True)
    monkeypatch.setattr(supervisor,'checkpoint',mocks['checkpoint']);monkeypatch.setattr(supervisor,'publish_package',mocks['publish'])
    return mocks

def test_healthy_api_preserves_tunnel_and_packages(recovery,monkeypatch):
    monkeypatch.setattr(supervisor,'healthy',lambda _:True);assert supervisor.cycle(0)==0
    recovery['start_api'].assert_not_called();recovery['stop'].assert_not_called();recovery['start'].assert_not_called()
    recovery['publish'].assert_called_once_with('https://temporary.example')

def test_transient_dns_failure_does_not_rotate_live_tunnel(recovery,monkeypatch):
    monkeypatch.setattr(supervisor,'healthy',lambda url:'127.0.0.1' in url);supervisor.cycle(0)
    recovery['stop'].assert_not_called();recovery['start'].assert_not_called();recovery['publish'].assert_not_called()
    assert recovery['checkpoint'].call_args.kwargs['state']=='waiting_for_public_network'

def test_dead_api_is_started_without_waiting_for_three_failures(recovery,monkeypatch):
    recovery['api_process'].return_value=None
    values=iter([False,True,True]);monkeypatch.setattr(supervisor,'healthy',lambda _:next(values));supervisor.cycle(0)
    recovery['start_api'].assert_called_once()

def test_running_api_is_not_killed_after_one_failed_probe(recovery,monkeypatch):
    monkeypatch.setattr(supervisor,'healthy',lambda _:False);assert supervisor.cycle(0)==1
    recovery['stop_api'].assert_not_called();recovery['start_api'].assert_not_called()

def test_three_failures_restart_only_the_verified_api(recovery,monkeypatch):
    values=iter([False,True,True]);monkeypatch.setattr(supervisor,'healthy',lambda _:next(values));supervisor.cycle(2)
    recovery['stop_api'].assert_called_once_with(recovery['api_process'].return_value);recovery['start_api'].assert_called_once()

def test_dead_tunnel_processes_trigger_controlled_recovery(recovery,monkeypatch):
    monkeypatch.setattr(supervisor,'healthy',lambda _:True);monkeypatch.setattr(supervisor,'public_processes_alive',lambda _:False)
    supervisor.cycle(0);recovery['stop'].assert_called_once();recovery['start'].assert_called_once_with(wait_for_health=False)

def test_terminal_rejection_recovers_even_when_tunnel_process_is_alive(recovery,monkeypatch):
    monkeypatch.setattr(supervisor,'healthy',lambda _:True)
    monkeypatch.setattr(supervisor,'public_tunnel_expired',lambda _:True)
    supervisor.cycle(0)
    recovery['stop'].assert_called_once();recovery['start'].assert_called_once_with(wait_for_health=False)

def test_rejection_from_previous_tunnel_does_not_rotate_current_url(recovery):
    log=supervisor.ROOT/'.private/public-api/tunnel.log'
    previous=b'ERR Unauthorized: Tunnel not found\n'
    log.write_bytes(previous+b'INF Registered tunnel connection\n')
    assert not supervisor.public_tunnel_expired({'tunnel_log_offset':len(previous)})
    assert supervisor.public_tunnel_expired({'tunnel_log_offset':0})
    assert not supervisor.public_tunnel_expired({})

def test_transient_errors_are_not_expired_tunnels(recovery):
    log=supervisor.ROOT/'.private/public-api/tunnel.log'
    log.write_bytes(b'ERR connection with edge closed\nINF Retrying connection\n')
    assert not supervisor.public_tunnel_expired({'tunnel_log_offset':0})

def test_missing_tunnel_log_does_not_break_recovery(recovery):
    assert not supervisor.public_tunnel_expired({'tunnel_log_offset':0})

def test_already_packaged_origin_does_not_rebuild_every_poll(recovery,monkeypatch):
    (supervisor.STATE/'package-origin.txt').write_text('https://temporary.example')
    monkeypatch.setattr(supervisor,'healthy',lambda _:True);supervisor.cycle(0);recovery['publish'].assert_not_called()

def test_disabled_startup_does_not_stop_unrelated_existing_api(recovery,monkeypatch):
    monkeypatch.setattr(sys,'argv',['api_supervisor.py'])
    monkeypatch.setattr(supervisor,'lock_instance',lambda:Mock())
    monkeypatch.setattr(supervisor,'enabled',lambda:False)
    monkeypatch.setattr(supervisor.ctypes,'windll',Mock(),raising=False)
    supervisor.main();recovery['stop_api'].assert_not_called();recovery['stop'].assert_not_called()

def test_operator_stop_is_completed_by_the_owning_supervisor(recovery,monkeypatch):
    monkeypatch.setattr(sys,'argv',['api_supervisor.py'])
    monkeypatch.setattr(supervisor,'lock_instance',lambda:Mock())
    values=iter([True,False,False]);monkeypatch.setattr(supervisor,'enabled',lambda:next(values))
    monkeypatch.setattr(supervisor,'cycle',lambda _:0)
    monkeypatch.setattr(supervisor.ctypes,'windll',Mock(),raising=False)
    supervisor.main();recovery['stop'].assert_called_once();recovery['stop_api'].assert_called_once()
    assert recovery['checkpoint'].call_args.kwargs['state']=='stopped'
