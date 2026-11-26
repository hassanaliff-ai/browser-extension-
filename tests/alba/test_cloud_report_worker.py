import importlib.util
import io
import json
from pathlib import Path
import urllib.error

import pytest

SCRIPT=Path(__file__).resolve().parents[2]/'scripts/run_cloud_reports.py'
spec=importlib.util.spec_from_file_location('isolated_cloud_worker',SCRIPT)
worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)


def response(value):
    return io.BytesIO(json.dumps(value).encode())


def test_worker_identity_refuses_non_github_endpoints(monkeypatch):
    monkeypatch.setenv('ACTIONS_ID_TOKEN_REQUEST_URL','https://attacker.example/token')
    monkeypatch.setenv('ACTIONS_ID_TOKEN_REQUEST_TOKEN','private-placeholder')
    with pytest.raises(worker.WorkerFailure):worker.identity()


@pytest.mark.parametrize('status',[401,403,409,422,429])
def test_rejected_protected_requests_are_not_blindly_replayed(monkeypatch,status):
    monkeypatch.setattr(worker,'identity',lambda:'private-identity')
    calls=[];waits=[]
    def opener(request,**_):
        calls.append(request)
        raise urllib.error.HTTPError(request.full_url,status,'private response',{},None)
    with pytest.raises(worker.WorkerFailure):worker.api('jobs',{},opener=opener,pause=waits.append)
    assert len(calls)==1 and waits==[]


def test_worker_recovers_from_cold_start_with_fresh_short_lived_identity(monkeypatch):
    identities=[]
    def mint():identities.append(True);return 'private-identity-'+str(len(identities))
    monkeypatch.setattr(worker,'identity',mint)
    calls=[];waits=[]
    def opener(request,**_):
        calls.append(request)
        if len(calls)<3:raise urllib.error.HTTPError(request.full_url,503,'cold start',{},None)
        return response({'jobs':[]})
    assert worker.api('jobs',{},opener=opener,pause=waits.append)=={'jobs':[]}
    assert len(identities)==3 and waits==[8,20]
    assert all(r.full_url==worker.ORIGIN+worker.PREFIX+'jobs' for r in calls)


def test_probe_writes_only_boolean_to_public_output(monkeypatch,tmp_path,capsys):
    monkeypatch.setenv('RUNNER_TEMP',str(tmp_path));out=tmp_path/'outputs'
    monkeypatch.setenv('GITHUB_OUTPUT',str(out))
    monkeypatch.setattr(worker,'api',lambda *_,**__: {'jobs':[{'ticket':'private-ticket','summary':'private-summary'}]})
    worker.probe()
    assert out.read_text()=='pending=true\n'
    assert 'private' not in capsys.readouterr().out
    assert json.loads(worker.jobs_path().read_text())[0]['ticket']=='private-ticket'


def test_model_manifest_is_checked_before_inference(monkeypatch):
    monkeypatch.setattr(worker.urllib.request,'urlopen',lambda *_,**__:response({'models':[{'name':worker.MODEL,'digest':'unapproved'}]}))
    with pytest.raises(worker.WorkerFailure,match='model_digest_mismatch'):worker.verify_model()


def test_worker_errors_never_print_private_exception_details(monkeypatch,capsys):
    monkeypatch.setattr(worker,'probe',lambda:(_ for _ in ()).throw(ValueError('private-token-and-response-body')))
    monkeypatch.setattr(worker.sys,'argv',['worker','--probe'])
    assert worker.main()==1
    output=capsys.readouterr().out
    assert 'private-token' not in output and 'operation_failed' in output
