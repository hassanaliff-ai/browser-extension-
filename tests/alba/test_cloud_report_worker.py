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


class EmptyResponse(io.BytesIO):
    status=204


@pytest.mark.parametrize('status',[401,403,404,409,422,429])
def test_rejected_requests_are_not_replayed(monkeypatch,status):
    monkeypatch.setattr(worker,'identity',lambda:'private-identity')
    calls=[];waits=[]
    def opener(request,**_):
        calls.append(request)
        raise urllib.error.HTTPError(request.full_url,status,'private response',{},None)
    with pytest.raises(worker.WorkerFailure):worker.trigger(opener=opener,pause=waits.append)
    assert len(calls)==1 and waits==[]


def test_trigger_retries_cold_start_without_receiving_report_data(monkeypatch):
    identities=[]
    def mint():identities.append(True);return 'private-identity-'+str(len(identities))
    monkeypatch.setattr(worker,'identity',mint)
    calls=[];waits=[]
    def opener(request,**_):
        calls.append(request)
        if len(calls)<3:raise urllib.error.HTTPError(request.full_url,503,'cold start',{},None)
        assert request.data==b'{}'
        return EmptyResponse()
    assert worker.trigger(opener=opener,pause=waits.append)is None
    assert len(identities)==3 and waits==[8,20]
    assert all(r.full_url==worker.ORIGIN+worker.PATH for r in calls)


def test_any_report_payload_is_rejected_and_not_logged(monkeypatch,capsys):
    monkeypatch.setattr(worker,'identity',lambda:'private-identity')
    def opener(*_,**__):return EmptyResponse(b'{"private_report":true}')
    with pytest.raises(worker.WorkerFailure,match='unexpected_response_payload'):worker.trigger(opener=opener)
    assert capsys.readouterr().out==''


def test_worker_errors_never_print_private_details(monkeypatch,capsys):
    monkeypatch.setattr(worker,'trigger',lambda:(_ for _ in ()).throw(ValueError('private-response-body')))
    assert worker.main()==1
    assert 'private-response' not in capsys.readouterr().out


def test_success_log_contains_no_project_information(monkeypatch,capsys):
    monkeypatch.setattr(worker,'trigger',lambda:None)
    assert worker.main()==0
    output=capsys.readouterr().out
    assert 'No project data was received' in output
