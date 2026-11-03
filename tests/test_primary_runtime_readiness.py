"""A previous worker answering the port cannot make a new deployment look ready."""
import importlib
from pathlib import Path
from unittest.mock import Mock
import pytest


@pytest.fixture
def runtime(tmp_path,monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'scripts'))
    module=importlib.import_module('primary_api_runtime')
    monkeypatch.setattr(module,'ROOT',tmp_path)
    monkeypatch.setattr(module.time,'sleep',lambda _:None)
    child=Mock();child.poll.return_value=None
    monkeypatch.setattr(module.subprocess,'Popen',Mock(return_value=child))
    response=Mock();response.status_code=200
    client=Mock();client.__enter__=Mock(return_value=client);client.__exit__=Mock(return_value=False)
    client.get.return_value=response
    monkeypatch.setattr(module.httpx,'Client',Mock(return_value=client))
    return module,child,response


def test_current_worker_policy_is_ready(runtime):
    module,child,response=runtime
    response.json.return_value={'service':'TestAPI','website_access_policy':module.WEBSITE_ACCESS_POLICY}
    module.start_api({})
    child.terminate.assert_not_called()


def test_old_healthy_process_is_not_mistaken_for_updated_worker(runtime):
    module,child,response=runtime
    response.json.return_value={'service':'TestAPI'}
    with pytest.raises(RuntimeError,match='current website-access policy'):module.start_api({})
    child.terminate.assert_called_once()


def test_failed_worker_does_not_claim_existing_ports_health(runtime):
    module,child,response=runtime
    child.poll.return_value=1
    response.json.return_value={'service':'TestAPI','website_access_policy':module.WEBSITE_ACCESS_POLICY}
    with pytest.raises(RuntimeError):module.start_api({})
    response.json.assert_not_called()
    child.terminate.assert_not_called()


def test_error_status_cannot_claim_readiness_even_with_matching_json(runtime):
    module,child,response=runtime
    response.status_code=503
    response.json.return_value={'service':'TestAPI','website_access_policy':module.WEBSITE_ACCESS_POLICY}
    with pytest.raises(RuntimeError):module.start_api({})
    child.terminate.assert_called_once()
