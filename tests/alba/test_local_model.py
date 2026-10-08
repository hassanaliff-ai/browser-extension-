"""Local-provider privacy, completion and evidence boundaries."""
import json
import httpx
import pytest
from alba_security.llm import write_narrative
from alba_security.model_provider import LocalModelClient, create_model_client
from alba_security.reports import ReportConfigurationError, ReportGenerationError
from tests.alba.test_governance import system  # noqa: F401


@pytest.fixture
def local(monkeypatch):
    monkeypatch.setenv('LLM_PROVIDER', 'ollama')
    monkeypatch.setenv('OLLAMA_MODEL', 'qwen3:4b-instruct')
    monkeypatch.delenv('OPENAI_API_KEY', raising=False)
    monkeypatch.delenv('OPENAI_MODEL', raising=False)


def transport(monkeypatch, *, content=None, reason='stop', tool_calls=None, status=200, raw=None):
    calls = []
    original = httpx.Client
    def handle(request):
        calls.append((request, json.loads(request.content)))
        if raw is not None:
            return httpx.Response(status, content=raw)
        message = {'content': content or json.dumps({'summary': 'Recorded activity requires review. No scanning activity is not evidence that all destinations were safe.', 'evidence_codes': [], 'recommendation_codes': ['investigate']})}
        if tool_calls:
            message['tool_calls'] = tool_calls
        return httpx.Response(status, json={'done': True, 'done_reason': reason, 'message': message})
    def factory(**kwargs):
        assert kwargs['trust_env'] is False
        assert kwargs['follow_redirects'] is False
        return original(transport=httpx.MockTransport(handle), **kwargs)
    monkeypatch.setattr('alba_security.model_provider.httpx.Client', factory)
    return calls


def test_local_model_needs_no_cloud_key(local):
    client, model = create_model_client()
    assert isinstance(client, LocalModelClient) and model == 'qwen3:4b-instruct'


def test_unknown_provider_is_not_a_cloud_fallback(monkeypatch):
    monkeypatch.setenv('LLM_PROVIDER', 'typo')
    with pytest.raises(ReportConfigurationError):
        create_model_client()


@pytest.mark.parametrize('model', ['', 'qwen3:cloud'])
def test_local_configuration_requires_local_model(local, monkeypatch, model):
    monkeypatch.setenv('OLLAMA_MODEL', model)
    with pytest.raises(ReportConfigurationError):
        create_model_client()


def test_local_structured_report_is_validated_and_loopback_only(local, monkeypatch):
    calls = transport(monkeypatch)
    result = write_narrative({'total_scans': 0})
    request, body = calls[0]
    assert str(request.url) == 'http://127.0.0.1:11434/api/chat'
    assert result['source'] == 'ollama'
    assert body['format']['additionalProperties'] is False
    assert 'tools' not in body and body['stream'] is False and body['think'] is False
    assert body['options']['num_predict'] == 900


def test_plain_monthly_summary_uses_same_local_adapter(local, monkeypatch):
    calls = transport(monkeypatch, content='A factual monthly review draft.')
    client, model = create_model_client()
    result = client.responses.create(model=model, instructions='Use only aggregate facts.', input='{}', max_output_tokens=400, store=False)
    assert result.status == 'completed' and result.output_text == 'A factual monthly review draft.'
    assert 'format' not in calls[0][1] and calls[0][1]['options']['num_predict'] == 400


def test_truncated_local_generation_cannot_be_saved(local, monkeypatch):
    transport(monkeypatch, reason='length')
    with pytest.raises(ReportGenerationError):
        write_narrative({})


def test_local_tool_call_is_rejected(local, monkeypatch):
    transport(monkeypatch, tool_calls=[{'function': {'name': 'browse'}}])
    with pytest.raises(ReportGenerationError):
        write_narrative({})


def test_oversized_local_response_is_rejected(local, monkeypatch):
    transport(monkeypatch, raw=b'x' * 65537)
    with pytest.raises(ReportGenerationError):
        write_narrative({})


def test_local_error_has_no_fake_or_remote_fallback_and_releases_slot(local, monkeypatch):
    calls = transport(monkeypatch, status=503)
    for _ in range(2):
        with pytest.raises(ReportGenerationError):
            write_narrative({})
    assert len(calls) == 2 and all('127.0.0.1:11434' in str(r.url) for r, _ in calls)


def test_invented_local_evidence_is_rejected(local, monkeypatch):
    transport(monkeypatch, content=json.dumps({'summary': 'There was a confirmed malware infection in this period.', 'evidence_codes': ['invented'], 'recommendation_codes': ['investigate']}))
    with pytest.raises(ReportGenerationError):
        write_narrative({}, evidence_codes=())


@pytest.mark.parametrize('invalid', [False, True])
def test_monthly_ml_workflow_uses_local_structured_validation_and_source(system, local, monkeypatch, invalid):
    from alba_security.reports import generate_monthly_report
    calls = transport(monkeypatch, content='invalid-json' if invalid else None)
    _, app, _, _ = system
    with app.state.session_factory() as db:
        if invalid:
            with pytest.raises(ReportGenerationError):
                generate_monthly_report(db, 2026, 9)
        else:
            report = generate_monthly_report(db, 2026, 9)
            assert report['summary_source'] == 'ollama'
            assert report['stats']['machine_learning']['status'] == 'insufficient_history'
    assert 'format' in calls[0][1]
