import time
from threading import Event
from uuid import uuid4

import pytest
from sqlalchemy import select
from alba_security.intelligence import IntelligenceReport
from tests.alba.test_governance import system, scan  # noqa: F401
from tests.alba.test_intelligence import model_fixture


def finish(client, headers, job_id):
    for _ in range(200):
        result = client.get('/api/ai-jobs/' + job_id, headers=headers)
        assert result.status_code == 200, result.text
        if result.json()['state'] in {'completed', 'failed'}:
            return result.json()
        time.sleep(0.01)
    pytest.fail('Synthetic background job did not complete')


def test_report_is_queued_then_saved_for_its_creator(system):
    client, app, headers, _ = system
    app.state.intelligence_llm_client = model_fixture()
    app.state.intelligence_model = 'test-model'
    result = client.post('/api/intelligence/reports/generate', headers={**headers['hasan'], 'Prefer': 'respond-async'}, json={'kind': 'weekly', 'period': '2026-09-28'})
    assert result.status_code == 202
    job_id = result.json()['job_id']
    assert client.get('/api/ai-jobs/' + job_id).status_code == 401
    assert client.get('/api/ai-jobs/' + job_id, headers=headers['reviewer']).status_code == 404
    done = finish(client, headers['hasan'], job_id)
    assert done['state'] == 'completed' and done['result']['kind'] == 'weekly'
    assert 'actor' not in done and 'route' not in done


def test_invalid_period_is_rejected_before_enqueuing(system):
    client, _, headers, _ = system
    result = client.post('/api/intelligence/reports/generate', headers={**headers['hasan'], 'Prefer': 'respond-async'}, json={'kind': 'weekly', 'period': '2026-09-29'})
    assert result.status_code == 422


def test_failed_model_returns_failure_and_saves_no_fake_report(system):
    client, app, headers, _ = system
    bad = model_fixture(); bad.responses.create.return_value.output_text = 'invalid-json'
    app.state.intelligence_llm_client = bad; app.state.intelligence_model = 'test-model'
    result = client.post('/api/intelligence/reports/generate', headers={**headers['hasan'], 'Prefer': 'respond-async'}, json={'kind': 'monthly', 'period': '2026-09'})
    done = finish(client, headers['hasan'], result.json()['job_id'])
    assert done['state'] == 'failed' and done['status_code'] == 502
    with app.state.session_factory() as db:
        assert not db.scalar(select(IntelligenceReport))


def test_only_one_generation_is_queued_at_a_time(system):
    client, app, headers, _ = system
    entered, release = Event(), Event()
    model = model_fixture()
    response = model.responses.create.return_value
    def blocked(**kwargs):
        entered.set(); release.wait(timeout=5); return response
    model.responses.create.side_effect = blocked
    app.state.intelligence_llm_client = model; app.state.intelligence_model = 'test-model'
    try:
        result = client.post('/api/intelligence/reports/generate', headers={**headers['hasan'], 'Prefer': 'respond-async'}, json={'kind': 'weekly', 'period': '2026-09-28'})
        assert result.status_code == 202 and entered.wait(timeout=2)
        duplicate = client.post('/api/intelligence/reports/generate', headers={**headers['hasan'], 'Prefer': 'respond-async'}, json={'kind': 'monthly', 'period': '2026-09'})
        assert duplicate.status_code == 429
    finally:
        release.set()
    assert finish(client, headers['hasan'], result.json()['job_id'])['state'] == 'completed'


def test_explanation_keeps_consent_and_ownership_checks(system):
    client, app, headers, _ = system
    record = scan(client)
    app.state.intelligence_llm_client = model_fixture(); app.state.intelligence_model = 'test-model'
    url = '/api/intelligence/scans/' + record['id'] + '/explain'
    rejected = client.post(url, headers={**headers['hasan'], 'Prefer': 'respond-async'}, json={'page_url': 'https://example.com/'})
    assert rejected.status_code == 422
    result = client.post(url, headers={**headers['hasan'], 'Prefer': 'respond-async'}, json={})
    done = finish(client, headers['hasan'], result.json()['job_id'])
    assert done['state'] == 'completed' and done['result']['scan_id'] == record['id']


def test_unknown_jobs_are_not_exposed(system):
    client, _, headers, _ = system
    assert client.get('/api/ai-jobs/' + str(uuid4()), headers=headers['hasan']).status_code == 404


def test_job_access_rechecks_role_after_demotion(system):
    from alba_security.registration import RegisteredAdmin
    client, app, headers, _ = system
    app.state.intelligence_llm_client = model_fixture(); app.state.intelligence_model = 'test-model'
    result = client.post('/api/intelligence/reports/generate', headers={**headers['reviewer'], 'Prefer': 'respond-async'}, json={'kind': 'weekly', 'period': '2026-09-28'})
    job_id = result.json()['job_id']
    assert finish(client, headers['reviewer'], job_id)['state'] == 'completed'
    with app.state.session_factory() as db:
        db.get(RegisteredAdmin, 'reviewer').role = 'manager'
        db.commit()
    assert client.get('/api/ai-jobs/' + job_id, headers=headers['reviewer']).status_code == 403
