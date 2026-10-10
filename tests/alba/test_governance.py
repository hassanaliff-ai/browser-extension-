"""End-to-end administrator decisions, scoring versions and privacy controls."""
from datetime import timedelta
import sqlite3

import pyotp
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import select

from alba_security.admin_auth import AdminAuth
from alba_security.api import create_app
from alba_security.models import Scan, utc_now

SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
# Independent 160-bit test authenticator, not a deployment credential.
REVIEWER_SECRET = 'KRSXG5DSNFXGOIDBNZSGK4TFOQXXI2DF'
INGEST = {'X-Ingest-Token': 'governance-ingest'}


@pytest.fixture
def system(tmp_path):
    hasher = PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1)
    primary = AdminAuth('hasan', hasher.hash('primary-test-password'), SECRET)
    reviewer = AdminAuth('reviewer', hasher.hash('reviewer-test-password'), REVIEWER_SECRET)
    database = tmp_path / 'governance.sqlite'
    app = create_app(database_url=f'sqlite:///{database.as_posix()}', ingest_token='governance-ingest',
                     admin_auth=primary, additional_admins=[reviewer], alert_notifier=lambda **_: [])
    with TestClient(app) as client:
        headers = {}
        for auth, password in [(primary, 'primary-test-password'), (reviewer, 'reviewer-test-password')]:
            if auth is reviewer:
                approved = client.post('/api/admin/registrations/reviewer/approve', headers=headers['hasan'],
                    json={'reason':'Owner verified independent reviewer access','role':'administrator'})
                assert approved.status_code == 200, approved.text
            first = client.post('/api/admin/login', json={'username': auth.username, 'password': password})
            assert first.status_code == 200, first.text
            second = client.post('/api/admin/verify', json={'challenge_token': first.json()['challenge_token'], 'totp_code': auth.totp.now()})
            assert second.status_code == 200, second.text
            headers[auth.username] = {'Authorization': 'Bearer ' + second.json()['access_token']}
        yield client, app, headers, database
    app.state.engine.dispose()


def scan(client, detected='malicious_url', status='detected'):
    response = client.post('/api/scans', headers=INGEST, json={'device_id': 'lab-device', 'device_name': 'Test device',
                           'target_kind': 'url', 'target': 'https://private.example/secret-query?key=PRIVATE',
                           'signals': [{'code': detected, 'status': status, 'detail': 'PRIVATE evidence must not persist'}]})
    assert response.status_code == 201, response.text
    return response.json()




@pytest.mark.parametrize('path', ['cases', 'privacy', 'privacy/retention-preview', 'evaluations', 'usability', 'governance/audit', 'admin/accounts'])
def test_new_data_views_require_completed_two_factor_session(system, path):
    client, _, _, _ = system
    assert client.get('/api/' + path).status_code == 401
    assert client.get('/api/' + path, headers=INGEST).status_code == 401


@pytest.mark.parametrize('path', ['cases', 'cases/missing/notes', 'cases/missing/status',
                                 'privacy',
                                 'privacy/retention-apply', 'evaluations', 'usability', 'usability/missing/status'])
def test_new_mutations_reject_ingest_tokens_and_password_only_challenges(system, path):
    client, _, _, _ = system
    first = client.post('/api/admin/login', json={'username': 'hasan', 'password': 'primary-test-password'})
    assert first.status_code == 200
    challenge_header = {'Authorization': 'Bearer ' + first.json()['challenge_token']}
    assert client.post('/api/' + path, headers=challenge_header, json={}).status_code == 401
    assert client.post('/api/' + path, headers=INGEST, json={}).status_code == 401








def test_cases_require_real_scan_real_assignee_and_audited_investigation(system):
    client, _, headers, _ = system
    header = headers['hasan']
    result = scan(client)
    payload = {'scan_id': result['id'], 'title': 'Investigate URL reputation', 'assignee': 'hasan'}
    assert client.post('/api/cases', headers=header, json={**payload, 'assignee': 'unconfigured'}).status_code == 422
    assert client.post('/api/cases', headers=header, json={**payload, 'scan_id': 'missing'}).status_code == 404
    created = client.post('/api/cases', headers=header, json=payload).json()
    route = '/api/cases/' + created['id']
    assert client.post(route + '/status', headers=header, json={'expected_revision': 1, 'status': 'resolved', 'assignee': 'hasan', 'reason': 'Skip the investigation stage'}).status_code == 409
    changed = client.post(route + '/status', headers=header, json={'expected_revision': 1, 'status': 'investigating', 'assignee': 'reviewer', 'reason': 'Investigating the linked evidence'})
    assert changed.status_code == 200
    assert client.post(route + '/status', headers=header, json={'expected_revision': 1, 'status': 'open', 'assignee': 'hasan', 'reason': 'Concurrent stale edit attempt'}).status_code == 409
    note = client.post(route + '/notes', headers=headers['reviewer'], json={'body': 'Checked the original scan and evidence.'})
    assert note.json()['notes'][0]['author'] == 'reviewer'
    resolved = client.post(route + '/status', headers=headers['reviewer'], json={'expected_revision': note.json()['revision'], 'status': 'resolved', 'assignee': 'reviewer', 'reason': 'Reputation evidence reviewed; case resolved'})
    assert resolved.status_code == 200
    assert resolved.json()['resolution']
    assert client.get('/api/scans/' + result['id'], headers=header).json()['score'] == 80
    reopened = client.post(route + '/status', headers=header, json={'expected_revision': resolved.json()['revision'], 'status': 'open', 'assignee': 'hasan', 'reason': 'Reopened after additional evidence'})
    assert reopened.status_code == 200
    assert reopened.json()['resolution'] is None


def test_privacy_masks_scan_displays_omits_new_hosts_and_rejects_stale_rules(system):
    client, _, headers, database = system
    header = headers['hasan']
    old = scan(client)
    rules = client.get('/api/privacy', headers=header).json()
    body = {'expected_revision': rules['revision'], 'retention_days': 30, 'show_hostnames': False,
            'collection_purpose': 'Record only the security evidence needed for investigations.', 'reason': 'Minimise browsing information in scan history'}
    updated = client.post('/api/privacy', headers=header, json=body)
    assert updated.status_code == 200, updated.text
    assert client.post('/api/privacy', headers=header, json=body).status_code == 409
    new = scan(client)
    assert new['target_display'].startswith('URL ')
    assert client.get('/api/scans/' + old['id'], headers=header).json()['target_display'].startswith('URL ')
    with sqlite3.connect(database) as db:
        display = db.execute('SELECT target_display FROM scans WHERE id=?', (new['id'],)).fetchone()[0]
        dump = '\n'.join(db.iterdump())
    assert display.startswith('URL ')
    assert 'secret-query' not in dump and '?key=PRIVATE' not in dump
    assert 'PRIVATE evidence' not in dump


def test_retention_protects_case_evidence_and_pending_alerts(system):
    client, app, headers, _ = system
    header = headers['hasan']
    eligible = scan(client, status='clear')
    held_case = scan(client, status='clear')
    held_alert = scan(client)
    case = client.post('/api/cases', headers=header, json={'scan_id': held_case['id'], 'title': 'Held investigation evidence', 'assignee': 'hasan'})
    assert case.status_code == 201
    with app.state.session_factory() as db:
        for row in db.scalars(select(Scan)):
            row.created_at = utc_now() - timedelta(days=100)
        db.commit()
    preview = client.get('/api/privacy/retention-preview', headers=header).json()
    assert preview['eligible_scans'] == 1
    assert preview['protected_case_scans'] == 2  # Manual case plus automatic high-risk containment case
    assert client.post('/api/privacy/retention-apply', headers=header, json={'expected_revision': preview['revision'], 'confirm': False}).status_code == 422
    deleted = client.post('/api/privacy/retention-apply', headers=header, json={'expected_revision': preview['revision'], 'confirm': True})
    assert deleted.status_code == 200, deleted.text
    assert deleted.json()['removed_scans'] == 1
    assert client.get('/api/scans/' + eligible['id'], headers=header).status_code == 404
    assert client.get('/api/scans/' + held_case['id'], headers=header).status_code == 200
    assert client.get('/api/scans/' + held_alert['id'], headers=header).status_code == 200


def test_evaluation_counts_false_positives_misses_and_unknown_separately(system):
    client, _, headers, _ = system
    body = {'dataset_version': 'reviewed-fixture-v1', 'scenarios': [
        {'name': 'True threat', 'expected': 'threat', 'signals': [{'code': 'malicious_url', 'status': 'detected'}]},
        {'name': 'Incorrect warning', 'expected': 'benign', 'signals': [{'code': 'malicious_url', 'status': 'detected'}]},
        {'name': 'Missed threat', 'expected': 'threat', 'signals': [{'code': 'malicious_url', 'status': 'clear'}]},
        {'name': 'Unavailable threat check', 'expected': 'threat', 'signals': [{'code': 'malicious_url', 'status': 'unknown'}]},
    ]}
    response = client.post('/api/evaluations', headers=headers['hasan'], json=body)
    assert response.status_code == 201, response.text
    results = response.json()['results']['current']
    assert results['true_positives'] == results['false_positives'] == results['false_negatives'] == results['unknown_outcomes'] == 1
    assert results['precision'] == results['recall'] == 0.5
    assert results['coverage'] == 0.75
    body['scenarios'][0]['expected'] = 'benign'
    assert client.post('/api/evaluations', headers=headers['hasan'], json=body).status_code == 409


def test_walkthrough_problem_requires_fix_then_retest(system):
    client, _, headers, _ = system
    header = headers['hasan']
    row = client.post('/api/usability', headers=header, json={'task': 'Read risk result by keyboard', 'category': 'keyboard',
                       'outcome': 'failed', 'observation': 'Focus was not visible on the review control.'}).json()
    route = '/api/usability/' + row['id'] + '/status'
    assert client.post(route, headers=header, json={'expected_revision': 1, 'status': 'verified', 'verification': 'Attempt to skip documenting a fix'}).status_code == 409
    fixed = client.post(route, headers=header, json={'expected_revision': 1, 'status': 'fixed', 'verification': 'Added a visible focus outline to the control'})
    assert fixed.status_code == 200
    verified = client.post(route, headers=headers['reviewer'], json={'expected_revision': 2, 'status': 'verified', 'verification': 'Retested keyboard navigation and focus visibility'})
    assert verified.status_code == 200
    assert verified.json()['status'] == 'verified'


def test_reviewer_identity_is_preserved_in_original_exception_workflow(system):
    client, _, headers, _ = system
    created = client.post('/api/overrides', headers=headers['reviewer'], json={'kind': 'domain', 'target': 'example.org', 'reason': 'Reviewed exact domain exception'})
    assert created.status_code == 201, created.text
    records = client.get('/api/overrides/audit', headers=headers['reviewer']).json()
    assert records[0]['actor'] == 'reviewer'


def test_signout_revokes_only_the_selected_administrator(system):
    client, _, headers, _ = system
    assert client.post('/api/admin/logout', headers=headers['reviewer']).status_code == 200
    assert client.get('/api/risk-policy', headers=headers['reviewer']).status_code == 401
    assert client.get('/api/risk-policy', headers=headers['hasan']).status_code == 200


def test_evaluation_recommends_evidence_review_without_changing_policy(system):
    client, _, headers, _ = system
    header = headers['hasan']
    policy_before = client.get('/api/risk-policy', headers=header).json()
    body = {'dataset_version': 'recommendations-v1', 'scenarios': [
        {'name': 'Benign labelled false alarm', 'expected': 'benign', 'signals': [{'code': 'malicious_url', 'status': 'detected'}]},
        {'name': 'Threat with missing signals', 'expected': 'threat', 'signals': [{'code': 'malicious_url', 'status': 'clear'}]},
        {'name': 'Unavailable reputation', 'expected': 'threat', 'signals': [{'code': 'malicious_url', 'status': 'unknown'}]},
    ]}
    response = client.post('/api/evaluations', headers=header, json=body)
    assert response.status_code == 201, response.text
    suggestions = {r['category']: r for r in response.json()['results']['recommendations']}
    assert suggestions['false_positive']['scenarios'] == ['Benign labelled false alarm']
    assert suggestions['false_positive']['signal_codes'] == ['malicious_url']
    assert suggestions['missed_threat']['scenarios'] == ['Threat with missing signals']
    assert suggestions['missed_threat']['signal_codes'] == []
    assert suggestions['incomplete_evidence']['scenarios'] == ['Unavailable reputation']
    assert client.get('/api/risk-policy', headers=header).json() == policy_before
    persisted = client.get('/api/evaluations', headers=header).json()[0]
    assert persisted['results']['recommendations'] == response.json()['results']['recommendations']


def test_clean_fixture_recommends_broader_validation_instead_of_accuracy_claim(system):
    client, _, headers, _ = system
    response = client.post('/api/evaluations', headers=headers['hasan'], json={
        'dataset_version': 'clean-fixture-v1', 'scenarios': [
            {'name': 'Known benign fixture', 'expected': 'benign', 'signals': [{'code': 'malicious_url', 'status': 'clear'}]},
        ]})
    assert response.status_code == 201
    assert response.json()['results']['recommendations'][0]['category'] == 'expand_validation'
