"""Run each new Streamlit screen and exercise key administrator submissions."""
from unittest.mock import Mock
import httpx
import pytest

from alba_security.risk import risk_policy
from alba_security.governance import EvaluationScenario, evaluate
from tests.test_dashboard import app, assert_clean, button, field, response


@pytest.fixture
def governance_http(monkeypatch):
    policy = risk_policy()
    privacy = {'revision': 1, 'retention_days': 90, 'show_hostnames': True,
               'collection_purpose': 'Investigate browser security findings and report aggregate statistics.',
               'inventory': [], 'retention_scope': 'Case evidence is held for investigation.', 'note_guidance': 'Keep sensitive data out of notes.'}
    from alba_security.permissions import profile
    values = {
        'admin/me': profile('hasan','head_administrator'),
        'case-assignees': [{'username': 'hasan'}, {'username': 'reviewer'}],
        'scans': [{'id': 'scan-one', 'severity': 'Critical', 'target_display': 'example.test'}],
        'cases': [], 'policies': {'active': policy, 'baseline': policy, 'revisions': [], 'independent_review_available': True},
        'risk-policy': policy, 'privacy': privacy,
        'privacy/retention-preview': {'eligible_scans': 2, 'protected_case_scans': 1, 'cutoff': '2026-07-01T00:00:00Z', 'revision': 1},
        'evaluations': [], 'usability': [], 'governance/audit': [],
    }
    def get_result(url, **kwargs):
        path = url.split('/api/', 1)[1]
        return response(values.get(path, []))
    get = Mock(side_effect=get_result)
    post = Mock(return_value=response({'id': 'saved'}, 201))
    monkeypatch.setattr(httpx, 'get', get)
    monkeypatch.setattr(httpx, 'post', post)
    return values, get, post


@pytest.mark.parametrize('view', ['Incident cases', 'Security policies', 'Privacy governance', 'Detection evaluation', 'Usability and accessibility', 'Security guidance'])
def test_new_screen_renders_without_exposing_secrets(governance_http, view):
    instance = app(True, view)
    assert_clean(instance)
    assert instance.header[0].value == view
    for request in governance_http[1].call_args_list:
        assert request.kwargs['headers'] == {'Authorization': 'Bearer verified-admin-token'}


@pytest.mark.parametrize('stored_recommendations', [True, False])
def test_evaluation_displays_review_recommendations_and_supports_older_runs(governance_http, stored_recommendations):
    results = evaluate([EvaluationScenario(name='Incorrect warning', expected='benign',
                        signals=[{'code': 'malicious_url', 'status': 'detected'}])], risk_policy())
    evidence = {'current': results, 'baseline': results}
    if stored_recommendations:
        evidence['recommendations'] = [{'category': 'false_positive', 'scenarios': ['Incorrect warning'],
                                       'signal_codes': ['malicious_url'], 'action': 'Review the contributing evidence before proposing a scoring change.'}]
    governance_http[0]['evaluations'] = [{'id': 'run-one', 'dataset_version': 'labelled-v1',
                                         'policy_version': risk_policy()['version'],
                                         'created_at': '2026-10-04T10:00:00Z', 'results': evidence}]
    instance = app(True, 'Detection evaluation')
    assert_clean(instance)
    if stored_recommendations:
        assert any('contributing evidence' in r.value for r in instance.markdown)
    else:
        assert any('older run' in r.value for r in instance.info)
    assert not governance_http[2].called


def test_case_creation_uses_selected_evidence_and_admin(governance_http):
    instance = app(True, 'Incident cases')
    field(instance, 'Case title').input('Investigate this URL finding')
    button(instance, 'Create incident case').click().run()
    assert_clean(instance)
    assert governance_http[2].call_args.kwargs['json'] == {'scan_id': 'scan-one', 'title': 'Investigate this URL finding', 'assignee': 'hasan'}


def test_alert_investigation_opens_case_view_with_original_scan(governance_http):
    governance_http[0]['alerts'] = [{'id': 'alert-one', 'scan_id': 'scan-one', 'severity': 'Critical', 'status': 'open', 'message': 'Review URL reputation'}]
    instance = app(True, 'Alerts')
    button(instance, 'Investigate in a case').click().run()
    assert_clean(instance)
    assert instance.header[0].value == 'Incident cases'
    source = next(r for r in instance.selectbox if r.label == 'Source scan')
    assert source.value == 'scan-one'


def test_policy_draft_keeps_the_base_version_and_server_signal_set(governance_http):
    instance = app(True, 'Security policies')
    next(r for r in instance.text_area if r.label == 'Reason for scoring change').input('Review scoring against labelled fixtures')
    button(instance, 'Save policy draft').click().run()
    assert_clean(instance)
    payload = governance_http[2].call_args.kwargs['json']
    assert payload['base_version'] == risk_policy()['version']
    assert set(payload['weights']) == {r['code'] for r in risk_policy()['signals']}
    assert (payload['medium'], payload['high'], payload['critical']) == (30, 60, 80)


def test_retention_requires_explicit_preview_confirmation(governance_http):
    instance = app(True, 'Privacy governance')
    assert button(instance, 'Apply scan retention').disabled
    next(r for r in instance.checkbox if r.key == 'retention_confirm').check().run()
    button(instance, 'Apply scan retention').click().run()
    assert_clean(instance)
    assert governance_http[2].call_args.kwargs['json'] == {'expected_revision': 1, 'confirm': True}


def test_bad_fixture_json_never_runs_evaluation(governance_http):
    instance = app(True, 'Detection evaluation')
    next(r for r in instance.text_area if r.label == 'Labelled scenarios as JSON').input('invalid-json')
    button(instance, 'Compare active policy with baseline').click().run()
    assert_clean(instance)
    assert instance.error
    assert not governance_http[2].called


def test_usability_observation_is_recorded_without_fake_pass(governance_http):
    instance = app(True, 'Usability and accessibility')
    field(instance, 'Task tested').input('Review a finding with keyboard navigation')
    next(r for r in instance.text_area if r.label == 'Observation and evidence').input('Keyboard focus was hard to identify during review')
    button(instance, 'Record walkthrough').click().run()
    assert_clean(instance)
    assert governance_http[2].call_args.kwargs['json']['outcome'] == 'failed'


def test_policy_service_denial_never_claims_saved_change(governance_http):
    governance_http[2].return_value = response({'detail': 'A different administrator must review this draft'}, 403)
    policy = risk_policy()
    governance_http[0]['policies']['revisions'] = [{'id': 'draft-one', 'author': 'hasan', 'reviewer': None, 'status': 'draft', 'reason': 'Review risk weights carefully', 'policy': policy}]
    instance = app(True, 'Security policies')
    next(r for r in instance.text_area if r.label == 'Independent review reason').input('Attempt to review the author draft')
    button(instance, 'Submit independent review').click().run()
    assert_clean(instance)
    assert not instance.success
    assert instance.session_state['admin_session_token'] == 'verified-admin-token'


def test_expired_session_during_form_submission_returns_to_signin(governance_http):
    governance_http[2].return_value = response({'detail': 'Administrator session expired'}, 401)
    instance = app(True, 'Incident cases')
    field(instance, 'Case title').input('Investigate this URL finding')
    button(instance, 'Create incident case').click().run()
    assert_clean(instance)
    assert field(instance, 'Password')
    assert 'admin_session_token' not in instance.session_state

