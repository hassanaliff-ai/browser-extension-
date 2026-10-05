"""Security changes and destructive cleanup require deliberate typed input."""
from datetime import timedelta

import pytest
from pydantic import ValidationError

from alba_security.governance import CaseChange, PolicyDraft, PrivacyChange, RetentionApply, UsabilityChange
from alba_security.models import Scan, utc_now
from alba_security.risk import risk_policy
from tests.alba.test_governance import scan, system  # noqa: F401


def policy_payload():
    return {
        'base_version': 'test-policy', 'weights': {r['code']: r['points'] for r in risk_policy()['signals']},
        'medium': 30, 'high': 60, 'critical': 80, 'reason': 'Typed threshold validation scenario',
    }


@pytest.mark.parametrize('field,value', [
    ('medium', True), ('medium', 30.0), ('medium', '30'),
    ('high', 60.0), ('high', '60'), ('critical', 80.0), ('critical', '80'),
])
def test_policy_thresholds_require_json_integers(field, value):
    with pytest.raises(ValidationError):
        PolicyDraft(**{**policy_payload(), field: value})


@pytest.mark.parametrize('model,payload', [
    (CaseChange, {'status': 'investigating', 'assignee': 'hasan', 'reason': 'Reviewed source evidence'}),
    (PrivacyChange, {'retention_days': 30, 'show_hostnames': False,
                    'collection_purpose': 'Retain only evidence needed for security monitoring.', 'reason': 'Reviewed retention period'}),
    (RetentionApply, {'confirm': True}),
    (UsabilityChange, {'status': 'fixed', 'verification': 'Added visible keyboard focus'}),
])
@pytest.mark.parametrize('value', [True, 1.0, '1'])
def test_optimistic_revisions_do_not_accept_coercion(model, payload, value):
    with pytest.raises(ValidationError):
        model(**payload, expected_revision=value)


@pytest.mark.parametrize('value', [1, 0, 'true', False])
def test_retention_requires_explicit_boolean_confirmation(value):
    with pytest.raises(ValidationError):
        RetentionApply(expected_revision=1, confirm=value)


@pytest.mark.parametrize('field,value', [('retention_days', '30'), ('retention_days', 30.0), ('show_hostnames', 'false'), ('show_hostnames', 1)])
def test_privacy_controls_require_exact_input_types(field, value):
    payload = {'expected_revision': 1, 'retention_days': 30, 'show_hostnames': False,
               'collection_purpose': 'Retain only evidence needed for security monitoring.', 'reason': 'Reviewed privacy settings'}
    with pytest.raises(ValidationError):
        PrivacyChange(**{**payload, field: value})


def test_numeric_confirmation_cannot_delete_scan_evidence(system):
    client, app, headers, _ = system
    evidence = scan(client, status='clear')
    with app.state.session_factory() as db:
        db.get(Scan, evidence['id']).created_at = utc_now() - timedelta(days=100)
        db.commit()
    preview = client.get('/api/privacy/retention-preview', headers=headers['hasan']).json()
    assert preview['eligible_scans'] == 1
    denied = client.post('/api/privacy/retention-apply', headers=headers['hasan'],
                         json={'expected_revision': preview['revision'], 'confirm': 1})
    assert denied.status_code == 422
    assert client.get('/api/scans/' + evidence['id'], headers=headers['hasan']).status_code == 200


def test_coerced_threshold_cannot_create_a_policy_draft(system):
    client, _, headers, _ = system
    current = client.get('/api/risk-policy', headers=headers['hasan']).json()
    response = client.post('/api/policies', headers=headers['hasan'],
                           json={**policy_payload(), 'base_version': current['version'], 'medium': True})
    assert response.status_code == 422
    stored = client.get('/api/policies', headers=headers['hasan']).json()
    assert stored['active']['version'] == current['version'] and stored['revisions'] == []
