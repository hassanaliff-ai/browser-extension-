"""Authentication history records outcomes without authentication material."""
import json
from datetime import timedelta

import pyotp
from sqlalchemy import select

from alba_security.admin_auth import AdminAuthState
from alba_security.governance import GovernanceAudit
from alba_security.models import utc_now
from tests.alba.test_governance import SECRET, system  # noqa: F401
from tests.alba.test_roles import roles  # noqa: F401


def events(app):
    with app.state.session_factory() as db:
        return [{'actor': row.actor, 'action': row.action, 'reference': row.reference,
                 'details': row.details}
                for row in db.scalars(select(GovernanceAudit).where(
                    GovernanceAudit.area == 'authentication'))]


def test_password_outcomes_use_known_account_identity_and_hide_unknown_input(system):
    client, app, _, _ = system
    password = 'PRIVATE incorrect password must not persist'
    for username in ('hasan', 'PRIVATE unknown email@example.invalid'):
        response = client.post('/api/admin/login', json={'username': username, 'password': password})
        assert response.status_code == 401
    rejected = [row for row in events(app) if row['action'] == 'password_rejected']
    assert {row['actor'] for row in rejected} == {'hasan', 'anonymous'}
    encoded = json.dumps(events(app))
    assert password not in encoded and 'PRIVATE' not in encoded and SECRET not in encoded


def test_password_and_totp_success_and_logout_are_audited_without_tokens(system):
    client, app, headers, _ = system
    owner_rows = [row for row in events(app) if row['actor'] == 'hasan']
    assert {row['action'] for row in owner_rows} == {'password_verified', 'mfa_verified'}
    token = headers['hasan']['Authorization'].removeprefix('Bearer ')
    assert client.post('/api/admin/logout', headers=headers['hasan']).status_code == 200
    assert client.get('/api/admin/me', headers=headers['hasan']).status_code == 401
    encoded = json.dumps(events(app))
    assert token not in encoded and SECRET not in encoded and 'primary-test-password' not in encoded
    assert any(row['actor'] == 'hasan' and row['action'] == 'signed_out' for row in events(app))


def test_second_factor_failure_and_lockout_are_sanitized_and_do_not_issue_access(system):
    client, app, _, _ = system
    # A valid current code was already used by the fixture. Its replay must
    # fail even when a correct password obtains a fresh challenge.
    first = client.post('/api/admin/login', json={'username': 'hasan', 'password': 'primary-test-password'})
    with app.state.session_factory() as db:
        primary = app.state.admin_directory.primary
        used_counter = db.get(AdminAuthState, primary.state_id).last_totp_counter
    code = pyotp.TOTP(SECRET).at(used_counter * pyotp.TOTP(SECRET).interval)
    response = client.post('/api/admin/verify', json={
        'challenge_token': first.json()['challenge_token'], 'totp_code': code,
    })
    assert response.status_code == 401 and 'access_token' not in response.json()
    with app.state.session_factory() as db:
        primary = app.state.admin_directory.primary
        state = db.get(AdminAuthState, primary.state_id)
        state.failed_attempts = primary.max_failed_attempts - 1
        db.commit()
    first = client.post('/api/admin/login', json={'username': 'hasan', 'password': 'primary-test-password'})
    now = utc_now()
    adjacent_codes = {pyotp.TOTP(SECRET).at(now + timedelta(seconds=offset)) for offset in (-30, 0, 30)}
    incorrect = next(f'{i:06}' for i in range(4) if f'{i:06}' not in adjacent_codes)
    locked = client.post('/api/admin/verify', json={
        'challenge_token': first.json()['challenge_token'], 'totp_code': incorrect,
    })
    assert locked.status_code == 429 and 'access_token' not in locked.json()
    rows = events(app)
    assert any(row['action'] == 'mfa_rejected' and row['actor'] == 'hasan' for row in rows)
    assert any(row['action'] == 'authentication_locked' and row['details']['stage'] == 'second_factor'
               for row in rows)
    encoded = json.dumps(rows)
    assert first.json()['challenge_token'] not in encoded and code not in encoded and incorrect not in encoded


def test_valid_session_permission_denial_is_audited_without_query_or_body(roles):
    client, app, headers, _ = roles
    response = client.get('/api/privacy?private=PRIVATE', headers=headers['normal_user'])
    assert response.status_code == 403
    rows = [row for row in events(app) if row['action'] == 'authorization_denied']
    assert rows[-1]['actor'] == 'normal_user'
    assert rows[-1]['details'] == {'role': 'normal_user', 'method': 'GET', 'route': '/api/privacy'}
    assert 'PRIVATE' not in json.dumps(rows)
