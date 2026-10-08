"""Code-free registration requires verified enrollment and approved access."""
from datetime import timedelta
import sqlite3
import pyotp
from alba_security.models import utc_now
from alba_security.registration import RegisteredAdmin, RegistrationEnrollment
from alba_security.admin_directory import AdminDirectory
from alba_security.admin_auth import AdminAuth
from tests.alba.test_governance import system, SECRET  # noqa: F401
from tests.test_dashboard import http, app, assert_clean, button, field, response  # noqa: F401

PASSWORD = 'A long private test passphrase 2026'


def enroll(client, name='new-admin'):
    result = client.post('/api/admin/register',json={'username':name,'password':PASSWORD})
    assert result.status_code == 201, result.text
    assert result.headers['cache-control'] == 'no-store'
    return result.json()


def finish(client, enrollment):
    result = client.post('/api/admin/register/verify',json={'enrollment_token':enrollment['enrollment_token'], 'totp_code':pyotp.TOTP(enrollment['totp_secret']).now()})
    assert result.status_code == 200, result.text
    assert result.json()['status'] == 'pending_review'
    assert 'access_token' not in result.json()


def approve(client, headers, name='new-admin'):
    result = client.post('/api/admin/registrations/'+name+'/approve',headers=headers['hasan'],json={'reason':'Identity checked and administrator access authorized','role':'administrator'})
    assert result.status_code == 200, result.text


def login(client, enrollment):
    first = client.post('/api/admin/login',json={'username':'new-admin','password':PASSWORD})
    assert first.status_code == 200, first.text
    second = client.post('/api/admin/verify',json={'challenge_token':first.json()['challenge_token'], 'totp_code':pyotp.TOTP(enrollment['totp_secret']).at(utc_now().timestamp()+30)})
    assert second.status_code == 200, second.text
    return {'Authorization':'Bearer '+second.json()['access_token']}


def test_registration_needs_no_invitation_but_validates_password_and_reserved_names(system):
    client, _, _, _ = system
    assert client.post('/api/admin/register',json={'username':'new-admin','password':'short'}).status_code == 422
    assert client.post('/api/admin/register',json={'username':'hasan','password':PASSWORD}).status_code == 409
    enroll(client)
    assert client.get('/api/admin/invitations').status_code == 404


def test_account_review_controls_require_completed_admin_two_factor(system):
    client, _, _, _ = system
    assert client.get('/api/admin/registrations').status_code == 401
    for action in ('approve','reject'):
        assert client.post('/api/admin/registrations/new-admin/'+action,json={'reason':'Unauthorized attempt to gain access'}).status_code == 401
    first = client.post('/api/admin/login',json={'username':'hasan','password':'primary-test-password'}).json()
    assert client.post('/api/admin/registrations/new-admin/approve',headers={'Authorization':'Bearer '+first['challenge_token']},json={'reason':'Password only approval must fail'}).status_code == 401


def test_pending_enrollment_and_verified_unapproved_account_have_no_access(system):
    client, _, headers, _ = system
    enrollment = enroll(client)
    assert client.get('/api/scans',headers={'Authorization':'Bearer '+enrollment['enrollment_token']}).status_code == 401
    finish(client,enrollment)
    assert client.post('/api/admin/login',json={'username':'new-admin','password':PASSWORD}).status_code == 401
    assert 'new-admin' not in [r['username'] for r in client.get('/api/admin/accounts',headers=headers['hasan']).json()]
    pending = client.get('/api/admin/registrations',headers=headers['hasan']).json()
    assert pending[0]['username'] == 'new-admin'
    assert 'password_hash' not in pending[0] and 'totp_encrypted' not in pending[0]


def test_enrollment_rejects_five_wrong_codes(system):
    client, _, _, _ = system
    enrollment = enroll(client)
    valid = pyotp.TOTP(enrollment['totp_secret']).now()
    wrong = '111111' if valid != '111111' else '222222'
    for _ in range(5):
        assert client.post('/api/admin/register/verify',json={'enrollment_token':enrollment['enrollment_token'],'totp_code':wrong}).status_code == 401
    assert client.post('/api/admin/register/verify',json={'enrollment_token':enrollment['enrollment_token'],'totp_code':valid}).status_code == 401


def test_approval_enables_password_and_two_factor_login_without_self_approval(system):
    client, _, headers, _ = system
    enrollment = enroll(client)
    finish(client,enrollment)
    assert client.post('/api/admin/registrations/new-admin/approve',headers={'Authorization':'Bearer '+enrollment['enrollment_token']},json={'reason':'Attempt to approve own account'}).status_code == 401
    approve(client,headers)
    assert client.post('/api/admin/registrations/new-admin/approve',headers=headers['hasan'],json={'reason':'Duplicate approval attempt'}).status_code == 409
    new_header = login(client,enrollment)
    assert client.get('/api/privacy',headers=new_header).status_code == 200
    assert client.get('/api/admin/accounts',headers=new_header).status_code == 200
    assert client.get('/api/admin/me',headers=new_header).json()['role'] == 'administrator'
    assert client.post('/api/admin/register/verify',json={'enrollment_token':enrollment['enrollment_token'],'totp_code':pyotp.TOTP(enrollment['totp_secret']).now()}).status_code == 401


def test_encrypted_account_survives_directory_restart_without_plaintext_secrets(system):
    client, application, headers, database = system
    enrollment = enroll(client)
    finish(client,enrollment)
    approve(client,headers)
    with application.state.session_factory() as db:
        row = db.get(RegisteredAdmin,'new-admin')
        assert row.password_hash.startswith('$argon2id$')
        restarted = AdminDirectory(AdminAuth('hasan','$argon2id$placeholder',SECRET))
        assert restarted.account(db,'new-admin').totp.secret == enrollment['totp_secret']
    with sqlite3.connect(database) as db:
        dump = '\n'.join(db.iterdump())
    for secret in (PASSWORD,enrollment['totp_secret'],enrollment['enrollment_token']): assert secret not in dump


def test_cancel_expiry_and_rejection_prevent_account_access(system):
    client, application, headers, _ = system
    enrollment = enroll(client)
    assert client.post('/api/admin/register/cancel',json={'enrollment_token':enrollment['enrollment_token']}).status_code == 200
    expired = enroll(client)
    with application.state.session_factory() as db:
        row = db.query(RegistrationEnrollment).one()
        row.expires_at = utc_now()-timedelta(seconds=1)
        db.commit()
    assert client.post('/api/admin/register/verify',json={'enrollment_token':expired['enrollment_token'],'totp_code':pyotp.TOTP(expired['totp_secret']).now()}).status_code == 401
    fresh = enroll(client)
    finish(client,fresh)
    assert client.post('/api/admin/registrations/new-admin/reject',headers=headers['hasan'],json={'reason':'Identity could not be verified for access'}).status_code == 200
    assert client.post('/api/admin/login',json={'username':'new-admin','password':PASSWORD}).status_code == 401


def test_disabling_approved_account_revokes_sessions(system):
    client, _, headers, _ = system
    enrollment = enroll(client)
    finish(client,enrollment)
    approve(client,headers)
    new_header = login(client,enrollment)
    assert client.post('/api/admin/accounts/new-admin/disable',headers=new_header).status_code == 403
    assert client.post('/api/admin/accounts/new-admin/disable',headers=headers['hasan']).status_code == 200
    assert client.get('/api/privacy',headers=new_header).status_code == 401


def test_registration_ui_has_no_invitation_and_checks_password_match(http):
    instance = app()
    next(r for r in instance.radio if r.label == 'Account access').set_value('Register new account').run()
    assert not any(r.label == 'Invitation code' for r in instance.text_input)
    field(instance,'New password').input(PASSWORD)
    field(instance,'Confirm password').input('different passphrase')
    button(instance,'Set up authenticator').click().run()
    assert_clean(instance)
    assert not http[1].called


def test_accounts_requires_access_confirmation_before_approval(http):
    original = http[0].side_effect
    http[0].side_effect = lambda url, **kw: response([{'username':'new-admin','status':'pending_review'}]) if url.endswith('/api/admin/registrations') else original(url,**kw)
    instance = app(True,'Accounts')
    assert_clean(instance)
    assert button(instance,'Approve access').disabled
    next(r for r in instance.checkbox if r.label == 'I verified this person’s identity and authorized their access').check().run()
    assert not button(instance,'Approve access').disabled


def test_registration_ui_finishes_with_approval_pending_and_no_session(http):
    http[1].return_value = response({'enrollment_token':'temporary-enrollment-token-123456','expires_at':(utc_now()+timedelta(minutes=15)).isoformat(),'totp_secret':SECRET,'provisioning_uri':pyotp.TOTP(SECRET).provisioning_uri('demo', issuer_name='ExtSecure')},201)
    instance = app()
    next(r for r in instance.radio if r.label == 'Account access').set_value('Register new account').run()
    for label,value in [('New username','new-admin'),('New password',PASSWORD),('Confirm password',PASSWORD)]: field(instance,label).input(value)
    button(instance,'Set up authenticator').click().run()
    assert_clean(instance)
    assert 'invitation_token' not in http[1].call_args.kwargs['json']
    http[1].return_value = response({'registered':True,'status':'pending_review','username':'new-admin'})
    field(instance,'Registration verification code').input('123456')
    button(instance,'Verify and create account').click().run()
    assert_clean(instance)
    assert 'admin_session_token' not in instance.session_state
    assert any('administrator must approve' in r.value for r in instance.success)
