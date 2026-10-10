"""Exercise real password/TOTP sessions, owner approval and route permissions."""
from datetime import timedelta
import re

import pyotp
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, select

from alba_security.admin_auth import AdminAuth, AdminSession, _digest
from alba_security.admin_directory import AdminDirectory
from alba_security.api import create_app
from alba_security.governance import GovernanceAudit
from alba_security.models import PersonalScan, utc_now
from alba_security.permissions import READ_ROUTES, ADMIN_WRITES, OWNER_ROUTES, allowed
from alba_security.registration import RegisteredAdmin
from alba_security.schema import ensure_schema
from tests.alba.test_governance import system, scan, SECRET, REVIEWER_SECRET  # noqa: F401

PASSWORD = 'Private role fixture password 2026'

@pytest.fixture
def roles(system):
    client, app, headers, database = system
    hasher = PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1)
    directory = AdminDirectory(AdminAuth('hasan', hasher.hash('primary-test-password'), SECRET))
    result = {'head_administrator': headers['hasan']}
    for role in ('administrator', 'manager', 'normal_user'):
        secret = pyotp.random_base32()
        with app.state.session_factory() as db:
            db.add(RegisteredAdmin(username=role, password_hash=hasher.hash(PASSWORD),
                totp_encrypted=directory.cipher().encrypt(secret.encode()).decode(), status='pending_review'))
            db.commit()
        approved = client.post(f'/api/admin/registrations/{role}/approve', headers=headers['hasan'],
            json={'role':role, 'reason':'Owner verified identity and the assigned responsibilities'})
        assert approved.status_code == 200, approved.text
        first = client.post('/api/admin/login', json={'username':role,'password':PASSWORD})
        assert first.status_code == 200, first.text
        second = client.post('/api/admin/verify', json={'challenge_token':first.json()['challenge_token'],
            'totp_code':pyotp.TOTP(secret).now()})
        assert second.status_code == 200, second.text
        result[role] = {'Authorization':'Bearer '+second.json()['access_token']}
    return client, app, result, database

def concrete(route):
    return re.sub(r'\{[^}]+\}', 'missing-reference', route)

def test_all_roles_have_distinct_server_owned_profiles(roles):
    client, _, headers, _ = roles
    for role, header in headers.items():
        response = client.get('/api/admin/me', headers=header)
        assert response.status_code == 200
        data = response.json()
        assert data['role'] == role
        assert ('Accounts' in data['views']) == (role in {'head_administrator','administrator','manager'})
        assert data['can_manage_reports'] == (role in {'head_administrator','administrator'})
    assert client.get('/api/admin/me',headers=headers['head_administrator']).json()['display_name'] == 'Head of Administrator'


def test_sensitive_api_responses_and_errors_are_not_cacheable(roles):
    client, _, headers, _ = roles
    owner = headers['head_administrator']
    for path in ('/api/overview', '/api/scans', '/api/events', '/api/cases',
                 '/api/privacy', '/api/reports/monthly', '/api/alerts'):
        response = client.get(path, headers=owner)
        assert response.status_code == 200
        assert response.headers.get('cache-control') == 'no-store', path
    for response in (
        client.get('/api/overview'),
        client.get('/api/privacy', headers=headers['normal_user']),
        client.get('/api/cases/missing', headers=owner),
        client.post('/api/cases', headers=owner, json={}),
    ):
        assert response.status_code in (401, 403, 404, 422)
        assert response.headers.get('cache-control') == 'no-store'


def test_mounted_monitoring_api_keeps_privacy_cache_headers(roles):
    from fastapi import FastAPI
    client, app, headers, _ = roles
    parent = FastAPI()
    parent.mount('/monitor', app)
    with TestClient(parent) as mounted:
        for path in ('/api/overview', '/api/privacy', '/api/cases', '/api/admin/me',
                     '/api/access/requests'):
            response = mounted.get('/monitor' + path, headers=headers['head_administrator'])
            assert response.status_code == 200
            assert response.headers.get('cache-control') == 'no-store', path


def test_monthly_report_json_requires_integer_calendar_values(roles):
    client, _, headers, _ = roles
    owner = headers['head_administrator']
    for month in (True, False, '1', 1.0, None, 0, 13):
        response = client.post('/api/reports/monthly/generate', headers=owner,
            json={'year': 2020, 'month': month})
        assert response.status_code == 422, (month, response.text)
    for year in ('2020', 2020.0, True):
        response = client.post('/api/reports/monthly/generate', headers=owner,
            json={'year': year, 'month': 1})
        assert response.status_code == 422, (year, response.text)


def test_account_reviews_need_a_reason_after_trimming(roles):
    client, _, headers, _ = roles
    owner = headers['head_administrator']
    for path in ('/api/admin/registrations/missing/approve',
                 '/api/admin/registrations/missing/reject',
                 '/api/admin/accounts/normal_user/role'):
        response = client.post(path, headers=owner,
            json={'role': 'normal_user', 'reason': '       x'})
        assert response.status_code == 422, (path, response.text)
    assert client.get('/api/admin/me', headers=headers['normal_user']).status_code == 200



def test_read_permissions_apply_to_every_protected_data_route(roles):
    client, _, headers, _ = roles
    for role, header in headers.items():
        for route in READ_ROUTES | {'/api/admin/accounts', '/api/admin/registrations'}:
            response = client.get(concrete(route), headers=header)
            permitted = allowed(role, 'GET', route)
            assert (response.status_code != 403) == permitted, (role,route,response.text)
            assert response.status_code != 401
    # Unknown or newly added endpoints cannot acquire privileges by a prefix.
    assert not allowed('administrator','POST','/api/admin/new-powerful-feature')
    assert not allowed('invented-role','GET','/api/overview')

def test_only_owner_can_approve_reject_change_roles_or_disable(roles):
    client, _, headers, _ = roles
    for role in ('administrator','manager','normal_user'):
        for method, route in OWNER_ROUTES:
            result = client.request(method, concrete(route), headers=headers[role],
                json={'reason':'Attempted privilege escalation','role':'administrator'} if method == 'POST' else None)
            assert result.status_code == 403, (role,route,result.text)

def test_manager_and_normal_user_cannot_change_security_configuration(roles):
    client, _, headers, _ = roles
    for role in ('manager','normal_user'):
        for route in ADMIN_WRITES:
            if allowed(role,'POST',route): continue
            result = client.post(concrete(route), headers=headers[role], json={})
            assert result.status_code == 403, (role,route,result.text)


def test_manager_cannot_fetch_hidden_governance_or_exception_data(roles):
    client, _, headers, _ = roles
    for path in ('/api/overrides','/api/overrides/audit','/api/privacy',
                 '/api/privacy/retention-preview','/api/evaluations','/api/usability','/api/governance/audit'):
        assert client.get(path,headers=headers['manager']).status_code == 403
    assert client.get('/api/reports/monthly',headers=headers['manager']).status_code == 200

def test_administrator_can_use_security_workflows_but_not_account_management(roles):
    client, _, headers, _ = roles
    for route in ADMIN_WRITES:
        result = client.post(concrete(route), headers=headers['administrator'], json={})
        assert result.status_code not in (401,403), (route,result.text)

def test_owner_account_cannot_be_disabled_demoted_or_duplicated(roles):
    client, _, headers, _ = roles
    owner = headers['head_administrator']
    assert client.post('/api/admin/accounts/hasan/disable',headers=owner).status_code == 409
    assert client.post('/api/admin/accounts/hasan/role',headers=owner,
        json={'reason':'Try to demote the only owner','role':'normal_user'}).status_code == 409
    assert client.post('/api/admin/accounts/administrator/role',headers=owner,
        json={'reason':'Try to add another owner account','role':'head_administrator'}).status_code == 422
    assert client.post('/api/admin/register',json={'username':'hasan','password':PASSWORD}).status_code == 409
    assert client.post('/api/admin/register',json={'username':'attacker','password':PASSWORD,'role':'head_administrator'}).status_code == 422

def test_role_change_revokes_sessions_and_is_audited(roles):
    client, app, headers, _ = roles
    result = client.post('/api/admin/accounts/administrator/role',headers=headers['head_administrator'],
        json={'role':'normal_user','reason':'Responsibilities reduced after owner review'})
    assert result.status_code == 200 and result.json()['sessions_revoked']
    assert client.get('/api/overview',headers=headers['administrator']).status_code == 401
    with app.state.session_factory() as db:
        row = db.get(RegisteredAdmin,'administrator')
        assert row.role == 'normal_user' and row.approved_by == 'hasan'
        audit = db.scalar(select(GovernanceAudit).where(GovernanceAudit.action == 'account_role_changed'))
        assert audit.actor == 'hasan' and audit.details['previous_role'] == 'administrator'

def test_disabled_account_loses_access_and_cannot_sign_in(roles):
    client, _, headers, _ = roles
    assert client.post('/api/admin/accounts/manager/disable',headers=headers['head_administrator']).status_code == 200
    assert client.get('/api/admin/me',headers=headers['manager']).status_code == 401
    assert client.post('/api/admin/login',json={'username':'manager','password':PASSWORD}).status_code == 401

def test_normal_file_checks_are_personal_and_cannot_spoof_devices(roles):
    client, app, headers, _ = roles
    payload = {'sha256':'a'*64,'device_id':'someone-elses-device','device_name':'Forged device',
        'extension_key':'forged-extension','extension_name':'Forged extension'}
    own = client.post('/api/admin/downloads/scan',headers=headers['normal_user'],json=payload)
    assert own.status_code == 201, own.text
    own_id = own.json()['id']
    admin_scan = client.post('/api/admin/downloads/scan',headers=headers['administrator'],json=payload)
    assert admin_scan.status_code == 201
    detail = client.get('/api/my/scans/'+own_id,headers=headers['normal_user']).json()
    assert detail['device_id'].startswith('user-')
    assert detail['extension_id'] is None
    history = client.get('/api/my/scans',headers=headers['normal_user']).json()
    assert [row['id'] for row in history] == [own_id]
    assert client.get('/api/my/scans/'+own_id,headers=headers['normal_user']).status_code == 200
    for header, other_id in [(headers['normal_user'],admin_scan.json()['id']), (headers['administrator'],own_id)]:
        assert client.get('/api/my/scans/'+other_id,headers=header).status_code == 404
    assert client.get('/api/scans/'+own_id,headers=headers['normal_user']).status_code == 403
    with app.state.session_factory() as db:
        assert db.get(PersonalScan,own_id).username == 'normal_user'

def test_normal_uploaded_files_use_the_same_personal_boundary(roles):
    client, _, headers, _ = roles
    result = client.post('/api/admin/downloads/scan-file',headers=headers['normal_user'],
        data={'device_id':'spoofed','device_name':'Spoofed'},files={'file':('private.txt',b'private file bytes')})
    assert result.status_code == 201, result.text
    detail = client.get('/api/my/scans/'+result.json()['id'],headers=headers['normal_user'])
    assert detail.status_code == 200
    assert detail.json()['device_id'].startswith('user-')

def test_manager_investigates_cases_but_normal_users_cannot_be_assigned(roles):
    client, _, headers, _ = roles
    evidence = scan(client)
    payload = {'scan_id':evidence['id'],'title':'Manager reviews a security threat','assignee':'manager'}
    created = client.post('/api/cases',headers=headers['manager'],json=payload)
    assert created.status_code == 201, created.text
    assert client.post('/api/cases/'+created.json()['id']+'/notes',headers=headers['manager'],
        json={'body':'Reviewing the evidence and coordinating remediation.'}).status_code == 201
    assert client.post('/api/cases',headers=headers['manager'],json={**payload,'assignee':'normal_user'}).status_code == 422
    assert 'normal_user' not in [r['username'] for r in client.get('/api/case-assignees',headers=headers['manager']).json()]

def test_status_and_approval_are_rechecked_even_with_an_existing_session(roles):
    client, app, headers, _ = roles
    with app.state.session_factory() as db:
        row = db.get(RegisteredAdmin,'manager')
        row.approved_by = 'missing-supervisor'  # The approval chain must reach an active higher role.
        db.commit()
    assert client.get('/api/admin/me',headers=headers['manager']).status_code == 401

def test_configured_reviewer_also_waits_for_owner_approval(tmp_path):
    hasher = PasswordHasher(time_cost=1,memory_cost=1024,parallelism=1)
    primary = AdminAuth('head-of-administrator',hasher.hash(PASSWORD),SECRET)
    reviewer = AdminAuth('reviewer',hasher.hash(PASSWORD),REVIEWER_SECRET)
    app = create_app(database_url=f'sqlite:///{(tmp_path/"configured.db").as_posix()}',
        ingest_token='test-machine-token',admin_auth=primary,additional_admins=[reviewer])
    with TestClient(app) as client:
        assert client.post('/api/admin/login',json={'username':'reviewer','password':PASSWORD}).status_code == 401
        with app.state.session_factory() as db:
            assert db.get(RegisteredAdmin,'reviewer').status == 'pending_review'
        first = client.post('/api/admin/login',json={'username':primary.username,'password':PASSWORD}).json()
        second = client.post('/api/admin/verify',json={'challenge_token':first['challenge_token'],'totp_code':primary.totp.now()}).json()
        owner = {'Authorization':'Bearer '+second['access_token']}
        assert client.post('/api/admin/registrations/reviewer/approve',headers=owner,
            json={'role':'administrator','reason':'Owner authorizes an independent policy reviewer'}).status_code == 200
        assert client.post('/api/admin/login',json={'username':'reviewer','password':PASSWORD}).status_code == 200
    app.state.engine.dispose()

def test_legacy_accounts_require_fresh_owner_approval_and_migration_is_repeatable(tmp_path):
    engine=create_engine(f'sqlite:///{(tmp_path/"legacy.db").as_posix()}')
    with engine.begin() as db:
        db.exec_driver_sql('CREATE TABLE registered_administrators (username VARCHAR(120) PRIMARY KEY, password_hash TEXT, totp_encrypted TEXT, status VARCHAR(20), created_at TIMESTAMP)')
        db.exec_driver_sql("INSERT INTO registered_administrators VALUES ('legacy','hash','ciphertext','active','2026-01-01')")
    ensure_schema(engine)
    ensure_schema(engine)
    assert {'role','approved_by','approved_at'} <= {c['name'] for c in inspect(engine).get_columns('registered_administrators')}
    with engine.connect() as db:
        row=db.exec_driver_sql('SELECT status, role, approved_by, password_hash FROM registered_administrators').one()
        assert tuple(row) == ('pending_review','normal_user',None,'hash')
    engine.dispose()
