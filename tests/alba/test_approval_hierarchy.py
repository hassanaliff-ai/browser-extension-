"""Exercise hierarchical approvals with authenticated sessions and durable grants."""
from sqlalchemy import select
from alba_security.permissions import can_approve_role
from alba_security.registration import RegisteredAdmin
from alba_security.governance import GovernanceAudit
from tests.alba.test_roles import roles, PASSWORD  # noqa: F401
from tests.alba.test_governance import system  # noqa: F401
from tests.alba.test_website_access import create, review


def test_website_approval_role_matrix_and_queue_flags(roles):
    client, _, headers, _ = roles
    for requester in headers:
        for reviewer in headers:
            request = create(client, headers[requester], f'https://example.com/{requester}/{reviewer}')
            queue = client.get('/api/access/requests', headers=headers[reviewer]).json()
            visible = next((r for r in queue if r['id'] == request['id']), None)
            allowed = can_approve_role(reviewer, requester, own=reviewer == requester)
            if visible:
                assert visible['can_review'] == allowed
                assert visible['requester_role'] == requester
            assert review(client, headers[reviewer], request).status_code == (200 if allowed else 403)


def test_head_self_approval_rejection_whitelist_and_audit(roles):
    client, app, h, _ = roles
    head = h['head_administrator']
    for decision in ('once', 'whitelist', 'reject'):
        target = f'https://example.com/self/{decision}'
        request = create(client, head, target)
        assert review(client, head, request, decision).status_code == 200
        result = client.post('/api/access/consume', headers=head, json={'target': target})
        assert result.status_code == (403 if decision == 'reject' else 200)
        if decision == 'once':
            assert client.post('/api/access/consume', headers=head, json={'target': target}).status_code == 403
        assert review(client, head, request, decision).status_code == 409
    with app.state.session_factory() as db:
        events = list(db.scalars(select(GovernanceAudit).where(GovernanceAudit.action.in_(['approved','rejected']))))
        assert len(events) == 3
        assert all(e.details['self_review'] is True for e in events)


def test_registration_hierarchy_and_forged_role_escalation(roles):
    client, app, h, _ = roles
    from argon2 import PasswordHasher
    from alba_security.admin_directory import AdminDirectory
    from alba_security.admin_auth import AdminAuth
    from tests.alba.test_governance import SECRET
    directory = AdminDirectory(AdminAuth('hasan', '$argon2id$placeholder', SECRET))
    import pyotp
    for reviewer, requested_role, allowed in [
        ('manager','normal_user',True), ('administrator','manager',True),
        ('head_administrator','administrator',True), ('manager','manager',False),
        ('manager','administrator',False), ('administrator','administrator',False),
        ('normal_user','normal_user',False)]:
        name = f'pending-{reviewer}-{requested_role}'
        with app.state.session_factory() as db:
            db.add(RegisteredAdmin(username=name, password_hash=PasswordHasher().hash(PASSWORD),
                totp_encrypted=directory.cipher().encrypt(pyotp.random_base32().encode()).decode(),
                status='pending_review', role=requested_role))
            db.commit()
        response = client.post(f'/api/admin/registrations/{name}/approve', headers=h[reviewer],
            json={'role':requested_role,'reason':'Verified identity and approved project responsibilities'})
        assert response.status_code == (200 if allowed else 403)
        if allowed:
            with app.state.session_factory() as db:
                assert directory.role(db,name) == requested_role
                assert directory.account(db,name) is not None
    # A manager cannot turn a normal-user application into an administrator.
    enrollment = client.post('/api/admin/register', json={'username':'forged-role','password':PASSWORD}).json()
    client.post('/api/admin/register/verify', json={'enrollment_token':enrollment['enrollment_token'],
        'totp_code':pyotp.TOTP(enrollment['totp_secret']).now()})
    assert client.post('/api/admin/registrations/forged-role/approve', headers=h['manager'],
        json={'role':'administrator','reason':'Attempt to assign broader access without authority'}).status_code == 403
    assert client.post('/api/admin/registrations/forged-role/reject', headers=h['manager'],
        json={'role':'normal_user','reason':'Identity could not be confirmed for this application'}).status_code == 200


def test_broken_or_cyclic_approval_chains_fail_closed(roles):
    _, app, _, _ = roles
    from alba_security.admin_directory import AdminDirectory
    from alba_security.admin_auth import AdminAuth
    from tests.alba.test_governance import SECRET
    directory = AdminDirectory(AdminAuth('hasan', '$argon2id$placeholder', SECRET))
    with app.state.session_factory() as db:
        user = db.get(RegisteredAdmin, 'normal_user')
        manager = db.get(RegisteredAdmin, 'manager')
        user.approved_by = 'manager'
        manager.approved_by = 'administrator'
        db.commit()
        assert directory.role(db,'normal_user') == 'normal_user'
        admin = db.get(RegisteredAdmin, 'administrator')
        admin.status = 'disabled'
        db.commit()
        assert directory.role(db,'normal_user') is None
        admin.status = 'active'
        admin.approved_by = 'normal_user'
        db.commit()
        assert directory.role(db,'manager') is None


def test_requested_role_routes_registration_to_higher_reviewer(roles):
    client, app, h, _ = roles
    import pyotp
    enrollment = client.post('/api/admin/register', json={'username':'requested-manager','password':PASSWORD}).json()
    result = client.post('/api/admin/register/verify', json={'enrollment_token':enrollment['enrollment_token'],
        'totp_code':pyotp.TOTP(enrollment['totp_secret']).now(), 'role':'manager'})
    assert result.status_code == 200
    assert client.post('/api/admin/login', json={'username':'requested-manager','password':PASSWORD}).status_code == 401
    for reviewer, visible in [('manager',False),('administrator',True),('head_administrator',True)]:
        rows = client.get('/api/admin/registrations', headers=h[reviewer]).json()
        assert ('requested-manager' in [r['username'] for r in rows]) == visible
    response = client.post('/api/admin/registrations/requested-manager/approve', headers=h['administrator'],
        json={'role':'manager','reason':'Identity checked and manager responsibilities confirmed'})
    assert response.status_code == 200
    assert client.post('/api/admin/login', json={'username':'requested-manager','password':PASSWORD}).status_code == 200
