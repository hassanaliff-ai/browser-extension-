"""Execute each role's actual Streamlit navigation and approval controls."""
import pytest

from alba_security.permissions import profile
from tests.test_dashboard import http, app, button, assert_clean, response  # noqa: F401

def role_http(http, role):
    original = http[0].side_effect
    http[0].side_effect = lambda url, **kw: response(profile(role,role)) if url.endswith('/api/admin/me') else original(url,**kw)

@pytest.mark.parametrize('role', ['head_administrator','administrator','manager','normal_user'])
def test_navigation_matches_backend_profile(http,role):
    role_http(http,role)
    instance=app(True)
    assert_clean(instance)
    workspace=instance.sidebar.radio[0]
    assert set(workspace.options) == set(profile(role,role)['views'])
    assert ('Accounts' in workspace.options) == (role in {'head_administrator','administrator','manager'})

def test_normal_user_cannot_restore_a_forbidden_workspace(http):
    role_http(http,'normal_user')
    instance=app(True,'Accounts')
    assert_clean(instance)
    assert instance.sidebar.radio[0].value != 'Accounts'
    assert not any('/api/admin/accounts' in call.args[0] for call in http[0].call_args_list)

def test_normal_file_check_hides_device_impersonation_controls(http):
    role_http(http,'normal_user')
    instance=app(True,'Downloaded-file checks')
    assert_clean(instance)
    assert not any(r.label in ('Device reference','Device name') for r in instance.text_input)
    assert button(instance,'Check file reputation')

def test_manager_reports_offer_analysis_but_no_generation_or_delivery(http):
    role_http(http,'manager')
    instance=app(True,'Reports')
    assert_clean(instance)
    assert not any(r.label in ('Generate LLM draft','Send report to administrators') for r in instance.button)
    assert any('Manager access' in r.value for r in instance.caption)
    assert not http[1].called

def test_owner_approves_explicit_role_and_records_reason(http):
    original=http[0].side_effect
    http[0].side_effect=lambda url, **kw: response([{'username':'new-manager','status':'pending_review'}]) if url.endswith('/api/admin/registrations') else original(url,**kw)
    http[1].return_value=response({'username':'new-manager','role':'manager','status':'active'})
    instance=app(True,'Accounts')
    assert_clean(instance)
    assert button(instance,'Approve access').disabled
    next(r for r in instance.checkbox if 'verified this person' in r.label).check().run()
    next(r for r in instance.selectbox if r.label == 'Approved role').select('manager')
    next(r for r in instance.text_area if r.label == 'Account review reason').input('Owner verified the manager and their monitoring duties')
    button(instance,'Approve access').click().run()
    assert_clean(instance)
    request=http[1].call_args
    assert request.args[0].endswith('/api/admin/registrations/new-manager/approve')
    assert request.kwargs['json']['role'] == 'manager'
    assert request.kwargs['headers'] == {'Authorization':'Bearer verified-admin-token'}
