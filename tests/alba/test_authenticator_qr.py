"""Decode real QR images and exercise enrollment UI without production secrets."""
from datetime import timedelta
from io import BytesIO
from pathlib import Path
import re

from dotenv import dotenv_values
from PIL import Image
import pyotp
import pytest
import zxingcpp
from streamlit.testing.v1 import AppTest

from alba_security.authenticator_qr import authenticator_qr_png
from alba_security.models import utc_now
from alba_security.provision_head import export_existing_qr, provision
from tests.alba.test_governance import SECRET, system  # noqa: F401
from tests.alba.test_registration import enroll
from tests.test_dashboard import DASHBOARD, http, assert_clean, button, response  # noqa: F401


def decode(png):
    result = zxingcpp.read_barcode(Image.open(BytesIO(png)))
    assert result is not None
    return result.text


@pytest.mark.parametrize('username', ['hasan', 'head-of-administrator', 'test.account-2026'])
def test_scannable_qr_and_manual_setup_produce_identical_codes(username):
    uri = pyotp.TOTP(SECRET).provisioning_uri(username, issuer_name='ExtSecure')
    decoded = decode(authenticator_qr_png(uri, secret=SECRET))
    assert decoded == uri
    scanned = pyotp.parse_uri(decoded)
    assert scanned.name == username and scanned.issuer == 'ExtSecure'
    for moment in (0, 30, 1791072030):
        assert scanned.at(moment) == pyotp.TOTP(SECRET).at(moment)


@pytest.mark.parametrize('uri', [
    'https://example.com/?secret='+SECRET,
    'otpauth://totp/ExtSecure:test?issuer=ExtSecure',
    pyotp.HOTP(SECRET).provisioning_uri('test', initial_count=0, issuer_name='ExtSecure'),
    pyotp.TOTP(SECRET).provisioning_uri('test', issuer_name='Other service'),
    pyotp.TOTP(SECRET, digits=8).provisioning_uri('test', issuer_name='ExtSecure'),
    pyotp.TOTP(SECRET, interval=60).provisioning_uri('test', issuer_name='ExtSecure'),
])
def test_invalid_enrollment_is_rejected_without_leaking_details(uri):
    with pytest.raises(ValueError) as failure:
        authenticator_qr_png(uri)
    assert SECRET not in str(failure.value)
    assert uri not in str(failure.value)


def test_mismatched_manual_key_is_not_shown_as_valid_qr():
    uri = pyotp.TOTP(SECRET).provisioning_uri('test', issuer_name='ExtSecure')
    with pytest.raises(ValueError, match='Restart enrollment'):
        authenticator_qr_png(uri, secret=pyotp.random_base32())


def enrollment_app(expires=None, uri=None):
    instance = AppTest.from_file(str(DASHBOARD), default_timeout=20)
    instance.session_state['account_access'] = 'Register new account'
    instance.session_state['registration_enrollment'] = {
        'enrollment_token':'synthetic-private-enrollment-token',
        'expires_at':expires or (utc_now()+timedelta(minutes=15)).isoformat(),
        'totp_secret':SECRET,
        'provisioning_uri':uri or pyotp.TOTP(SECRET).provisioning_uri('test', issuer_name='ExtSecure'),
    }
    return instance.run()


def test_registration_displays_qr_and_collapsed_manual_fallback(http):
    instance = enrollment_app()
    assert_clean(instance)
    assert len(instance.get('image')) == 1
    assert 'setup key manually' in instance.expander[0].label
    assert not instance.expander[0].proto.expanded
    assert instance.code[0].value == SECRET
    assert not instance.text_area  # Raw enrollment URI is not displayed.
    assert 'admin_session_token' not in instance.session_state
    assert not http[0].called and not http[1].called


def test_expired_enrollment_clears_sensitive_setup_before_rendering(http):
    instance = enrollment_app(expires=(utc_now()-timedelta(seconds=1)).isoformat())
    assert_clean(instance)
    assert not instance.get('image') and not instance.code
    assert 'registration_enrollment' not in instance.session_state
    assert any('expired' in item.value for item in instance.warning)


def test_cancel_enrollment_removes_qr_and_manual_key(http):
    http[1].return_value = response({'cancelled':True})
    instance = enrollment_app()
    button(instance, 'Cancel enrollment').click().run()
    assert_clean(instance)
    assert not instance.get('image') and not instance.code
    assert 'registration_enrollment' not in instance.session_state
    assert http[1].call_args.kwargs['json']['enrollment_token'] == 'synthetic-private-enrollment-token'


def test_invalid_setup_clears_seed_without_creating_account(http):
    instance = enrollment_app(uri='https://example.com/'+SECRET)
    assert_clean(instance)
    assert not instance.get('image') and not instance.code
    assert 'registration_enrollment' not in instance.session_state
    assert SECRET not in instance.error[0].value
    assert not http[1].called


def test_backend_accepts_code_from_decoded_qr_but_still_requires_owner_approval(system):
    client, _, _, _ = system
    enrollment = enroll(client)
    decoded = pyotp.parse_uri(decode(authenticator_qr_png(enrollment['provisioning_uri'], secret=enrollment['totp_secret'])))
    assert decoded.secret == enrollment['totp_secret']
    result = client.post('/api/admin/register/verify', json={
        'enrollment_token':enrollment['enrollment_token'], 'totp_code':decoded.now(),
    })
    assert result.status_code == 200 and result.json()['status'] == 'pending_review'
    assert 'access_token' not in result.json()
    assert client.post('/api/admin/login', json={'username':'new-admin','password':'A long private test passphrase 2026'}).status_code == 401


def test_existing_owner_qr_export_preserves_all_credentials_and_is_offline(tmp_path):
    env = tmp_path/'.env'
    original = f'ADMIN_USERNAME=head-of-administrator\nADMIN_PASSWORD_HASH=existing-hash\nADMIN_TOTP_SECRET={SECRET}\nVT_API_KEY=synthetic-service-key\n'
    env.write_text(original, encoding='utf-8')
    files = export_existing_qr(env)
    assert env.read_text(encoding='utf-8') == original
    assert not (tmp_path/'.private'/'Head of Administrator Setup.txt').exists()
    page = Path(files['qr_setup_page']).read_text(encoding='utf-8')
    assert 'data:image/png;base64,' in page and '<details>' in page
    assert not re.search(r'(src|href)=["\']https?://', page)
    assert '<script' not in page and 'existing-hash' not in page
    scanned = pyotp.parse_uri(decode(Path(files['qr_file']).read_bytes()))
    assert scanned.secret == SECRET and scanned.name == 'head-of-administrator'


def test_fresh_owner_provision_includes_working_private_qr(tmp_path):
    env = tmp_path/'.env'
    env.write_text('VT_API_KEY=synthetic-service-key\n', encoding='utf-8')
    files = provision(env)
    values = dotenv_values(env)
    scanned = pyotp.parse_uri(decode(Path(files['qr_file']).read_bytes()))
    assert scanned.secret == values['ADMIN_TOTP_SECRET']
    assert scanned.name == values['ADMIN_USERNAME']
    assert 'Password:' not in Path(files['qr_setup_page']).read_text(encoding='utf-8')
