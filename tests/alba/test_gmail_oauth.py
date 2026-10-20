"""Isolated Google sign-in tests: no browser, live secrets or real mail."""
import base64
import json
from email import message_from_bytes
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.fernet import Fernet
from alba_security import gmail_oauth as gmail
from alba_security.notifications import NotificationSettings, send_high_severity_alert, send_monthly_report


@pytest.fixture
def grant(tmp_path, monkeypatch):
    monkeypatch.setenv('ADMIN_ACCOUNT_ENCRYPTION_KEY', Fernet.generate_key().decode())
    path = tmp_path / 'private' / 'authorization.enc'
    monkeypatch.setattr(gmail, 'TOKEN_PATH', path)
    data = dict(client_id='test.apps.googleusercontent.com', client_secret='fixture-client-secret',
                refresh_token='fixture-refresh-token', sender='sender@example.com', recipient='admin@example.com')
    gmail.save_authorization(data)
    return path, data


def test_private_grant_is_encrypted_and_roundtrips(grant):
    path, data = grant
    assert gmail.load_authorization() == data
    assert b'fixture-refresh-token' not in path.read_bytes()
    assert b'admin@example.com' not in path.read_bytes()


def test_wrong_key_cannot_read_private_grant(grant, monkeypatch):
    monkeypatch.setenv('ADMIN_ACCOUNT_ENCRYPTION_KEY', Fernet.generate_key().decode())
    with pytest.raises(gmail.GmailAuthorizationError, match='not authorized'):
        gmail.load_authorization()


def test_encryption_key_required_before_saving(tmp_path, monkeypatch):
    monkeypatch.delenv('ADMIN_ACCOUNT_ENCRYPTION_KEY', raising=False)
    monkeypatch.delenv('ADMIN_TOTP_SECRET', raising=False)
    with pytest.raises(gmail.GmailAuthorizationError):
        gmail.save_authorization({}, tmp_path / 'grant')
    assert not (tmp_path / 'grant').exists()


def test_client_requires_desktop_app(tmp_path):
    path = tmp_path / 'client.json'
    path.write_text(json.dumps({'web': {'client_id': 'test.apps.googleusercontent.com', 'client_secret': 'x'}}))
    with pytest.raises(gmail.GmailAuthorizationError):
        gmail.load_client(path)


def test_imported_endpoints_are_never_trusted(tmp_path):
    path = tmp_path / 'client.json'
    path.write_text(json.dumps({'installed': {'client_id': 'test.apps.googleusercontent.com',
        'client_secret': 'x', 'token_uri': 'https://attacker.invalid'}}))
    assert set(gmail.load_client(path)) == {'client_id', 'client_secret'}


def test_authorization_uses_send_only_scope_and_pkce():
    params = gmail.authorization_parameters('client', 'http://127.0.0.1:123/callback', 'state', 'a' * 64)
    assert params['code_challenge_method'] == 'S256'
    assert params['code_challenge'] != 'a' * 64
    assert params['access_type'] == 'offline'
    assert params['scope'].split() == ['openid', 'email', 'https://www.googleapis.com/auth/gmail.send']
    assert 'code_verifier' not in params


@pytest.mark.parametrize('path', ['/other?state=ok&code=x', '/callback?state=wrong&code=x',
    '/callback?state=ok&state=ok&code=x', '/callback?state=ok&code=a&code=b',
    '/callback?state=ok&error=access_denied', '/callback?code=x'])
def test_invalid_callback_rejected(path):
    with pytest.raises(gmail.GmailAuthorizationError):
        gmail.validate_callback(path, 'ok')


def test_valid_callback():
    assert gmail.validate_callback('/callback?state=ok&code=one', 'ok') == 'one'


def mock_transport(monkeypatch):
    factory = MagicMock()
    client = factory.return_value.__enter__.return_value
    monkeypatch.setattr(gmail.httpx, 'Client', factory)
    refresh = MagicMock(status_code=200)
    refresh.json.return_value = {'access_token': 'fixture-access'}
    sent = MagicMock(status_code=200)
    sent.json.return_value = {'id': 'google-message'}
    client.post.side_effect = [refresh, sent, sent]
    return factory, client


def test_delivery_refreshes_and_sends_separate_private_messages(grant, monkeypatch):
    factory, client = mock_transport(monkeypatch)
    gmail.deliver(('one@example.com', 'two@example.com'), 'ExtSecure alert', 'Scan id: test')
    factory.assert_called_once_with(timeout=10, follow_redirects=False)
    assert client.post.call_args_list[0].args[0] == gmail.TOKEN_URL
    for call, expected in zip(client.post.call_args_list[1:], ['one@example.com', 'two@example.com']):
        assert call.args[0] == gmail.SEND_URL
        message = message_from_bytes(base64.urlsafe_b64decode(call.kwargs['json']['raw']))
        assert message['To'] == expected
        assert message['From'] == 'ExtSecure <sender@example.com>'
        assert message['Bcc'] is None


def test_revoked_token_never_sends_or_falls_back(grant, monkeypatch):
    _, client = mock_transport(monkeypatch)
    client.post.side_effect = None
    client.post.return_value.status_code = 400
    with pytest.raises(gmail.GmailAuthorizationError, match='revoked'):
        gmail.deliver(('admin@example.com',), 'Subject', 'Body')
    assert client.post.call_count == 1


def test_send_failure_not_retried(grant, monkeypatch):
    _, client = mock_transport(monkeypatch)
    refresh = MagicMock(status_code=200)
    refresh.json.return_value = {'access_token': 'fixture'}
    client.post.side_effect = [refresh, TimeoutError('private timeout')]
    with pytest.raises(TimeoutError):
        gmail.deliver(('admin@example.com',), 'Subject', 'Body')
    assert client.post.call_count == 2


def test_alerts_and_reports_use_google_without_smtp(monkeypatch):
    sender = MagicMock()
    settings = NotificationSettings(email_provider='gmail_oauth', admin_emails=('admin@example.com',))
    result = send_high_severity_alert(alert_id='alert', scan_id='scan', severity='Critical', message='private URL', settings=settings, email_sender=sender)
    assert result[0]['status'] == 'sent'
    assert 'private URL' not in sender.call_args.args[2]
    result = send_monthly_report({'subject': 'Report', 'body': 'Totals'}, settings=settings, email_sender=sender)
    assert result[0]['status'] == 'sent'


def test_environment_google_provider_loads_authorized_recipient(grant, monkeypatch):
    monkeypatch.setenv('EMAIL_PROVIDER', 'gmail_oauth')
    monkeypatch.setenv('ADMIN_EMAILS', 'different@example.com')
    assert NotificationSettings.from_env().admin_emails == ('admin@example.com',)


def test_missing_google_grant_is_not_reported_as_sent(tmp_path, monkeypatch):
    monkeypatch.setenv('EMAIL_PROVIDER', 'gmail_oauth')
    monkeypatch.setattr(gmail, 'TOKEN_PATH', tmp_path / 'missing')
    settings = NotificationSettings.from_env()
    result = send_high_severity_alert(alert_id='alert', scan_id='scan', severity='High', message='', settings=settings)
    assert result[0] == {'channel': 'email', 'status': 'skipped', 'reason': 'not_configured'}


def test_existing_strong_server_secret_can_encrypt(tmp_path, monkeypatch):
    monkeypatch.delenv('ADMIN_ACCOUNT_ENCRYPTION_KEY', raising=False)
    monkeypatch.setenv('ADMIN_TOTP_SECRET', base64.b32encode(b'server-secret-with-entropy-fixture').decode())
    path = tmp_path / 'grant'
    gmail.save_authorization({'refresh_token': 'fixture'}, path)
    assert gmail.load_authorization(path)['refresh_token'] == 'fixture'


def test_google_consent_flow_verifies_identity_before_saving(grant, monkeypatch, tmp_path):
    from io import BytesIO
    from urllib.parse import urlencode
    config = tmp_path / 'client.json'
    config.write_text(json.dumps({'installed': {'client_id': 'test.apps.googleusercontent.com', 'client_secret': 'client-fixture'}}))
    opened = {}
    monkeypatch.setattr(gmail.webbrowser, 'open', lambda url: opened.setdefault('url', url))

    class Server:
        server_port = 12345
        def __init__(self, address, handler):
            assert address == ('127.0.0.1', 0)
            self.handler = handler
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def handle_request(self):
            query = parse_qs(urlsplit(opened['url']).query)
            callback = object.__new__(self.handler)
            callback.path = '/callback?' + urlencode({'state': query['state'][0], 'code': 'fixture-code'})
            callback.wfile = BytesIO()
            callback.send_response = MagicMock()
            callback.send_header = MagicMock()
            callback.end_headers = MagicMock()
            callback.do_GET()

    monkeypatch.setattr(gmail, 'HTTPServer', Server)
    factory = MagicMock()
    client = factory.return_value.__enter__.return_value
    client.post.return_value.status_code = 200
    client.post.return_value.json.return_value = {'refresh_token': 'new-refresh-fixture',
        'access_token': 'access-fixture', 'scope': gmail.SCOPES}
    client.get.return_value.status_code = 200
    client.get.return_value.json.return_value = {'email_verified': True, 'email': 'verified@example.com'}
    monkeypatch.setattr(gmail.httpx, 'Client', factory)
    assert gmail.authorize(config, 'recipient@example.com') == 'verified@example.com'
    assert gmail.load_authorization()['sender'] == 'verified@example.com'
    assert gmail.load_authorization()['refresh_token'] == 'new-refresh-fixture'
    assert client.post.call_args.args[0] == gmail.TOKEN_URL
    assert 'code_verifier' in client.post.call_args.kwargs['data']
    assert client.post.call_count == 1  # Authorization does not send mail.
