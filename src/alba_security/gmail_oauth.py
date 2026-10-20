"""Google authorization for the local mail service; never collects Gmail passwords."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import webbrowser
from email.message import EmailMessage
from email.utils import formataddr
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parents[2]
TOKEN_PATH = ROOT / '.private' / 'gmail-oauth' / 'authorization.enc'
AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
TOKEN_URL = 'https://oauth2.googleapis.com/token'
SEND_URL = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send'
SCOPES = 'openid email https://www.googleapis.com/auth/gmail.send'


class GmailAuthorizationError(RuntimeError):
    pass


def cipher():
    secret = os.environ.get('ADMIN_ACCOUNT_ENCRYPTION_KEY')
    if not secret:
        secret = os.environ.get('ADMIN_TOTP_SECRET')
        try:
            if not secret or len(base64.b32decode(secret, casefold=True)) < 20:
                raise ValueError('Missing strong server secret')
        except Exception:
            raise GmailAuthorizationError('Server encryption key is required before Gmail setup.') from None
    # Separate Gmail token encryption from account encryption.
    key = base64.urlsafe_b64encode(hashlib.sha256(('ExtSecure Gmail OAuth v1:' + secret).encode()).digest())
    return Fernet(key)


def save_authorization(data, path=None):
    target = Path(path) if path else TOKEN_PATH
    encoded = cipher().encrypt(json.dumps(data).encode())
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix('.tmp')
    temporary.write_bytes(encoded)
    temporary.replace(target)


def load_authorization(path=None):
    target = Path(path) if path else TOKEN_PATH
    try:
        return json.loads(cipher().decrypt(target.read_bytes()))
    except Exception:
        raise GmailAuthorizationError('Gmail is not authorized. Complete local Google sign-in.') from None


def load_client(path):
    data = json.loads(Path(path).read_text(encoding='utf-8')).get('installed', {})
    client_id = data.get('client_id', '')
    if not client_id.endswith('.apps.googleusercontent.com') or not data.get('client_secret'):
        raise GmailAuthorizationError('Choose a Google Desktop app OAuth client JSON file.')
    # Imported endpoints are deliberately ignored; requests go only to Google.
    return {'client_id': client_id, 'client_secret': data['client_secret']}


def authorization_parameters(client_id, redirect_uri, state, verifier):
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).rstrip(b'=').decode()
    return dict(client_id=client_id, redirect_uri=redirect_uri, response_type='code', scope=SCOPES,
                state=state, code_challenge=challenge, code_challenge_method='S256',
                access_type='offline', prompt='consent select_account')


def validate_callback(path, expected_state):
    parsed = urlsplit(path)
    query = parse_qs(parsed.query)
    if parsed.path != '/callback' or len(query.get('state', [])) != 1:
        raise GmailAuthorizationError('Google sign-in response was not accepted.')
    if not secrets.compare_digest(query['state'][0], expected_state):
        raise GmailAuthorizationError('Google sign-in response was not accepted.')
    if 'error' in query or len(query.get('code', [])) != 1:
        raise GmailAuthorizationError('Google authorization was cancelled or refused.')
    return query['code'][0]


def authorize(client_path, recipient, *, timeout=300):
    from email.utils import parseaddr
    if not recipient or parseaddr(recipient)[1] != recipient or any(c in recipient for c in '\r\n'):
        raise GmailAuthorizationError('Enter one valid administrator recipient address.')
    cipher()  # Fail before opening the browser if private storage is unavailable.
    client_config = load_client(client_path)
    state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    result = {}

    class Callback(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Authorization codes must never enter HTTP logs.

        def do_GET(self):
            try:
                result['code'] = validate_callback(self.path, state)
            except GmailAuthorizationError:
                query = parse_qs(urlsplit(self.path).query)
                if query.get('state') == [state] and 'error' in query:
                    result['cancelled'] = True
                self.send_response(400)
                body = b'Sign-in response rejected. Return to ExtSecure or try again.'
            else:
                self.send_response(200)
                body = b'Google sign-in received. You can close this tab and return to ExtSecure.'
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with HTTPServer(('127.0.0.1', 0), Callback) as server:
        server.timeout = 1
        redirect = f'http://127.0.0.1:{server.server_port}/callback'
        params = authorization_parameters(client_config['client_id'], redirect, state, verifier)
        if not webbrowser.open(AUTH_URL + '?' + urlencode(params)):
            raise GmailAuthorizationError('Could not open your browser for Google sign-in.')
        deadline = time.monotonic() + timeout
        while not result and time.monotonic() < deadline:
            server.handle_request()
        if result.get('cancelled'):
            raise GmailAuthorizationError('Google authorization was cancelled or refused.')
        if 'code' not in result:
            raise GmailAuthorizationError('Google sign-in timed out. Try again.')
    with httpx.Client(timeout=20, follow_redirects=False) as client:
        response = client.post(TOKEN_URL, data={**client_config, 'code': result['code'],
            'code_verifier': verifier, 'redirect_uri': redirect, 'grant_type': 'authorization_code'})
        if response.status_code != 200:
            raise GmailAuthorizationError('Google could not authorize sending. Check your OAuth client and consent settings.')
        token = response.json()
        required_scope = 'https://www.googleapis.com/auth/gmail.send'
        if not token.get('refresh_token') or required_scope not in token.get('scope', '').split():
            raise GmailAuthorizationError('Google did not grant background email permission. Please consent again.')
        identity = client.get('https://openidconnect.googleapis.com/v1/userinfo',
                              headers={'Authorization': 'Bearer ' + token['access_token']})
        if identity.status_code != 200:
            raise GmailAuthorizationError('Could not verify the Google sender identity.')
        user = identity.json()
        email = user.get('email', '')
        if user.get('email_verified') is not True or '@' not in email or any(c in email for c in '\r\n'):
            raise GmailAuthorizationError('Google sender email is not verified.')
    save_authorization({**client_config, 'refresh_token': token['refresh_token'], 'sender': email,
                        'recipient': recipient})
    return email


def deliver(recipients, subject, body, timeout=10):
    credentials = load_authorization()
    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        refreshed = client.post(TOKEN_URL, data={
            'client_id': credentials['client_id'], 'client_secret': credentials['client_secret'],
            'refresh_token': credentials['refresh_token'], 'grant_type': 'refresh_token'})
        if refreshed.status_code != 200:
            raise GmailAuthorizationError('Google authorization expired or was revoked. Sign in again locally.')
        access_token = refreshed.json().get('access_token')
        if not access_token:
            raise GmailAuthorizationError('Google did not provide a sending token.')
        for recipient in recipients:
            message = EmailMessage()
            message['From'] = formataddr(('ExtSecure', credentials['sender']))
            message['To'] = recipient
            message['Subject'] = subject
            message.set_content(body)
            raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
            response = client.post(SEND_URL, headers={'Authorization': 'Bearer ' + access_token}, json={'raw': raw})
            if response.status_code != 200 or not response.json().get('id'):
                # No automatic retries: a timeout can occur after Google accepted a message.
                raise GmailAuthorizationError('Google did not confirm email acceptance.')
