"""Provision a fresh local owner without replacing an established account."""
from __future__ import annotations

import argparse
import base64
import csv
from html import escape
import os
from pathlib import Path
import secrets
import subprocess

from argon2 import PasswordHasher
from dotenv import dotenv_values
import pyotp

from alba_security.authenticator_qr import authenticator_qr_png


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name == 'nt':
        identity = subprocess.run(['whoami', '/user', '/fo', 'csv', '/nh'],
            check=True, capture_output=True, text=True)
        sid = next(csv.reader(identity.stdout.strip().splitlines()))[1]
        subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r',
            '*'+sid+':(OI)(CI)F', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F'],
            check=True, capture_output=True)
    else:
        path.chmod(0o700)


def _write_private_qr(private: Path, username: str, secret: str) -> dict[str, str]:
    uri = pyotp.TOTP(secret).provisioning_uri(username, issuer_name='ExtSecure')
    png = authenticator_qr_png(uri, secret=secret)
    _private_directory(private)
    image_path = private / 'Head of Administrator Authenticator QR.png'
    page_path = private / 'Head of Administrator Authenticator Setup.html'
    image_path.write_bytes(png)
    # The offline page contains no password, scripts, or external resources.
    page_path.write_text(f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>ExtSecure — Private authenticator setup</title>
<style>body{{font:17px/1.6 system-ui,sans-serif;background:#f2f7f7;color:#183331;margin:0;padding:32px}}
main{{max-width:600px;margin:auto;background:white;border-radius:20px;padding:32px;box-shadow:0 8px 32px #15333012}}
h1{{font-size:26px;line-height:1.3}}.brand{{color:#007f78;font-weight:700;letter-spacing:.08em}}
img{{display:block;max-width:100%;width:320px;margin:20px auto}}code{{display:block;word-break:break-all;padding:12px;background:#eef6f5;border-radius:8px}}
.private{{border-left:4px solid #b45309;padding-left:12px}}summary{{cursor:pointer;font-weight:600}}</style>
</head><body><main><div class="brand">EXTSECURE</div><h1>Set up your authenticator</h1>
<p><strong>Head of Administrator</strong><br>Account: {escape(username)}</p>
<p>In your authenticator app, choose <strong>Add account → Scan QR code</strong>, then scan this image.</p>
<img src="data:image/png;base64,{base64.b64encode(png).decode('ascii')}" alt="Private ExtSecure authenticator setup QR code">
<details><summary>Cannot scan? Enter the setup key manually</summary>
<p>Add a time-based account named ExtSecure ({escape(username)}) and use this key:</p><code>{escape(secret)}</code></details>
<p>Open ExtSecure and log in with your username and password. Complete the second step with the six-digit code from your authenticator app.</p>
<p class="private">Keep this page, the QR image, and the manual key private. They all contain the same authenticator secret. Store the secret securely and remove enrollment copies when no longer needed.</p>
</main></body></html>''', encoding='utf-8')
    if os.name != 'nt':
        image_path.chmod(0o600)
        page_path.chmod(0o600)
    return {'qr_file':str(image_path), 'qr_setup_page':str(page_path)}


def export_existing_qr(env_path: Path) -> dict[str, str]:
    """Export only the current owner's enrollment QR; never rotate credentials."""
    env_path = env_path.resolve()
    values = dotenv_values(env_path)
    username, secret = values.get('ADMIN_USERNAME'), values.get('ADMIN_TOTP_SECRET')
    if not username or not secret:
        raise RuntimeError('An existing primary account is required to export its authenticator QR')
    return _write_private_qr(env_path.parent / '.private', username, secret)


def provision(env_path: Path) -> dict:
    env_path = env_path.resolve()
    values = dotenv_values(env_path) if env_path.exists() else {}
    if any(values.get(k) for k in ('ADMIN_USERNAME', 'ADMIN_PASSWORD_HASH', 'ADMIN_TOTP_SECRET')):
        raise RuntimeError('Primary account settings already exist; owner credentials were not replaced')
    private = env_path.parent / '.private'
    _private_directory(private)
    setup = private / 'Head of Administrator Setup.txt'
    backup = private / 'environment-before-owner.txt'
    if setup.exists() or backup.exists():
        raise RuntimeError('Private setup files already exist; review them before provisioning again')
    password = secrets.token_urlsafe(24)
    secret = pyotp.random_base32()
    username = 'head-of-administrator'
    uri = pyotp.TOTP(secret).provisioning_uri(username, issuer_name='ExtSecure')
    qr_files = _write_private_qr(private, username, secret)
    database = values.get('DATABASE_URL') or 'sqlite:///'+(env_path.parent/'extsecure.db').as_posix()
    changes = {
        'DATABASE_URL':database, 'ADMIN_USERNAME':username,
        'ADMIN_PASSWORD_HASH':PasswordHasher().hash(password), 'ADMIN_TOTP_SECRET':secret,
        'INGEST_TOKEN':values.get('INGEST_TOKEN') or secrets.token_urlsafe(48),
        'MONITORING_ENABLED':'1',
    }
    original = env_path.read_text(encoding='utf-8') if env_path.exists() else ''
    # Private files and the new environment are written inside the restricted
    # folder. The final replacement retains their restricted file permissions.
    backup.write_text(original,encoding='utf-8')
    setup.write_text(
        'ExtSecure — private main administrator setup\n\n'
        'Display name: Head of Administrator\n'
        f'Username: {username}\nPassword: {password}\n\n'
        'Open Head of Administrator Authenticator Setup.html in this private folder\n'
        'and scan its QR code with your authenticator app. Manual setup is also available.\n'
        f'2FA setup key: {secret}\nAuthenticator URI: {uri}\n\n'
        'Log in with the username and password, then enter a fresh six-digit\n'
        'authenticator code. This account has full access and exclusively\n'
        'approves other users and assigns their roles. Do not share this file.\n'
        'Store these credentials securely; password recovery is not implemented.\n',encoding='utf-8')
    staged = private/'owner-environment.tmp'
    staged.write_text(original.rstrip()+'\n\n# ExtSecure protected main administrator\n'+
        '\n'.join(f'{k}={v}' for k,v in changes.items())+'\n',encoding='utf-8')
    if os.name != 'nt':
        for file in (backup,setup,staged): file.chmod(0o600)
    staged.replace(env_path)
    return {'username':username,'setup_file':str(setup),'configuration':str(env_path),**qr_files}


def main():
    parser=argparse.ArgumentParser(description='Create a protected Head of Administrator for a fresh local installation')
    parser.add_argument('--env',type=Path,default=Path('.env'))
    parser.add_argument('--export-qr',action='store_true',help='Export the existing owner authenticator QR without changing credentials')
    arguments=parser.parse_args()
    if arguments.export_qr:
        result=export_existing_qr(arguments.env)
        print('Private authenticator setup: '+result['qr_setup_page'])
    else:
        result=provision(arguments.env)
        print('Created '+result['username']+'. Private setup: '+result['setup_file'])


if __name__ == '__main__':
    main()
