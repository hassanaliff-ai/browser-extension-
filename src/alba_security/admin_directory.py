"""Resolve authenticated actors without trusting names supplied by callers."""
from __future__ import annotations

import hashlib
import base64
import hmac
import os
from sqlalchemy.orm import Session
from alba_security.admin_auth import AdminAuth, AdminLoginChallenge, AdminSession, AuthenticationError, _digest


class AdminDirectory:
    def __init__(self, primary: AdminAuth, additional: list[AdminAuth] | None = None):
        self.primary = primary
        self.username = primary.username
        self.accounts = {primary.username: primary}
        for account in additional or []:
            if account.username in self.accounts or len(account.username) > 120:
                raise RuntimeError("Administrator names must be distinct and at most 120 characters")
            if any(account.totp.secret == existing.totp.secret for existing in self.accounts.values()):
                raise RuntimeError("Each administrator requires a separate authenticator secret")
            account.state_id = hashlib.sha256(account.username.encode()).hexdigest()[:32]
            account.allow_legacy = False
            self.accounts[account.username] = account

    @classmethod
    def configured(cls, primary: AdminAuth):
        names = ['ADMIN_REVIEWER_USERNAME', 'ADMIN_REVIEWER_PASSWORD_HASH', 'ADMIN_REVIEWER_TOTP_SECRET']
        values = [os.getenv(name, '') for name in names]
        if any(values) and not all(values):
            raise RuntimeError("Configure all three ADMIN_REVIEWER settings together")
        additional = [AdminAuth(*values)] if all(values) else []
        return cls(primary, additional)

    def begin_login(self, db: Session, username: str, password: str):
        # Unknown names still incur password verification through the primary account.
        return (self.account(db, username) or self.primary).begin_login(db, username, password)

    def cipher(self):
        from cryptography.fernet import Fernet
        key = os.getenv('ADMIN_ACCOUNT_ENCRYPTION_KEY')
        if not key:
            # Domain-separated derivation from the existing high-entropy server secret.
            key = base64.urlsafe_b64encode(hmac.digest(base64.b32decode(self.primary.totp.secret), b'ExtSecure account encryption v1', 'sha256'))
        return Fernet(key)

    def build_account(self, username, password_hash, secret):
        account = AdminAuth(username, password_hash, secret,
                            challenge_ttl_seconds=int(self.primary.challenge_ttl.total_seconds()),
                            session_ttl_seconds=int(self.primary.session_ttl.total_seconds()),
                            max_failed_attempts=self.primary.max_failed_attempts,
                            lockout_seconds=int(self.primary.lockout.total_seconds()), clock=self.primary.clock)
        account.state_id = hashlib.sha256(username.encode()).hexdigest()[:32]
        account.allow_legacy = False
        return account

    def account(self, db, username):
        if username == self.primary.username:
            return self.primary
        from alba_security.registration import RegisteredAdmin
        from cryptography.fernet import InvalidToken
        row = db.get(RegisteredAdmin, username)
        if row is None or self.role(db, username) is None: return None
        try: secret = self.cipher().decrypt(row.totp_encrypted.encode()).decode()
        except InvalidToken: raise AuthenticationError('Account configuration is unavailable') from None
        return self.accounts.get(username) or self.build_account(row.username, row.password_hash, secret)

    def all_accounts(self, db):
        from alba_security.registration import RegisteredAdmin
        from sqlalchemy import select
        return {self.primary.username: self.primary, **{r.username: None for r in db.scalars(select(RegisteredAdmin).where(RegisteredAdmin.status == 'active')) if self.role(db, r.username)}}

    def complete_login(self, db: Session, challenge_token: str, totp_code: str):
        challenge = db.get(AdminLoginChallenge, _digest(challenge_token))
        if challenge is None:
            raise AuthenticationError("Invalid administrator sign-in")
        username = challenge.username or self.primary.username
        account = self.account(db, username)
        if account is None:
            raise AuthenticationError("Invalid administrator sign-in")
        return account.complete_login(db, challenge_token, totp_code)

    def actor(self, db: Session, token: str) -> str | None:
        session = db.get(AdminSession, _digest(token))
        if not session: return None
        username = session.username or self.primary.username
        try: account = self.account(db, username)
        except AuthenticationError: return None
        return username if account and account.verify_session(db, token) else None

    def verify_session(self, db: Session, token: str) -> bool:
        return self.actor(db, token) is not None

    def logout(self, db: Session, token: str) -> bool:
        actor = self.actor(db, token)
        return self.account(db, actor).logout(db, token) if actor else False

    def initialize_accounts(self, db):
        from alba_security.registration import RegisteredAdmin
        for username, account in self.accounts.items():
            if username == self.primary.username or db.get(RegisteredAdmin, username):
                continue
            db.add(RegisteredAdmin(username=username, password_hash=account.password_hash,
                totp_encrypted=self.cipher().encrypt(account.totp.secret.encode()).decode(),
                status='pending_review', role='administrator'))
        db.commit()

    def role(self, db, username, _visited=None):
        if not username: return None
        if username == self.primary.username: return 'head_administrator'
        visited = set(_visited or ())
        if username in visited or len(visited) >= 4: return None
        visited.add(username)
        from alba_security.registration import RegisteredAdmin
        from alba_security.permissions import can_approve_role
        row = db.get(RegisteredAdmin, username)
        if row and row.status == 'active' and row.role in {'administrator', 'manager', 'normal_user'}:
            reviewer_role = self.role(db, row.approved_by, visited)
            return row.role if can_approve_role(reviewer_role, row.role) else None
        return None

    def operators(self, db):
        return {name: account for name, account in self.all_accounts(db).items()
                if self.role(db, name) in {'head_administrator', 'administrator', 'manager'}}
