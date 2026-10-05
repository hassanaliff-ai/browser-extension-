"""Public registration; verified enrollment and admin approval gate access."""
from datetime import datetime, timedelta
import secrets
from typing import Literal
import pyotp
from argon2 import PasswordHasher
from fastapi import Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import DateTime, String, Text, Integer, delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column
from alba_security.models import Base, new_id, utc_now
from alba_security.admin_auth import _digest, _utc, AdminAuthState


class RegisteredAdmin(Base):
    __tablename__ = 'registered_administrators'
    username: Mapped[str] = mapped_column(String(120), primary_key=True)
    password_hash: Mapped[str] = mapped_column(Text)
    totp_encrypted: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default='pending_review')
    role: Mapped[str] = mapped_column(String(30), default='normal_user')
    approved_by: Mapped[str | None] = mapped_column(String(120))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AdminInvitation(Base):
    # Preserve legacy records; invitation endpoints are retired.
    __tablename__ = 'admin_invitations'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    username: Mapped[str] = mapped_column(String(120))
    author: Mapped[str] = mapped_column(String(120))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RegistrationEnrollment(Base):
    # New table avoids changing legacy non-null invitation-linked enrollments.
    __tablename__ = 'account_registration_enrollments'
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    totp_encrypted: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)


class AccountName(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r'^[a-z0-9][a-z0-9._-]*$')


class RegistrationStart(AccountName):
    model_config = ConfigDict(extra='forbid')
    password: str = Field(min_length=12, max_length=128)


class EnrollmentToken(BaseModel):
    enrollment_token: str = Field(min_length=20, max_length=200)


class RegistrationConfirm(EnrollmentToken):
    totp_code: str = Field(pattern=r'^\d{6}$')


class AccountReview(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    reason: str = Field(min_length=8, max_length=500, pattern=r'.*\S.*')
    role: Literal['administrator', 'manager', 'normal_user'] = 'normal_user'


def install_registration(app, session_scope, require_actor, directory, throttle):
    from alba_security.governance import audit
    from alba_security.admin_auth import AdminSession
    def require_head(actor: str = Depends(require_actor)):
        if actor != directory.primary.username:
            raise HTTPException(403, 'Only the Head of Administrator can manage access')
        return actor
    Admin = Depends(require_head)

    @app.get('/api/admin/registrations')
    def requests(actor: str = Admin, db: Session = Depends(session_scope)):
        rows = db.scalars(select(RegisteredAdmin).where(RegisteredAdmin.status == 'pending_review').order_by(RegisteredAdmin.created_at).limit(200))
        return [{'username':r.username,'status':r.status,'role':r.role,'created_at':_utc(r.created_at).isoformat()} for r in rows]

    def review_account(username, payload, actor, db, decision):
        changed = db.execute(update(RegisteredAdmin).where(RegisteredAdmin.username == username, RegisteredAdmin.status == 'pending_review').values(status=decision, role=payload.role if decision == 'active' else 'normal_user',
                approved_by=actor if decision == 'active' else None, approved_at=utc_now() if decision == 'active' else None))
        if changed.rowcount != 1:
            db.rollback()
            raise HTTPException(409, 'This account is no longer pending review')
        audit(db, 'account', username, actor, 'registration_approved' if decision == 'active' else 'registration_rejected', reason=payload.reason, role=payload.role if decision == 'active' else None)
        db.commit()
        return {'username':username,'status':decision,'role':payload.role if decision == 'active' else 'normal_user'}

    @app.post('/api/admin/registrations/{username}/approve')
    def approve(username: str, payload: AccountReview, actor: str = Admin, db: Session = Depends(session_scope)):
        return review_account(username,payload,actor,db,'active')

    @app.post('/api/admin/registrations/{username}/reject')
    def reject(username: str, payload: AccountReview, actor: str = Admin, db: Session = Depends(session_scope)):
        return review_account(username,payload,actor,db,'rejected')

    @app.post('/api/admin/register', status_code=201, dependencies=[Depends(throttle)])
    def register(payload: RegistrationStart, db: Session = Depends(session_scope)):
        now = utc_now()
        if any(n.casefold() == payload.username for n in directory.accounts) or db.get(RegisteredAdmin, payload.username):
            raise HTTPException(409, 'This account name is already reserved')
        db.execute(delete(RegistrationEnrollment).where(RegistrationEnrollment.expires_at <= now))
        secret = pyotp.random_base32()
        token = secrets.token_urlsafe(32)
        row = RegistrationEnrollment(token_hash=_digest(token), username=payload.username,
                                     password_hash=PasswordHasher().hash(payload.password), totp_encrypted=directory.cipher().encrypt(secret.encode()).decode(),
                                     expires_at=now+timedelta(minutes=15), failed_attempts=0)
        db.add(row)
        try: db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, 'An enrollment is already pending; complete it or wait for it to expire') from None
        return {'enrollment_token':token,'expires_at':_utc(row.expires_at).isoformat(),
                'totp_secret':secret,'provisioning_uri':pyotp.TOTP(secret).provisioning_uri(name=payload.username, issuer_name='ExtSecure')}

    @app.post('/api/admin/register/verify', dependencies=[Depends(throttle)])
    def confirm(payload: RegistrationConfirm, db: Session = Depends(session_scope)):
        now = utc_now()
        enrollment = db.scalar(select(RegistrationEnrollment).where(RegistrationEnrollment.token_hash == _digest(payload.enrollment_token)).with_for_update())
        if not enrollment or _utc(enrollment.expires_at) <= now or enrollment.failed_attempts >= 5:
            raise HTTPException(401, 'Enrollment is invalid or expired')
        secret = directory.cipher().decrypt(enrollment.totp_encrypted.encode()).decode()
        totp = pyotp.TOTP(secret)
        current = int(now.timestamp()) // totp.interval
        counter = next((i for i in (current, current-1, current+1) if secrets.compare_digest(payload.totp_code, totp.at(i*totp.interval))), None)
        if counter is None:
            db.execute(update(RegistrationEnrollment).where(RegistrationEnrollment.token_hash == enrollment.token_hash).values(failed_attempts=RegistrationEnrollment.failed_attempts+1))
            db.commit()
            raise HTTPException(401, 'Authenticator code was not accepted')
        claim = db.execute(delete(RegistrationEnrollment).where(RegistrationEnrollment.token_hash == enrollment.token_hash,
                           RegistrationEnrollment.expires_at > now, RegistrationEnrollment.failed_attempts < 5)
                           .execution_options(synchronize_session=False))
        if claim.rowcount != 1:
            db.rollback()
            raise HTTPException(409, 'Enrollment was already completed or expired')
        db.add(RegisteredAdmin(username=enrollment.username, password_hash=enrollment.password_hash, totp_encrypted=enrollment.totp_encrypted, status='pending_review'))
        account = directory.build_account(enrollment.username, enrollment.password_hash, secret)
        db.add(AdminAuthState(id=account.state_id, failed_attempts=0, last_totp_counter=counter))
        audit(db, 'account', enrollment.username, enrollment.username, 'registration_verified', status='pending_review')
        try: db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, 'Account already exists or enrollment was completed concurrently') from None
        return {'registered':True,'username':enrollment.username,'status':'pending_review', 'next_step':'The Head of Administrator must approve access and assign your role before you can log in.'}

    @app.post('/api/admin/register/cancel', dependencies=[Depends(throttle)])
    def cancel(payload: EnrollmentToken, db: Session = Depends(session_scope)):
        db.execute(delete(RegistrationEnrollment).where(RegistrationEnrollment.token_hash == _digest(payload.enrollment_token)))
        db.commit()
        return {'cancelled':True}

    @app.post('/api/admin/register/qr', dependencies=[Depends(throttle)])
    def enrollment_qr(payload: EnrollmentToken, db: Session = Depends(session_scope)):
        """Render enrollment locally; no authenticator secret reaches a QR provider."""
        from fastapi.responses import Response
        from alba_security.authenticator_qr import authenticator_qr_png
        row = db.get(RegistrationEnrollment, _digest(payload.enrollment_token))
        if not row or _utc(row.expires_at) <= utc_now() or row.failed_attempts >= 5:
            raise HTTPException(401, 'Enrollment is invalid or expired')
        secret = directory.cipher().decrypt(row.totp_encrypted.encode()).decode()
        uri = pyotp.TOTP(secret).provisioning_uri(name=row.username, issuer_name='ExtSecure')
        return Response(authenticator_qr_png(uri, secret=secret), media_type='image/png',
                        headers={'Cache-Control': 'no-store'})

    @app.post('/api/admin/accounts/{username}/disable')
    def disable(username: str, actor: str = Admin, db: Session = Depends(session_scope)):
        if username == directory.primary.username: raise HTTPException(409, 'The main administrator account is protected')
        row = db.get(RegisteredAdmin, username)
        if row is None: raise HTTPException(404, 'Registered account not found')
        row.status = 'disabled'
        db.execute(update(AdminSession).where(AdminSession.username == username).values(revoked_at=utc_now()))
        audit(db, 'account', username, actor, 'account_disabled')
        db.commit()
        return {'disabled':True}

    @app.post('/api/admin/accounts/{username}/role')
    def change_role(username: str, payload: AccountReview, actor: str = Admin, db: Session = Depends(session_scope)):
        if username == directory.primary.username:
            raise HTTPException(409, 'The main administrator account is protected')
        row = db.get(RegisteredAdmin, username)
        if row is None or row.status != 'active':
            raise HTTPException(404, 'Active registered account not found')
        previous = row.role
        row.role = payload.role
        row.approved_by = actor
        row.approved_at = utc_now()
        db.execute(update(AdminSession).where(AdminSession.username == username).values(revoked_at=utc_now()))
        audit(db, 'account', username, actor, 'account_role_changed', previous_role=previous, role=payload.role, reason=payload.reason)
        db.commit()
        return {'username':username,'role':payload.role,'sessions_revoked':True}
