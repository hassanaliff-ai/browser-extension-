"""Authenticated website approvals. Browser enforcement lives in the MV3 package."""
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit, urlunsplit

import idna
from fastapi import Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import DateTime, Integer, String, Text, func, select, update
from sqlalchemy.orm import Mapped, Session, mapped_column

from alba_security.governance import audit
from alba_security.models import Base, new_id, utc_now


def clean_url(value):
    """One scheme/host/port/path; queries and fragments are deliberately excluded."""
    try:
        p = urlsplit(value.strip())
        if p.scheme not in {'http', 'https'} or not p.hostname or p.username or p.password:
            raise ValueError()
        host = p.hostname.lower().removesuffix('.')
        host = '[' + host + ']' if ':' in host else idna.encode(host, uts46=True).decode('ascii')
        port = p.port
        authority = host + (':' + str(port) if port and port != {'http': 80, 'https': 443}[p.scheme] else '')
        path = p.path or '/'
        if any(ord(c) < 33 or ord(c) > 126 for c in path) or '\\' in path or '/./' in path or '/../' in path:
            raise ValueError()
        return urlunsplit((p.scheme, authority, path, '', ''))
    except (ValueError, UnicodeError):
        raise ValueError('Use a valid HTTP(S) URL without credentials; encode non-ASCII paths') from None


def iso(value):
    return value.replace(tzinfo=timezone.utc).isoformat() if value and value.tzinfo is None else value.isoformat() if value else None


class WebsiteRequest(Base):
    __tablename__ = 'website_access_requests'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    requester: Mapped[str] = mapped_column(String(120), index=True)
    target: Mapped[str] = mapped_column(String(2048), index=True)
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default='pending', index=True)
    decision: Mapped[str | None] = mapped_column(String(20))
    reviewer: Mapped[str | None] = mapped_column(String(120))
    review_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revision: Mapped[int] = mapped_column(Integer, default=1)


class WebsiteWhitelist(Base):
    __tablename__ = 'website_access_whitelist'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    target: Mapped[str] = mapped_column(String(2048), index=True)
    reviewer: Mapped[str] = mapped_column(String(120))
    reason: Mapped[str] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Reason(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    reason: str = Field(min_length=8, max_length=1000)


class Target(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    target: str = Field(min_length=8, max_length=2048)
    _clean = field_validator('target')(clean_url)


class Create(Target, Reason):
    pass


class Review(Reason):
    decision: str = Field(pattern=r'^(once|whitelist|reject)$')
    expected_revision: int = Field(ge=1)
    whitelist_days: int = Field(default=30, ge=1, le=90)


def record(item):
    return {k: getattr(item, k) for k in ('id', 'requester', 'target', 'reason', 'status', 'decision', 'reviewer', 'review_reason', 'revision')} | {
        'created_at': iso(item.created_at), 'expires_at': iso(item.expires_at)}


def install_website_access(app, session_scope, require_actor, directory):
    Actor = Depends(require_actor)
    DB = Depends(session_scope)

    def role(db, actor):
        return directory.role(db, actor)

    def current_whitelist(db, target):
        return db.scalar(select(WebsiteWhitelist).where(WebsiteWhitelist.target == target,
            WebsiteWhitelist.active.is_(True), WebsiteWhitelist.expires_at > utc_now()).order_by(WebsiteWhitelist.created_at.desc()))

    @app.get('/api/access/requests')
    def requests(actor: str = Actor, db: Session = DB):
        query = select(WebsiteRequest)
        if role(db, actor) == 'normal_user':
            query = query.where(WebsiteRequest.requester == actor)
        return [record(r) for r in db.scalars(query.order_by(WebsiteRequest.created_at.desc()).limit(200))]

    @app.post('/api/access/requests', status_code=201)
    def request_access(payload: Create, actor: str = Actor, db: Session = DB):
        existing = db.scalar(select(WebsiteRequest).where(WebsiteRequest.requester == actor,
            WebsiteRequest.target == payload.target, WebsiteRequest.status == 'pending', WebsiteRequest.expires_at > utc_now()))
        if existing:
            return record(existing)
        recent = db.scalar(select(func.count()).select_from(WebsiteRequest).where(
            WebsiteRequest.requester == actor, WebsiteRequest.created_at > utc_now() - timedelta(hours=1)))
        if recent >= 20:
            raise HTTPException(429, 'Limit of 20 website access requests per hour')
        item = WebsiteRequest(requester=actor, target=payload.target, reason=payload.reason,
            expires_at=utc_now() + timedelta(days=14))
        db.add(item)
        db.flush()
        audit(db, 'website_access', item.id, actor, 'requested')
        db.commit()
        return record(item)

    @app.post('/api/access/requests/{request_id}/review')
    def review(request_id: str, payload: Review, actor: str = Actor, db: Session = DB):
        item = db.get(WebsiteRequest, request_id)
        if not item:
            raise HTTPException(404, 'Website request not found')
        if item.requester == actor:
            raise HTTPException(403, 'Another manager or administrator must review your own request')
        now = utc_now()
        outcome = 'rejected' if payload.decision == 'reject' else 'approved'
        expiry = now + (timedelta(minutes=10) if payload.decision == 'once' else timedelta(days=payload.whitelist_days))
        changed = db.execute(update(WebsiteRequest).execution_options(synchronize_session=False).where(WebsiteRequest.id == request_id,
            WebsiteRequest.status == 'pending', WebsiteRequest.revision == payload.expected_revision,
            WebsiteRequest.expires_at > now).values(status=outcome, decision=payload.decision,
            reviewer=actor, review_reason=payload.reason, expires_at=expiry, revision=WebsiteRequest.revision + 1))
        if changed.rowcount != 1:
            raise HTTPException(409, 'Request changed or expired; refresh before reviewing')
        superseded = 0
        if payload.decision == 'whitelist':
            # Renew an exact destination rather than accumulate independent live
            # grants. Keep the older rows for the decision history and audit.
            superseded = db.execute(update(WebsiteWhitelist).execution_options(synchronize_session=False).where(
                WebsiteWhitelist.target == item.target, WebsiteWhitelist.active.is_(True)).values(active=False)).rowcount
            db.add(WebsiteWhitelist(target=item.target, reviewer=actor, reason=payload.reason, expires_at=expiry))
        audit(db, 'website_access', request_id, actor, outcome, decision=payload.decision,
              superseded_entries=superseded)
        db.commit()
        db.expire_all()
        return record(db.get(WebsiteRequest, request_id))

    @app.get('/api/access/whitelist')
    def whitelist(actor: str = Actor, db: Session = DB):
        rows = db.scalars(select(WebsiteWhitelist).where(WebsiteWhitelist.active.is_(True),
            WebsiteWhitelist.expires_at > utc_now()).order_by(WebsiteWhitelist.created_at.desc()).limit(200))
        return [{'id': r.id, 'target': r.target, 'reviewer': r.reviewer, 'reason': r.reason,
                 'created_at': iso(r.created_at), 'expires_at': iso(r.expires_at)} for r in rows]

    @app.post('/api/access/whitelist/{entry_id}/revoke')
    def revoke(entry_id: str, payload: Reason, actor: str = Actor, db: Session = DB):
        entry = db.get(WebsiteWhitelist, entry_id)
        if not entry or not entry.active:
            raise HTTPException(409, 'Whitelist entry is missing or already revoked; refresh before revoking')
        # Older deployments (or concurrent approvals) can contain duplicates.
        # Revoking the displayed URL must close every live whitelist grant for
        # that exact URL, otherwise a hidden duplicate would keep it allowed.
        changed = db.execute(update(WebsiteWhitelist).execution_options(synchronize_session=False).where(WebsiteWhitelist.target == entry.target,
            WebsiteWhitelist.active.is_(True)).values(active=False))
        if changed.rowcount < 1:
            raise HTTPException(409, 'Whitelist entry is missing or already revoked')
        audit(db, 'website_access', entry_id, actor, 'revoked', reason=payload.reason,
              revoked_entries=changed.rowcount)
        db.commit()
        return {'revoked': True, 'revoked_entries': changed.rowcount}

    def permit(db, actor, target, consume=False):
        entry = current_whitelist(db, target)
        if entry:
            if consume:
                audit(db, 'website_access', entry.id, actor, 'whitelist_visit')
                db.commit()
            return {'allowed': True, 'kind': 'whitelist', 'expires_at': iso(entry.expires_at)}
        query = select(WebsiteRequest).where(WebsiteRequest.requester == actor, WebsiteRequest.target == target,
            WebsiteRequest.status == 'approved', WebsiteRequest.decision == 'once', WebsiteRequest.expires_at > utc_now())
        item = db.scalar(query.order_by(WebsiteRequest.created_at.desc()))
        if not item:
            return {'allowed': False, 'kind': None}
        if consume:
            changed = db.execute(update(WebsiteRequest).execution_options(synchronize_session=False).where(WebsiteRequest.id == item.id,
                WebsiteRequest.status == 'approved', WebsiteRequest.expires_at > utc_now()).values(
                    status='consumed', revision=WebsiteRequest.revision + 1))
            if changed.rowcount != 1:
                raise HTTPException(409, 'This one-visit approval was already used or expired')
            audit(db, 'website_access', item.id, actor, 'once_consumed')
            db.commit()
        return {'allowed': True, 'kind': 'once', 'expires_at': iso(item.expires_at)}

    @app.post('/api/access/check')
    def check(payload: Target, actor: str = Actor, db: Session = DB):
        return permit(db, actor, payload.target)

    @app.post('/api/access/consume')
    def consume(payload: Target, actor: str = Actor, db: Session = DB):
        result = permit(db, actor, payload.target, consume=True)
        if not result['allowed']:
            raise HTTPException(403, 'A manager or administrator must approve this URL first')
        return result
