"""Scan-linked user concerns and administrator decisions, without changing verdicts."""
from __future__ import annotations

from typing import Literal
from datetime import datetime
from fastapi import Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column
from alba_security.models import Base, PersonalScan, Scan, new_id, utc_now
from alba_security.governance import audit, iso


class UserSecurityFeedback(Base):
    __tablename__ = 'user_security_feedback'
    __table_args__ = (
        UniqueConstraint('scan_id', 'reporter', name='uq_feedback_scan_reporter'),
        CheckConstraint("category IN ('suspicious_result','challenge_warning')", name='ck_feedback_category'),
        CheckConstraint("status IN ('pending','reviewed')", name='ck_feedback_status'),
        CheckConstraint("outcome IS NULL OR outcome IN ('threat_confirmed','false_positive','inconclusive')", name='ck_feedback_outcome'),
        CheckConstraint('revision >= 1', name='ck_feedback_revision'),
        CheckConstraint('length(message) BETWEEN 10 AND 2000', name='ck_feedback_message'),
        CheckConstraint("(status='pending' AND outcome IS NULL AND reviewed_by IS NULL AND reviewed_at IS NULL AND review_note IS NULL) OR (status='reviewed' AND outcome IS NOT NULL AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL AND review_note IS NOT NULL)", name='ck_feedback_review'),
        Index('ix_feedback_status_created', 'status', 'created_at'),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey('scans.id'), index=True)
    reporter: Mapped[str] = mapped_column(String(120), index=True)
    category: Mapped[str] = mapped_column(String(30))
    message: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default='pending')
    outcome: Mapped[str | None] = mapped_column(String(24))
    review_note: Mapped[str | None] = mapped_column(Text)
    reviewed_by: Mapped[str | None] = mapped_column(String(120))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class FeedbackCreate(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    scan_id: str = Field(min_length=1, max_length=36)
    category: Literal['suspicious_result', 'challenge_warning']
    message: str = Field(min_length=10, max_length=2000)


class FeedbackReview(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    expected_revision: int = Field(strict=True, ge=1)
    outcome: Literal['threat_confirmed', 'false_positive', 'inconclusive']
    review_note: str = Field(min_length=10, max_length=2000)


def install_user_feedback(app, session_scope, require_actor, directory):
    Actor = Depends(require_actor)

    def is_reviewer(db, actor):
        return directory.role(db, actor) in {'head_administrator', 'administrator'}

    def record(db, row, scan=None, show_hostnames=None):
        from alba_security.governance import privacy_settings
        scan = scan if scan is not None else db.get(Scan, row.scan_id)
        if show_hostnames is None:
            show_hostnames = privacy_settings(db)['show_hostnames']
        display = scan.target_display
        if scan.target_kind == 'url' and not show_hostnames:
            display = 'URL ' + scan.target_fingerprint[:12]
        return {'id': row.id, 'scan_id': row.scan_id, 'reporter': row.reporter,
                'category': row.category, 'message': row.message, 'status': row.status,
                'outcome': row.outcome, 'review_note': row.review_note,
                'reviewed_by': row.reviewed_by,
                'reviewed_at': iso(row.reviewed_at),
                'revision': row.revision, 'created_at': iso(row.created_at),
                'target_display': display, 'severity': scan.severity}

    @app.post('/api/feedback', status_code=201)
    def submit(payload: FeedbackCreate, actor: str = Actor, db: Session = Depends(session_scope)):
        scan = db.get(Scan, payload.scan_id)
        # Organization readers may reference scans they can inspect. Normal users
        # can submit only for their authenticated personal scan ownership.
        if directory.role(db, actor) == 'normal_user':
            owner = db.get(PersonalScan, payload.scan_id)
            if not owner or owner.username != actor:
                raise HTTPException(404, 'Scan not found')
        if not scan:
            raise HTTPException(404, 'Scan not found')
        row = UserSecurityFeedback(**payload.model_dump(), reporter=actor)
        db.add(row)
        try:
            db.flush()
            # Free text stays in the access-controlled feedback record only.
            audit(db, 'user_feedback', row.id, actor, 'submitted', scan_id=row.scan_id, category=row.category)
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, 'You already submitted feedback for this scan. Open User feedback to view its review.') from None
        return record(db, row)

    @app.get('/api/feedback')
    def listing(actor: str = Actor, db: Session = Depends(session_scope),
                status: Literal['pending', 'reviewed'] | None = None,
                limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0, le=100000)):
        query = select(UserSecurityFeedback, Scan).join(Scan, UserSecurityFeedback.scan_id == Scan.id)
        if not is_reviewer(db, actor):
            query = query.where(UserSecurityFeedback.reporter == actor)
        if status:
            query = query.where(UserSecurityFeedback.status == status)
        from alba_security.governance import privacy_settings
        show_hostnames = privacy_settings(db)['show_hostnames']
        return [record(db, row, scan, show_hostnames) for row, scan in db.execute(query.order_by(
            UserSecurityFeedback.created_at.desc(), UserSecurityFeedback.id.desc()).offset(offset).limit(limit))]

    @app.post('/api/feedback/{feedback_id}/review')
    def review(feedback_id: str, payload: FeedbackReview, actor: str = Actor, db: Session = Depends(session_scope)):
        if not is_reviewer(db, actor):
            raise HTTPException(403, 'Administrator review required')
        row = db.get(UserSecurityFeedback, feedback_id)
        if not row:
            raise HTTPException(404, 'Feedback not found')
        changed = db.execute(update(UserSecurityFeedback).where(
            UserSecurityFeedback.id == feedback_id, UserSecurityFeedback.status == 'pending',
            UserSecurityFeedback.revision == payload.expected_revision).values(
                status='reviewed', outcome=payload.outcome, review_note=payload.review_note,
                reviewed_by=actor, reviewed_at=utc_now(), revision=payload.expected_revision + 1))
        if changed.rowcount != 1:
            db.rollback()
            raise HTTPException(409, 'This feedback was already reviewed or changed. Refresh the list.')
        audit(db, 'user_feedback', feedback_id, actor, 'reviewed', scan_id=row.scan_id, outcome=payload.outcome)
        db.commit()
        db.refresh(row)
        return record(db, row)
