"""Account-owned improvement suggestions with audited administrator responses."""
from datetime import datetime, timezone
import hashlib
import json
from typing import Literal
from fastapi import Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import CheckConstraint, DateTime, Index, Integer, String, Text, UniqueConstraint, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column
from alba_security.models import Base, new_id, utc_now
from alba_security.governance import audit, iso

SuggestionStatus = Literal['new', 'under_review', 'planned', 'completed', 'declined']


class UserSuggestion(Base):
    __tablename__ = 'user_suggestions'
    __table_args__ = (
        UniqueConstraint('reporter', 'content_digest', name='uq_suggestion_reporter_content'),
        CheckConstraint("category IN ('feature','interface','accessibility','other')", name='ck_suggestion_category'),
        CheckConstraint("status IN ('new','under_review','planned','completed','declined')", name='ck_suggestion_status'),
        CheckConstraint('length(title) BETWEEN 5 AND 160', name='ck_suggestion_title'),
        CheckConstraint('length(description) BETWEEN 20 AND 3000', name='ck_suggestion_description'),
        CheckConstraint('revision >= 1', name='ck_suggestion_revision'),
        CheckConstraint("(status='new' AND response IS NULL AND reviewed_by IS NULL AND reviewed_at IS NULL) OR (status<>'new' AND response IS NOT NULL AND length(response) BETWEEN 10 AND 2000 AND reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL)", name='ck_suggestion_review'),
        Index('ix_suggestion_status_created', 'status', 'created_at'),
        Index('ix_suggestion_reporter_created', 'reporter', 'created_at'),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    reporter: Mapped[str] = mapped_column(String(120))
    category: Mapped[str] = mapped_column(String(24))
    title: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text)
    content_digest: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24), default='new')
    response: Mapped[str | None] = mapped_column(Text)
    reviewed_by: Mapped[str | None] = mapped_column(String(120))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revision: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class SuggestionCreate(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    title: str = Field(min_length=5, max_length=160)
    category: Literal['feature', 'interface', 'accessibility', 'other']
    description: str = Field(min_length=20, max_length=3000)


class SuggestionReview(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    expected_revision: int = Field(strict=True, ge=1)
    status: Literal['under_review', 'planned', 'completed', 'declined']
    response: str = Field(min_length=10, max_length=2000)


def suggestion_record(row):
    def utc_iso(value):
        return iso(value.astimezone(timezone.utc) if value and value.tzinfo else value)
    return {key: getattr(row, key) for key in (
        'id', 'reporter', 'category', 'title', 'description', 'status', 'response', 'reviewed_by', 'revision')
    } | {'created_at': utc_iso(row.created_at), 'reviewed_at': utc_iso(row.reviewed_at)}


def install_user_suggestions(app, session_scope, require_actor, directory):
    Actor = Depends(require_actor)

    @app.post('/api/suggestions', status_code=201)
    def submit(payload: SuggestionCreate, actor: str = Actor, db: Session = Depends(session_scope)):
        fingerprint=hashlib.sha256(json.dumps(payload.model_dump(), sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        row=UserSuggestion(**payload.model_dump(), reporter=actor, content_digest=fingerprint)
        db.add(row)
        try:
            db.flush()
            audit(db, 'user_suggestion', row.id, actor, 'submitted', category=row.category)
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, 'You already submitted this suggestion. View its status in User suggestions.') from None
        return suggestion_record(row)

    @app.get('/api/suggestions')
    def listing(actor: str = Actor, db: Session = Depends(session_scope),
                status: SuggestionStatus | None = None,
                limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=100000)):
        query=select(UserSuggestion)
        if directory.role(db, actor) not in {'head_administrator', 'administrator'}:
            query=query.where(UserSuggestion.reporter == actor)
        if status:
            query=query.where(UserSuggestion.status == status)
        return [suggestion_record(row) for row in db.scalars(query.order_by(
            UserSuggestion.created_at.desc(), UserSuggestion.id.desc()).offset(offset).limit(limit))]

    @app.post('/api/suggestions/{suggestion_id}/review')
    def review(suggestion_id: str, payload: SuggestionReview, actor: str = Actor, db: Session = Depends(session_scope)):
        if directory.role(db, actor) not in {'head_administrator', 'administrator'}:
            raise HTTPException(403, 'Administrator review required')
        row=db.get(UserSuggestion, suggestion_id)
        if row is None:
            raise HTTPException(404, 'Suggestion not found')
        old_status=row.status
        change=db.execute(update(UserSuggestion).where(UserSuggestion.id == suggestion_id,
            UserSuggestion.revision == payload.expected_revision).values(
                status=payload.status, response=payload.response, reviewed_by=actor,
                reviewed_at=utc_now(), revision=payload.expected_revision+1))
        if change.rowcount != 1:
            db.rollback()
            raise HTTPException(409, 'This suggestion changed. Refresh before recording your response.')
        audit(db, 'user_suggestion', suggestion_id, actor, 'reviewed', before=old_status, after=payload.status)
        db.commit();db.refresh(row)
        return suggestion_record(row)
