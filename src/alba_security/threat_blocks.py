"""Evidence-backed containment; approvals and notification exceptions cannot bypass it."""
from __future__ import annotations

import hashlib
from datetime import datetime
from urllib.parse import urlsplit
import idna
from fastapi import Depends, HTTPException
from pydantic import Field
from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String, select, update
from sqlalchemy.orm import Mapped, Session, mapped_column
from alba_security.models import Base, Scan, utc_now
from alba_security.governance import IncidentCase, Reason, audit, iso


def block_identity(kind, target):
    if kind == 'url':
        host = urlsplit(target).hostname
        if not host:
            raise ValueError('Use a valid website URL')
        host = host.lower().removesuffix('.')
        if ':' not in host:
            host = idna.encode(host, uts46=True).decode('ascii')
        return 'host', hashlib.sha256(host.encode()).hexdigest(), host
    if kind in {'download', 'hash'}:
        return 'file', target.lower(), None
    return kind, hashlib.sha256(target.encode()).hexdigest(), None


class ThreatBlock(Base):
    __tablename__ = 'security_threat_blocks'
    __table_args__ = (CheckConstraint("severity IN ('High','Critical')", name='ck_threat_block_severity'),)
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey('scans.id'), nullable=False, index=True)
    target_display: Mapped[str] = mapped_column(String(180), nullable=False)
    severity: Mapped[str] = mapped_column(String(12), nullable=False)
    active: Mapped[bool] = mapped_column(default=True, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


def active_block(db, kind, target):
    category, fingerprint, _ = block_identity(kind, target)
    row = db.get(ThreatBlock, category + ':' + fingerprint)
    return row if row and row.active else None


def block_record(row, db):
    case = db.scalar(select(IncidentCase).where(IncidentCase.scan_id == row.scan_id).order_by(IncidentCase.created_at))
    return {'id': row.id, 'kind': row.kind, 'fingerprint': row.fingerprint,
            'target_display': row.target_display, 'severity': row.severity, 'active': row.active,
            'revision': row.revision, 'scan_id': row.scan_id, 'case_id': case.id if case else None,
            'case_status': case.status if case else None,
            'created_at': iso(row.created_at), 'updated_at': iso(row.updated_at)}


def contain_scan(db, scan, target, directory):
    if scan.severity not in {'High', 'Critical'}:
        return None
    category, fingerprint, host = block_identity(scan.target_kind, target)
    key = category + ':' + fingerprint
    now = utc_now()
    values = dict(id=key, kind=category, fingerprint=fingerprint, scan_id=scan.id,
                  target_display=scan.target_display, severity=scan.severity, active=True,
                  revision=1, created_at=now, updated_at=now)
    # Atomic upsert prevents concurrent scans from losing containment or revisions.
    dialect = db.bind.dialect.name
    if dialect == 'postgresql':
        from sqlalchemy.dialects.postgresql import insert
    elif dialect == 'sqlite':
        from sqlalchemy.dialects.sqlite import insert
    else:
        raise RuntimeError('Threat containment requires PostgreSQL or SQLite')
    statement = insert(ThreatBlock).values(**values)
    db.execute(statement.on_conflict_do_update(index_elements=['id'], set_={
        'scan_id': scan.id, 'target_display': scan.target_display, 'severity': scan.severity,
        'active': True, 'revision': ThreatBlock.revision + 1, 'updated_at': now}))
    db.flush()
    row = db.get(ThreatBlock, key, populate_existing=True)
    people = directory.operators(db)
    if people and not db.scalar(select(IncidentCase.id).where(IncidentCase.scan_id == scan.id)):
        owner = directory.username if directory.username in people else sorted(people)[0]
        case = IncidentCase(scan_id=scan.id, title=f'{scan.severity} threat containment investigation', assignee=owner)
        db.add(case)
        db.flush()
        audit(db, 'case', case.id, 'system', 'created', scan_id=scan.id, assignee=owner, containment=True)
    audit(db, 'containment', key, 'system', 'blocked', scan_id=scan.id, severity=scan.severity)
    return block_record(row, db) | {'host': host, 'scope': 'hostname' if host else 'fingerprint'}


class Release(Reason):
    expected_revision: int = Field(strict=True, ge=1)
    confirmed: bool = Field(strict=True)


def install_threat_blocks(app, session_scope, require_actor):
    Actor = Depends(require_actor)
    DB = Depends(session_scope)

    @app.get('/api/threat-blocks')
    def blocks(actor: str = Actor, db: Session = DB):
        return [block_record(row, db) for row in db.scalars(select(ThreatBlock).order_by(ThreatBlock.updated_at.desc()).limit(500))]

    @app.post('/api/threat-blocks/{block_id}/release')
    def release(block_id: str, body: Release, actor: str = Actor, db: Session = DB):
        if not body.confirmed:
            raise HTTPException(422, 'Confirm the investigation supports releasing this threat block')
        row = db.get(ThreatBlock, block_id)
        if not row:
            raise HTTPException(404, 'Threat block not found')
        case = db.scalar(select(IncidentCase).where(IncidentCase.scan_id == row.scan_id, IncidentCase.status == 'resolved'))
        if not case:
            raise HTTPException(409, 'Resolve the latest linked investigation before releasing its block')
        changed = db.execute(update(ThreatBlock).where(ThreatBlock.id == block_id,
            ThreatBlock.revision == body.expected_revision, ThreatBlock.active.is_(True)).values(
                active=False, revision=ThreatBlock.revision + 1, updated_at=utc_now()))
        if changed.rowcount != 1:
            db.rollback()
            raise HTTPException(409, 'Threat evidence changed; refresh before releasing')
        audit(db, 'containment', block_id, actor, 'released', reason=body.reason, case_id=case.id)
        db.commit()
        db.refresh(row)
        return block_record(row, db)
