"""Persistence models for scan results and administrator monitoring."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid4())


class Base(DeclarativeBase):
    pass


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class Extension(Base):
    __tablename__ = "extensions"
    __table_args__ = (
        UniqueConstraint("device_id", "extension_key", name="uq_extension_device_key"),
        UniqueConstraint('id', 'device_id', name='uq_extensions_id_device'),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), nullable=False, index=True)
    extension_key: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    version: Mapped[str | None] = mapped_column(String(40))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_created_at", "created_at"),
        Index("ix_scans_severity_created", "severity", "created_at"),
        Index('ix_scans_domain_created', 'domain_id', 'created_at'),
        Index('ix_scans_device_history', 'device_id', 'created_at', 'id'),
        Index('ix_scans_history_cursor', 'created_at', 'id'),
        UniqueConstraint('id', 'device_id', name='uq_scans_id_device'),
        UniqueConstraint('id', 'extension_id', name='uq_scans_id_extension'),
        ForeignKeyConstraint(['extension_id', 'device_id'], ['extensions.id', 'extensions.device_id'],
                             name='fk_scans_extension_device'),
        CheckConstraint("score IS NULL OR (score >= 0 AND score <= 100)",name='ck_scans_score_range'),
        CheckConstraint("severity IN ('Unknown','Low','Medium','High','Critical')",name='ck_scans_severity'),
        CheckConstraint("completeness IN ('complete','partial','unknown')",name='ck_scans_completeness'),
        CheckConstraint("target_kind IN ('url','ip','hash','download','extension')",name='ck_scans_target_kind'),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), nullable=False, index=True)
    extension_id: Mapped[str | None] = mapped_column(ForeignKey("extensions.id"), index=True)
    domain_id: Mapped[str | None] = mapped_column(ForeignKey('domains.id'), index=True)
    risk_policy_version: Mapped[str | None] = mapped_column(String(80))
    override_id: Mapped[str | None] = mapped_column(ForeignKey("admin_overrides.id"), index=True)
    target_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    target_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    target_display: Mapped[str] = mapped_column(String(180), nullable=False)
    signals: Mapped[list] = mapped_column(JSON, nullable=False)
    score: Mapped[int | None] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(12), nullable=False)
    completeness: Mapped[str] = mapped_column(String(12), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class PersonalScan(Base):
    __tablename__ = 'personal_scan_ownership'
    scan_id: Mapped[str] = mapped_column(ForeignKey('scans.id', ondelete='CASCADE'), primary_key=True)
    username: Mapped[str] = mapped_column(String(120), index=True, nullable=False)


class Domain(Base):
    """Canonical hosts only: never URL paths, queries, credentials or fragments."""
    __tablename__ = 'domains'
    __table_args__ = (
        CheckConstraint('length(hostname) > 0',name='ck_domains_hostname_nonempty'),
        CheckConstraint('last_seen >= first_seen', name='ck_domains_time_order'),
    )
    id: Mapped[str] = mapped_column(String(36),primary_key=True,default=new_id)
    hostname: Mapped[str] = mapped_column(String(253),unique=True,nullable=False,index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True),default=utc_now,nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True),default=utc_now,nullable=False,index=True)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_created_at", "created_at"),
        ForeignKeyConstraint(['scan_id', 'device_id'], ['scans.id', 'scans.device_id'],
                             name='fk_findings_scan_device'),
        ForeignKeyConstraint(['scan_id', 'extension_id'], ['scans.id', 'scans.extension_id'],
                             name='fk_findings_scan_extension'),
        CheckConstraint('points >= 0 AND points <= 100', name='ck_findings_points_range'),
        CheckConstraint("severity IN ('Unknown','Low','Medium','High','Critical')", name='ck_findings_severity'),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), nullable=False, index=True)
    extension_id: Mapped[str | None] = mapped_column(ForeignKey("extensions.id"), index=True)
    signal_code: Mapped[str] = mapped_column(String(60), nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    points: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(12), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_status_created", "status", "created_at"),
        CheckConstraint("status IN ('open','acknowledged','resolved','suppressed')", name='ck_alerts_status'),
        CheckConstraint("severity IN ('Unknown','Low','Medium','High','Critical')", name='ck_alerts_severity'),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(12), nullable=False)
    message: Mapped[str] = mapped_column(String(300), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="open", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_events_created_at", "created_at"),
        ForeignKeyConstraint(['scan_id', 'device_id'], ['scans.id', 'scans.device_id'],
                             name='fk_events_scan_device'),
        ForeignKeyConstraint(['scan_id', 'extension_id'], ['scans.id', 'scans.extension_id'],
                             name='fk_events_scan_extension'),
        CheckConstraint("severity IN ('Unknown','Low','Medium','High','Critical')", name='ck_events_severity'),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(12), nullable=False)
    message: Mapped[str] = mapped_column(String(300), nullable=False)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), nullable=False, index=True)
    extension_id: Mapped[str | None] = mapped_column(ForeignKey("extensions.id"), index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
