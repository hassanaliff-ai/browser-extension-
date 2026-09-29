"""Persistence models for scan results and administrator monitoring."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
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
    __table_args__ = (UniqueConstraint("device_id", "extension_key", name="uq_extension_device_key"),)

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
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), nullable=False, index=True)
    extension_id: Mapped[str | None] = mapped_column(ForeignKey("extensions.id"), index=True)
    override_id: Mapped[str | None] = mapped_column(ForeignKey("admin_overrides.id"), index=True)
    target_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    target_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    target_display: Mapped[str] = mapped_column(String(180), nullable=False)
    signals: Mapped[list] = mapped_column(JSON, nullable=False)
    score: Mapped[int | None] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(12), nullable=False)
    completeness: Mapped[str] = mapped_column(String(12), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_created_at", "created_at"),)

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
    __table_args__ = (Index("ix_alerts_status_created", "status", "created_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(12), nullable=False)
    message: Mapped[str] = mapped_column(String(300), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="open", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (Index("ix_events_created_at", "created_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(12), nullable=False)
    message: Mapped[str] = mapped_column(String(300), nullable=False)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), nullable=False, index=True)
    extension_id: Mapped[str | None] = mapped_column(ForeignKey("extensions.id"), index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
