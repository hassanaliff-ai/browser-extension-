"""Administrator device registration and authenticated Chrome inventory snapshots.

An IP is descriptive metadata, never a credential. Device credentials are hashed
at rest and paired with an approved account session on every business request.
"""
from __future__ import annotations

import hashlib
import ipaddress
import secrets
from typing import Literal
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, select, update
from sqlalchemy.orm import Mapped, Session, mapped_column
from sqlalchemy.exc import IntegrityError

from alba_security.models import Base, Device, Extension, new_id, utc_now
from alba_security.governance import audit


class InventoryPolicy(Base):
    __tablename__ = 'inventory_policy'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enrollment_required: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class DeviceRegistration(Base):
    __tablename__ = 'device_registrations'
    device_id: Mapped[str] = mapped_column(ForeignKey('devices.id'), primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    operating_system: Mapped[str] = mapped_column(String(32), nullable=False)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    added_by: Mapped[str] = mapped_column(String(120), nullable=False)
    pairing_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    pairing_expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    chrome_extension_id: Mapped[str | None] = mapped_column(String(100))
    detected_os: Mapped[str | None] = mapped_column(String(32))
    last_sync: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class BrowserCredential(Base):
    __tablename__ = 'inventory_browser_credentials'
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey('devices.id'), nullable=False, index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class ChromeObservation(Base):
    __tablename__ = 'chrome_extension_observations'
    extension_id: Mapped[str] = mapped_column(ForeignKey('extensions.id'), primary_key=True)
    present: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_sync: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class DeviceEnrollment(Base):
    __tablename__ = 'inventory_device_enrollments'
    device_id: Mapped[str] = mapped_column(ForeignKey('devices.id'), primary_key=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(120), nullable=False)
    ip_source: Mapped[str] = mapped_column(String(24), nullable=False)


OS_NAMES = {'Windows', 'macOS', 'Linux', 'ChromeOS', 'Android', 'OpenBSD', 'Other'}
digest = lambda value: hashlib.sha256(value.encode()).hexdigest()


def iso(value):
    return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value).isoformat() if value else None


class Input(BaseModel):
    model_config = ConfigDict(extra='forbid')

    @field_validator('*', mode='before')
    @classmethod
    def trim(cls, value):
        return value.strip() if isinstance(value, str) else value


class AddDevice(Input):
    name: str = Field(min_length=2, max_length=120)
    ip_address: str = Field(min_length=3, max_length=45)
    operating_system: str = Field(max_length=32)
    reason: str = Field(min_length=8, max_length=1000)

    @field_validator('ip_address')
    @classmethod
    def valid_ip(cls, value):
        ip = ipaddress.ip_address(value)
        if ip.is_unspecified or ip.is_multicast:
            raise ValueError('Use a device IPv4 or IPv6 address')
        return ip.compressed

    @field_validator('operating_system')
    @classmethod
    def valid_os(cls, value):
        if value not in OS_NAMES:
            raise ValueError('Choose a supported operating system')
        return value


class DeviceDecision(Input):
    blocked: bool = Field(strict=True)
    expected_revision: int = Field(strict=True, ge=1)
    reason: str = Field(min_length=8, max_length=1000)


class PairCode(Input):
    expected_revision: int = Field(strict=True, ge=1)
    reason: str = Field(min_length=8, max_length=1000)


class ChromeItem(Input):
    id: str = Field(pattern=r'^[a-p]{32}$')
    name: str = Field(min_length=1, max_length=160)
    version: str = Field(min_length=1, max_length=40)


class PairBrowser(Input):
    code: str = Field(min_length=20, max_length=100)
    extension: ChromeItem
    operating_system: str = Field(max_length=32)

    _os = field_validator('operating_system')(AddDevice.valid_os.__func__)


class ChromeSnapshot(Input):
    extensions: list[ChromeItem] = Field(max_length=500)

    @field_validator('extensions')
    @classmethod
    def unique_ids(cls, items):
        if len({item.id for item in items}) != len(items):
            raise ValueError('Duplicate extension IDs')
        return items


class ConnectBrowser(Input):
    # A random key generated once by the worker makes retries idempotent.
    browser_token: str = Field(min_length=43, max_length=100, pattern=r'^[A-Za-z0-9_-]+$')
    name: str | None = Field(default=None, min_length=2, max_length=120)
    ip_address: str | None = Field(default=None, min_length=3, max_length=45)
    operating_system: str = Field(max_length=32)
    extension: ChromeItem
    initial_access: Literal['trusted', 'blocked'] | None = None

    _ip = field_validator('ip_address')(lambda value: AddDevice.valid_ip(value) if value is not None else None)
    _os = field_validator('operating_system')(AddDevice.valid_os.__func__)


def is_pending(db, row):
    enrollment = db.get(DeviceEnrollment, row.device_id) if row else None
    return bool(enrollment and enrollment.status == 'pending')


def device_metadata(db, device_id):
    row = db.get(DeviceRegistration, device_id)
    if not row:
        return {'registered': False, 'status': 'Scan record', 'ip_address': None,
                'operating_system': None, 'revision': None, 'last_sync': None}
    linked = bool(db.scalar(select(BrowserCredential).where(
        BrowserCredential.device_id == device_id, BrowserCredential.revoked.is_(False))))
    enrollment = db.get(DeviceEnrollment, device_id)
    pending = is_pending(db, row)
    return {'registered': True, 'status': 'Pending approval' if pending else 'Blocked' if row.blocked else 'Active' if linked else 'Awaiting pairing',
            'trusted': linked and not row.blocked and not pending,
            'blocked': row.blocked and not pending, 'pending': pending, 'linked': linked,
            'requested_by': enrollment.requested_by if enrollment else row.added_by,
            'ip_source': enrollment.ip_source if enrollment else 'Entered IP',
            'ip_address': None if row.ip_address == 'Not available' else row.ip_address,
            'operating_system': row.operating_system, 'detected_os': row.detected_os,
            'revision': row.revision, 'last_sync': iso(row.last_sync)}


def browser_registration(db, request):
    token = request.headers.get('x-extsecure-device', '')
    credential = db.get(BrowserCredential, digest(token)) if token and len(token) <= 256 else None
    return db.get(DeviceRegistration, credential.device_id) if credential and not credential.revoked else None


def browser_state(db, request):
    policy = db.get(InventoryPolicy, 1)
    row = browser_registration(db, request)
    return {'enrollment_required': bool(policy and policy.enrollment_required),
            'device_id': row.device_id if row else None,
            'device_name': db.get(Device, row.device_id).name if row else None,
            'blocked': bool(row and row.blocked and not is_pending(db, row)),
            'trusted': bool(row and not row.blocked and not is_pending(db, row)),
            'pending': is_pending(db, row), 'linked': bool(row)}


def enforce_device(db, request, *, role=None, route=None):
    # Authentication/recovery and inventory control remain available to avoid
    # locking administrators out of unblocking or enrolling their browser.
    if route in {'/api/admin/me', '/api/admin/logout', '/api/inventory/self', '/api/inventory/pair', '/api/inventory/connect'}:
        return None
    if role in {'head_administrator', 'administrator'} and route in {
        '/api/devices', '/api/extensions', '/api/inventory/devices',
        '/api/inventory/devices/{device_id}/status', '/api/inventory/devices/{device_id}/pairing-code'}:
        return None
    row = browser_registration(db, request)
    if is_pending(db, row):
        raise HTTPException(403, 'This device is waiting for administrator approval.')
    if row and row.blocked:
        raise HTTPException(403, 'This device is blocked. Contact an administrator.')
    policy = db.get(InventoryPolicy, 1)
    if not row and (request.headers.get('x-extsecure-device') or (policy and policy.enrollment_required)):
        raise HTTPException(403, 'Click Add this device in My account before continuing.')
    if row:
        request.state.inventory_device_id = row.device_id
    return row


def scan_device_fields(db, device_id):
    row = db.get(DeviceRegistration, device_id) if device_id else None
    if not row:
        return {}
    if row.blocked:
        raise HTTPException(403, 'This device is blocked. Contact an administrator.')
    extension = db.scalar(select(Extension).where(Extension.device_id == device_id,
                                                  Extension.extension_key == row.chrome_extension_id))
    return {'device_id': device_id, 'device_name': db.get(Device, device_id).name,
            'extension_key': row.chrome_extension_id, 'extension_name': extension.name if extension else 'ExtSecure',
            'extension_version': extension.version if extension else None}


def extension_metadata(db, extension_id):
    item = db.get(ChromeObservation, extension_id)
    return {'source': 'Chrome inventory' if item else 'Scan record',
            'status': 'Enabled' if item and item.present else 'Not in latest snapshot' if item else 'Unverified',
            'last_sync': iso(item.last_sync) if item else None}


def save_extensions(db, row, items, *, full_snapshot=False):
    now = utc_now()
    if full_snapshot:
        ids = select(Extension.id).where(Extension.device_id == row.device_id)
        db.execute(update(ChromeObservation).where(ChromeObservation.extension_id.in_(ids)).values(present=False))
    for item in items:
        extension = db.scalar(select(Extension).where(Extension.device_id == row.device_id,
                                                     Extension.extension_key == item.id))
        if not extension:
            extension = Extension(device_id=row.device_id, extension_key=item.id, name=item.name, version=item.version)
            db.add(extension)
            db.flush()
        extension.name, extension.version, extension.last_seen = item.name, item.version, now
        observation = db.get(ChromeObservation, extension.id)
        if not observation:
            observation = ChromeObservation(extension_id=extension.id)
            db.add(observation)
        observation.present, observation.last_sync = True, now
    db.get(Device, row.device_id).last_seen = now
    if full_snapshot:
        row.last_sync = now


def apply_device_decision(db, device_id, payload, actor):
    """Shared transactional device protection for inventory and incident actions."""
    result = db.execute(update(DeviceRegistration).where(DeviceRegistration.device_id == device_id,
        DeviceRegistration.revision == payload.expected_revision).values(blocked=payload.blocked,
        revision=DeviceRegistration.revision + 1))
    if result.rowcount != 1:
        raise HTTPException(409, 'Device changed or was not registered. Refresh the inventory.')
    enrollment = db.get(DeviceEnrollment, device_id)
    action = 'device_blocked' if payload.blocked else 'device_unblocked'
    if enrollment and enrollment.status in {'pending', 'rejected', 'blocked'}:
        enrollment.status = 'rejected' if payload.blocked else 'approved'
        action = 'device_rejected' if payload.blocked else 'device_approved'
    audit(db, 'inventory', device_id, actor, action, reason=payload.reason)


def install_inventory(app, session_scope, require_actor, directory):
    def pairing_code(row):
        code = secrets.token_urlsafe(24)
        row.pairing_hash = digest(code)
        row.pairing_expires = utc_now() + timedelta(minutes=30)
        return {'pairing_code': code, 'expires_at': iso(row.pairing_expires)}

    @app.get('/api/inventory/self')
    def own_browser(request: Request, actor: str = Depends(require_actor), db: Session = Depends(session_scope)):
        return browser_state(db, request)

    @app.post('/api/inventory/connect')
    def connect_browser(payload: ConnectBrowser, request: Request, actor: str = Depends(require_actor), db: Session = Depends(session_scope)):
        token_hash = digest(payload.browser_token)
        header_token = request.headers.get('x-extsecure-device')
        if header_token and header_token != payload.browser_token:
            raise HTTPException(409, 'The browser connection changed. Refresh and try again.')

        def result(row):
            return {'device_id': row.device_id, 'device_name': db.get(Device, row.device_id).name,
                    **device_metadata(db, row.device_id)}

        credential = db.get(BrowserCredential, token_hash)
        if credential:
            if credential.revoked:
                raise HTTPException(403, 'This device connection was revoked. Contact an administrator to reconnect.')
            row = db.get(DeviceRegistration, credential.device_id)
            if not row:
                raise HTTPException(409, 'Device registration is unavailable. Contact an administrator.')
            # A retry is never an unblock or an approval, even for administrators.
            if row.blocked:
                return result(row)
            changed = []
            if payload.name:
                if db.get(Device, row.device_id).name != payload.name:
                    changed.append('name')
                db.get(Device, row.device_id).name = payload.name
            if payload.ip_address:
                if row.ip_address != payload.ip_address:
                    changed.append('ip_address')
                row.ip_address = payload.ip_address
                enrollment = db.get(DeviceEnrollment, row.device_id)
                if enrollment:
                    enrollment.ip_source = 'Entered IP'
            row.detected_os = payload.operating_system
            if row.operating_system != payload.operating_system:
                changed.append('operating_system')
            row.operating_system = payload.operating_system
            if row.chrome_extension_id != payload.extension.id:
                changed.append('chrome_extension_id')
            row.chrome_extension_id = payload.extension.id
            save_extensions(db, row, [payload.extension])
            if changed:
                row.revision = DeviceRegistration.revision + 1
                audit(db, 'inventory', row.device_id, actor, 'device_details_updated', fields=changed)
            db.commit()
            db.refresh(row)
            return result(row)

        # The approved account determines enrollment privileges on the server.
        if payload.initial_access is None:
            raise HTTPException(422, 'Choose Trusted device or Blocked device before adding this device.')
        blocked_requested = payload.initial_access == 'blocked'
        approved = not blocked_requested and directory.role(db, actor) in {'head_administrator', 'administrator'}
        enrollment_status = 'blocked' if blocked_requested else 'approved' if approved else 'pending'
        name = payload.name or f'{actor} · {payload.operating_system} Chrome'[:120]
        address, source = payload.ip_address, 'Entered IP'
        if not address:
            try:
                peer = ipaddress.ip_address(request.client.host)
                if not peer.is_loopback and not peer.is_unspecified and not peer.is_multicast:
                    address, source = peer.compressed, 'Connection IP'
            except (ValueError, AttributeError):
                pass
        if not address:
            address, source = 'Not available', 'Not available'
        try:
            device = Device(id='device-'+new_id(), name=name)
            db.add(device)
            db.flush()
            row = DeviceRegistration(device_id=device.id, ip_address=address,
                operating_system=payload.operating_system, detected_os=payload.operating_system,
                chrome_extension_id=payload.extension.id, added_by=actor, blocked=not approved)
            db.add(row)
            db.add(DeviceEnrollment(device_id=device.id, requested_by=actor,
                status=enrollment_status, ip_source=source))
            db.add(BrowserCredential(token_hash=token_hash, device_id=device.id))
            policy = db.get(InventoryPolicy, 1)
            if not policy:
                policy = InventoryPolicy(id=1)
                db.add(policy)
            policy.enrollment_required = True
            save_extensions(db, row, [payload.extension])
            audit(db, 'inventory', device.id, actor, 'device_added_blocked' if blocked_requested else 'device_connected' if approved else 'device_requested', initial_access=payload.initial_access)
            db.commit()
        except IntegrityError:
            db.rollback()
            credential = db.get(BrowserCredential, token_hash)
            if credential and not credential.revoked:
                return result(db.get(DeviceRegistration, credential.device_id))
            raise HTTPException(409, 'Enrollment changed. Click Add this device again.') from None
        return result(row)

    @app.post('/api/inventory/devices', status_code=201)
    def add_device(payload: AddDevice, actor: str = Depends(require_actor), db: Session = Depends(session_scope)):
        device = Device(id='device-'+new_id(), name=payload.name)
        db.add(device)
        db.flush()
        row = DeviceRegistration(device_id=device.id, ip_address=payload.ip_address,
                                 operating_system=payload.operating_system, added_by=actor)
        db.add(row)
        policy = db.get(InventoryPolicy, 1)
        if not policy:
            policy = InventoryPolicy(id=1)
            db.add(policy)
        policy.enrollment_required = True
        code = pairing_code(row)
        audit(db, 'inventory', device.id, actor, 'device_added', reason=payload.reason)
        db.commit()
        return {'id': device.id, 'name': device.name, **device_metadata(db, device.id), **code}

    @app.post('/api/inventory/devices/{device_id}/status')
    def change_status(device_id: str, payload: DeviceDecision, actor: str = Depends(require_actor), db: Session = Depends(session_scope)):
        apply_device_decision(db, device_id, payload, actor)
        db.commit()
        return {'id': device_id, **device_metadata(db, device_id)}

    @app.post('/api/inventory/devices/{device_id}/pairing-code')
    def reissue_code(device_id: str, payload: PairCode, actor: str = Depends(require_actor), db: Session = Depends(session_scope)):
        code = secrets.token_urlsafe(24)
        expires = utc_now() + timedelta(minutes=30)
        result = db.execute(update(DeviceRegistration).where(DeviceRegistration.device_id == device_id,
            DeviceRegistration.revision == payload.expected_revision).values(pairing_hash=digest(code),
            pairing_expires=expires, revision=DeviceRegistration.revision + 1))
        if result.rowcount != 1:
            raise HTTPException(409, 'Device changed or was not registered. Refresh the inventory.')
        audit(db, 'inventory', device_id, actor, 'pairing_code_issued', reason=payload.reason)
        db.commit()
        return {'id': device_id, 'name': db.get(Device, device_id).name,
                'pairing_code': code, 'expires_at': iso(expires)}

    @app.post('/api/inventory/pair')
    def pair_browser(payload: PairBrowser, request: Request, actor: str = Depends(require_actor), db: Session = Depends(session_scope)):
        row = db.scalar(select(DeviceRegistration).where(DeviceRegistration.pairing_hash == digest(payload.code)))
        if not row or not row.pairing_expires or row.blocked:
            raise HTTPException(403, 'Pairing code is invalid, expired, or belongs to a blocked device.')
        result = db.execute(update(DeviceRegistration).where(DeviceRegistration.device_id == row.device_id,
            DeviceRegistration.pairing_hash == digest(payload.code), DeviceRegistration.pairing_expires > utc_now(),
            DeviceRegistration.blocked.is_(False)).execution_options(synchronize_session='fetch').values(pairing_hash=None, pairing_expires=None,
            chrome_extension_id=payload.extension.id, detected_os=payload.operating_system,
            revision=DeviceRegistration.revision + 1))
        if result.rowcount != 1:
            raise HTTPException(403, 'Pairing code is invalid or expired.')
        db.execute(update(BrowserCredential).where(BrowserCredential.device_id == row.device_id).values(revoked=True))
        previous_token = request.headers.get('x-extsecure-device', '')
        if previous_token and len(previous_token) <= 256:
            db.execute(update(BrowserCredential).where(BrowserCredential.token_hash == digest(previous_token)).values(revoked=True))
        token = secrets.token_urlsafe(48)
        db.add(BrowserCredential(token_hash=digest(token), device_id=row.device_id))
        save_extensions(db, row, [payload.extension])
        audit(db, 'inventory', row.device_id, actor, 'browser_paired')
        db.commit()
        return {'device_token': token, 'device_id': row.device_id, 'device_name': db.get(Device, row.device_id).name}

    @app.post('/api/inventory/sync')
    def sync_browser(payload: ChromeSnapshot, request: Request, actor: str = Depends(require_actor), db: Session = Depends(session_scope)):
        row = browser_registration(db, request)
        if not row or row.blocked:
            raise HTTPException(403, 'Link an active device before syncing Chrome inventory.')
        # The inventory API describes a client snapshot, not independent endpoint attestation.
        if row.chrome_extension_id not in {item.id for item in payload.extensions}:
            raise HTTPException(422, 'The enabled ExtSecure extension must be included in the snapshot.')
        save_extensions(db, row, payload.extensions, full_snapshot=True)
        audit(db, 'inventory', row.device_id, actor, 'chrome_inventory_synced', enabled_count=len(payload.extensions))
        db.commit()
        return {'device_id': row.device_id, 'enabled_count': len(payload.extensions), 'last_sync': iso(row.last_sync)}
