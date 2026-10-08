"""Ingestion and administrator API for security monitoring.

The extension supplies check outcomes. This service owns the risk policy,
stores only privacy-preserving target identifiers, and records each scan and
its threat events in one transaction.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Callable, Literal
from urllib.parse import urlsplit

import httpx
import idna
from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile, status
from pydantic import BaseModel, Field, ValidationError, field_validator
from sqlalchemy import case, create_engine, event, func, select, update
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from alba_security.admin_auth import AdminAuth, AdminLoginChallenge, AuthenticationError, AuthenticationLocked, _digest
from alba_security.admin_directory import AdminDirectory
from alba_security.registration import install_registration
from alba_security.intelligence import install_intelligence
from alba_security.website_access import install_website_access
from alba_security.inventory import (install_inventory, enforce_device, browser_state,
    device_metadata, extension_metadata, scan_device_fields, DeviceRegistration)
from alba_security.governance import active_policy, audit, initialize_governance, install_governance, privacy_settings
from alba_security.overrides import (
    Override, OverrideAudit, create_override, deactivate_override, list_overrides, match_override,
)
from alba_security.models import Alert, Base, Device, Extension, Finding, Scan, SecurityEvent, utc_now
from alba_security.file_lookup import lookup_file_hash
from alba_security.notifications import send_high_severity_alert
from alba_security.notifications import EmailSender, NotificationSettings
from alba_security.report_job import MonthlyReportRecord, dispatch_monthly_report, prepare_monthly_report
from alba_security.reports import (
    ReportConfigurationError, ReportGenerationError, aggregate_month,
)
from alba_security.request_limits import DownloadRequestLimit, SignInRateLimit
from alba_security.schema import ensure_schema
from alba_security.risk import RiskFinding, RiskResult, SignalInput, assess, suggested_action


Severity = Literal["Unknown", "Low", "Medium", "High", "Critical"]
SEVERITIES: tuple[Severity, ...] = ("Unknown", "Low", "Medium", "High", "Critical")
SEVERITY_RANK = {label: rank for rank, label in enumerate(SEVERITIES)}
SAFE_ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"


class ScanCreate(BaseModel):
    device_id: str = Field(min_length=1, max_length=100, pattern=SAFE_ID)
    device_name: str = Field(min_length=1, max_length=120)
    extension_key: str | None = Field(default=None, min_length=1, max_length=100, pattern=SAFE_ID)
    extension_name: str | None = Field(default=None, min_length=1, max_length=160)
    extension_version: str | None = Field(default=None, max_length=40)
    target_kind: Literal["url", "ip", "hash", "download", "extension"]
    target: str = Field(min_length=1, max_length=4096)
    signals: list[SignalInput] = Field(default_factory=list, max_length=11)


class DownloadScanCreate(BaseModel):
    device_id: str = Field(min_length=1, max_length=100, pattern=SAFE_ID)
    device_name: str = Field(min_length=1, max_length=120)
    extension_key: str | None = Field(default=None, min_length=1, max_length=100, pattern=SAFE_ID)
    extension_name: str | None = Field(default=None, min_length=1, max_length=160)
    extension_version: str | None = Field(default=None, max_length=40)
    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")


class AdminLogin(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=512)


class AdminVerify(BaseModel):
    challenge_token: str = Field(min_length=1, max_length=256)
    totp_code: str = Field(pattern=r"^[0-9]{6}$")


class OverrideCreate(BaseModel):
    kind: Literal["domain", "url"]
    target: str = Field(min_length=1, max_length=4096)
    reason: str = Field(min_length=1, max_length=2000)
    expires_at: datetime | None = None


class ReportPeriod(BaseModel):
    year: int = Field(strict=True, ge=2000, le=2100)
    month: int = Field(strict=True, ge=1, le=12)


class AlertStatusChange(BaseModel):
    status: Literal["open", "acknowledged", "resolved"]
    reason: str = Field(min_length=8, max_length=500)
    expected_status: Literal["open", "acknowledged", "resolved"] | None = None

    @field_validator("reason")
    @classmethod
    def meaningful_reason(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 8:
            raise ValueError("Enter a reason of at least 8 characters")
        return value


def _target_identity(kind: str, target: str) -> tuple[str, str]:
    """Return an irreversible fingerprint and a safe short display value."""
    if kind == "url":
        try:
            parsed = urlsplit(target)
            host = parsed.hostname
            if parsed.scheme not in {"http", "https"} or not host:
                raise ValueError
            # A hostname is useful to an admin without retaining paths, query
            # strings, fragments, or embedded credentials.
            host = host.lower()
            if ":" not in host:
                host = idna.encode(host, uts46=True, transitional=False).decode("ascii")
            host = host.removesuffix(".")
        except (ValueError, UnicodeError):
            raise HTTPException(status_code=422, detail="Target must be a valid HTTP(S) URL") from None
        return hashlib.sha256(target.encode("utf-8")).hexdigest(), host[:180]

    if kind == "download":
        if not re.fullmatch(r"[0-9a-fA-F]{64}", target):
            raise HTTPException(status_code=422, detail="Download target must be a SHA-256 hash")
        digest = target.lower()
        return digest, f"SHA-256 {digest[:12]}…"

    if kind == "ip":
        try:
            address = ipaddress.ip_address(target)
        except ValueError:
            raise HTTPException(status_code=422, detail="IP target must be a valid IPv4 or IPv6 address") from None
        fingerprint = hashlib.sha256(address.compressed.encode("ascii")).hexdigest()
        return fingerprint, f"IPv{address.version} {fingerprint[:12]}…"

    if kind == "hash":
        if not re.fullmatch(r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", target):
            raise HTTPException(status_code=422, detail="Hash target must be MD5, SHA-1, or SHA-256")
        digest = target.lower()
        algorithm = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}[len(digest)]
        fingerprint = hashlib.sha256(f"{algorithm}:{digest}".encode("ascii")).hexdigest()
        return fingerprint, f"{algorithm} {digest[:12]}…"

    if not re.fullmatch(SAFE_ID, target) or len(target) > 100:
        raise HTTPException(status_code=422, detail="Extension target must be a safe identifier")
    return hashlib.sha256(target.encode("utf-8")).hexdigest(), target


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _highest(scans: list[Scan]) -> Severity:
    if not scans:
        return "Unknown"
    return max((scan.severity for scan in scans), key=lambda label: SEVERITY_RANK.get(label, 0))


def _event_record(item: SecurityEvent, db: Session, context: tuple) -> dict:
    devices, scans, owners, show_hostnames = context
    device = devices.get(item.device_id)
    scan = scans.get(item.scan_id)
    ownership = owners.get(item.scan_id)
    username = item.details.get('scan_username') or (ownership.username if ownership else None)
    target = scan.target_display if scan else None
    if scan and scan.target_kind == 'url' and not show_hostnames:
        target = f'URL {scan.target_fingerprint[:12]}'
    return {
        "id": item.id,
        "event_type": item.event_type,
        "severity": item.severity,
        "message": item.message,
        "scan_id": item.scan_id,
        "device_id": item.device_id,
        "device_name": item.details.get("device_name") or (device.name if device else None),
        "username": username or item.details.get("actor"),
        "target_kind": scan.target_kind if scan else None,
        "target_display": target,
        "extension_id": item.extension_id,
        "score": item.details.get("score"),
        "completeness": item.details.get("completeness"),
        "created_at": _iso(item.created_at),
        "actor": item.details.get("actor"),
        "reason": item.details.get("reason"),
        "previous_status": item.details.get("previous_status"),
        "status": item.details.get("status"),
        "alert_id": item.details.get("alert_id"),
        "channel": item.details.get("channel"),
    }


def _report_record(item: MonthlyReportRecord) -> dict:
    return {
        "id": item.id,
        "period": item.period,
        "subject": item.subject,
        "body": item.body,
        "stats": item.stats,
        "summary_source": item.summary_source,
        "status": item.status,
        "generated_at": _iso(item.generated_at),
        "sent_at": _iso(item.sent_at) if item.sent_at else None,
        "delivery_outcomes": item.delivery_outcomes,
    }


def _event_records(items, db: Session) -> list[dict]:
    from alba_security.models import PersonalScan
    items = list(items)
    device_ids = {item.device_id for item in items if item.device_id}
    scan_ids = {item.scan_id for item in items if item.scan_id}
    devices = {row.id: row for row in db.scalars(select(Device).where(Device.id.in_(device_ids)))} if device_ids else {}
    scans = {row.id: row for row in db.scalars(select(Scan).where(Scan.id.in_(scan_ids)))} if scan_ids else {}
    owners = {row.scan_id: row for row in db.scalars(select(PersonalScan).where(PersonalScan.scan_id.in_(scan_ids)))} if scan_ids else {}
    context = (devices, scans, owners, privacy_settings(db)['show_hostnames'])
    return [_event_record(item, db, context) for item in items]


def create_app(
    database_url: str | None = None,
    ingest_token: str | None = None,
    vt_api_key: str | None = None,
    vt_client: httpx.Client | None = None,
    admin_auth: AdminAuth | None = None,
    alert_notifier: Callable[..., list[dict]] | None = None,
    notification_settings: NotificationSettings | None = None,
    report_llm_client: Any | None = None,
    report_model: str | None = None,
    report_email_sender: EmailSender | None = None,
    additional_admins: list[AdminAuth] | None = None,
) -> FastAPI:
    """Create the application, with explicit settings for deployments/tests."""
    database_url = database_url or os.getenv("DATABASE_URL")
    ingest_token = ingest_token or os.getenv("INGEST_TOKEN")
    admin_auth = admin_auth or AdminAuth.from_environment()
    admin_auth = (AdminDirectory(admin_auth, additional_admins) if additional_admins is not None
                  else AdminDirectory.configured(admin_auth))
    if alert_notifier is None:
        def alert_notifier(**kwargs):
            return send_high_severity_alert(**kwargs, settings=notification_settings)
    if not database_url:
        raise RuntimeError("DATABASE_URL is required")
    if not ingest_token:
        raise RuntimeError("INGEST_TOKEN is required")

    engine_options: dict = {"pool_pre_ping": True}
    if database_url.startswith("sqlite"):
        engine_options["connect_args"] = {"check_same_thread": False}
        if database_url in {"sqlite://", "sqlite:///:memory:"}:
            engine_options["poolclass"] = StaticPool
    engine = create_engine(database_url, **engine_options)
    if database_url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _foreign_keys(dbapi_connection, _connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    ensure_schema(engine)
    session_factory = sessionmaker(engine, expire_on_commit=False)
    with session_factory() as db:
        initialize_governance(db)
        admin_auth.initialize_accounts(db)
    app = FastAPI(title="ExtSecure Monitoring API", version="0.3.0")
    @app.middleware('http')
    async def private_api_responses(request: Request, call_next):
        response = await call_next(request)
        # Mounted applications retain the parent prefix in scope['path'].
        # Match against this application's path when deployed under /monitor.
        # Security results, case notes and reports are private too; prohibit
        # caching successes and validation/permission errors across the API.
        path = request.scope['path']
        root_path = request.scope.get('root_path', '')
        if root_path and path.startswith(root_path + '/'):
            path = path[len(root_path):]
        if path.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-store'
        return response
    # Multipart parsing can spool bytes to disk before the route sees UploadFile.
    # Allow 32 MiB of file data plus a small allowance for form headers/fields.
    app.add_middleware(DownloadRequestLimit, max_bytes=33 * 1024 * 1024)
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.admin_directory = admin_auth
    app.state.ingest_token = ingest_token
    sign_in_limit = SignInRateLimit()

    def require_sign_in_capacity(request: Request) -> None:
        # Use the connection peer, never caller-supplied forwarding headers.
        # A trusted ingress should also enforce a shared limit across workers.
        client_id = request.client.host if request.client else "unknown-peer"
        retry_after = sign_in_limit.retry_after(client_id)
        if retry_after:
            raise HTTPException(status_code=429, detail="Too many sign-in attempts. Please try again shortly.",
                                headers={"Retry-After": str(retry_after)})

    def session_scope():
        with session_factory() as session:
            yield session

    def audit_identity(db: Session, username: str | None) -> str:
        # Only server-owned account names belong in the audit. Unknown input
        # can contain a private email address or arbitrary attacker text.
        from alba_security.registration import RegisteredAdmin
        if username in admin_auth.accounts or (username and db.get(RegisteredAdmin, username)):
            return username
        return 'anonymous'

    def authentication_audit(db: Session, actor: str, action: str, **details) -> None:
        # Intentionally omit credentials, OTPs, challenge/session hashes,
        # request bodies, IP addresses and caller-controlled error messages.
        audit(db, 'authentication', 'authentication', actor, action, **details)
        db.commit()

    def require_admin(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
        db: Session = Depends(session_scope),
    ) -> str:
        prefix = "Bearer "
        if not authorization or not authorization.startswith(prefix):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Administrator sign-in required")
        token = authorization[len(prefix):]
        if not admin_auth.verify_session(db, token):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Administrator session expired")
        from alba_security.permissions import allowed
        actor = admin_auth.actor(db, token)
        role = admin_auth.role(db, actor)
        route = request.scope.get('route')
        if not allowed(role, request.method, getattr(route, 'path', '')):
            authentication_audit(db, actor, 'authorization_denied', role=role,
                                 method=request.method, route=getattr(route, 'path', ''))
            raise HTTPException(403, 'Your role does not permit this action')
        enforce_device(db, request, role=role, route=getattr(route, 'path', ''))
        return token

    def require_ingest(x_ingest_token: Annotated[str | None, Header()] = None):
        if x_ingest_token is None or not hmac.compare_digest(x_ingest_token.encode("utf-8"), ingest_token.encode("utf-8")):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid ingest token")

    def require_actor(token: str = Depends(require_admin), db: Session = Depends(session_scope)) -> str:
        actor = admin_auth.actor(db, token)
        if actor is None:
            raise HTTPException(401, "Administrator session expired")
        return actor

    install_governance(app, session_scope, require_actor, admin_auth)
    install_registration(app, session_scope, require_actor, admin_auth, require_sign_in_capacity)
    install_website_access(app, session_scope, require_actor, admin_auth)
    from alba_security.ai_jobs import install_ai_jobs
    install_ai_jobs(app, require_actor, admin_auth)
    install_intelligence(app, session_scope, require_actor, admin_auth)
    install_inventory(app, session_scope, require_actor, admin_auth)

    def scan_display(db: Session, scan: Scan) -> str:
        if scan.target_kind == "url" and not privacy_settings(db)["show_hostnames"]:
            return f"URL {scan.target_fingerprint[:12]}"
        return scan.target_display

    Admin = Depends(require_admin)
    Ingest = Depends(require_ingest)
    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/admin/login", dependencies=[Depends(require_sign_in_capacity)])
    def admin_login(payload: AdminLogin, db: Session = Depends(session_scope)) -> dict:
        actor = audit_identity(db, payload.username)
        try:
            challenge = admin_auth.begin_login(db, payload.username, payload.password)
        except AuthenticationLocked as error:
            authentication_audit(db, actor, 'authentication_locked', stage='password')
            raise HTTPException(status_code=429, detail=str(error)) from error
        except AuthenticationError as error:
            authentication_audit(db, actor, 'password_rejected')
            raise HTTPException(status_code=401, detail=str(error)) from error
        authentication_audit(db, actor, 'password_verified')
        return {"challenge_token": challenge.challenge_token, "expires_at": _iso(challenge.expires_at)}

    @app.post("/api/admin/verify", dependencies=[Depends(require_sign_in_capacity)])
    def admin_verify(payload: AdminVerify, db: Session = Depends(session_scope)) -> dict:
        challenge = db.get(AdminLoginChallenge, _digest(payload.challenge_token))
        actor = audit_identity(db, (challenge.username or admin_auth.primary.username) if challenge else None)
        try:
            session = admin_auth.complete_login(db, payload.challenge_token, payload.totp_code)
        except AuthenticationLocked as error:
            authentication_audit(db, actor, 'authentication_locked', stage='second_factor')
            raise HTTPException(status_code=429, detail=str(error)) from error
        except AuthenticationError as error:
            authentication_audit(db, actor, 'mfa_rejected')
            raise HTTPException(status_code=401, detail=str(error)) from error
        authentication_audit(db, actor, 'mfa_verified')
        return {"access_token": session.access_token, "expires_at": _iso(session.expires_at)}

    @app.get('/api/admin/me')
    def current_account(request: Request, actor: str = Depends(require_actor), db: Session = Depends(session_scope)):
        from alba_security.permissions import profile
        result = profile(actor, admin_auth.role(db, actor))
        result['inventory'] = browser_state(db, request)
        return result

    @app.post("/api/admin/logout")
    def admin_logout(
        token: str = Depends(require_admin),
        db: Session = Depends(session_scope),
    ) -> dict:
        actor = admin_auth.actor(db, token)
        admin_auth.logout(db, token)
        authentication_audit(db, actor, 'signed_out')
        return {"signed_out": True}

    def record_scan(payload: ScanCreate, db: Session, *, notify: bool = True, actor: str | None = None) -> dict:
        registration = db.get(DeviceRegistration, payload.device_id)
        if registration and registration.blocked:
            raise HTTPException(403, 'This device is blocked. Contact an administrator.')
        fingerprint, display = _target_identity(payload.target_kind, payload.target)
        policy = active_policy(db)
        if payload.target_kind == "url" and not privacy_settings(db)["show_hostnames"]:
            display = f"URL {fingerprint[:12]}"
        applied_override = None
        if payload.target_kind == "url":
            try:
                applied_override = match_override(db, payload.target)
            except ValueError as error:
                raise HTTPException(status_code=422, detail=str(error)) from error
        # Caller-supplied detail can contain private URL/file information.
        # Keep only codes and statuses and use fixed, server-owned explanations.
        safe_signals = [SignalInput(code=item.code, status=item.status) for item in payload.signals]
        try:
            result = assess(safe_signals, policy)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error

        now = utc_now()
        device = db.get(Device, payload.device_id)
        if device is None:
            device = Device(id=payload.device_id, name=payload.device_name, first_seen=now, last_seen=now)
            db.add(device)
        else:
            device.name = payload.device_name
            device.last_seen = now

        extension = None
        if payload.extension_key is not None:
            extension = db.scalar(select(Extension).where(
                Extension.device_id == payload.device_id,
                Extension.extension_key == payload.extension_key,
            ))
            if extension is None:
                extension = Extension(
                    device_id=payload.device_id,
                    extension_key=payload.extension_key,
                    name=payload.extension_name or payload.extension_key,
                    version=payload.extension_version,
                    first_seen=now,
                    last_seen=now,
                )
                db.add(extension)
                db.flush()
            else:
                extension.name = payload.extension_name or extension.name
                extension.version = payload.extension_version or extension.version
                extension.last_seen = now

        scan = Scan(
            device_id=device.id,
            extension_id=extension.id if extension else None,
            override_id=applied_override.id if applied_override else None,
            target_kind=payload.target_kind,
            target_fingerprint=fingerprint,
            target_display=display,
            signals=[item.model_dump(include={"code", "status"}) for item in safe_signals],
            score=result.score,
            severity=result.severity,
            completeness=result.completeness,
            created_at=now,
        )
        db.add(scan)
        db.flush()

        for finding in result.findings:
            db.add(Finding(
                scan_id=scan.id,
                device_id=device.id,
                extension_id=scan.extension_id,
                signal_code=finding.code,
                title=finding.title,
                detail=finding.detail,
                points=finding.points,
                severity=next(band["severity"] for band in policy["severity_bands"]
                              if band["min_score"] <= finding.points <= band["max_score"]),
                created_at=now,
            ))

        event_identity = {"device_name": device.name, "scan_username": actor}
        db.add(SecurityEvent(
            event_type="scan_completed",
            severity=result.severity,
            message=f"{payload.target_kind.capitalize()} scan completed: {result.severity} risk",
            scan_id=scan.id,
            device_id=device.id,
            extension_id=scan.extension_id,
            details={
                **event_identity,
                "actor": actor,
                "target_kind": payload.target_kind,
                "risk_policy_version": policy["version"],
                "score": result.score,
                "completeness": result.completeness,
                "detected_codes": [item.code for item in result.findings],
                "unknown_codes": result.unknown_codes,
                "override_id": scan.override_id,
            },
            created_at=now,
        ))
        if result.severity in {"High", "Critical"}:
            message = f"{result.severity} risk detected in {payload.target_kind} scan"
            alert = Alert(
                scan_id=scan.id,
                severity=result.severity,
                message=message,
                status="suppressed" if applied_override else "open",
                created_at=now,
            )
            db.add(alert)
            db.add(SecurityEvent(
                event_type="threat_detected",
                severity=result.severity,
                message=message,
                scan_id=scan.id,
                device_id=device.id,
                extension_id=scan.extension_id,
                details={
                    **event_identity,
                    "actor": actor,
                    "score": result.score,
                    "completeness": result.completeness,
                    "detected_codes": [item.code for item in result.findings],
                    "override_id": scan.override_id,
                },
                created_at=now,
            ))
            if applied_override:
                db.add(SecurityEvent(
                    event_type="notification_suppressed",
                    severity=result.severity,
                    message="External notification suppressed by administrator exception",
                    scan_id=scan.id,
                    device_id=device.id,
                    extension_id=scan.extension_id,
                    details={**event_identity, "override_id": applied_override.id},
                    created_at=now,
                ))
        db.commit()
        if notify and result.severity in {"High", "Critical"} and not applied_override:
            try:
                outcomes = alert_notifier(
                    alert_id=alert.id,
                    scan_id=scan.id,
                    severity=result.severity,
                    message=message,
                    score=result.score,
                )
            except Exception as error:
                outcomes = [{"channel": "notification", "status": "failed", "error_type": type(error).__name__}]
            for outcome in outcomes:
                db.add(SecurityEvent(
                    event_type="notification_delivery",
                    severity=result.severity,
                    message=f"{outcome.get('channel', 'notification')} notification {outcome.get('status', 'failed')}",
                    scan_id=scan.id,
                    device_id=device.id,
                    extension_id=scan.extension_id,
                    details={**outcome, **event_identity},
                    created_at=utc_now(),
                ))
            db.commit()
        return {
            "id": scan.id,
            "score": result.score,
            "severity": result.severity,
            "completeness": result.completeness,
            "findings": [item.model_dump() for item in result.findings],
            "unknown_codes": result.unknown_codes,
            "target_kind": payload.target_kind,
            "target_display": display,
            "override_id": scan.override_id,
            "risk_policy_version": policy["version"],
            "suggested_action": suggested_action(result),
        }

    app.state.record_scan = record_scan

    @app.post("/api/scans", status_code=201, dependencies=[Ingest])
    def create_scan(payload: ScanCreate, db: Session = Depends(session_scope)) -> dict:
        return record_scan(payload, db)

    def personal_download(payload: DownloadScanCreate, request: Request, db: Session) -> tuple[DownloadScanCreate, str | None]:
        # Ingestion is a separate machine identity and never claims a user scan.
        if not request.scope['route'].path.startswith('/api/admin/'):
            return payload, None
        token = request.headers.get('authorization', '')[7:]
        actor = admin_auth.actor(db, token)
        linked_device = getattr(request.state, 'inventory_device_id', None)
        if linked_device:
            payload = payload.model_copy(update=scan_device_fields(db, linked_device))
        elif admin_auth.role(db, actor) == 'normal_user':
            payload = payload.model_copy(update={
                'device_id':'user-'+hashlib.sha256(actor.encode()).hexdigest()[:32],
                'device_name':'Personal file checks', 'extension_key':None,
                'extension_name':None, 'extension_version':None})
        return payload, actor

    def _scan_download(payload: DownloadScanCreate, db: Session, owner: str | None = None) -> dict:
        registration = db.get(DeviceRegistration, payload.device_id)
        if registration and registration.blocked:
            raise HTTPException(403, 'This device is blocked. Contact an administrator.')
        verdict = lookup_file_hash(db, payload.sha256, api_key=vt_api_key, client=vt_client)
        scan_input = ScanCreate(
            device_id=payload.device_id,
            device_name=payload.device_name,
            extension_key=payload.extension_key,
            extension_name=payload.extension_name,
            extension_version=payload.extension_version,
            target_kind="download",
            target=payload.sha256,
            signals=[SignalInput(**item) for item in verdict.signals()],
        )
        result = record_scan(scan_input, db, actor=owner)
        result["file_lookup"] = verdict.public()
        if owner:
            from alba_security.models import PersonalScan
            db.add(PersonalScan(scan_id=result['id'], username=owner))
            db.commit()
        return result

    @app.post("/api/admin/downloads/scan", status_code=201, dependencies=[Admin])
    @app.post("/api/downloads/scan", status_code=201, dependencies=[Ingest])
    def scan_download_hash(payload: DownloadScanCreate, request: Request, db: Session = Depends(session_scope)) -> dict:
        """Check a downloaded file by SHA-256 without sending file bytes."""
        payload, owner = personal_download(payload, request, db)
        return _scan_download(payload, db, owner)

    @app.post("/api/admin/downloads/scan-file", status_code=201, dependencies=[Admin])
    @app.post("/api/downloads/scan-file", status_code=201, dependencies=[Ingest])
    def scan_download_file(
        request: Request,
        db: Session = Depends(session_scope),
        file: UploadFile = File(...),
        device_id: str = Form(...),
        device_name: str = Form(...),
        extension_key: str | None = Form(default=None),
        extension_name: str | None = Form(default=None),
        extension_version: str | None = Form(default=None),
    ) -> dict:
        """Hash an uploaded download and discard its temporary file bytes."""
        digest = hashlib.sha256()
        size = 0
        max_bytes = 32 * 1024 * 1024
        while chunk := file.file.read(1024 * 1024):
            size += len(chunk)
            if size > max_bytes:
                raise HTTPException(status_code=413, detail="File exceeds the 32 MB scan limit")
            digest.update(chunk)
        try:
            payload = DownloadScanCreate(
                device_id=device_id,
                device_name=device_name,
                extension_key=extension_key,
                extension_name=extension_name,
                extension_version=extension_version,
                sha256=digest.hexdigest(),
            )
        except ValidationError:
            raise HTTPException(status_code=422, detail="Invalid device or extension information") from None
        payload, owner = personal_download(payload, request, db)
        return _scan_download(payload, db, owner)

    @app.get('/api/my/scans', dependencies=[Admin])
    def personal_scans(actor: str = Depends(require_actor), db: Session = Depends(session_scope),
                       limit: int = Query(200, ge=1, le=500)):
        from alba_security.models import PersonalScan
        rows = db.scalars(select(Scan).join(PersonalScan).where(PersonalScan.username == actor)
            .order_by(Scan.created_at.desc(), Scan.id.desc()).limit(limit))
        return [{'id':row.id, 'target_display':scan_display(db,row), 'score':row.score,
            'severity':row.severity, 'completeness':row.completeness, 'created_at':_iso(row.created_at)} for row in rows]

    @app.get('/api/my/scans/{scan_id}', dependencies=[Admin])
    def personal_scan_evidence(scan_id: str, actor: str = Depends(require_actor), db: Session = Depends(session_scope)):
        from alba_security.models import PersonalScan
        ownership = db.get(PersonalScan, scan_id)
        if not ownership or ownership.username != actor:
            raise HTTPException(404, 'Personal scan not found')
        return scan_evidence(scan_id, db)

    @app.get("/api/overview", dependencies=[Admin])
    def overview(db: Session = Depends(session_scope)) -> dict:
        severity_counts = {label: 0 for label in SEVERITIES}
        for label, count in db.execute(select(Scan.severity, func.count()).group_by(Scan.severity)):
            severity_counts[label] = count
        recent = db.scalars(select(SecurityEvent).order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc()).limit(10)).all()
        today = utc_now().date()
        start = datetime.combine(today - timedelta(days=13), datetime.min.time(), tzinfo=timezone.utc)
        daily_activity = {
            (start.date() + timedelta(days=offset)).isoformat(): {"scans": 0, "high_risk": 0}
            for offset in range(14)
        }
        for created_at, label in db.execute(select(Scan.created_at, Scan.severity).where(Scan.created_at >= start)):
            day = created_at.date().isoformat()
            if day in daily_activity:
                daily_activity[day]["scans"] += 1
                daily_activity[day]["high_risk"] += int(label in {"High", "Critical"})
        return {
            "total_scans": db.scalar(select(func.count()).select_from(Scan)),
            "high_risk": severity_counts["High"] + severity_counts["Critical"],
            "open_alerts": db.scalar(select(func.count()).select_from(Alert).where(Alert.status == "open")),
            "pending_alerts": db.scalar(select(func.count()).select_from(Alert).where(Alert.status.in_(["open", "acknowledged"]))),
            "devices": db.scalar(select(func.count()).select_from(Device)),
            "extensions": db.scalar(select(func.count()).select_from(Extension)),
            "severity_counts": severity_counts,
            "recent_events": _event_records(recent, db),
            "daily_activity": [{"date": day, **totals} for day, totals in daily_activity.items()],
        }

    @app.get("/api/risk-policy", dependencies=[Admin])
    def current_risk_policy(db: Session = Depends(session_scope)) -> dict:
        return active_policy(db)

    @app.get("/api/devices", dependencies=[Admin])
    def devices(db: Session = Depends(session_scope)) -> list[dict]:
        risk_rank = case(*((Scan.severity == label, rank) for label, rank in SEVERITY_RANK.items()), else_=0)
        totals = select(Scan.device_id.label("device_id"), func.count().label("scans"),
                        func.max(risk_rank).label("risk_rank")).group_by(Scan.device_id).subquery()
        ranks = {rank: label for label, rank in SEVERITY_RANK.items()}
        rows = db.execute(select(Device, totals.c.scans, totals.c.risk_rank)
                          .outerjoin(totals, Device.id == totals.c.device_id).order_by(Device.last_seen.desc())).all()
        return [
            {
                "id": item.id,
                "name": item.name,
                "last_seen": _iso(item.last_seen),
                "scan_count": scan_count or 0,
                "highest_severity": ranks.get(rank, "Unknown"),
                **device_metadata(db, item.id),
            }
            for item, scan_count, rank in rows
        ]

    @app.get("/api/extensions", dependencies=[Admin])
    def extensions(db: Session = Depends(session_scope)) -> list[dict]:
        risk_rank = case(*((Scan.severity == label, rank) for label, rank in SEVERITY_RANK.items()), else_=0)
        totals = select(Scan.extension_id.label("extension_id"), func.count().label("scans"),
                        func.max(risk_rank).label("risk_rank")).where(Scan.extension_id.is_not(None)).group_by(Scan.extension_id).subquery()
        ranks = {rank: label for label, rank in SEVERITY_RANK.items()}
        rows = db.execute(select(Extension, totals.c.scans, totals.c.risk_rank)
                          .outerjoin(totals, Extension.id == totals.c.extension_id).order_by(Extension.last_seen.desc())).all()
        return [
            {
                "id": item.id,
                "name": item.name,
                "version": item.version,
                "extension_key": item.extension_key,
                "device_name": db.get(Device, item.device_id).name,
                **extension_metadata(db, item.id),
                "device_id": item.device_id,
                "last_seen": _iso(item.last_seen),
                "scan_count": scan_count or 0,
                "highest_severity": ranks.get(rank, "Unknown"),
            }
            for item, scan_count, rank in rows
        ]

    @app.get("/api/findings", dependencies=[Admin])
    def findings(db: Session = Depends(session_scope), limit: int = Query(default=200, ge=1, le=500)) -> list[dict]:
        items = db.scalars(select(Finding).order_by(Finding.created_at.desc(), Finding.id.desc()).limit(limit)).all()
        return [
            {
                "id": item.id,
                "scan_id": item.scan_id,
                "device_id": item.device_id,
                "extension_id": item.extension_id,
                "signal_code": item.signal_code,
                "title": item.title,
                "detail": item.detail,
                "points": item.points,
                "severity": item.severity,
                "created_at": _iso(item.created_at),
            }
            for item in items
        ]

    @app.get("/api/scans", dependencies=[Admin])
    def scans(db: Session = Depends(session_scope), limit: int = Query(default=200, ge=1, le=500)) -> list[dict]:
        items = db.scalars(select(Scan).order_by(Scan.created_at.desc(), Scan.id.desc()).limit(limit)).all()
        finding_codes: dict[str, list[str]] = defaultdict(list)
        if items:
            for scan_id, code in db.execute(
                select(Finding.scan_id, Finding.signal_code)
                .where(Finding.scan_id.in_([item.id for item in items]))
                .order_by(Finding.created_at, Finding.id)
            ):
                finding_codes[scan_id].append(code)
        return [
            {
                "id": item.id,
                "device_id": item.device_id,
                "extension_id": item.extension_id,
                "override_id": item.override_id,
                "target_kind": item.target_kind,
                "target_display": scan_display(db, item),
                "score": item.score,
                "severity": item.severity,
                "completeness": item.completeness,
                "finding_codes": finding_codes[item.id],
                "created_at": _iso(item.created_at),
            }
            for item in items
        ]

    @app.get("/api/scans/{scan_id}", dependencies=[Admin])
    def scan_evidence(scan_id: str, db: Session = Depends(session_scope)) -> dict:
        item = db.get(Scan, scan_id)
        if item is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        findings = db.scalars(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.points.desc())).all()
        events = db.scalars(select(SecurityEvent).where(SecurityEvent.scan_id == scan_id).order_by(SecurityEvent.created_at, SecurityEvent.id)).all()
        version = next((event.details.get("risk_policy_version") for event in events
                        if event.event_type == "scan_completed"), None)
        unknown_codes = [signal["code"] for signal in item.signals if signal.get("status") == "unknown"]
        stored_result = RiskResult(score=item.score, severity=item.severity, completeness=item.completeness,
                                   findings=[RiskFinding(code=row.signal_code, title=row.title,
                                                         detail=row.detail or "", points=row.points) for row in findings],
                                   unknown_codes=unknown_codes)
        return {
            "id": item.id, "device_id": item.device_id, "extension_id": item.extension_id,
            "target_kind": item.target_kind, "target_display": scan_display(db, item),
            "score": item.score, "severity": item.severity, "completeness": item.completeness,
            "override_id": item.override_id, "created_at": _iso(item.created_at),
            "risk_policy_version": version or "legacy", "suggested_action": suggested_action(stored_result),
            "signals": item.signals, "unknown_codes": unknown_codes,
            "findings": [{"code": row.signal_code, "title": row.title, "detail": row.detail,
                          "points": row.points, "severity": row.severity} for row in findings],
            "events": _event_records(events, db),
        }

    @app.get("/api/overrides", dependencies=[Admin])
    def overrides(db: Session = Depends(session_scope)) -> list[dict]:
        now = utc_now()
        return [
            {
                "id": item.id,
                "kind": item.kind,
                "target_display": item.target_display,
                "match_key": item.match_key,
                "reason": item.reason,
                "active": item.active,
                "effective": item.active and (item.expires_at is None or
                    (item.expires_at.replace(tzinfo=timezone.utc) if item.expires_at.tzinfo is None else item.expires_at) > now),
                "created_by": item.created_by,
                "created_at": _iso(item.created_at),
                "expires_at": _iso(item.expires_at) if item.expires_at else None,
                "deactivated_by": item.deactivated_by,
                "deactivated_at": _iso(item.deactivated_at) if item.deactivated_at else None,
            }
            for item in list_overrides(db)
        ]

    @app.post("/api/overrides", status_code=201, dependencies=[Admin])
    def add_override(payload: OverrideCreate, actor: str = Depends(require_actor), db: Session = Depends(session_scope)) -> dict:
        expiry = payload.expires_at or utc_now() + timedelta(days=30)
        if expiry.tzinfo is None or expiry > utc_now() + timedelta(days=90):
            raise HTTPException(status_code=422, detail="Exception expiry must include a timezone and be within 90 days")
        try:
            item = create_override(
                db, payload.kind, payload.target, payload.reason,
                actor, expires_at=expiry,
            )
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        db.commit()
        return {"id": item.id, "kind": item.kind, "target_display": item.target_display,
                "reason": item.reason, "expires_at": _iso(item.expires_at)}

    @app.post("/api/overrides/{override_id}/deactivate", dependencies=[Admin])
    def remove_override(override_id: str, actor: str = Depends(require_actor), db: Session = Depends(session_scope)) -> dict:
        try:
            item = deactivate_override(db, override_id, actor)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        db.commit()
        return {"id": item.id, "active": item.active, "deactivated_at": _iso(item.deactivated_at)}

    @app.get("/api/overrides/audit", dependencies=[Admin])
    def override_audit(db: Session = Depends(session_scope), limit: int = Query(default=200, ge=1, le=500)) -> list[dict]:
        items = db.scalars(select(OverrideAudit).order_by(OverrideAudit.created_at.desc()).limit(limit)).all()
        return [{
            "id": item.id,
            "override_id": item.override_id,
            "action": item.action,
            "actor": item.actor,
            "details": item.details,
            "created_at": _iso(item.created_at),
        } for item in items]

    @app.get("/api/reports/monthly/stats", dependencies=[Admin])
    def monthly_stats(
        db: Session = Depends(session_scope),
        year: int = Query(ge=2000, le=2100),
        month: int = Query(ge=1, le=12),
    ) -> dict:
        return aggregate_month(db, year, month)

    @app.get("/api/reports/monthly/ml", dependencies=[Admin])
    def monthly_machine_learning(year: int = Query(ge=2000, le=2100),
                                 month: int = Query(ge=1, le=12), db: Session = Depends(session_scope)):
        if (year, month) >= (utc_now().year, utc_now().month):
            raise HTTPException(422, "Monthly machine learning requires a completed UTC month")
        from alba_security.monthly_ml import analyze_month
        return analyze_month(db, year, month)

    @app.get("/api/reports/monthly", dependencies=[Admin])
    def monthly_reports(db: Session = Depends(session_scope)) -> list[dict]:
        items = db.scalars(select(MonthlyReportRecord).order_by(MonthlyReportRecord.period.desc())).all()
        return [_report_record(item) for item in items]

    @app.post("/api/reports/monthly/generate", status_code=201, dependencies=[Admin])
    def generate_report(payload: ReportPeriod, request: Request, actor: str = Depends(require_actor), db: Session = Depends(session_scope)):
        current = utc_now()
        if (payload.year, payload.month) >= (current.year, current.month):
            raise HTTPException(status_code=422, detail="Monthly reports require a completed UTC month")
        if request is not None and request.headers.get('prefer') == 'respond-async':
            return app.state.submit_ai_job(actor, '/api/reports/monthly/generate',
                lambda fresh: generate_report(payload, None, actor, fresh))
        try:
            record = prepare_monthly_report(
                db, payload.year, payload.month,
                llm_client=report_llm_client, model=report_model,
            )
        except ReportConfigurationError as error:
            raise HTTPException(status_code=503, detail=str(error)) from error
        except ReportGenerationError as error:
            raise HTTPException(status_code=502, detail=str(error)) from error
        return _report_record(record)

    @app.post("/api/reports/monthly/{period}/send", dependencies=[Admin])
    def send_report(period: str, db: Session = Depends(session_scope)) -> dict:
        if not re.fullmatch(r"20[0-9]{2}-(0[1-9]|1[0-2])", period):
            raise HTTPException(status_code=422, detail="Period must use YYYY-MM")
        record = db.scalar(select(MonthlyReportRecord).where(MonthlyReportRecord.period == period))
        if record is None:
            raise HTTPException(status_code=404, detail="Monthly report not found")
        sent = dispatch_monthly_report(
            db, record, settings=notification_settings, email_sender=report_email_sender,
        )
        return _report_record(sent)

    @app.get("/api/alerts", dependencies=[Admin])
    def alerts(db: Session = Depends(session_scope), limit: int = Query(default=200, ge=1, le=500)) -> list[dict]:
        items = db.scalars(select(Alert).order_by(Alert.created_at.desc(), Alert.id.desc()).limit(limit)).all()
        return [
            {
                "id": item.id,
                "scan_id": item.scan_id,
                "severity": item.severity,
                "message": item.message,
                "status": item.status,
                "created_at": _iso(item.created_at),
            }
            for item in items
        ]

    @app.post("/api/alerts/{alert_id}/status", dependencies=[Admin])
    def change_alert_status(alert_id: str, payload: AlertStatusChange, actor: str = Depends(require_actor), db: Session = Depends(session_scope)) -> dict:
        alert = db.get(Alert, alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        previous = alert.status
        if previous == "suppressed":
            raise HTTPException(status_code=409, detail="This alert was suppressed by an exception. Review the exception before running a new scan.")
        if payload.expected_status is not None and payload.expected_status != previous:
            raise HTTPException(status_code=409, detail="The alert changed since it was loaded. Refresh and review its current status.")
        if payload.status == previous:
            return {"id": alert.id, "status": previous, "changed": False}
        scan = db.get(Scan, alert.scan_id)
        changed = db.execute(update(Alert).where(Alert.id == alert.id, Alert.status == previous)
                             .values(status=payload.status))
        if changed.rowcount != 1:
            db.rollback()
            raise HTTPException(status_code=409, detail="The alert changed since it was loaded. Refresh and try again.")
        db.add(SecurityEvent(
            event_type="alert_status_changed", severity=alert.severity,
            message=f"Alert status changed from {previous} to {payload.status}",
            scan_id=scan.id, device_id=scan.device_id, extension_id=scan.extension_id,
            details={"alert_id": alert.id, "previous_status": previous, "status": payload.status,
                     "actor": actor, "reason": payload.reason,
                     "score": scan.score, "completeness": scan.completeness},
            created_at=utc_now(),
        ))
        db.commit()
        return {"id": alert.id, "status": payload.status, "changed": True}

    @app.get("/api/events", dependencies=[Admin])
    def events(db: Session = Depends(session_scope), limit: int = Query(default=200, ge=1, le=500)) -> list[dict]:
        items = db.scalars(select(SecurityEvent).order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc()).limit(limit)).all()
        return _event_records(items, db)

    return app
