"""ExtSecure VirusTotal API with optional administrator monitoring."""

from __future__ import annotations

import logging
import hashlib
import hmac
import os
import secrets
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from urllib.parse import urlsplit, urlunsplit

from app.config import get_settings
from app.services.cache import TTLCache
from app.services.virustotal import (
    AnalysisTimeoutError,
    InvalidAPIKeyError,
    InvalidTargetError,
    NotFoundError,
    RateLimitError,
    ScanResult,
    UpstreamError,
    VirusTotalClient,
    VirusTotalError,
)

settings = get_settings()
logger = logging.getLogger(__name__)
_MONITOR_REQUIRED = (
    "DATABASE_URL",
    "ADMIN_USERNAME",
    "ADMIN_PASSWORD_HASH",
    "ADMIN_TOTP_SECRET",
)


@asynccontextmanager
async def lifespan(application: FastAPI):
    application.state.vt = VirusTotalClient(settings.vt_api_key)
    application.state.cache = TTLCache[ScanResult](settings.cache_ttl_seconds)
    try:
        async with AsyncExitStack() as stack:
            monitor = application.state.monitoring_app
            if monitor is not None:
                await stack.enter_async_context(monitor.router.lifespan_context(monitor))
            yield
    finally:
        await application.state.vt.aclose()


class ScanRequest(BaseModel):
    """Request body for submitting a target to be scanned."""

    target: str = Field(..., min_length=1, description="URL, file hash, or IP address")
    scan_type: Literal["url", "hash", "ip"] = Field(
        default="url", description="Type of scan: 'url', 'hash', or 'ip'"
    )


class ScanResponse(BaseModel):
    """Preserved public scan response contract."""

    target: str
    scan_type: Literal["url", "hash", "ip"]
    verdict: Literal["malicious", "suspicious", "harmless"]
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    cached: bool


class HealthResponse(BaseModel):
    status: str
    service: str


class ExtensionScanRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    target: str = Field(min_length=1, max_length=4096)

    @field_validator('target')
    @classmethod
    def private_url(cls, value):
        try:
            parsed = urlsplit(value)
            if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
                raise ValueError()
            if parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError()
            parsed.port
        except ValueError:
            raise ValueError('Use an HTTP(S) URL without credentials, query strings or fragments') from None
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or '/', '', ''))


def _extension_record(monitor, target, verdict, actor, device_id=None):
    from alba_security.models import PersonalScan
    payload = _monitoring_payload(ScanRequest(target=target), verdict)
    payload = payload.model_copy(update={
        'device_id': 'user-'+hashlib.sha256(actor.encode()).hexdigest()[:32],
        'device_name': 'ExtSecure browser checks', 'extension_key': 'extsecure-browser',
        'extension_name': 'ExtSecure', 'extension_version': '0.7.4',
    })
    with monitor.state.session_factory() as db:
        from alba_security.inventory import scan_device_fields
        payload = payload.model_copy(update=scan_device_fields(db, device_id))
        result = monitor.state.record_scan(payload, db, notify=True, actor=actor)
        db.add(PersonalScan(scan_id=result['id'], username=actor))
        db.commit()
        return result


async def extension_scan(body: ExtensionScanRequest, request: Request):
    monitor = request.app.state.monitoring_app
    if monitor is None:
        raise HTTPException(503, 'Approved-account monitoring must be configured before extension scans')
    # A machine ingest token cannot impersonate a signed-in extension user.
    if not request.headers.get('authorization', '').startswith('Bearer '):
        raise HTTPException(401, 'Approved account sign-in required')
    actor = await run_in_threadpool(_authorize_scan, monitor, request)
    if actor is None:
        raise HTTPException(401, 'Personal account sign-in required')
    retry_after = request.app.state.extension_scan_limit.retry_after(actor)
    if retry_after:
        raise HTTPException(429, 'Scan limit reached. Try again shortly.', headers={'Retry-After':str(retry_after)})
    cache = request.app.state.cache
    key = ('url', body.target)
    result = cache.get(key)
    cached = result is not None
    if result is None:
        try:
            result = await request.app.state.vt.scan_url(body.target)
        except VirusTotalError as error:
            if isinstance(error, InvalidTargetError):
                raise
            record = await run_in_threadpool(_extension_record, monitor, body.target, None, actor, getattr(request.state, 'inventory_device_id', None))
            record['lookup'] = {'status':'unavailable', 'reason':_ERROR_STATUS.get(type(error),(502,'Lookup unavailable'))[1]}
            return JSONResponse(record, headers={'Cache-Control':'no-store'})
        cache.set(key, result)
    record = await run_in_threadpool(_extension_record, monitor, body.target, result.verdict, actor, getattr(request.state, 'inventory_device_id', None))
    record['lookup'] = {'status':'complete', 'cached':cached, 'malicious':result.malicious,
                        'suspicious':result.suspicious, 'harmless':result.harmless, 'undetected':result.undetected}
    return JSONResponse(record, status_code=201, headers={'Cache-Control':'no-store'})


_ERROR_STATUS: dict[type[VirusTotalError], tuple[int, str]] = {
    InvalidTargetError: (422, "The target is not valid for this scan type."),
    NotFoundError: (404, "VirusTotal has no record of this target."),
    RateLimitError: (429, "VirusTotal rate limit reached. Try again shortly."),
    AnalysisTimeoutError: (504, "The scan did not finish in time. Try again."),
    InvalidAPIKeyError: (502, "Upstream authentication with VirusTotal failed."),
    UpstreamError: (502, "VirusTotal is unavailable or returned a bad response."),
}


async def virustotal_error_handler(_: Request, exc: VirusTotalError) -> JSONResponse:
    status_code, detail = _ERROR_STATUS.get(type(exc), (502, "VirusTotal error."))
    headers = {"Retry-After": "60"} if isinstance(exc, RateLimitError) else None
    return JSONResponse({"detail": detail}, status_code=status_code, headers=headers)


async def root() -> HealthResponse:
    return HealthResponse(status="ok", service="ExtSecure API")


async def health() -> HealthResponse:
    return HealthResponse(status="ok", service="ExtSecure API")


def _monitoring_payload(body: ScanRequest, verdict: str | None):
    """Translate a VirusTotal verdict into server-owned risk signals."""
    from alba_security.api import ScanCreate
    from alba_security.risk import SignalInput

    if body.scan_type == "url":
        kind = "url"
        malicious_code, suspicious_code = "malicious_url", "suspicious_url"
    elif body.scan_type == "ip":
        kind = "ip"
        malicious_code, suspicious_code = "malicious_ip", "suspicious_ip"
    else:
        kind = "download" if len(body.target) == 64 else "hash"
        malicious_code, suspicious_code = "malicious_file_hash", "suspicious_file_hash"

    if verdict is None:
        malicious_status = suspicious_status = "unknown"
    else:
        malicious_status = "detected" if verdict == "malicious" else "clear"
        suspicious_status = "detected" if verdict == "suspicious" else "clear"

    return ScanCreate(
        device_id="public-unidentified",
        device_name="Unidentified public scan",
        target_kind=kind,
        target=body.target,
        signals=[
            SignalInput(code=malicious_code, status=malicious_status),
            SignalInput(code=suspicious_code, status=suspicious_status),
        ],
    )


def _authorize_scan(monitoring_app: FastAPI, request: Request) -> str | None:
    supplied = request.headers.get('x-ingest-token', '')
    if supplied and hmac.compare_digest(supplied.encode(), monitoring_app.state.ingest_token.encode()):
        return None  # Trusted machine identity, not a personal account.
    authorization = request.headers.get('authorization', '')
    if not authorization.startswith('Bearer '):
        raise HTTPException(401, 'Approved account sign-in required')
    with monitoring_app.state.session_factory() as db:
        directory = monitoring_app.state.admin_directory
        actor = directory.actor(db, authorization[7:])
        if not actor:
            raise HTTPException(401, 'Approved account sign-in required')
        if directory.role(db, actor) not in {'head_administrator', 'administrator', 'normal_user'}:
            raise HTTPException(403, 'Your role does not permit scan submission')
        from alba_security.inventory import enforce_device
        enforce_device(db, request)
        return actor


def _record_monitoring_scan(monitoring_app: FastAPI, body: ScanRequest, verdict: str | None, owner: str | None = None, device_id: str | None = None) -> None:
    payload = _monitoring_payload(body, verdict)
    if owner:
        payload = payload.model_copy(update={'device_id':'user-'+hashlib.sha256(owner.encode()).hexdigest()[:32],
                                              'device_name':'Personal scan checks'})
    with monitoring_app.state.session_factory() as db:
        from alba_security.inventory import scan_device_fields
        payload = payload.model_copy(update=scan_device_fields(db, device_id))
        # The public endpoint has no verified device identity. Persist the scan
        # for administrators, but do not send email or webhooks for public calls.
        result = monitoring_app.state.record_scan(payload, db, notify=False, actor=owner)
        if owner:
            from alba_security.models import PersonalScan
            db.add(PersonalScan(scan_id=result['id'], username=owner))
            db.commit()


async def scan(body: ScanRequest, request: Request) -> ScanResponse:
    """Scan with VirusTotal and record its risk result when monitoring is enabled."""
    vt: VirusTotalClient = request.app.state.vt
    cache: TTLCache[ScanResult] = request.app.state.cache
    monitor: FastAPI | None = request.app.state.monitoring_app
    owner = await run_in_threadpool(_authorize_scan, monitor, request) if monitor is not None else None

    cache_key = (body.scan_type, body.target)
    result = cache.get(cache_key)
    cached = result is not None

    if result is None:
        scanners = {"url": vt.scan_url, "hash": vt.scan_hash, "ip": vt.scan_ip}
        try:
            result = await scanners[body.scan_type](body.target)
        except VirusTotalError as exc:
            if monitor is not None and not isinstance(exc, InvalidTargetError):
                try:
                    await run_in_threadpool(_record_monitoring_scan, monitor, body, None, owner, getattr(request.state, 'inventory_device_id', None))
                except Exception:
                    # The upstream error and its existing HTTP mapping take priority.
                    logger.exception("Could not record an unknown monitoring result")
            raise

    if monitor is not None:
        try:
            await run_in_threadpool(_record_monitoring_scan, monitor, body, result.verdict, owner, getattr(request.state, 'inventory_device_id', None))
        except Exception as exc:
            logger.exception("Could not record a successful monitoring result")
            raise HTTPException(status_code=503, detail="Scan result could not be recorded.") from exc

    if not cached:
        cache.set(cache_key, result)

    return ScanResponse(
        target=result.target,
        scan_type=result.scan_type,
        verdict=result.verdict,
        malicious=result.malicious,
        suspicious=result.suspicious,
        harmless=result.harmless,
        undetected=result.undetected,
        cached=cached,
    )


def create_app() -> FastAPI:
    """Build the public API and mount monitoring when its settings are present."""
    # BaseSettings reads .env for VirusTotal, while monitoring uses os.environ.
    # Load the same project file without replacing explicit process settings.
    load_dotenv(dotenv_path=Path(__file__).with_name(".env"), override=False)
    application = FastAPI(
        title="ExtSecure API",
        description="Backend API for ExtSecure, a security scanning service.",
        version="0.3.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )
    # Preserve the legacy extension API's CORS behavior. Restrict origins at
    # the deployment ingress when exposing this service outside localhost.
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    application.add_exception_handler(VirusTotalError, virustotal_error_handler)
    application.add_api_route("/", root, response_model=HealthResponse, methods=["GET"], tags=["Health"])
    application.add_api_route("/health", health, response_model=HealthResponse, methods=["GET"], tags=["Health"])
    application.add_api_route("/scan", scan, response_model=ScanResponse, methods=["POST"], tags=["Scan"])
    from alba_security.request_limits import SignInRateLimit
    application.state.extension_scan_limit = SignInRateLimit(max_attempts=12, window_seconds=60)
    application.add_api_route('/extension/scan', extension_scan, methods=['POST'], tags=['Extension'])

    application.state.monitoring_app = None
    monitoring_enabled = os.getenv("MONITORING_ENABLED", "1").strip().lower() not in {"0", "false", "off"}
    if monitoring_enabled and all(os.getenv(name) for name in _MONITOR_REQUIRED):
        from alba_security.api import create_app as create_monitoring_app

        ingest_token = os.getenv("INGEST_TOKEN") or secrets.token_urlsafe(48)
        monitor = create_monitoring_app(
            database_url=os.environ["DATABASE_URL"],
            ingest_token=ingest_token,
            vt_api_key=settings.vt_api_key,
        )
        application.state.monitoring_app = monitor
        application.mount("/monitor", monitor, name="monitor")

    return application


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
