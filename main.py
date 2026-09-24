"""SecureScope backend API.

FastAPI application exposing endpoints for scanning URLs, file hashes and
IP addresses against threat intelligence sources (currently VirusTotal).
"""

from contextlib import asynccontextmanager
from typing import Literal

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

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


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.vt = VirusTotalClient(settings.vt_api_key)
    app.state.cache = TTLCache[ScanResult](settings.cache_ttl_seconds)
    yield
    await app.state.vt.aclose()


app = FastAPI(
    title="SecureScope API",
    description="Backend API for SecureScope, a security scanning service.",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# TODO: lock this down to the extension's origin before Alba deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    """Request body for submitting a target to be scanned."""

    target: str = Field(..., min_length=1, description="URL, file hash, or IP address")
    scan_type: Literal["url", "hash", "ip"] = Field(
        default="url", description="Type of scan: 'url', 'hash', or 'ip'"
    )


class ScanResponse(BaseModel):
    """Response body returned after a scan is processed."""

    target: str
    scan_type: Literal["url", "hash", "ip"]
    verdict: Literal["malicious", "suspicious", "harmless"]
    malicious: int
    suspicious: int
    harmless: int
    undetected: int
    cached: bool


class HealthResponse(BaseModel):
    """Response body for health check endpoints."""

    status: str
    service: str


_ERROR_STATUS: dict[type[VirusTotalError], tuple[int, str]] = {
    InvalidTargetError: (422, "The target is not valid for this scan type."),
    NotFoundError: (404, "VirusTotal has no record of this target."),
    RateLimitError: (429, "VirusTotal rate limit reached. Try again shortly."),
    AnalysisTimeoutError: (504, "The scan did not finish in time. Try again."),
    InvalidAPIKeyError: (502, "Upstream authentication with VirusTotal failed."),
    UpstreamError: (502, "VirusTotal is unavailable or returned a bad response."),
}


@app.exception_handler(VirusTotalError)
async def virustotal_error_handler(_: Request, exc: VirusTotalError) -> JSONResponse:
    status_code, detail = _ERROR_STATUS.get(type(exc), (502, "VirusTotal error."))
    headers = {"Retry-After": "60"} if isinstance(exc, RateLimitError) else None
    return JSONResponse({"detail": detail}, status_code=status_code, headers=headers)


@app.get("/", response_model=HealthResponse, tags=["Health"])
async def root() -> HealthResponse:
    """Root health check endpoint."""
    return HealthResponse(status="ok", service="SecureScope API")


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health() -> HealthResponse:
    """Health check endpoint used for uptime/liveness probes."""
    return HealthResponse(status="ok", service="SecureScope API")


@app.post("/scan", response_model=ScanResponse, tags=["Scan"])
async def scan(body: ScanRequest, request: Request) -> ScanResponse:
    """Scan a URL, file hash, or IP address with VirusTotal."""
    vt: VirusTotalClient = request.app.state.vt
    cache: TTLCache[ScanResult] = request.app.state.cache

    cache_key = (body.scan_type, body.target)
    result = cache.get(cache_key)
    cached = result is not None

    if result is None:
        scanners = {"url": vt.scan_url, "hash": vt.scan_hash, "ip": vt.scan_ip}
        result = await scanners[body.scan_type](body.target)
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


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
