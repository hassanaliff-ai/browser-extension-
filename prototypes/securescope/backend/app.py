"""Local development API for SecureScope's RDAP domain-age component.

This endpoint reports evidence, not a safety verdict. Bind it to loopback for
the current prototype; authentication and deployment are later work.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import tldextract
from fastapi import FastAPI, HTTPException
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from backend.rdap_lookup import lookup_domain_age
from backend.virustotal import VirusTotalDomainClient


app = FastAPI(title="SecureScope RDAP prototype", version="0.1.0", docs_url=None)
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")


@app.get("/docs", include_in_schema=False)
def local_api_docs():
    """Serve Swagger UI without depending on an external CDN."""
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} - Swagger UI",
        swagger_js_url="/static/swagger-ui-bundle.js",
        swagger_css_url="/static/swagger-ui.css",
        swagger_favicon_url="/static/favicon.png",
    )


_extract = tldextract.TLDExtract(suffix_list_urls=())
# Deliberately has no API key. Live reputation lookups require an approved
# licence and a separate explicit configuration step.
_reputation = VirusTotalDomainClient()


class RdapRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    origin: str = Field(min_length=10, max_length=2048)


class CheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=10, max_length=2048)
    source: Literal["visited", "manual"]
    checked_at: int = Field(strict=True, ge=0)


class CheckResponse(BaseModel):
    origin: str
    severity: Literal["Low", "Medium", "High", "Critical"]
    reasons: list[str]
    lookup_status: Literal["complete", "partial"]
    cached: bool


def registered_domain_from_origin(origin: str) -> str:
    """Accept a bare HTTP(S) origin and derive its registered domain."""
    if not isinstance(origin, str) or re.search(r"[\s\x00-\x1f\x7f]", origin):
        raise ValueError("A bare HTTP(S) origin is required")
    try:
        parsed = urlsplit(origin)
        host = parsed.hostname
        port = parsed.port  # Raises ValueError for a malformed port.
    except ValueError as exc:
        raise ValueError("A bare HTTP(S) origin is required") from exc
    if (parsed.scheme not in {"http", "https"} or not host or
            parsed.username is not None or parsed.password is not None or
            parsed.path or parsed.query or parsed.fragment):
        raise ValueError("A bare HTTP(S) origin is required")
    if not re.fullmatch(r"[a-z0-9.-]+", host) or host.endswith(".") or ".." in host:
        raise ValueError("A public DNS hostname is required")
    labels = host.split(".")
    if len(host) > 253 or any(
        not 1 <= len(label) <= 63 or label.startswith("-") or label.endswith("-")
        for label in labels
    ):
        raise ValueError("A valid public DNS hostname is required")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses do not have an RDAP domain age")
    expected = f"{parsed.scheme}://{host}" + (f":{port}" if port is not None else "")
    if origin != expected:
        raise ValueError("A canonical bare origin is required")
    extracted = _extract(host)
    domain = extracted.top_domain_under_public_suffix
    if not domain:
        raise ValueError("A registered public domain is required")
    return domain


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/v1/rdap")
def rdap_evidence(request: RdapRequest) -> dict:
    try:
        domain = registered_domain_from_origin(request.origin)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    # A synchronous route runs in FastAPI's worker pool, off the event loop.
    # The lookup sends only the registered domain, never a page path or query.
    return lookup_domain_age(domain)


def _score_evidence(origin: str, rdap: dict, reputation: dict) -> CheckResponse:
    """Temporary domain-reputation policy; Hasan must approve final rules."""
    malicious = reputation["malicious"]
    suspicious = reputation["suspicious"]
    if malicious >= 2:
        severity = "High"
    elif malicious or suspicious:
        severity = "Medium"
    else:
        severity = "Low"
    if malicious or suspicious:
        reasons = [f"VirusTotal: {malicious} malicious and {suspicious} suspicious engine reports"]
    else:
        reasons = ["No malicious or suspicious VirusTotal engine reports; this does not prove safety"]
    if rdap.get("status") == "Known" and type(rdap.get("age_days")) is int:
        reasons.append(f"RDAP: domain registered {rdap['age_days']} days ago")
        status = "complete"
    else:
        reasons.append("RDAP registration age unavailable")
        status = "partial"
    return CheckResponse(origin=origin, severity=severity, reasons=reasons,
                         lookup_status=status, cached=reputation.get("cached") is True)


@app.post(
    "/api/v1/check",
    response_model=CheckResponse,
    responses={503: {"description": "Reputation evidence unavailable; no safety verdict"}},
)
def check(request: CheckRequest) -> CheckResponse:
    try:
        domain = registered_domain_from_origin(request.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    # Check reputation first. With no approved provider, avoid even an RDAP
    # network call for a request that cannot produce a scan verdict.
    reputation = _reputation.lookup(domain)
    if reputation.get("status") != "Known":
        raise HTTPException(status_code=503, detail="Reputation evidence unavailable")
    rdap = lookup_domain_age(domain)
    return _score_evidence(request.url, rdap, reputation)
