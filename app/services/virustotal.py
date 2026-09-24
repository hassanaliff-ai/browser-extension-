"""Async client for the VirusTotal v3 API."""

import asyncio
import base64
import ipaddress
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

VT_BASE_URL = "https://www.virustotal.com/api/v3"
_HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")


class VirusTotalError(Exception):
    """Base class for all VirusTotal client errors."""


class InvalidAPIKeyError(VirusTotalError):
    """VirusTotal rejected the API key (HTTP 401/403)."""


class RateLimitError(VirusTotalError):
    """VirusTotal quota or rate limit exceeded (HTTP 429)."""


class NotFoundError(VirusTotalError):
    """VirusTotal has no record of the target (HTTP 404)."""


class InvalidTargetError(VirusTotalError):
    """The target is malformed for the requested scan type."""


class AnalysisTimeoutError(VirusTotalError):
    """A submitted URL analysis did not complete in time."""


class UpstreamError(VirusTotalError):
    """VirusTotal was unreachable or returned an unexpected response."""


@dataclass(frozen=True)
class ScanResult:
    target: str
    scan_type: str
    verdict: str
    malicious: int
    suspicious: int
    harmless: int
    undetected: int


MALICIOUS_THRESHOLD = 3
SUSPICIOUS_THRESHOLD = 3


def verdict_from_stats(stats: dict[str, int]) -> str:
    malicious = stats.get("malicious", 0)
    if malicious >= MALICIOUS_THRESHOLD:
        return "malicious"
    if malicious > 0 or stats.get("suspicious", 0) >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "harmless"


def _build_result(target: str, scan_type: str, stats: dict[str, int]) -> ScanResult:
    return ScanResult(
        target=target,
        scan_type=scan_type,
        verdict=verdict_from_stats(stats),
        malicious=stats.get("malicious", 0),
        suspicious=stats.get("suspicious", 0),
        harmless=stats.get("harmless", 0),
        undetected=stats.get("undetected", 0),
    )


class VirusTotalClient:
    def __init__(
        self,
        api_key: str,
        *,
        poll_initial_delay: float = 3.0,
        poll_max_delay: float = 10.0,
        poll_backoff: float = 1.5,
        poll_timeout: float = 60.0,
    ) -> None:
        self._client = httpx.AsyncClient(
            base_url=VT_BASE_URL,
            headers={"x-apikey": api_key, "accept": "application/json"},
            timeout=httpx.Timeout(15.0),
        )
        self._poll_initial_delay = poll_initial_delay
        self._poll_max_delay = poll_max_delay
        self._poll_backoff = poll_backoff
        self._poll_timeout = poll_timeout

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = await self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise UpstreamError(f"Could not reach VirusTotal: {exc!r}") from exc

        status = response.status_code
        if status in (401, 403):
            raise InvalidAPIKeyError("VirusTotal rejected the API key.")
        if status == 404:
            raise NotFoundError("VirusTotal has no record of this target.")
        if status == 429:
            raise RateLimitError("VirusTotal rate limit or quota exceeded.")
        if status == 400:
            raise InvalidTargetError("VirusTotal rejected the target as invalid.")
        if status >= 400:
            raise UpstreamError(f"VirusTotal returned HTTP {status}.")

        try:
            return response.json()
        except ValueError as exc:
            raise UpstreamError("VirusTotal returned a non-JSON response.") from exc

    @staticmethod
    def _stats_from(payload: dict[str, Any], key: str) -> dict[str, int]:
        try:
            return payload["data"]["attributes"][key]
        except (KeyError, TypeError) as exc:
            raise UpstreamError("Unexpected VirusTotal response shape.") from exc

    async def scan_url(self, url: str) -> ScanResult:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise InvalidTargetError("URL must be absolute and use http or https.")

        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        try:
            payload = await self._request("GET", f"/urls/{url_id}")
            stats = self._stats_from(payload, "last_analysis_stats")
        except NotFoundError:
            stats = await self._submit_and_wait(url)
        return _build_result(url, "url", stats)

    async def _submit_and_wait(self, url: str) -> dict[str, int]:
        submitted = await self._request("POST", "/urls", data={"url": url})
        try:
            analysis_id = submitted["data"]["id"]
        except (KeyError, TypeError) as exc:
            raise UpstreamError("Unexpected VirusTotal submission response.") from exc

        deadline = time.monotonic() + self._poll_timeout
        delay = self._poll_initial_delay
        while True:
            await asyncio.sleep(delay)
            payload = await self._request("GET", f"/analyses/{analysis_id}")
            attributes = payload.get("data", {}).get("attributes", {})
            if attributes.get("status") == "completed":
                return self._stats_from(payload, "stats")
            if time.monotonic() + delay >= deadline:
                raise AnalysisTimeoutError(
                    "VirusTotal analysis did not complete in time."
                )
            delay = min(delay * self._poll_backoff, self._poll_max_delay)

    async def scan_hash(self, file_hash: str) -> ScanResult:
        if not _HASH_RE.match(file_hash):
            raise InvalidTargetError("Hash must be a valid MD5, SHA-1, or SHA-256.")
        payload = await self._request("GET", f"/files/{file_hash}")
        stats = self._stats_from(payload, "last_analysis_stats")
        return _build_result(file_hash, "hash", stats)

    async def scan_ip(self, ip: str) -> ScanResult:
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise InvalidTargetError("Target is not a valid IP address.") from exc
        payload = await self._request("GET", f"/ip_addresses/{ip}")
        stats = self._stats_from(payload, "last_analysis_stats")
        return _build_result(ip, "ip", stats)
