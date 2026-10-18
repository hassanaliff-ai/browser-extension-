"""Optional VirusTotal domain evidence. Not connected to a browser endpoint.

Only a registered domain may be queried. The API key stays server-side.
Live use requires an approved licence and data-sharing decision.
"""

from __future__ import annotations

import ipaddress
import json
import re
import threading
import time
from collections import OrderedDict, deque
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

import tldextract


MAX_RESPONSE_BYTES = 1_000_000
VT_BASE_URL = "https://www.virustotal.com/api/v3/domains/"
_extract = tldextract.TLDExtract(suffix_list_urls=())


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("VirusTotal redirected the request")


_opener = build_opener(HTTPSHandler(), _NoRedirect())


def _registered_domain(value: str) -> str:
    if not isinstance(value, str) or len(value) > 253 or not re.fullmatch(r"[a-z0-9.-]+", value):
        raise ValueError("Expected an ASCII registered domain")
    labels = value.split(".")
    if any(not 1 <= len(label) <= 63 or label.startswith("-") or label.endswith("-") for label in labels):
        raise ValueError("Invalid domain label")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("IP address is not a registered domain")
    if _extract(value).top_domain_under_public_suffix != value:
        raise ValueError("Expected a registered domain, not a hostname or URL")
    return value


def _fetch_report(domain: str, api_key: str) -> dict:
    url = VT_BASE_URL + quote(domain, safe="")
    request = Request(url, headers={"Accept": "application/json", "x-apikey": api_key})
    with _opener.open(request, timeout=3) as response:
        if response.geturl() != url:
            raise ValueError("Unexpected VirusTotal response URL")
        content = response.read(MAX_RESPONSE_BYTES + 1)
        if len(content) > MAX_RESPONSE_BYTES:
            raise ValueError("VirusTotal response too large")
    result = json.loads(content)
    if not isinstance(result, dict):
        raise ValueError("VirusTotal response was not an object")
    return result


def _parse_report(domain: str, report: dict) -> dict:
    item = report.get("data") if isinstance(report, dict) else None
    if not isinstance(item, dict) or item.get("type") != "domain" or item.get("id") != domain:
        raise ValueError("Mismatched VirusTotal domain report")
    attributes = item.get("attributes")
    stats = attributes.get("last_analysis_stats") if isinstance(attributes, dict) else None
    if not isinstance(stats, dict):
        raise ValueError("Missing VirusTotal analysis statistics")
    counts = {}
    for name in ("malicious", "suspicious", "harmless", "undetected"):
        count = stats.get(name)
        if type(count) is not int or not 0 <= count <= 1000:
            raise ValueError("Invalid VirusTotal analysis count")
        counts[name] = count
    if sum(counts.values()) == 0:
        raise ValueError("No VirusTotal analysis evidence")
    return {"domain": domain, "status": "Known", **counts, "cached": False}


class VirusTotalDomainClient:
    """Bounded in-memory cache and quota guard for an explicitly enabled client."""

    def __init__(self, api_key: str | None = None, *, fetch_report=None,
                 clock=None, cache_seconds: int = 3600,
                 max_per_minute: int = 4, max_per_day: int = 500):
        self.api_key = api_key
        self.fetch_report = fetch_report or _fetch_report
        self.clock = clock or time.monotonic
        self.cache_seconds = cache_seconds
        self.max_per_minute = max_per_minute
        self.max_per_day = max_per_day
        self._cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self._minute: deque[float] = deque()
        self._day: deque[float] = deque()
        self._lock = threading.Lock()

    def lookup(self, domain: str) -> dict:
        try:
            domain = _registered_domain(domain)
        except ValueError:
            return {"domain": "", "status": "Unknown", "reason": "Invalid registered domain"}
        if not self.api_key:
            return {"domain": domain, "status": "Unknown", "reason": "Reputation source not configured"}
        now = self.clock()
        with self._lock:
            cached = self._cache.get(domain)
            if cached and now - cached[0] < self.cache_seconds:
                self._cache.move_to_end(domain)
                return {**cached[1], "cached": True}
            while self._minute and now - self._minute[0] >= 60:
                self._minute.popleft()
            while self._day and now - self._day[0] >= 86400:
                self._day.popleft()
            if len(self._minute) >= self.max_per_minute or len(self._day) >= self.max_per_day:
                return {"domain": domain, "status": "Unknown", "reason": "Reputation rate limit reached"}
            self._minute.append(now)
            self._day.append(now)
        try:
            evidence = _parse_report(domain, self.fetch_report(domain, self.api_key))
        except (HTTPError, URLError, OSError, TimeoutError, ValueError, TypeError, KeyError):
            return {"domain": domain, "status": "Unknown", "reason": "Reputation lookup failed"}
        with self._lock:
            self._cache[domain] = (now, evidence)
            self._cache.move_to_end(domain)
            if len(self._cache) > 500:
                self._cache.popitem(last=False)
        return evidence
