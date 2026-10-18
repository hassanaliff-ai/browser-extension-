"""Look up a registered domain's age using the IANA RDAP bootstrap registry.

The caller must supply the registered domain (for example, example.co.uk),
not a URL or an arbitrary hostname. Domain extraction belongs in the backend
and must use a maintained Public Suffix List implementation.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from functools import lru_cache
from urllib.parse import quote, urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener


BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
MAX_RESPONSE_BYTES = 2_000_000
TIMEOUT_SECONDS = 5


class _HTTPSOnlyRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _safe_https_url(newurl):
            raise ValueError("RDAP redirect did not use a public HTTPS host")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_opener = build_opener(HTTPSHandler(), _HTTPSOnlyRedirect())


def _safe_https_url(value: str) -> bool:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return False
    if parsed.hostname == "localhost" or parsed.hostname.endswith(".localhost"):
        return False
    try:
        return ipaddress.ip_address(parsed.hostname).is_global
    except ValueError:
        return True


def _fetch_json(url: str) -> dict:
    if not _safe_https_url(url):
        raise ValueError("RDAP request did not use a public HTTPS host")
    request = Request(url, headers={"Accept": "application/rdap+json, application/json"})
    with _opener.open(request, timeout=TIMEOUT_SECONDS) as response:
        if not _safe_https_url(response.geturl()):
            raise ValueError("RDAP response came from an unsafe URL")
        data = response.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            raise ValueError("RDAP response too large")
    result = json.loads(data)
    if not isinstance(result, dict):
        raise ValueError("RDAP response was not an object")
    return result


@lru_cache(maxsize=1)
def _bootstrap() -> dict:
    # Cache the IANA registry within the process; do not fetch it per domain.
    return _fetch_json(BOOTSTRAP_URL)


def _normalized_domain(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Domain must be text")
    value = value.strip().rstrip(".").lower()
    try:
        ascii_domain = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid domain") from exc
    labels = ascii_domain.split(".")
    if (len(labels) < 2 or len(ascii_domain) > 253 or
            any(not 1 <= len(label) <= 63 or
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
                for label in labels)):
        raise ValueError("Invalid registered domain")
    return ascii_domain


def _rdap_url(domain: str, bootstrap: dict) -> str | None:
    best_length = -1
    best_urls: list[str] = []
    for service in bootstrap.get("services", []):
        if not isinstance(service, list) or len(service) != 2:
            continue
        suffixes, urls = service
        if not isinstance(suffixes, list) or not isinstance(urls, list):
            continue
        for suffix in suffixes:
            if not isinstance(suffix, str):
                continue
            suffix = suffix.lower()
            if domain == suffix or domain.endswith("." + suffix):
                length = len(suffix.split("."))
                if length > best_length:
                    best_length, best_urls = length, urls
    for base in best_urls:
        if isinstance(base, str) and _safe_https_url(base):
            return base.rstrip("/") + "/domain/" + quote(domain, safe="")
    return None


def _registered_at(rdap: dict, domain: str) -> datetime | None:
    if rdap.get("objectClassName") != "domain":
        return None
    returned_domain = rdap.get("ldhName")
    if not isinstance(returned_domain, str) or returned_domain.lower().rstrip(".") != domain:
        return None
    dates = []
    for event in rdap.get("events", []):
        if not isinstance(event, dict) or event.get("eventAction") != "registration":
            continue
        try:
            when = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
            if when.tzinfo is not None:
                dates.append(when.astimezone(timezone.utc))
        except (KeyError, AttributeError, TypeError, ValueError):
            continue
    # A registry response with different registration dates is ambiguous.
    # Taking the oldest one would overstate age, so leave age Unknown.
    unique_dates = set(dates)
    return next(iter(unique_dates)) if len(unique_dates) == 1 else None


def lookup_domain_age(registered_domain: str, *, fetch_json=None,
                      bootstrap: dict | None = None,
                      now: datetime | None = None) -> dict:
    """Return registration evidence or Unknown; never treat failure as safe.

    ``fetch_json`` and ``bootstrap`` are injectable for offline tests. The
    normal call fetches only the registered domain from its IANA-listed RDAP
    server. No page path, query, account data, or browser history is sent.
    """
    try:
        domain = _normalized_domain(registered_domain)
    except ValueError:
        return {"domain": "", "status": "Unknown", "reason": "Invalid registered domain"}

    fetch = fetch_json or _fetch_json
    try:
        registry = bootstrap if bootstrap is not None else _bootstrap()
        url = _rdap_url(domain, registry)
        if url is None:
            return {"domain": domain, "status": "Unknown", "reason": "No HTTPS RDAP server listed by IANA"}
        rdap = fetch(url)
        registered = _registered_at(rdap, domain)
        if registered is None:
            return {"domain": domain, "status": "Unknown", "reason": "Registration date unavailable, conflicting, or mismatched"}
        clock = now or datetime.now(timezone.utc)
        age_days = (clock - registered).days
        if age_days < 0:
            return {"domain": domain, "status": "Unknown", "reason": "Registration date is in the future"}
        return {
            "domain": domain,
            "status": "Known",
            "registered_at": registered.isoformat(),
            "age_days": age_days,
            "source": url,
        }
    except (OSError, TimeoutError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return {"domain": domain, "status": "Unknown", "reason": "RDAP lookup failed"}
