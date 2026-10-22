"""Look up a registered domain's age using the IANA RDAP bootstrap registry.

The caller must supply the registered domain (for example, example.co.uk),
not a URL or an arbitrary hostname. Domain extraction belongs in the backend
and must use a maintained Public Suffix List implementation.
"""

from __future__ import annotations

import ipaddress
import json
import re
import http.client
import time
from datetime import datetime, timezone
from functools import lru_cache
from urllib.parse import quote, urlsplit, urljoin
from alba_security.content_reader import PinnedHTTPS, resolve_public


BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
MAX_RESPONSE_BYTES = 2_000_000
TIMEOUT_SECONDS = 5


def _safe_https_url(value: str) -> bool:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.port not in {None, 443}:
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
    deadline = time.monotonic() + 8
    for redirect in range(3):
        if not _safe_https_url(url):
            raise ValueError("Unsafe RDAP redirect")
        parsed = urlsplit(url)
        host = parsed.hostname
        addresses = resolve_public(host)
        connection = PinnedHTTPS(host, addresses[0])
        connection.timeout = TIMEOUT_SECONDS
        try:
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            connection.request("GET", path, headers={
                "Accept": "application/rdap+json, application/json",
                "Accept-Encoding": "identity", "Connection": "close",
                "User-Agent": "ExtSecure-SecureScope/1.0",
            })
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader("Location")
                if not location or redirect == 2:
                    raise ValueError("RDAP redirect limit exceeded")
                url = urljoin(url, location)
                continue
            if response.status != 200 or response.getheader("Content-Encoding", "identity").lower() != "identity":
                raise ValueError("RDAP server unavailable")
            chunks, size = [], 0
            while size <= MAX_RESPONSE_BYTES:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("RDAP reading deadline exceeded")
                if connection.sock:
                    connection.sock.settimeout(min(remaining, TIMEOUT_SECONDS))
                chunk = response.read1(min(8192, MAX_RESPONSE_BYTES + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            if size > MAX_RESPONSE_BYTES:
                raise ValueError("RDAP response too large")
            data = b"".join(chunks)
            break
        finally:
            connection.close()
    else:
        raise ValueError("RDAP redirect limit exceeded")
    result = json.loads(data)
    if not isinstance(result, dict):
        raise ValueError("RDAP response was not an object")
    return result


@lru_cache(maxsize=2)
def _bootstrap_cached(bucket: int) -> dict:
    # Cache the IANA registry within the process; do not fetch it per domain.
    return _fetch_json(BOOTSTRAP_URL)


def _bootstrap() -> dict:
    return _bootstrap_cached(int(time.monotonic() // 21600))


def _normalized_domain(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Domain must be text")
    value = value.strip().rstrip(".").lower()
    try:
        ascii_domain = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Invalid domain") from exc
    try:
        ipaddress.ip_address(ascii_domain)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses have no domain registration age")
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
    events = rdap.get("events", [])
    if not isinstance(events, list):
        return None
    for event in events:
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
    except (OSError, TimeoutError, ValueError, KeyError, TypeError, AttributeError, RecursionError, http.client.HTTPException):
        return {"domain": domain, "status": "Unknown", "reason": "RDAP lookup failed"}
