"""SecureScope domain-age evidence shared by authenticated browser scans.

Only registered domains leave this service. No URL paths, credentials or query
strings are forwarded. Age is supporting evidence, never a safety verdict.
"""
from __future__ import annotations

import copy
import asyncio
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import threading
import time
from urllib.parse import urlsplit

import idna
import tldextract

from alba_security import rdap_lookup

NEW_DOMAIN_DAYS = 30
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def registered_domain(target: str) -> str:
    if not isinstance(target, str) or any(ord(c) <= 32 for c in target) or "\\" in target:
        raise ValueError("Invalid web address")
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("Public HTTP(S) domain required")
    parsed.port
    host = idna.encode(parsed.hostname.rstrip("."), uts46=True).decode("ascii").lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses have no domain registration age")
    domain = _extract(host).top_domain_under_public_suffix
    if not domain:
        raise ValueError("Public registered domain required")
    return domain


class DomainAgeService:
    def __init__(self, *, clock=time.monotonic, max_entries=1024):
        if type(max_entries) is not int or max_entries < 1:
            raise ValueError("Cache capacity must be a positive integer")
        self.clock = clock
        self.max_entries = max_entries
        self.cache = {}
        self.guard = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="extsecure-rdap")
        self.capacity = threading.BoundedSemaphore(8)
        # Coalesce concurrent lookups and cap outbound concurrency per process.
        self.locks = [threading.Lock() for _ in range(8)]

    async def async_lookup(self, target: str, *, timeout=2.5) -> dict:
        """Bound response latency and queued work; late lookups only warm cache."""
        unavailable = {"status": "Unknown", "reason": "RDAP lookup temporarily unavailable", "cached": False}
        if not self.capacity.acquire(blocking=False):
            return unavailable
        try:
            pending = self.executor.submit(self.lookup, target)
        except RuntimeError:
            self.capacity.release()
            return unavailable
        # Release when the actual thread finishes, not when HTTP times out.
        pending.add_done_callback(lambda _: self.capacity.release())
        future = asyncio.wrap_future(pending)
        future.add_done_callback(lambda f: f.exception() if not f.cancelled() else None)
        try:
            return await asyncio.wait_for(asyncio.shield(future), timeout=timeout)
        except Exception:
            return unavailable

    def close(self):
        self.executor.shutdown(wait=False, cancel_futures=True)

    def lookup(self, target: str) -> dict:
        try:
            domain = registered_domain(target)
        except (ValueError, UnicodeError):
            return {"status": "Unknown", "reason": "Public registered domain unavailable", "cached": False}
        with self.locks[hash(domain) % len(self.locks)]:
            now = self.clock()
            with self.guard:
                entry = self.cache.get(domain)
                if entry and entry[0] > now:
                    return {**copy.deepcopy(entry[1]), "cached": True}
            evidence = rdap_lookup.lookup_domain_age(domain)
            ttl = 21600 if evidence.get("status") == "Known" else 60
            with self.guard:
                self.cache = {k: v for k, v in self.cache.items() if v[0] > self.clock()}
                while len(self.cache) >= self.max_entries:
                    del self.cache[next(iter(self.cache))]
                self.cache[domain] = (self.clock() + ttl, copy.deepcopy(evidence))
            return {**evidence, "cached": False}


def age_signal(evidence: dict) -> dict:
    age = evidence.get("age_days")
    if evidence.get("status") == "Known" and type(age) is int and age >= 0:
        return {"code": "new_domain", "status": "detected" if age < NEW_DOMAIN_DAYS else "clear",
                "detail": f"SecureScope RDAP: registered {evidence.get('registered_at', 'date unavailable')}; age {age} days. Newly registered means under {NEW_DOMAIN_DAYS} days; age alone does not establish safety or a threat."}
    return {"code": "new_domain", "status": "unknown",
            "detail": "SecureScope RDAP: domain age unavailable. " + evidence.get("reason", "Lookup unavailable")}
