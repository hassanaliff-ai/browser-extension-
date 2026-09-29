"""Privacy-preserving downloaded-file hash lookup via VirusTotal v3.

Only SHA-256 values leave this service. A missing report, quota failure, or
network problem is Unknown, never a clean verdict.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import DateTime, Integer, String, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from alba_security.models import Base, utc_now


VT_ENDPOINT = "https://www.virustotal.com/api/v3/files"


class FileReputationCache(Base):
    __tablename__ = "file_reputation_cache"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    malicious_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    suspicious_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class VirusTotalQuota(Base):
    __tablename__ = "virustotal_quota"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    minute_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    minute_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    day_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    day_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    blocked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


@dataclass(frozen=True)
class FileVerdict:
    verdict: str  # malicious, suspicious, clear, unknown
    malicious_count: int = 0
    suspicious_count: int = 0
    reason: str | None = None
    cache_hit: bool = False
    retry_after_seconds: int | None = None

    def signals(self) -> list[dict[str, str]]:
        if self.verdict == "malicious":
            return [
                {"code": "malicious_file_hash", "status": "detected"},
                {"code": "suspicious_file_hash", "status": "detected" if self.suspicious_count else "clear"},
            ]
        if self.verdict == "suspicious":
            return [
                {"code": "malicious_file_hash", "status": "clear"},
                {"code": "suspicious_file_hash", "status": "detected"},
            ]
        status = "clear" if self.verdict == "clear" else "unknown"
        return [
            {"code": "malicious_file_hash", "status": status},
            {"code": "suspicious_file_hash", "status": status},
        ]

    def public(self) -> dict:
        return {
            "verdict": self.verdict,
            "malicious_count": self.malicious_count,
            "suspicious_count": self.suspicious_count,
            "reason": self.reason,
            "cache_hit": self.cache_hit,
            "retry_after_seconds": self.retry_after_seconds,
        }


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _quota_reserve(db: Session, now: datetime, minute_limit: int, day_limit: int) -> int | None:
    minute_start = now.replace(second=0, microsecond=0)
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    quota = db.scalar(select(VirusTotalQuota).where(VirusTotalQuota.id == 1).with_for_update())
    if quota is None:
        quota = VirusTotalQuota(
            id=1, minute_start=minute_start, minute_count=0,
            day_start=day_start, day_count=0,
        )
        db.add(quota)
        try:
            db.flush()
        except IntegrityError:
            # Another worker created the singleton first. Reopen the row
            # under a lock before reserving this request's quota.
            db.rollback()
            quota = db.scalar(select(VirusTotalQuota).where(VirusTotalQuota.id == 1).with_for_update())
            if quota is None:
                raise
    if _aware(quota.minute_start) != minute_start:
        quota.minute_start, quota.minute_count = minute_start, 0
    if _aware(quota.day_start) != day_start:
        quota.day_start, quota.day_count = day_start, 0
    if quota.blocked_until and _aware(quota.blocked_until) > now:
        return max(1, int((_aware(quota.blocked_until) - now).total_seconds()))
    if quota.minute_count >= minute_limit:
        return max(1, int((minute_start + timedelta(minutes=1) - now).total_seconds()))
    if quota.day_count >= day_limit:
        return max(1, int((day_start + timedelta(days=1) - now).total_seconds()))
    quota.minute_count += 1
    quota.day_count += 1
    # Persist the reservation before the network call so a failed scan still
    # counts against the provider quota. PostgreSQL row locking serializes it.
    db.commit()
    return None


def _store_cache(db: Session, sha256: str, verdict: FileVerdict, now: datetime, ttl: timedelta) -> None:
    item = db.get(FileReputationCache, sha256)
    if item is None:
        item = FileReputationCache(sha256=sha256)
        db.add(item)
    item.verdict = verdict.verdict
    item.malicious_count = verdict.malicious_count
    item.suspicious_count = verdict.suspicious_count
    item.checked_at = now
    item.expires_at = now + ttl
    try:
        db.commit()
    except IntegrityError:
        # Concurrent first lookups may insert the same hash. Keep the scan
        # path available by reloading and updating the winning cache row.
        db.rollback()
        item = db.get(FileReputationCache, sha256)
        if item is None:
            raise
        item.verdict = verdict.verdict
        item.malicious_count = verdict.malicious_count
        item.suspicious_count = verdict.suspicious_count
        item.checked_at = now
        item.expires_at = now + ttl
        db.commit()


def lookup_file_hash(
    db: Session,
    sha256: str,
    *,
    api_key: str | None = None,
    client: httpx.Client | None = None,
    now: datetime | None = None,
    minute_limit: int = 4,
    day_limit: int = 500,
) -> FileVerdict:
    """Look up an existing file report by hash; never upload file contents."""
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
        raise ValueError("A 64-character SHA-256 hash is required")
    sha256 = sha256.lower()
    now = now or utc_now()
    cached = db.get(FileReputationCache, sha256)
    if cached and _aware(cached.expires_at) > now:
        return FileVerdict(
            cached.verdict, cached.malicious_count,
            cached.suspicious_count, cache_hit=True,
        )

    api_key = api_key or os.getenv("VT_API_KEY")
    if not api_key:
        return FileVerdict("unknown", reason="not_configured")
    if minute_limit < 1 or day_limit < 1:
        raise ValueError("VirusTotal quota limits must be positive")
    delay = _quota_reserve(db, now, minute_limit, day_limit)
    if delay is not None:
        return FileVerdict("unknown", reason="rate_limited", retry_after_seconds=delay)

    try:
        if client is None:
            with httpx.Client(timeout=8.0) as owned_client:
                response = owned_client.get(
                    f"{VT_ENDPOINT}/{sha256}",
                    headers={"x-apikey": api_key, "accept": "application/json"},
                )
        else:
            response = client.get(
                f"{VT_ENDPOINT}/{sha256}",
                headers={"x-apikey": api_key, "accept": "application/json"},
                timeout=8.0,
            )
    except httpx.RequestError:
        return FileVerdict("unknown", reason="lookup_failed")

    if response.status_code == 404:
        verdict = FileVerdict("unknown", reason="not_found")
        _store_cache(db, sha256, verdict, now, timedelta(hours=1))
        return verdict
    if response.status_code == 429:
        retry_header = response.headers.get("Retry-After", "60")
        retry_seconds = min(3600, max(1, int(retry_header))) if retry_header.isdigit() else 60
        quota = db.get(VirusTotalQuota, 1)
        if quota:
            quota.blocked_until = now + timedelta(seconds=retry_seconds)
            db.commit()
        return FileVerdict("unknown", reason="rate_limited", retry_after_seconds=retry_seconds)
    if response.status_code in {401, 403}:
        return FileVerdict("unknown", reason="provider_auth_failed")
    if response.status_code != 200:
        return FileVerdict("unknown", reason="lookup_failed")

    try:
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats["malicious"]
        suspicious = stats["suspicious"]
        if not isinstance(malicious, int) or isinstance(malicious, bool) or malicious < 0:
            raise ValueError
        if not isinstance(suspicious, int) or isinstance(suspicious, bool) or suspicious < 0:
            raise ValueError
        if not any(isinstance(value, int) and value > 0 for value in stats.values()):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        return FileVerdict("unknown", reason="invalid_response")

    verdict = FileVerdict(
        "malicious" if malicious else "suspicious" if suspicious else "clear",
        malicious_count=malicious,
        suspicious_count=suspicious,
    )
    _store_cache(db, sha256, verdict, now, timedelta(hours=24))
    return verdict
