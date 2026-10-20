"""Bounded, privacy-conscious High/Critical webhook delivery."""
from __future__ import annotations
import hashlib
import hmac
import json
import math
import os
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit
import httpx

WebhookSender = Callable[[str, dict[str, Any], "NotificationSettings"], None]


@dataclass(frozen=True)
class NotificationSettings:
    webhook_urls: tuple[str, ...] = ()
    webhook_secret: str | None = None
    timeout_seconds: float = 10.0

    def __post_init__(self):
        if not math.isfinite(self.timeout_seconds) or not 0 < self.timeout_seconds <= 60:
            raise ValueError("Notification timeout must be finite and between 0 and 60 seconds")
        object.__setattr__(self, "webhook_urls", tuple(dict.fromkeys(
            value.strip() for value in self.webhook_urls if value.strip())))

    @classmethod
    def from_env(cls):
        urls = os.getenv("ALERT_WEBHOOK_URLS") or os.getenv("ALERT_WEBHOOK_URL", "")
        return cls(webhook_urls=tuple(value.strip() for value in urls.split(',') if value.strip()),
                   webhook_secret=os.getenv("ALERT_WEBHOOK_SECRET"),
                   timeout_seconds=float(os.getenv("NOTIFICATION_TIMEOUT_SECONDS", "10")))


def _deliver_webhook(url: str, payload: dict[str, Any], settings: NotificationSettings) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Webhook URL must be HTTPS without embedded credentials")
    if settings.timeout_seconds <= 0:
        raise ValueError("Notification timeout must be positive")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if payload.get("alert_id"):
        # Receivers can use this stable key to deduplicate a repeated delivery.
        # The receiving service must implement idempotency; HTTP cannot promise it.
        headers["Idempotency-Key"] = str(payload["alert_id"])
    if settings.webhook_secret:
        digest = hmac.new(settings.webhook_secret.encode("utf-8"), encoded, hashlib.sha256).hexdigest()
        headers["X-Alba-Signature"] = f"sha256={digest}"
    with httpx.Client(timeout=settings.timeout_seconds, follow_redirects=False) as client:
        response = client.post(url, content=encoded, headers=headers)
        response.raise_for_status()


def _outcome(channel: str, status: str, **extra: Any) -> dict[str, Any]:
    return {"channel": channel, "status": status, **extra}


def send_high_severity_alert(
    *,
    alert_id: str,
    scan_id: str,
    severity: str,
    message: str,
    score: int | None = None,
    settings: NotificationSettings | None = None,
    webhook_sender: WebhookSender | None = None,
) -> list[dict[str, Any]]:
    """Send a High/Critical threat notice to configured HTTPS webhooks.

    Caller-supplied message is deliberately excluded: a URL or file name could
    be embedded there. Only severity, identifiers, and score leave the system.
    """
    if severity not in {"High", "Critical"}:
        return []
    del message
    if settings is None:
        try:
            settings = NotificationSettings.from_env()
        except (ValueError, OverflowError) as error:
            return [_outcome("configuration", "failed", error_type=type(error).__name__)]
    webhook_sender = webhook_sender or _deliver_webhook
    safe_message = f"{severity}-severity threat detected in a security scan."
    outcomes = []
    payload = {
        "event": "high_severity_threat",
        "alert_id": alert_id,
        "scan_id": scan_id,
        "severity": severity,
        "score": score,
        "message": safe_message,
    }
    if not settings.webhook_urls:
        outcomes.append(_outcome("webhook", "skipped", reason="not_configured"))
    for index, url in enumerate(settings.webhook_urls, start=1):
        try:
            webhook_sender(url, payload, settings)
        except Exception as error:
            outcomes.append(_outcome(
                "webhook", "failed", destination_index=index, error_type=type(error).__name__
            ))
        else:
            outcomes.append(_outcome("webhook", "sent", destination_index=index))
    return outcomes
