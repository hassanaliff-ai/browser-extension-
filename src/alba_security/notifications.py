"""Bounded, privacy-conscious SMTP and webhook delivery adapters."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

import httpx


EmailSender = Callable[[tuple[str, ...], str, str, "NotificationSettings"], None]
WebhookSender = Callable[[str, dict[str, Any], "NotificationSettings"], None]


@dataclass(frozen=True)
class NotificationSettings:
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    admin_emails: tuple[str, ...] = ()
    webhook_urls: tuple[str, ...] = ()
    webhook_secret: str | None = None
    timeout_seconds: float = 10.0

    @classmethod
    def from_env(cls) -> "NotificationSettings":
        webhook_list = os.getenv("ALERT_WEBHOOK_URLS") or os.getenv("ALERT_WEBHOOK_URL", "")
        return cls(
            smtp_host=os.getenv("SMTP_HOST"),
            smtp_port=int(os.getenv("SMTP_PORT", "587")),
            smtp_username=os.getenv("SMTP_USERNAME"),
            smtp_password=os.getenv("SMTP_PASSWORD"),
            smtp_from=os.getenv("SMTP_FROM"),
            admin_emails=tuple(
                email.strip() for email in os.getenv("ADMIN_EMAILS", "").split(",") if email.strip()
            ),
            webhook_urls=tuple(url.strip() for url in webhook_list.split(",") if url.strip()),
            webhook_secret=os.getenv("ALERT_WEBHOOK_SECRET"),
            timeout_seconds=float(os.getenv("NOTIFICATION_TIMEOUT_SECONDS", "10")),
        )


def _deliver_email(
    recipients: tuple[str, ...], subject: str, body: str, settings: NotificationSettings
) -> None:
    if settings.timeout_seconds <= 0:
        raise ValueError("Notification timeout must be positive")
    if not settings.smtp_host or not settings.smtp_from:
        raise ValueError("SMTP sender settings are incomplete")
    if settings.smtp_username and not settings.smtp_password:
        raise ValueError("SMTP password is required when username is set")

    message = EmailMessage()
    message["From"] = settings.smtp_from
    # The envelope sends to each administrator without exposing the list.
    message["To"] = "undisclosed-recipients:;"
    message["Subject"] = subject
    message.set_content(body)
    tls_context = ssl.create_default_context()
    if settings.smtp_port == 465:
        with smtplib.SMTP_SSL(
            settings.smtp_host, settings.smtp_port,
            timeout=settings.timeout_seconds, context=tls_context,
        ) as smtp:
            if settings.smtp_username:
                smtp.login(settings.smtp_username, settings.smtp_password)
            refused = smtp.send_message(message, to_addrs=list(recipients))
            if refused:
                raise smtplib.SMTPRecipientsRefused(refused)
    else:
        with smtplib.SMTP(
            settings.smtp_host, settings.smtp_port, timeout=settings.timeout_seconds
        ) as smtp:
            smtp.starttls(context=tls_context)
            if settings.smtp_username:
                smtp.login(settings.smtp_username, settings.smtp_password)
            refused = smtp.send_message(message, to_addrs=list(recipients))
            if refused:
                raise smtplib.SMTPRecipientsRefused(refused)


def _deliver_webhook(url: str, payload: dict[str, Any], settings: NotificationSettings) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Webhook URL must be HTTPS without embedded credentials")
    if settings.timeout_seconds <= 0:
        raise ValueError("Notification timeout must be positive")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if settings.webhook_secret:
        digest = hmac.new(settings.webhook_secret.encode("utf-8"), encoded, hashlib.sha256).hexdigest()
        headers["X-Alba-Signature"] = f"sha256={digest}"
    with httpx.Client(timeout=settings.timeout_seconds, follow_redirects=False) as client:
        response = client.post(url, content=encoded, headers=headers)
        response.raise_for_status()


def _outcome(channel: str, status: str, **extra: Any) -> dict[str, Any]:
    return {"channel": channel, "status": status, **extra}


def _send_email_result(
    recipients: tuple[str, ...], subject: str, body: str,
    settings: NotificationSettings, sender: EmailSender,
) -> dict[str, Any]:
    if not recipients or not settings.smtp_host or not settings.smtp_from:
        return _outcome("email", "skipped", reason="not_configured")
    try:
        sender(recipients, subject, body, settings)
    except Exception as error:
        # Do not expose SMTP credentials, recipient addresses, or content in logs.
        return _outcome("email", "failed", error_type=type(error).__name__)
    return _outcome("email", "sent")


def send_high_severity_alert(
    *,
    alert_id: str,
    scan_id: str,
    severity: str,
    message: str,
    score: int | None = None,
    settings: NotificationSettings | None = None,
    email_sender: EmailSender | None = None,
    webhook_sender: WebhookSender | None = None,
) -> list[dict[str, Any]]:
    """Send a High/Critical threat notice by every configured channel.

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
    email_sender = email_sender or _deliver_email
    webhook_sender = webhook_sender or _deliver_webhook
    safe_message = f"{severity}-severity threat detected in a security scan."
    subject = f"Alba Security: {severity}-severity threat"
    body = f"{safe_message}\n\nAlert ID: {alert_id}\nScan ID: {scan_id}\n"
    if score is not None:
        body += f"Risk score: {score}/100\n"
    outcomes = [_send_email_result(settings.admin_emails, subject, body, settings, email_sender)]
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


def send_monthly_report(
    report: Mapping[str, Any],
    *,
    settings: NotificationSettings | None = None,
    email_sender: EmailSender | None = None,
) -> list[dict[str, Any]]:
    """Email a previously generated monthly report to configured admins."""
    if settings is None:
        try:
            settings = NotificationSettings.from_env()
        except (ValueError, OverflowError) as error:
            return [_outcome("configuration", "failed", error_type=type(error).__name__)]
    sender = email_sender or _deliver_email
    return [_send_email_result(
        settings.admin_emails,
        str(report["subject"]),
        str(report["body"]),
        settings,
        sender,
    )]
