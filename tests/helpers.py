"""Shared builders for VirusTotal v3 payloads used across the test suite."""

import base64

VT_BASE = "https://www.virustotal.com/api/v3"


def url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def stats(malicious=0, suspicious=0, harmless=0, undetected=0) -> dict:
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": 0,
    }


def object_payload(**counts: int) -> dict:
    """Body of GET /urls/{id}, /files/{hash} or /ip_addresses/{ip}."""
    return {"data": {"attributes": {"last_analysis_stats": stats(**counts)}}}


def analysis_payload(status: str, **counts: int) -> dict:
    """Body of GET /analyses/{id}."""
    return {"data": {"attributes": {"status": status, "stats": stats(**counts)}}}
