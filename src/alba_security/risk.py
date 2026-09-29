"""Deterministic risk scoring for browser and extension security signals.

The score measures confirmed findings. Unknown checks remain visible through the
completeness field and never count as a clear result.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


SignalCode = Literal[
    "sensitive_permission",
    "broad_host_access",
    "obfuscated_code",
    "external_data_transfer",
    "malicious_url",
    "suspicious_url",
    "malicious_ip",
    "suspicious_ip",
    "new_domain",
    "malicious_file_hash",
    "suspicious_file_hash",
]
SignalStatus = Literal["detected", "clear", "unknown"]
RiskSeverity = Literal["Unknown", "Low", "Medium", "High", "Critical"]
Completeness = Literal["complete", "partial", "unknown"]


class SignalInput(BaseModel):
    """One result from a security check, without caller-controlled scoring."""

    model_config = ConfigDict(extra="forbid")

    code: SignalCode
    status: SignalStatus
    detail: str | None = None


class RiskFinding(BaseModel):
    code: SignalCode
    title: str
    detail: str
    points: int = Field(ge=0, le=100)


class RiskResult(BaseModel):
    # None means that no signal was assessable; it must not be displayed as 0.
    score: int | None = Field(default=None, ge=0, le=100)
    severity: RiskSeverity
    completeness: Completeness
    findings: list[RiskFinding]
    unknown_codes: list[SignalCode]


_WEIGHTS: dict[SignalCode, int] = {
    "sensitive_permission": 20,
    "broad_host_access": 15,
    "obfuscated_code": 25,
    "external_data_transfer": 25,
    "malicious_url": 80,
    "suspicious_url": 30,
    "malicious_ip": 80,
    "suspicious_ip": 30,
    "new_domain": 15,
    "malicious_file_hash": 90,
    "suspicious_file_hash": 40,
}

_TITLES: dict[SignalCode, str] = {
    "sensitive_permission": "Sensitive permission",
    "broad_host_access": "Broad host access",
    "obfuscated_code": "Obfuscated code",
    "external_data_transfer": "External data transfer",
    "malicious_url": "Malicious URL",
    "suspicious_url": "Suspicious URL",
    "malicious_ip": "Malicious IP address",
    "suspicious_ip": "Suspicious IP address",
    "new_domain": "Newly registered domain",
    "malicious_file_hash": "Malicious downloaded file hash",
    "suspicious_file_hash": "Suspicious downloaded file hash",
}

_DEFAULT_DETAILS: dict[SignalCode, str] = {
    "sensitive_permission": "The extension requests a sensitive browser permission.",
    "broad_host_access": "The extension can access a broad range of websites.",
    "obfuscated_code": "Obfuscated code was found in the extension.",
    "external_data_transfer": "Potential transfer of data to an external destination was found.",
    "malicious_url": "The URL was identified as malicious.",
    "suspicious_url": "The URL shows suspicious characteristics.",
    "malicious_ip": "The IP address was identified as malicious.",
    "suspicious_ip": "The IP address shows suspicious characteristics.",
    "new_domain": "The domain was registered recently.",
    "malicious_file_hash": "The downloaded file hash was identified as malicious.",
    "suspicious_file_hash": "The downloaded file hash has suspicious analysis results.",
}


def _severity(score: int) -> RiskSeverity:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def assess(signals: list[SignalInput]) -> RiskResult:
    """Score unique signals and state whether any checks could not be assessed.

    A duplicate code is rejected even when its statuses differ. This prevents a
    caller from increasing a score by repeating the same finding.
    """

    seen: set[SignalCode] = set()
    findings: list[RiskFinding] = []
    unknown_codes: list[SignalCode] = []
    assessed_count = 0

    for item in signals:
        signal = SignalInput.model_validate(item)
        if signal.code in seen:
            raise ValueError(f"Duplicate risk signal: {signal.code}")
        seen.add(signal.code)

        if signal.status == "unknown":
            unknown_codes.append(signal.code)
            continue

        assessed_count += 1
        if signal.status == "detected":
            findings.append(
                RiskFinding(
                    code=signal.code,
                    title=_TITLES[signal.code],
                    detail=signal.detail or _DEFAULT_DETAILS[signal.code],
                    points=_WEIGHTS[signal.code],
                )
            )

    if assessed_count == 0:
        return RiskResult(
            score=None,
            severity="Unknown",
            completeness="unknown",
            findings=[],
            unknown_codes=unknown_codes,
        )

    score = min(100, sum(finding.points for finding in findings))
    return RiskResult(
        score=score,
        severity=_severity(score),
        completeness="partial" if unknown_codes else "complete",
        findings=findings,
        unknown_codes=unknown_codes,
    )
