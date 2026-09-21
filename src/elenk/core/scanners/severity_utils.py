"""Shared helper to map each tool's severity scale (Semgrep:
ERROR/WARNING/INFO, Trivy/OSV-Scanner: CRITICAL/HIGH/MEDIUM/LOW,
Gitleaks: no native severity, etc.) to the engine's single `Severity`
enum."""

from __future__ import annotations

from elenk.core.models import Severity

_MAP = {
    "critical": Severity.CRITICAL,
    "error": Severity.HIGH,  # semgrep uses ERROR for actionable findings
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "warning": Severity.MEDIUM,  # semgrep WARNING
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "note": Severity.INFO,
    "unknown": Severity.UNKNOWN,
}


def map_severity(raw: str | None) -> Severity:
    if not raw:
        return Severity.UNKNOWN
    return _MAP.get(raw.strip().lower(), Severity.UNKNOWN)
