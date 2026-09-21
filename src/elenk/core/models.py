"""
Shared data models for the Elenk engine: `Finding` and `ScanResult`.
Every report generator in `elenk.core.reports` consumes these same
models.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Normalized severity. Each scanner has its own scale; the wrappers
    in `core.scanners.*` are responsible for mapping the tool's native
    severity to one of these values."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        """Higher = more severe. Used to sort findings."""
        order = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
            Severity.UNKNOWN: 0,
        }
        return order[self]


class FindingCategory(str, Enum):
    """Functional category of a finding, independent of which tool
    detected it. Used to group findings in reports."""

    STATIC_CODE = "static_code_analysis"      # SAST (e.g. Semgrep)
    DEPENDENCY = "vulnerable_dependency"       # CVEs in libraries (e.g. OSV-Scanner, Trivy)
    SECRET = "exposed_secret"                  # credentials/API keys (e.g. Gitleaks)
    MISCONFIGURATION = "misconfiguration"      # IaC / containers (e.g. Trivy)
    UNKNOWN = "unknown"


@dataclass
class Finding:
    """A single normalized finding, regardless of which tool produced it."""

    tool: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: FindingCategory = FindingCategory.UNKNOWN
    file_path: Optional[str] = None
    line: Optional[int] = None
    end_line: Optional[int] = None
    cwe_ids: List[str] = field(default_factory=list)
    package_name: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    references: List[str] = field(default_factory=list)
    remediation: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        """Stable, deterministic identifier, used to dedupe equivalent
        findings reported by more than one tool."""
        key = "|".join(
            [
                self.tool,
                self.rule_id,
                self.file_path or "",
                str(self.line or ""),
                self.package_name or "",
            ]
        )
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tool": self.tool,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "file_path": self.file_path,
            "line": self.line,
            "end_line": self.end_line,
            "cwe_ids": self.cwe_ids,
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "references": self.references,
            "remediation": self.remediation,
        }


@dataclass
class ScannerRunInfo:
    """Metadata about a single scanner's execution: whether it ran, was
    skipped and why, how long it took, and how many findings it produced."""

    tool: str
    applicable: bool
    available: bool
    ran: bool
    duration_seconds: float = 0.0
    finding_count: int = 0
    skipped_reason: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "applicable": self.applicable,
            "available": self.available,
            "ran": self.ran,
            "duration_seconds": round(self.duration_seconds, 3),
            "finding_count": self.finding_count,
            "skipped_reason": self.skipped_reason,
            "error": self.error,
        }


@dataclass
class ScanResult:
    """Consolidated result of scanning a repository. This is the object
    every report generator (JSON, Markdown, HTML) consumes."""

    repo_url: str
    repo_name: str
    commit_sha: Optional[str]
    detected_ecosystems: List[str]
    findings: List[Finding]
    scanner_runs: List[ScannerRunInfo]
    started_at: datetime
    finished_at: datetime

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def summary_by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def summary_by_tool(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.tool] = counts.get(f.tool, 0) + 1
        return counts

    @property
    def summary_by_category(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.category.value] = counts.get(f.category.value, 0) + 1
        return counts

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def risk_score(self) -> int:
        """Simple 0-100 score used to derive `security_score`. Not meant
        to be a CVSS score: it's a severity-weighted heuristic for
        prioritization, aimed at non-technical readers."""
        weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 5,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
            Severity.UNKNOWN: 0,
        }
        raw_score = sum(weights[f.severity] for f in self.findings)
        return min(100, raw_score)

    @property
    def security_score(self) -> int:
        """0-100 score, inverse of `risk_score`, meant to be shown
        prominently in reports: 100 = no findings detected, 0 = maximum
        risk. Easier to read at a glance than the raw risk score (where
        higher = worse)."""
        return 100 - self.risk_score

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: f.severity.rank, reverse=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repo_url": self.repo_url,
            "repo_name": self.repo_name,
            "commit_sha": self.commit_sha,
            "detected_ecosystems": self.detected_ecosystems,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "duration_seconds": round(self.duration_seconds, 3),
            "summary": {
                "total_findings": self.total_findings,
                "by_severity": self.summary_by_severity,
                "by_tool": self.summary_by_tool,
                "by_category": self.summary_by_category,
                "risk_score": self.risk_score,
                "security_score": self.security_score,
            },
            "scanner_runs": [r.to_dict() for r in self.scanner_runs],
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
