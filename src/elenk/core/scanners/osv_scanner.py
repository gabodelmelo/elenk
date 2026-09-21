"""OSV-Scanner (Google) wrapper, for known vulnerabilities in
dependencies using the open OSV.dev database.

Run in addition to Trivy on purpose: both tools query different
vulnerability databases (OSV.dev vs Trivy/Aqua's own), so combined
coverage is usually broader than either alone. The orchestrator doesn't
dedupe dependency findings between the two tools because each
contributes different context/IDs (CVE vs GHSA); they're listed
separately in the report.

Reference: https://google.github.io/osv-scanner/output/
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Set

from elenk.core.models import Finding, FindingCategory, Severity
from elenk.core.scanners.base import Scanner

_CVSS_SEVERITY_BUCKETS = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
)


class OsvScanner(Scanner):
    name = "osv-scanner"
    binary_name = "osv-scanner"
    relevant_ecosystems: Set[str] = {
        "python",
        "node",
        "go",
        "java",
        "ruby",
        "php",
        "rust",
    }
    timeout_seconds = 300

    def build_command(self, repo_path: Path) -> List[str]:
        return [
            "osv-scanner",
            "--format",
            "json",
            "--recursive",
            str(repo_path),
        ]

    def parse_output(self, stdout: str, repo_path: Path) -> List[Finding]:
        if not stdout.strip():
            return []
        data = json.loads(stdout)
        findings: List[Finding] = []

        for result in data.get("results", []) or []:
            source = (result.get("source") or {}).get("path")

            for pkg_entry in result.get("packages", []) or []:
                package = pkg_entry.get("package", {}) or {}
                pkg_name = package.get("name")
                pkg_version = package.get("version")

                for vuln in pkg_entry.get("vulnerabilities", []) or []:
                    findings.append(
                        Finding(
                            tool=self.name,
                            rule_id=vuln.get("id", "unknown-vuln"),
                            title=vuln.get("summary") or vuln.get("id", "Dependency vulnerability"),
                            description=vuln.get("details", "") or "",
                            severity=self._resolve_severity(vuln),
                            category=FindingCategory.DEPENDENCY,
                            file_path=source,
                            package_name=pkg_name,
                            installed_version=pkg_version,
                            references=[
                                ref.get("url") for ref in vuln.get("references", []) or [] if ref.get("url")
                            ][:10],
                            raw=vuln,
                        )
                    )

        return findings

    @staticmethod
    def _resolve_severity(vuln: dict) -> Severity:
        db_specific = vuln.get("database_specific", {}) or {}
        label = db_specific.get("severity")
        if isinstance(label, str):
            lookup = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "moderate": Severity.MEDIUM,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
            }
            mapped = lookup.get(label.lower())
            if mapped:
                return mapped

        for entry in vuln.get("severity", []) or []:
            score_raw = entry.get("score")
            score = _extract_cvss_base_score(score_raw)
            if score is not None:
                for threshold, severity in _CVSS_SEVERITY_BUCKETS:
                    if score >= threshold:
                        return severity

        return Severity.UNKNOWN


def _extract_cvss_base_score(score_raw) -> float | None:
    """OSV-Scanner may report the score as a number or as a CVSS vector
    string (e.g. 'CVSS:3.1/AV:N/AC:L/...'). If it's a vector, we don't
    try to recompute the score (would need a full CVSS library); in
    that case we return None and the finding stays UNKNOWN."""
    if score_raw is None:
        return None
    if isinstance(score_raw, (int, float)):
        return float(score_raw)
    try:
        return float(score_raw)
    except (TypeError, ValueError):
        return None
