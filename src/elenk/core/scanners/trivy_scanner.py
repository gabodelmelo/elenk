"""Trivy wrapper, used here for two things:
  - Known vulnerabilities (CVEs) in project dependencies.
  - IaC/container misconfigurations (Dockerfile, Terraform, k8s).

Secret detection is left exclusively to Gitleaks (`gitleaks_scanner.py`)
to avoid duplicating the same kind of finding across two tools in the
same report.

`--format json` output reference:
https://aquasecurity.github.io/trivy/latest/docs/configuration/reporting/
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Set

from elenk.core.models import Finding, FindingCategory
from elenk.core.scanners.base import Scanner
from elenk.core.scanners.severity_utils import map_severity


class TrivyScanner(Scanner):
    name = "trivy"
    binary_name = "trivy"
    relevant_ecosystems: Set[str] = set()  # trivy fs covers almost every manifest type
    timeout_seconds = 600

    def build_command(self, repo_path: Path) -> List[str]:
        return [
            "trivy",
            "fs",
            "--scanners",
            "vuln,misconfig",
            "--format",
            "json",
            "--quiet",
            str(repo_path),
        ]

    def parse_output(self, stdout: str, repo_path: Path) -> List[Finding]:
        if not stdout.strip():
            return []
        data = json.loads(stdout)
        findings: List[Finding] = []

        for result in data.get("Results", []) or []:
            target = result.get("Target")

            for vuln in result.get("Vulnerabilities", []) or []:
                findings.append(
                    Finding(
                        tool=self.name,
                        rule_id=vuln.get("VulnerabilityID", "unknown-cve"),
                        title=vuln.get("Title") or vuln.get("VulnerabilityID", "Dependency vulnerability"),
                        description=vuln.get("Description", "") or "",
                        severity=map_severity(vuln.get("Severity")),
                        category=FindingCategory.DEPENDENCY,
                        file_path=target,
                        cwe_ids=list(vuln.get("CweIDs", []) or []),
                        package_name=vuln.get("PkgName"),
                        installed_version=vuln.get("InstalledVersion"),
                        fixed_version=vuln.get("FixedVersion"),
                        references=list(vuln.get("References", []) or [])[:10],
                        remediation=(
                            f"Update {vuln.get('PkgName')} to version {vuln.get('FixedVersion')} or later."
                            if vuln.get("FixedVersion")
                            else None
                        ),
                        raw=vuln,
                    )
                )

            for misconf in result.get("Misconfigurations", []) or []:
                findings.append(
                    Finding(
                        tool=self.name,
                        rule_id=misconf.get("ID", "unknown-misconfig"),
                        title=misconf.get("Title", "Misconfiguration detected"),
                        description=misconf.get("Description", "") or "",
                        severity=map_severity(misconf.get("Severity")),
                        category=FindingCategory.MISCONFIGURATION,
                        file_path=target,
                        references=list(misconf.get("References", []) or [])[:10],
                        remediation=misconf.get("Resolution"),
                        raw=misconf,
                    )
                )

        return findings
