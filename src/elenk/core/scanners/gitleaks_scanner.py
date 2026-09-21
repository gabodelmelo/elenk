"""Gitleaks wrapper (detects exposed secrets/credentials in code: API
keys, tokens, hardcoded passwords, etc.)

Gitleaks doesn't reliably support writing the JSON report to stdout
across all its versions, so this wrapper writes it to a temp file and
reads it back from there (see the overridden `run()`).

Reference: https://github.com/gitleaks/gitleaks
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import List, Set

from elenk.core.models import Finding, FindingCategory, Severity
from elenk.core.scanners.base import Scanner, ScannerRunOutcome


class GitleaksScanner(Scanner):
    name = "gitleaks"
    binary_name = "gitleaks"
    relevant_ecosystems: Set[str] = set()  # secrets can show up in any repo
    timeout_seconds = 300

    def build_command(self, repo_path: Path) -> List[str]:
        # run() is overridden, this method isn't used directly but is
        # implemented to satisfy the `Scanner` interface.
        return [
            "gitleaks",
            "detect",
            "--source",
            str(repo_path),
            "--no-git",
            "--exit-code",
            "0",
            "--report-format",
            "json",
        ]

    def parse_output(self, stdout: str, repo_path: Path) -> List[Finding]:
        return self._parse_report(stdout, repo_path)

    def run(self, repo_path: Path) -> ScannerRunOutcome:
        import subprocess
        import time

        fd, report_path = tempfile.mkstemp(prefix="gitleaks_", suffix=".json")
        os.close(fd)

        command = [
            "gitleaks",
            "detect",
            "--source",
            str(repo_path),
            "--no-git",
            "--exit-code",
            "0",
            "--report-format",
            "json",
            "--report-path",
            report_path,
        ]

        start = time.monotonic()
        try:
            result = subprocess.run(
                command,
                cwd=repo_path,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            os.unlink(report_path) if os.path.exists(report_path) else None
            return ScannerRunOutcome(
                duration_seconds=time.monotonic() - start,
                error=f"{self.name} exceeded the {self.timeout_seconds}s timeout",
            )
        except FileNotFoundError:
            return ScannerRunOutcome(
                duration_seconds=time.monotonic() - start,
                error=f"binary '{self.binary_name}' not found",
            )

        duration = time.monotonic() - start

        try:
            report_text = Path(report_path).read_text(encoding="utf-8") if os.path.exists(report_path) else ""
        finally:
            if os.path.exists(report_path):
                os.unlink(report_path)

        try:
            findings = self._parse_report(report_text, repo_path)
        except Exception as exc:  # noqa: BLE001
            return ScannerRunOutcome(
                duration_seconds=duration,
                error=f"couldn't parse {self.name} output: {exc}",
                raw_stdout=report_text,
            )

        error = None
        if result.returncode not in (0, 1):
            error = (result.stderr or "").strip()[:500] or f"{self.name} exited with code {result.returncode}"

        return ScannerRunOutcome(
            findings=findings,
            duration_seconds=duration,
            error=error,
            raw_stdout=report_text,
        )

    def _parse_report(self, report_text: str, repo_path: Path) -> List[Finding]:
        if not report_text.strip():
            return []
        data = json.loads(report_text)
        if not isinstance(data, list):
            return []

        findings: List[Finding] = []
        for leak in data:
            findings.append(
                Finding(
                    tool=self.name,
                    rule_id=leak.get("RuleID", "unknown-rule"),
                    title=f"Exposed secret: {leak.get('Description', leak.get('RuleID', 'unknown'))}",
                    description="Possible secret detected. Value redacted for safety.",
                    # Gitleaks has no severity of its own: any exposed
                    # secret is treated as HIGH by default.
                    severity=Severity.HIGH,
                    category=FindingCategory.SECRET,
                    file_path=leak.get("File"),
                    line=leak.get("StartLine"),
                    end_line=leak.get("EndLine"),
                    remediation="Rotate the credential and remove it from git history; use a secrets manager instead.",
                    raw={k: v for k, v in leak.items() if k not in ("Secret", "Match")},
                )
            )
        return findings
