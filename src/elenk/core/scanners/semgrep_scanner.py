"""Semgrep wrapper (SAST - static code analysis).

`--json` output format reference:
https://semgrep.dev/docs/cli-reference (see "output-formats")
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Set

from elenk.core.models import Finding, FindingCategory
from elenk.core.scanners.base import Scanner
from elenk.core.scanners.severity_utils import map_severity


class SemgrepScanner(Scanner):
    name = "semgrep"
    binary_name = "semgrep"
    # Applies to code in general; not restricted to a specific
    # ecosystem since Semgrep has rules for many languages.
    relevant_ecosystems: Set[str] = set()
    timeout_seconds = 600

    def build_command(self, repo_path: Path) -> List[str]:
        return [
            "semgrep",
            "scan",
            "--config",
            "auto",
            "--json",
            "--quiet",
            "--timeout",
            "60",
            str(repo_path),
        ]

    def parse_output(self, stdout: str, repo_path: Path) -> List[Finding]:
        if not stdout.strip():
            return []
        data = json.loads(stdout)
        findings: List[Finding] = []

        for item in data.get("results", []):
            extra = item.get("extra", {}) or {}
            metadata = extra.get("metadata", {}) or {}
            file_path = item.get("path")
            try:
                rel_path = str(Path(file_path).relative_to(repo_path)) if file_path else None
            except ValueError:
                rel_path = file_path

            cwe_raw = metadata.get("cwe", [])
            if isinstance(cwe_raw, str):
                cwe_raw = [cwe_raw]

            findings.append(
                Finding(
                    tool=self.name,
                    rule_id=item.get("check_id", "unknown-rule"),
                    title=metadata.get("shortlink") or item.get("check_id", "Semgrep finding"),
                    description=extra.get("message", ""),
                    severity=map_severity(extra.get("severity")),
                    category=FindingCategory.STATIC_CODE,
                    file_path=rel_path,
                    line=(item.get("start") or {}).get("line"),
                    end_line=(item.get("end") or {}).get("line"),
                    cwe_ids=list(cwe_raw),
                    references=list(metadata.get("references", []) or []),
                    raw=item,
                )
            )

        return findings
