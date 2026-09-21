"""
Common interface implemented by every scanner wrapper (Semgrep, Trivy,
Gitleaks, OSV-Scanner...). Adding a new scanner to the engine means
writing a class that inherits from `Scanner` and implementing these
methods; the orchestrator (`core.orchestrator`) doesn't need to know
anything specific about the underlying tool.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set

from elenk.core.models import Finding


@dataclass
class ScannerRunOutcome:
    """What `Scanner.run()` returns: the already-normalized findings,
    plus run metadata used to populate `ScannerRunInfo`."""

    findings: List[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0
    error: Optional[str] = None
    raw_stdout: str = ""


class Scanner(ABC):
    """Base class for an external scanner wrapper."""

    #: short, stable name, used in Finding.tool and in the CLI config
    name: str = "base"

    #: command/binary that must exist on PATH for this scanner to run
    binary_name: str = ""

    #: ecosystems (see core.detector) this scanner applies to. If
    #: empty, it's interpreted as "always applies".
    relevant_ecosystems: Set[str] = set()

    #: defensive per-run timeout, in seconds
    timeout_seconds: int = 300

    def is_available(self) -> bool:
        """True if the underlying binary is installed on the system."""
        return shutil.which(self.binary_name) is not None

    def is_applicable(self, ecosystems: Set[str]) -> bool:
        """True if, given what was detected in the repo, it makes sense
        to run this scanner."""
        if not self.relevant_ecosystems:
            return True
        return bool(self.relevant_ecosystems & ecosystems)

    @abstractmethod
    def build_command(self, repo_path: Path) -> List[str]:
        """Returns the command (argv list) to run."""
        raise NotImplementedError

    @abstractmethod
    def parse_output(self, stdout: str, repo_path: Path) -> List[Finding]:
        """Converts the tool's raw stdout into normalized `Finding`s.
        Must tolerate empty/unexpected output: we'd rather return fewer
        findings than break the whole analysis."""
        raise NotImplementedError

    def run(self, repo_path: Path) -> ScannerRunOutcome:
        """Runs the underlying binary and returns normalized findings.
        Doesn't raise on subprocess failures: those are reported via
        `ScannerRunOutcome.error` so the orchestrator can continue with
        the remaining scanners."""
        command = self.build_command(repo_path)
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

        # Most of these tools return a non-zero exit code when they DO
        # find something (not an error). That's why we don't filter by
        # returncode here; we let parse_output decide whether stdout is
        # usable, and only report an error if stdout is empty and
        # stderr suggests a real execution failure.
        try:
            findings = self.parse_output(result.stdout, repo_path)
        except Exception as exc:  # noqa: BLE001 - degrade gracefully, don't crash
            return ScannerRunOutcome(
                duration_seconds=duration,
                error=f"couldn't parse {self.name} output: {exc}",
                raw_stdout=result.stdout,
            )

        error = None
        if not result.stdout.strip() and result.returncode not in (0, 1):
            error = (result.stderr or "").strip()[:500] or f"{self.name} exited with code {result.returncode}"

        return ScannerRunOutcome(
            findings=findings,
            duration_seconds=duration,
            error=error,
            raw_stdout=result.stdout,
        )
