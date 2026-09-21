import tempfile
import unittest
from pathlib import Path
from typing import List, Set

from elenk.core.models import Finding, Severity
from elenk.core.orchestrator import run_scan
from elenk.core.scanners.base import Scanner, ScannerRunOutcome


class _FakeScanner(Scanner):
    """Test scanner: doesn't run any subprocess, returns fixed findings
    so the orchestrator can be tested in isolation."""

    name = "fake-available"
    binary_name = "fake-available-binary"
    relevant_ecosystems: Set[str] = set()
    findings_to_return: List[Finding] = []

    def is_available(self) -> bool:
        return True

    def build_command(self, repo_path: Path) -> List[str]:
        return ["true"]

    def parse_output(self, stdout: str, repo_path: Path) -> List[Finding]:
        return []

    def run(self, repo_path: Path) -> ScannerRunOutcome:
        return ScannerRunOutcome(findings=list(self.findings_to_return), duration_seconds=0.01)


class _FakeUnavailableScanner(_FakeScanner):
    name = "fake-unavailable"
    binary_name = "definitely-not-installed-binary"

    def is_available(self) -> bool:
        return False


class _FakeNotApplicableScanner(_FakeScanner):
    name = "fake-not-applicable"
    relevant_ecosystems: Set[str] = {"go"}  # the test repo has no go.mod


class TestRunScan(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo_path = Path(self._tmp.name)
        (self.repo_path / "requirements.txt").write_text("flask==1.0")

    def tearDown(self):
        self._tmp.cleanup()

    def test_available_applicable_scanner_runs_and_reports_findings(self):
        finding = Finding(
            tool="fake-available",
            rule_id="r1",
            title="t",
            description="d",
            severity=Severity.HIGH,
        )
        _FakeScanner.findings_to_return = [finding]
        result = run_scan(
            repo_path=self.repo_path,
            repo_url="https://github.com/x/y",
            repo_name="x/y",
            commit_sha="abc",
            scanner_classes=[_FakeScanner],
        )
        self.assertEqual(result.total_findings, 1)
        run_info = result.scanner_runs[0]
        self.assertTrue(run_info.ran)
        self.assertEqual(run_info.finding_count, 1)

    def test_unavailable_scanner_is_skipped_not_errored(self):
        result = run_scan(
            repo_path=self.repo_path,
            repo_url="https://github.com/x/y",
            repo_name="x/y",
            commit_sha="abc",
            scanner_classes=[_FakeUnavailableScanner],
        )
        run_info = result.scanner_runs[0]
        self.assertFalse(run_info.ran)
        self.assertIsNotNone(run_info.skipped_reason)
        self.assertIsNone(run_info.error)

    def test_not_applicable_scanner_is_skipped(self):
        result = run_scan(
            repo_path=self.repo_path,
            repo_url="https://github.com/x/y",
            repo_name="x/y",
            commit_sha="abc",
            scanner_classes=[_FakeNotApplicableScanner],
        )
        run_info = result.scanner_runs[0]
        self.assertFalse(run_info.applicable)
        self.assertFalse(run_info.ran)

    def test_dedupe_removes_identical_findings(self):
        finding = Finding(
            tool="fake-available",
            rule_id="r1",
            title="t",
            description="d",
            severity=Severity.HIGH,
            file_path="app.py",
            line=1,
        )
        _FakeScanner.findings_to_return = [finding, finding]  # exact duplicate
        result = run_scan(
            repo_path=self.repo_path,
            repo_url="https://github.com/x/y",
            repo_name="x/y",
            commit_sha="abc",
            scanner_classes=[_FakeScanner],
        )
        self.assertEqual(result.total_findings, 1)

    def test_detects_python_ecosystem_from_requirements_txt(self):
        result = run_scan(
            repo_path=self.repo_path,
            repo_url="https://github.com/x/y",
            repo_name="x/y",
            commit_sha="abc",
            scanner_classes=[_FakeScanner],
        )
        self.assertIn("python", result.detected_ecosystems)


if __name__ == "__main__":
    unittest.main()
