import unittest
from datetime import datetime, timedelta, timezone

from elenk.core.models import Finding, ScanResult, ScannerRunInfo, Severity


def _finding(severity: Severity, **kwargs) -> Finding:
    defaults = dict(
        tool="semgrep",
        rule_id="rule-1",
        title="Test finding",
        description="desc",
        severity=severity,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


class TestSeverity(unittest.TestCase):
    def test_rank_order(self):
        self.assertGreater(Severity.CRITICAL.rank, Severity.HIGH.rank)
        self.assertGreater(Severity.HIGH.rank, Severity.MEDIUM.rank)
        self.assertGreater(Severity.MEDIUM.rank, Severity.LOW.rank)
        self.assertGreater(Severity.LOW.rank, Severity.INFO.rank)
        self.assertGreater(Severity.INFO.rank, Severity.UNKNOWN.rank)


class TestFinding(unittest.TestCase):
    def test_id_is_deterministic(self):
        f1 = _finding(Severity.HIGH, file_path="a.py", line=10)
        f2 = _finding(Severity.HIGH, file_path="a.py", line=10)
        self.assertEqual(f1.id, f2.id)

    def test_id_differs_on_location(self):
        f1 = _finding(Severity.HIGH, file_path="a.py", line=10)
        f2 = _finding(Severity.HIGH, file_path="a.py", line=11)
        self.assertNotEqual(f1.id, f2.id)

    def test_to_dict_has_expected_keys(self):
        f = _finding(Severity.MEDIUM)
        data = f.to_dict()
        for key in ("id", "tool", "rule_id", "title", "severity", "category"):
            self.assertIn(key, data)


class TestScanResult(unittest.TestCase):
    def _result(self, findings):
        now = datetime.now(timezone.utc)
        return ScanResult(
            repo_url="https://github.com/x/y",
            repo_name="x/y",
            commit_sha="abc123",
            detected_ecosystems=["python"],
            findings=findings,
            scanner_runs=[ScannerRunInfo(tool="semgrep", applicable=True, available=True, ran=True)],
            started_at=now - timedelta(seconds=5),
            finished_at=now,
        )

    def test_summary_by_severity(self):
        result = self._result([_finding(Severity.CRITICAL), _finding(Severity.HIGH), _finding(Severity.HIGH)])
        summary = result.summary_by_severity
        self.assertEqual(summary["critical"], 1)
        self.assertEqual(summary["high"], 2)
        self.assertEqual(summary["low"], 0)

    def test_risk_score_zero_when_no_findings(self):
        result = self._result([])
        self.assertEqual(result.risk_score, 0)

    def test_risk_score_increases_with_severity(self):
        low_risk = self._result([_finding(Severity.LOW)])
        high_risk = self._result([_finding(Severity.CRITICAL), _finding(Severity.CRITICAL)])
        self.assertGreater(high_risk.risk_score, low_risk.risk_score)

    def test_risk_score_capped_at_100(self):
        result = self._result([_finding(Severity.CRITICAL) for _ in range(50)])
        self.assertEqual(result.risk_score, 100)

    def test_security_score_is_100_when_no_findings(self):
        result = self._result([])
        self.assertEqual(result.security_score, 100)

    def test_security_score_is_inverse_of_risk_score(self):
        result = self._result([_finding(Severity.CRITICAL), _finding(Severity.HIGH)])
        self.assertEqual(result.security_score, 100 - result.risk_score)

    def test_security_score_floor_when_risk_capped(self):
        result = self._result([_finding(Severity.CRITICAL) for _ in range(50)])
        self.assertEqual(result.security_score, 0)

    def test_sorted_findings_orders_by_severity_desc(self):
        result = self._result([_finding(Severity.LOW), _finding(Severity.CRITICAL), _finding(Severity.MEDIUM)])
        severities = [f.severity for f in result.sorted_findings()]
        self.assertEqual(severities, [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW])

    def test_duration_seconds(self):
        result = self._result([])
        self.assertGreaterEqual(result.duration_seconds, 5.0)


if __name__ == "__main__":
    unittest.main()
