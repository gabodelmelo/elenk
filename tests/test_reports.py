import json
import unittest
from datetime import datetime, timezone

from elenk.core.models import Finding, ScanResult, ScannerRunInfo, Severity
from elenk.core.reports import to_json, to_markdown
from elenk.core.reports.html_report import _shorten as html_shorten
from elenk.core.reports.markdown_report import _shorten as markdown_shorten


def _sample_result() -> ScanResult:
    now = datetime.now(timezone.utc)
    finding = Finding(
        tool="trivy",
        rule_id="CVE-2023-0001",
        title="Example vulnerability",
        description="Example description",
        severity=Severity.CRITICAL,
        package_name="flask",
        installed_version="1.0",
        fixed_version="2.0",
        remediation="Update flask",
    )
    return ScanResult(
        repo_url="https://github.com/x/y",
        repo_name="x/y",
        commit_sha="abc123",
        detected_ecosystems=["python"],
        findings=[finding],
        scanner_runs=[ScannerRunInfo(tool="trivy", applicable=True, available=True, ran=True, finding_count=1)],
        started_at=now,
        finished_at=now,
    )


class TestOssReports(unittest.TestCase):
    def test_to_json_roundtrips(self):
        result = _sample_result()
        data = json.loads(to_json(result))
        self.assertEqual(data["summary"]["total_findings"], 1)
        self.assertEqual(data["findings"][0]["package_name"], "flask")

    def test_to_markdown_contains_key_sections(self):
        markdown = to_markdown(_sample_result())
        self.assertIn("Vulnerability report", markdown)
        self.assertIn("CRITICAL", markdown)
        self.assertIn("flask", markdown)


class TestShortenDescription(unittest.TestCase):
    """`_shorten` is duplicated in html_report and markdown_report (kept
    independent on purpose); both must behave the same."""

    def test_short_text_is_untouched(self):
        for shorten in (html_shorten, markdown_shorten):
            self.assertEqual(shorten("A short description."), "A short description.")

    def test_prefers_ending_on_the_first_sentence(self):
        text = (
            "First sentence here, already past the short-description limit on its own. "
            "Second sentence that would otherwise get cut off awkwardly mid-word if we just chopped at a fixed length."
        )
        for shorten in (html_shorten, markdown_shorten):
            self.assertEqual(
                shorten(text),
                "First sentence here, already past the short-description limit on its own.",
            )

    def test_never_cuts_off_mid_word(self):
        # A long, single run-on sentence with no early period: must fall
        # back to a clean word boundary, not a mid-word chop.
        text = "word " * 60
        for shorten in (html_shorten, markdown_shorten):
            result = shorten(text.strip())
            self.assertTrue(result.endswith("…"))
            self.assertNotIn(" w…", result)  # would indicate a mid-word cut


if __name__ == "__main__":
    unittest.main()
