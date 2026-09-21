import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from elenk.core.models import FindingCategory, Severity
from elenk.core.scanners.gitleaks_scanner import GitleaksScanner
from elenk.core.scanners.osv_scanner import OsvScanner
from elenk.core.scanners.semgrep_scanner import SemgrepScanner
from elenk.core.scanners.trivy_scanner import TrivyScanner

REPO_PATH = Path("/tmp/fake-repo")


class TestSemgrepScanner(unittest.TestCase):
    def test_parses_results_into_findings(self):
        payload = {
            "results": [
                {
                    "check_id": "python.lang.security.audit.dangerous-subprocess-use",
                    "path": str(REPO_PATH / "app.py"),
                    "start": {"line": 10},
                    "end": {"line": 10},
                    "extra": {
                        "message": "dangerous use of subprocess",
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-78: OS Command Injection"], "references": ["https://x"]},
                    },
                }
            ]
        }
        findings = SemgrepScanner().parse_output(json.dumps(payload), REPO_PATH)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, Severity.HIGH)
        self.assertEqual(f.category, FindingCategory.STATIC_CODE)
        self.assertEqual(f.file_path, "app.py")
        self.assertEqual(f.line, 10)
        self.assertIn("CWE-78: OS Command Injection", f.cwe_ids)

    def test_empty_output_returns_no_findings(self):
        self.assertEqual(SemgrepScanner().parse_output("", REPO_PATH), [])

    def test_empty_results_list(self):
        self.assertEqual(SemgrepScanner().parse_output(json.dumps({"results": []}), REPO_PATH), [])


class TestTrivyScanner(unittest.TestCase):
    def test_parses_vulnerabilities_and_misconfigs(self):
        payload = {
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-0001",
                            "PkgName": "flask",
                            "InstalledVersion": "1.0",
                            "FixedVersion": "2.0",
                            "Title": "Vuln in flask",
                            "Severity": "HIGH",
                            "CweIDs": ["CWE-79"],
                        }
                    ],
                    "Misconfigurations": [
                        {
                            "ID": "AVD-DS-0001",
                            "Title": "Dockerfile runs as root",
                            "Severity": "MEDIUM",
                            "Resolution": "Add a non-root USER",
                        }
                    ],
                }
            ]
        }
        findings = TrivyScanner().parse_output(json.dumps(payload), REPO_PATH)
        self.assertEqual(len(findings), 2)

        vuln_finding = next(f for f in findings if f.category == FindingCategory.DEPENDENCY)
        self.assertEqual(vuln_finding.package_name, "flask")
        self.assertEqual(vuln_finding.fixed_version, "2.0")
        self.assertIn("flask", vuln_finding.remediation)

        misconfig_finding = next(f for f in findings if f.category == FindingCategory.MISCONFIGURATION)
        self.assertEqual(misconfig_finding.severity, Severity.MEDIUM)


class TestGitleaksScanner(unittest.TestCase):
    def test_parses_leaks_and_redacts_secret_value(self):
        payload = [
            {
                "Description": "AWS Access Key",
                "RuleID": "aws-access-token",
                "File": "config.py",
                "StartLine": 5,
                "EndLine": 5,
                "Secret": "AKIA_SUPER_SECRET_VALUE",
                "Match": "AKIA_SUPER_SECRET_VALUE",
            }
        ]
        findings = GitleaksScanner()._parse_report(json.dumps(payload), REPO_PATH)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, Severity.HIGH)
        self.assertEqual(f.category, FindingCategory.SECRET)
        self.assertNotIn("Secret", f.raw)
        self.assertNotIn("Match", f.raw)

    def test_empty_report_returns_no_findings(self):
        self.assertEqual(GitleaksScanner()._parse_report("", REPO_PATH), [])
        self.assertEqual(GitleaksScanner()._parse_report("[]", REPO_PATH), [])


class TestOsvScanner(unittest.TestCase):
    def test_parses_vulnerabilities_with_database_specific_severity(self):
        payload = {
            "results": [
                {
                    "source": {"path": "requirements.txt"},
                    "packages": [
                        {
                            "package": {"name": "flask", "version": "1.0"},
                            "vulnerabilities": [
                                {
                                    "id": "GHSA-xxxx",
                                    "summary": "Vuln in flask",
                                    "database_specific": {"severity": "HIGH"},
                                    "references": [{"url": "https://x"}],
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        findings = OsvScanner().parse_output(json.dumps(payload), REPO_PATH)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, Severity.HIGH)
        self.assertEqual(f.package_name, "flask")

    def test_falls_back_to_unknown_severity_without_data(self):
        payload = {
            "results": [
                {
                    "source": {"path": "requirements.txt"},
                    "packages": [
                        {
                            "package": {"name": "flask", "version": "1.0"},
                            "vulnerabilities": [{"id": "GHSA-yyyy", "summary": "no severity"}],
                        }
                    ],
                }
            ]
        }
        findings = OsvScanner().parse_output(json.dumps(payload), REPO_PATH)
        self.assertEqual(findings[0].severity, Severity.UNKNOWN)

    def test_recognizes_no_package_sources_message_as_benign(self):
        scanner = OsvScanner()
        self.assertTrue(
            scanner.is_benign_empty_result(128, "No package sources found, --help for usage information.")
        )
        self.assertFalse(scanner.is_benign_empty_result(128, "some unrelated failure"))

    def test_run_reports_no_error_when_no_lockfile_present(self):
        # osv-scanner exits 128 (not 0/1) with this message when the
        # target has no lockfile/manifest at all — should surface as
        # zero findings, not a scanner error.
        stderr = (
            "Scanning dir /tmp/fake-repo\n"
            "Starting filesystem walk for root: C:\\\n"
            "End status: 1 dirs visited, 1 inodes visited, 0 Extract calls, 0.5ms elapsed\n"
            "No package sources found, --help for usage information.\n"
        )
        with patch(
            "elenk.core.scanners.base.subprocess.run",
            return_value=subprocess.CompletedProcess(args=["osv-scanner"], returncode=128, stdout="", stderr=stderr),
        ):
            outcome = OsvScanner().run(REPO_PATH)
        self.assertIsNone(outcome.error)
        self.assertEqual(outcome.findings, [])

    def test_run_still_reports_real_errors(self):
        with patch(
            "elenk.core.scanners.base.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["osv-scanner"], returncode=128, stdout="", stderr="panic: something actually broke"
            ),
        ):
            outcome = OsvScanner().run(REPO_PATH)
        self.assertIsNotNone(outcome.error)
        self.assertIn("something actually broke", outcome.error)


if __name__ == "__main__":
    unittest.main()
