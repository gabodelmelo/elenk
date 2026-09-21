import subprocess
import sys
import unittest
from unittest.mock import patch

from elenk.core.scanner_setup import SCANNERS, install_command, is_installed, run_install

_SEMGREP = next(s for s in SCANNERS if s.name == "semgrep")
_TRIVY = next(s for s in SCANNERS if s.name == "trivy")
_GITLEAKS = next(s for s in SCANNERS if s.name == "gitleaks")
_OSV = next(s for s in SCANNERS if s.name == "osv-scanner")


class TestIsInstalled(unittest.TestCase):
    def test_true_when_binary_on_path(self):
        with patch("elenk.core.scanner_setup.shutil.which", return_value="/usr/bin/trivy"):
            self.assertTrue(is_installed(_TRIVY))

    def test_false_when_binary_missing(self):
        with patch("elenk.core.scanner_setup.shutil.which", return_value=None):
            self.assertFalse(is_installed(_TRIVY))


class TestInstallCommand(unittest.TestCase):
    def test_semgrep_always_uses_pip_regardless_of_os(self):
        with patch("elenk.core.scanner_setup.platform.system", return_value="Linux"), patch(
            "elenk.core.scanner_setup.shutil.which", return_value=None
        ):
            command = install_command(_SEMGREP)
        self.assertEqual(command, [sys.executable, "-m", "pip", "install", "semgrep"])

    def test_windows_uses_winget_with_correct_package_id(self):
        with patch("elenk.core.scanner_setup.platform.system", return_value="Windows"), patch(
            "elenk.core.scanner_setup.shutil.which", return_value="C:\\winget.exe"
        ):
            command = install_command(_TRIVY)
        self.assertIn("winget", command)
        self.assertIn("AquaSecurity.Trivy", command)

    def test_windows_without_winget_returns_none(self):
        with patch("elenk.core.scanner_setup.platform.system", return_value="Windows"), patch(
            "elenk.core.scanner_setup.shutil.which", return_value=None
        ):
            self.assertIsNone(install_command(_GITLEAKS))

    def test_macos_uses_brew_formula(self):
        with patch("elenk.core.scanner_setup.platform.system", return_value="Darwin"), patch(
            "elenk.core.scanner_setup.shutil.which", return_value="/usr/local/bin/brew"
        ):
            command = install_command(_OSV)
        self.assertEqual(command, ["brew", "install", "osv-scanner"])

    def test_linux_without_brew_returns_none(self):
        with patch("elenk.core.scanner_setup.platform.system", return_value="Linux"), patch(
            "elenk.core.scanner_setup.shutil.which", return_value=None
        ):
            self.assertIsNone(install_command(_TRIVY))


class TestRunInstall(unittest.TestCase):
    def test_no_command_available_reports_manual_url(self):
        with patch("elenk.core.scanner_setup.install_command", return_value=None):
            ok, message = run_install(_TRIVY)
        self.assertFalse(ok)
        self.assertIn(_TRIVY.manual_url, message)

    def test_success_reports_installed(self):
        with patch("elenk.core.scanner_setup.install_command", return_value=["true"]), patch(
            "elenk.core.scanner_setup.subprocess.run",
            return_value=subprocess.CompletedProcess(args=["true"], returncode=0, stdout="", stderr=""),
        ), patch("elenk.core.scanner_setup.is_installed", return_value=True):
            ok, message = run_install(_TRIVY)
        self.assertTrue(ok)
        self.assertEqual(message, "installed successfully")

    def test_success_but_not_yet_on_path_warns_to_reopen_terminal(self):
        with patch("elenk.core.scanner_setup.install_command", return_value=["true"]), patch(
            "elenk.core.scanner_setup.subprocess.run",
            return_value=subprocess.CompletedProcess(args=["true"], returncode=0, stdout="", stderr=""),
        ), patch("elenk.core.scanner_setup.is_installed", return_value=False):
            ok, message = run_install(_TRIVY)
        self.assertTrue(ok)
        self.assertIn("PATH", message)

    def test_nonzero_returncode_is_failure(self):
        with patch("elenk.core.scanner_setup.install_command", return_value=["false"]), patch(
            "elenk.core.scanner_setup.subprocess.run",
            return_value=subprocess.CompletedProcess(args=["false"], returncode=1, stdout="", stderr="boom"),
        ):
            ok, message = run_install(_TRIVY)
        self.assertFalse(ok)
        self.assertIn("boom", message)

    def test_winget_already_installed_nonzero_returncode_is_success(self):
        winget_output = (
            "Found an existing package already installed. Trying to upgrade the installed package...\n"
            "No available upgrade found.\n"
            "No newer package versions are available from the configured sources."
        )
        with patch("elenk.core.scanner_setup.install_command", return_value=["winget", "install"]), patch(
            "elenk.core.scanner_setup.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["winget", "install"], returncode=-1978335189, stdout=winget_output, stderr=""
            ),
        ):
            ok, message = run_install(_TRIVY)
        self.assertTrue(ok)
        self.assertIn("already installed", message)


if __name__ == "__main__":
    unittest.main()
