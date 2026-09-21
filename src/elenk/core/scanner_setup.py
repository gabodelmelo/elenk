"""
Automatic installation of the external scanners the engine orchestrates
(Semgrep, Trivy, Gitleaks, OSV-Scanner). Elenk doesn't reimplement them,
so it depends on having them installed on the system — this module
automates that step (`elenk install-scanners`) instead of leaving it
fully manual (see the prerequisites table in the README).

Coverage by operating system:
  - Windows: via winget, with each package's official ID.
  - macOS: via Homebrew, with the official homebrew-core formulas.
  - Linux: there's no single package manager with reliable coverage for
    trivy/gitleaks/osv-scanner across every distro, so instead of
    guessing blindly this links to each tool's official install docs
    (or uses linuxbrew if the user already has it).

Semgrep is the exception: it's a pure, cross-platform PyPI package, so
besides being handled here (via pip) it's also declared as a regular
dependency in pyproject.toml — it installs with `pip install -e .`,
no extra steps needed.
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import List, Optional, Tuple

# Phrases (in English; winget doesn't localize these messages even when
# the rest of the UI is in another language) that winget/brew use to say
# "already installed, nothing to update" while still returning a
# non-zero exit code.
_ALREADY_INSTALLED_MARKERS = re.compile(
    r"already installed|no applicable update found|no newer package versions are available|"
    r"no available upgrade found",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ScannerSpec:
    name: str
    binary_name: str
    windows_winget_id: Optional[str]
    brew_formula: Optional[str]
    manual_url: str


SCANNERS: List[ScannerSpec] = [
    ScannerSpec(
        name="semgrep",
        binary_name="semgrep",
        windows_winget_id=None,
        brew_formula=None,
        manual_url="https://semgrep.dev/docs/getting-started/",
    ),
    ScannerSpec(
        name="trivy",
        binary_name="trivy",
        windows_winget_id="AquaSecurity.Trivy",
        brew_formula="trivy",
        manual_url="https://trivy.dev/latest/getting-started/installation/",
    ),
    ScannerSpec(
        name="gitleaks",
        binary_name="gitleaks",
        windows_winget_id="Gitleaks.Gitleaks",
        brew_formula="gitleaks",
        manual_url="https://github.com/gitleaks/gitleaks#installing",
    ),
    ScannerSpec(
        name="osv-scanner",
        binary_name="osv-scanner",
        windows_winget_id="Google.OSVScanner",
        brew_formula="osv-scanner",
        manual_url="https://google.github.io/osv-scanner/installation/",
    ),
]


def is_installed(spec: ScannerSpec) -> bool:
    return shutil.which(spec.binary_name) is not None


def install_command(spec: ScannerSpec) -> Optional[List[str]]:
    """Command to install `spec` on this operating system, or None if
    there's no supported automatic method here (Linux without Homebrew)."""
    if spec.name == "semgrep":
        return [sys.executable, "-m", "pip", "install", "semgrep"]

    system = platform.system()
    if system == "Windows" and spec.windows_winget_id and shutil.which("winget"):
        return [
            "winget",
            "install",
            "--id",
            spec.windows_winget_id,
            "-e",
            "--source",
            "winget",
            "--accept-package-agreements",
            "--accept-source-agreements",
        ]
    if system in ("Darwin", "Linux") and spec.brew_formula and shutil.which("brew"):
        return ["brew", "install", spec.brew_formula]
    return None


def run_install(spec: ScannerSpec) -> Tuple[bool, str]:
    """Installs `spec`. Returns (ok, message)."""
    command = install_command(spec)
    if command is None:
        return False, f"no automatic method on this system; install manually: {spec.manual_url}"

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
        )
    except FileNotFoundError:
        return False, f"couldn't find the package manager needed to install {spec.name}"
    except subprocess.TimeoutExpired:
        return False, f"installing {spec.name} exceeded the time limit (600s)"

    output = f"{result.stdout or ''}\n{result.stderr or ''}"

    if result.returncode != 0:
        if _ALREADY_INSTALLED_MARKERS.search(output):
            # winget returns a non-zero code when the package is already
            # installed and there's no newer version to upgrade to — not
            # an error, it's exactly the outcome we want (already there).
            return True, (
                "already installed according to the package manager. If 'list-scanners' still "
                "doesn't see it, this terminal hasn't picked up the PATH change — open a new one."
            )
        detail = output.strip()[:400]
        return False, detail or f"the installer exited with code {result.returncode}"

    if is_installed(spec):
        return True, "installed successfully"
    return True, (
        "the installer finished without errors, but the binary still isn't visible on this "
        "terminal's PATH. Open a new terminal and check with 'elenk list-scanners'."
    )
