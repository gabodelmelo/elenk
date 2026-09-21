from elenk.core.scanners.base import Scanner, ScannerRunOutcome
from elenk.core.scanners.gitleaks_scanner import GitleaksScanner
from elenk.core.scanners.osv_scanner import OsvScanner
from elenk.core.scanners.semgrep_scanner import SemgrepScanner
from elenk.core.scanners.trivy_scanner import TrivyScanner

#: Central registry of scanners available in the engine. Adding a new
#: scanner = write the class + register it here.
ALL_SCANNERS: list[type[Scanner]] = [
    SemgrepScanner,
    TrivyScanner,
    GitleaksScanner,
    OsvScanner,
]

__all__ = [
    "Scanner",
    "ScannerRunOutcome",
    "SemgrepScanner",
    "TrivyScanner",
    "GitleaksScanner",
    "OsvScanner",
    "ALL_SCANNERS",
]
