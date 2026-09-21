"""
Orchestrator: given a repo already cloned on disk, decides which
scanners to run, runs them, and consolidates everything into a
`ScanResult`.

This module is the heart of the engine.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence, Type

from elenk.core.detector import detect_ecosystems
from elenk.core.models import Finding, ScanResult, ScannerRunInfo, utcnow
from elenk.core.scanners import ALL_SCANNERS, Scanner


def run_scan(
    repo_path: Path,
    repo_url: str,
    repo_name: str,
    commit_sha: Optional[str],
    scanner_classes: Optional[Sequence[Type[Scanner]]] = None,
    on_scanner_start: Optional[Callable[[str], None]] = None,
    on_scanner_done: Optional[Callable[[ScannerRunInfo], None]] = None,
) -> ScanResult:
    """Runs the full analysis pipeline over a repo already present on
    disk (normally handed over by `repo_fetcher`).

    `scanner_classes` restricts which scanners run (e.g. from the CLI
    with `--scanners semgrep,gitleaks`); by default every scanner
    registered in `ALL_SCANNERS` is considered.

    `on_scanner_start`/`on_scanner_done` are optional callbacks invoked
    before/after processing each scanner (whether it applies, is
    available, or not) — meant to let the CLI show a real progress bar
    without the orchestrator knowing anything about terminals.
    """
    started_at = utcnow()
    classes = list(scanner_classes) if scanner_classes else ALL_SCANNERS

    ecosystems = detect_ecosystems(repo_path)

    all_findings: List[Finding] = []
    run_infos: List[ScannerRunInfo] = []

    for scanner_cls in classes:
        scanner = scanner_cls()
        if on_scanner_start:
            on_scanner_start(scanner.name)

        applicable = scanner.is_applicable(ecosystems)
        available = scanner.is_available()

        if not applicable:
            run_info = ScannerRunInfo(
                tool=scanner.name,
                applicable=False,
                available=available,
                ran=False,
                skipped_reason="doesn't apply to the ecosystems detected in this repo",
            )
        elif not available:
            run_info = ScannerRunInfo(
                tool=scanner.name,
                applicable=True,
                available=False,
                ran=False,
                skipped_reason=(
                    f"'{scanner.binary_name}' isn't installed; see the README for install instructions"
                ),
            )
        else:
            outcome = scanner.run(repo_path)
            deduped = _dedupe(outcome.findings)
            all_findings.extend(deduped)
            run_info = ScannerRunInfo(
                tool=scanner.name,
                applicable=True,
                available=True,
                ran=True,
                duration_seconds=outcome.duration_seconds,
                finding_count=len(deduped),
                error=outcome.error,
            )

        run_infos.append(run_info)
        if on_scanner_done:
            on_scanner_done(run_info)

    finished_at = utcnow()

    return ScanResult(
        repo_url=repo_url,
        repo_name=repo_name,
        commit_sha=commit_sha,
        detected_ecosystems=sorted(ecosystems),
        findings=all_findings,
        scanner_runs=run_infos,
        started_at=started_at,
        finished_at=finished_at,
    )


def _dedupe(findings: Iterable[Finding]) -> List[Finding]:
    """Removes exact duplicates (same tool+rule+file+line+package) that
    tools sometimes report more than once for the same finding (e.g.
    Semgrep with overlapping rules)."""
    seen: set[str] = set()
    result: List[Finding] = []
    for finding in findings:
        if finding.id in seen:
            continue
        seen.add(finding.id)
        result.append(finding)
    return result
