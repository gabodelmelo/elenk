"""Elenk open source CLI — audit a public GitHub repo before you trust it.

Basic usage:

    elenk scan https://github.com/owner/repo

Examples:

    # Choose output formats and destination folder
    elenk scan https://github.com/owner/repo --format json,markdown -o ./reports

    # Restrict to specific scanners
    elenk scan https://github.com/owner/repo --scanners semgrep,gitleaks

    # Keep the repo clone (don't delete the temp directory)
    elenk scan https://github.com/owner/repo --keep-clone

If the `elenk` executable isn't on PATH, any of these commands work the
same as `python -m elenk scan ...`.
"""

from __future__ import annotations

import sys
import threading
import webbrowser
from pathlib import Path
from typing import Optional, Tuple

import click

from elenk.core.orchestrator import run_scan
from elenk.core.repo_fetcher import InvalidRepoUrlError, RepoCloneError, cloned_repo
from elenk.core.reports import to_json, write_html_report, write_json_report, write_markdown_report
from elenk.core.scanners import ALL_SCANNERS

_SCANNER_BY_NAME = {cls().name: cls for cls in ALL_SCANNERS}


class _SmoothProgress:
    """Drives a click progress bar as a real 0-100% gauge instead of one
    big jump per scanner. Individual scanners don't report fine-grained
    progress themselves, so a background ticker fills each scanner's
    slice of the bar smoothly while it runs (capped short of the slice's
    edge, so it never looks "done" before the scanner actually is), and
    `on_scanner_done` snaps the bar to the real boundary the moment a
    scanner finishes."""

    def __init__(self, bar: "click.progressbar", total_steps: int, tick_interval: float = 0.12) -> None:
        self._bar = bar
        self._total_steps = max(total_steps, 1)
        self._tick_interval = tick_interval
        self._pos = 0.0
        self._index = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _slice_bounds(self, index: int) -> Tuple[float, float]:
        start = index * 100 / self._total_steps
        end = (index + 1) * 100 / self._total_steps
        return start, end

    def _advance_to(self, target: float) -> None:
        target = min(target, 100.0)
        if target > self._pos:
            self._bar.update(target - self._pos)
            self._pos = target

    def _run(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                start, end = self._slice_bounds(self._index)
                ceiling = start + (end - start) * 0.92
                if self._pos < ceiling:
                    self._advance_to(min(self._pos + 0.6, ceiling))
            self._stop.wait(self._tick_interval)

    def start(self) -> None:
        self._thread.start()

    def on_scanner_start(self, name: str) -> None:
        with self._lock:
            self._bar.label = f"Scanning with {name}"

    def on_scanner_done(self, run_info) -> None:
        with self._lock:
            _, end = self._slice_bounds(self._index)
            self._advance_to(end)
            self._index += 1

    def finish(self) -> None:
        self._stop.set()
        self._thread.join(timeout=1)
        with self._lock:
            self._advance_to(100.0)


@click.group()
@click.version_option(package_name="elenk")
def main() -> None:
    """Elenk — audit a public GitHub repo before you trust it."""


@main.command()
@click.argument("repo_url")
@click.option(
    "-o",
    "--output-dir",
    "output_dir",
    type=click.Path(path_type=Path),
    default=Path("./elenk-report"),
    show_default=True,
    help="Folder where generated reports are saved.",
)
@click.option(
    "--format",
    "formats",
    default="json,markdown,html",
    show_default=True,
    help="Report formats to generate, comma-separated (json,markdown,html).",
)
@click.option(
    "--scanners",
    "scanners_filter",
    default=None,
    help=(
        "Comma-separated list of scanners to run "
        f"(available: {', '.join(_SCANNER_BY_NAME)}). Runs every applicable one by default."
    ),
)
@click.option(
    "--keep-clone",
    is_flag=True,
    default=False,
    help="Don't delete the temp directory the repo was cloned into.",
)
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice(["critical", "high", "medium", "low", "never"], case_sensitive=False),
    default="never",
    show_default=True,
    help="Exit with an error code if a finding of this severity or higher is found (useful for scripting an automatic accept/reject decision).",
)
@click.option(
    "--no-open",
    "no_open",
    is_flag=True,
    default=False,
    help="Don't open the HTML report in the browser when done (it opens automatically by default).",
)
def scan(
    repo_url: str,
    output_dir: Path,
    formats: str,
    scanners_filter: Optional[str],
    keep_clone: bool,
    fail_on: str,
    no_open: bool,
) -> None:
    """Clones REPO_URL (must be a public GitHub repo) and runs the
    vulnerability analysis on it."""

    selected_formats = {f.strip().lower() for f in formats.split(",") if f.strip()}
    invalid_formats = selected_formats - {"json", "markdown", "html"}
    if invalid_formats:
        raise click.UsageError(
            f"Unsupported format(s): {', '.join(invalid_formats)}. Use json, markdown and/or html."
        )

    scanner_classes = None
    if scanners_filter:
        names = [s.strip().lower() for s in scanners_filter.split(",") if s.strip()]
        unknown = [n for n in names if n not in _SCANNER_BY_NAME]
        if unknown:
            raise click.UsageError(
                f"Unknown scanner(s): {', '.join(unknown)}. Available: {', '.join(_SCANNER_BY_NAME)}"
            )
        scanner_classes = [_SCANNER_BY_NAME[n] for n in names]

    click.echo(f"Cloning {repo_url}...")
    try:
        with cloned_repo(repo_url, keep=keep_clone) as fetched:
            click.echo(f"Scanning {fetched.full_name} (commit {fetched.commit_sha[:12] if fetched.commit_sha else '?'})...")

            scanners_to_run = scanner_classes or ALL_SCANNERS
            with click.progressbar(
                length=100,
                label="Scanning",
                show_eta=False,
                show_percent=True,
                show_pos=False,
            ) as bar:
                progress = _SmoothProgress(bar, len(scanners_to_run))
                progress.start()
                result = run_scan(
                    repo_path=fetched.path,
                    repo_url=repo_url,
                    repo_name=fetched.full_name,
                    commit_sha=fetched.commit_sha,
                    scanner_classes=scanner_classes,
                    on_scanner_start=progress.on_scanner_start,
                    on_scanner_done=progress.on_scanner_done,
                )
                progress.finish()
    except InvalidRepoUrlError as exc:
        raise click.UsageError(str(exc))
    except RepoCloneError as exc:
        click.echo(f"Error cloning the repository: {exc}", err=True)
        sys.exit(2)

    output_dir.mkdir(parents=True, exist_ok=True)

    if "json" in selected_formats:
        path = write_json_report(result, output_dir / "report.json")
        click.echo(f"JSON report written to {path}")

    if "markdown" in selected_formats:
        path = write_markdown_report(result, output_dir / "report.md")
        click.echo(f"Markdown report written to {path}")

    if "html" in selected_formats:
        path = write_html_report(result, output_dir / "report.html")
        click.echo(f"HTML report written to {path}")
        if not no_open:
            webbrowser.open(path.resolve().as_uri())

    click.echo("")
    click.echo(
        f"Summary: {result.total_findings} finding(s), security score {result.security_score}/100 — "
        + ", ".join(f"{k}: {v}" for k, v in result.summary_by_severity.items() if v)
    )

    if fail_on != "never":
        threshold_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2}[fail_on]
        if any(f.severity.rank >= threshold_rank for f in result.findings):
            click.echo(
                f"Found findings with severity >= {fail_on}. Exiting with a non-zero code.",
                err=True,
            )
            sys.exit(1)


@main.command("list-scanners")
def list_scanners() -> None:
    """Shows the scanners registered in the engine and whether they're installed."""
    for cls in ALL_SCANNERS:
        scanner = cls()
        status = "installed" if scanner.is_available() else "NOT installed"
        click.echo(f"- {scanner.name} ({scanner.binary_name}): {status}")


@main.command("install-scanners")
@click.option("--yes", "-y", is_flag=True, default=False, help="Don't ask for confirmation before installing.")
@click.option("--dry-run", is_flag=True, default=False, help="Show the commands that would run, without installing anything.")
def install_scanners(yes: bool, dry_run: bool) -> None:
    """Automatically installs Semgrep, Trivy, Gitleaks and OSV-Scanner
    (the scanners the engine orchestrates) if they aren't already present.

    On Windows it uses winget; on macOS/Linux with Homebrew installed it
    uses brew. Semgrep always installs via pip, on any system."""
    from elenk.core.scanner_setup import SCANNERS, install_command, is_installed, run_install

    missing = [s for s in SCANNERS if not is_installed(s)]
    if not missing:
        click.echo("Every scanner is already installed. Nothing to do.")
        return

    click.echo(f"Missing scanners: {', '.join(s.name for s in missing)}")
    click.echo("")

    plan = []
    for spec in missing:
        command = install_command(spec)
        if command is None:
            click.echo(f"  - {spec.name}: no automatic method on this system. Install manually: {spec.manual_url}")
        else:
            plan.append(spec)
            click.echo(f"  - {spec.name}: {' '.join(command)}")

    if not plan:
        click.echo("")
        click.echo("None of the missing scanners can be installed automatically on this system.", err=True)
        sys.exit(1)

    if dry_run:
        return

    click.echo("")
    if not yes and not click.confirm("Run these commands now?", default=True):
        click.echo("Cancelled. You can run the commands above yourself whenever you want.")
        return

    failures = 0
    for spec in plan:
        click.echo(f"Installing {spec.name}...")
        ok, message = run_install(spec)
        click.echo(f"  {'OK' if ok else 'ERROR'}: {message}")
        if not ok:
            failures += 1

    click.echo("")
    click.echo("Check the result with: elenk list-scanners")
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
