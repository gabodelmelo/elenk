# Elenk

Elenk is an open source **due-diligence tool for auditing a public GitHub repository before you trust it**. Point it at a repo URL — a third-party dependency you're about to pull in, a vendor's open-source codebase you're evaluating, a target you're doing quick security recon on — and it clones the code, runs well-known open source security scanners against it (Semgrep, Trivy, Gitleaks, OSV-Scanner), and produces a JSON, Markdown, and interactive HTML report, with a 0-100 security score and a filterable dashboard of every finding.

**This isn't a CI/CD gate.** Plenty of tools already wrap the same scanners to check *your own* repo on every push. Elenk is built for the opposite moment: looking at *someone else's* code before you decide to depend on it — vetting a library before you add it, assessing a vendor's repo before a partnership, or doing a quick pass on a codebase you don't control and want to understand before you trust it. The scanners underneath are the same commodity tools everyone uses; what's different is the workflow, built around one-off, ad-hoc audits of external repos rather than continuous scanning of your own.

Elenk doesn't reimplement security analysis itself: it orchestrates tools already trusted by the community, normalizes their output into one consistent model, and consolidates everything into a single report.

## Table of contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Optional scanners (automatic install)](#optional-scanners-automatic-install)
- [Troubleshooting](#troubleshooting)
- [Usage](#usage)
- [Architecture](#architecture)
- [Tests](#tests)
- [Current scope and next steps](#current-scope-and-next-steps)

## Prerequisites

### Git (required)

`git` **isn't optional**: Elenk uses it to clone the repository being analyzed (`git clone --depth 1`), so if it isn't installed the command fails right away with `git isn't installed on this system; it's required to clone repos.`

- Windows: [git-scm.com/download/win](https://git-scm.com/download/win) (official installer) or `winget install --id Git.Git -e --source winget`
- macOS: `brew install git` (or comes with Xcode Command Line Tools)
- Linux: your distro's package manager (`apt install git`, `dnf install git`, etc.)
- Verify the install with `git --version` in a new terminal (you may need to reopen the terminal for the PATH to update).

## Installation

Requires Python 3.9+.

```bash
git clone <this-repo>
cd elenk
pip install -e .
```

(If `pip install -e .` fails with `An application control policy blocked this file`, use `python -m pip install -e .` — see [Troubleshooting](#troubleshooting).)

This installs the `elenk` command and, as a normal package dependency, **Semgrep** (it's a pure PyPI package, so it comes automatically with `pip install -e .`, no extra steps needed).

For the rest of the scanners (Trivy, Gitleaks, OSV-Scanner — native binaries `pip` can't install), run this right after:

```bash
elenk install-scanners
```

See [Optional scanners](#optional-scanners-automatic-install) below for details.

## Optional scanners (automatic install)

Elenk **doesn't reimplement** security analysis: it orchestrates well-tested open source tools. Each one is auto-detected if installed; if one is missing, the report says so clearly and continues with the rest (the whole analysis never fails just because one tool is missing) — so this is optional, but installing all of them gives you full coverage (SAST + dependencies + secrets + misconfiguration).

```bash
elenk install-scanners
```

Detects what's missing and installs it automatically:

| Tool | What it's for | How `install-scanners` installs it |
|---|---|---|
| [Semgrep](https://semgrep.dev/docs/getting-started/) | Static code analysis (SAST) | `pip install semgrep` (already comes with `pip install -e .`, see above) |
| [Trivy](https://trivy.dev/latest/getting-started/installation/) | Vulnerable dependencies + IaC/Docker misconfiguration | Windows: winget (`AquaSecurity.Trivy`) · macOS/Linux: Homebrew (`trivy`) |
| [Gitleaks](https://github.com/gitleaks/gitleaks#installing) | Exposed secrets/credentials in code | Windows: winget (`Gitleaks.Gitleaks`) · macOS/Linux: Homebrew (`gitleaks`) |
| [OSV-Scanner](https://google.github.io/osv-scanner/installation/) | Vulnerable dependencies (OSV.dev database) | Windows: winget (`Google.OSVScanner`) · macOS/Linux: Homebrew (`osv-scanner`) |

Options:

```bash
elenk install-scanners --dry-run   # only show the commands, install nothing
elenk install-scanners --yes       # install without asking for confirmation (useful in scripts/automation)
```

On Windows it needs `winget` (preinstalled since Windows 10 2019+/Windows 11); on macOS/Linux it needs [Homebrew](https://brew.sh/). If your system has neither (typical on Linux without Homebrew, where there's no single package manager with reliable coverage for these three binaries across every distro), the command doesn't guess: it shows the official install link for each tool so you can do it manually.

Check what ended up installed with:

```bash
elenk list-scanners
```

**Important:** after running `install-scanners`, **open a new terminal** before checking — both winget and `pip` install binaries into folders that get added to `PATH`, but a terminal you already had open won't reread that variable until you restart it. If in the new terminal `list-scanners` still marks something as "NOT installed" even though the installer didn't report an error, see [Troubleshooting](#troubleshooting).

> **Note (Windows with Application Control policies / managed corporate environments):** in an environment with Windows Defender Application Control, Smart App Control, or a similar corporate security policy, Semgrep may install without error via `pip` but fail at runtime with `OSError: [WinError 4551] An application control policy blocked this file` — Semgrep uses a native binary internally (it isn't pure Python), and that class of policy blocks unsigned/untrusted executables as a rule. This isn't a bug in Elenk or `install-scanners`: it's a security restriction from your system or organization. If this happens, Elenk still works fine with the other scanners (Trivy/Gitleaks/OSV-Scanner didn't hit this issue) — to enable Semgrep, ask whoever manages the policy to allow its executable, or run it inside a Docker/WSL2 container that isn't subject to the same policy.

## Troubleshooting

### Windows: "'elenk' is not recognized as an internal or external command..." (or the same with `semgrep`)

`pip install -e .` did install the package (and, with it, the `semgrep.exe` script), but the folder where Windows keeps those executables isn't on `PATH`. It's the same issue in both cases because `pip` installs them into the same folder. Two fixes:

**Quick (doesn't touch PATH):** call the same command through Python, from the project folder:

```bat
python -m elenk scan https://github.com/owner/repo
python -m elenk install-scanners
```

(The long form `python -m elenk.cli` also works the same, in case you see it in older examples.)

This doesn't apply to `semgrep`: its own CLI dropped support for `python -m semgrep` (unlike `elenk`, which does support `python -m` as a shortcut). If `semgrep` isn't recognized, you need to fix the PATH — see below.

**Permanent:** the most reliable source for the exact folder is the warning `pip install` itself prints at the time, e.g.:

```
WARNING: The script elenk.exe is installed in 'C:\Users\<you>\AppData\Roaming\Python\Python3XX\Scripts' which is not on PATH.
```

That path (the same one for `elenk.exe` and `semgrep.exe`, since the same `pip` installs both) is what you need to add via *Control Panel → System → Advanced system settings → Environment Variables → PATH → Edit → New*. If you didn't save that warning, run `pip install -e .` again to see it (it won't reinstall anything if it's already installed).

You can also test it without restarting the terminal with (only lasts while that window stays open):

```bat
set PATH=%PATH%;<the path from the pip warning>
```

After changing PATH permanently, **open a new terminal** for the change to take effect.

### Windows: `elenk install-scanners` didn't error but `list-scanners` still says "NOT installed"

Almost always the same PATH issue as above, applied to Trivy/Gitleaks/OSV-Scanner: winget installed them correctly on disk (you can confirm with `winget list`), but the current terminal hasn't reread the updated PATH. **Open a new terminal** — no need to restart Windows, a new terminal window is enough.

### Windows: `pip install -e .` fails with "An application control policy blocked this file"

Same class of policy that can block Semgrep (see above), but applied directly to `pip.exe`. It happens in any folder, it's not specific to this project. The workaround is to invoke pip as a Python module instead of calling the executable directly — `python.exe` isn't subject to the same block:

```bash
python -m pip install -e .
```

If that doesn't work either, `python.exe` itself is being blocked — in that case ask whoever manages the policy to allow `python.exe` and `pip.exe`.

### Semgrep installs but fails with `OSError: [WinError 4551]`

See the note about Application Control in the [Optional scanners](#optional-scanners-automatic-install) section — it's a security policy on your system/organization, not a bug.

## Usage

```bash
# Basic scan (generates json + markdown + html by default)
elenk scan https://github.com/owner/repo

# Choose formats and output folder
elenk scan https://github.com/owner/repo --format json,markdown -o ./reports

# Restrict to specific scanners
elenk scan https://github.com/owner/repo --scanners semgrep,gitleaks

# Scripted vetting: exit non-zero on critical findings, e.g. to auto-reject a dependency
elenk scan https://github.com/owner/repo --fail-on critical --no-open
```

While the scanners run, the terminal shows a real progress bar (how many scanners out of the total, and which one is currently running) — so you can see the scan is still going even if a tool takes a while. When it's done, if `report.html` was generated, **it opens automatically in your default browser**; pass `--no-open` to disable this (recommended when scripting Elenk or running it headless, where there's no browser to open).

The `--format html` report (`report.html`) is a single-page interactive dashboard with no external dependencies (all CSS/JS is inline, works offline): a 0-100 security score, summary cards per severity, a table of scanners that ran, and the full list of findings with filters by severity, tool, category, and free text.

Real sample output (generated by this same project against a public test repo, with no scanners installed) in [`examples/sample_output/`](examples/sample_output/).

Current scope: only **public** repos via URL, cloned without authentication. Private-repo support via token is reserved in the architecture (`core.repo_fetcher.fetch_repo`, `auth_token` parameter) but not implemented yet.

## Architecture

```
src/elenk/
├── core/                  # Analysis engine
│   ├── models.py          # Finding, ScanResult, Severity
│   ├── repo_fetcher.py     # Cloning public GitHub repos
│   ├── detector.py         # Ecosystem detection (python/node/docker/...)
│   ├── scanner_setup.py    # `install-scanners`: automatic scanner installation
│   ├── scanners/           # Semgrep, Trivy, Gitleaks, OSV-Scanner wrappers
│   ├── orchestrator.py     # Runs the applicable scanners and consolidates results
│   └── reports/            # JSON, Markdown and HTML report generators
└── cli.py                 # CLI: `elenk`
```

Every scanner wrapper implements the same small interface (`core/scanners/base.py`): build the command, parse the tool's raw output into normalized `Finding` objects. Adding a new scanner means writing one such wrapper and registering it — the orchestrator, detector, and reports don't need to know anything tool-specific.

## Tests

No extra dependencies are needed to run the tests (they use the standard library's `unittest`):

```bash
python -m unittest discover -s tests -v
```

The scanner wrapper tests (`test_scanners.py`) use sample JSON matching each tool's documented output shape, so they don't depend on having the binaries installed. The `install-scanners` tests (`test_scanner_setup.py`) simulate each operating system (Windows/macOS/Linux, with and without winget/Homebrew) so the suite doesn't depend on actually installing anything.

## Current scope and next steps

This first delivery prioritizes a solid engine and a clear architecture over maximum feature coverage. Explicitly out of scope for now:

- Private-repo access (the interface is already reserved in `core.repo_fetcher.fetch_repo`, GitHub OAuth/token support still needs implementing) — useful for vetting a vendor's private repo once you have read access, not for scanning your own private CI checkouts.
- Historical tracking of findings across scans (each run is currently independent, with no persistence between them) — would let you re-audit a dependency after an update and see what changed.
- Side-by-side comparison of multiple candidate repos (e.g. two libraries you're choosing between).
