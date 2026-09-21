"""
Downloads (clones) a public GitHub repository into a temporary
directory so it can be analyzed locally with the various scanners.

Current scope: only PUBLIC repos via URL, cloned without authentication
(git clone --depth 1). The interface already leaves room to add
authentication (PAT/OAuth) later without breaking the rest of the
engine: see the `auth_token` parameter (not used yet) in `fetch_repo`.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

_GITHUB_URL_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$"
)


class InvalidRepoUrlError(ValueError):
    pass


class RepoCloneError(RuntimeError):
    pass


@dataclass
class FetchedRepo:
    """Result of cloning a repository: where it ended up on disk and
    its identity (owner/repo, commit)."""

    path: Path
    owner: str
    repo: str
    commit_sha: Optional[str]

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.repo}"


def parse_github_url(url: str) -> tuple[str, str]:
    """Validates and splits a GitHub URL into (owner, repo).

    Accepts variants like:
      - https://github.com/owner/repo
      - https://github.com/owner/repo.git
      - github.com/owner/repo
    """
    match = _GITHUB_URL_RE.match(url.strip())
    if not match:
        raise InvalidRepoUrlError(
            f"'{url}' doesn't look like a valid GitHub repository URL "
            "(expected something like https://github.com/owner/repo)"
        )
    return match.group("owner"), match.group("repo")


def _run_git(args: list[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )


def fetch_repo(
    url: str,
    dest_dir: Optional[Path] = None,
    auth_token: Optional[str] = None,
) -> FetchedRepo:
    """Clones the public repository `url` into `dest_dir` (or a fresh
    temporary directory if none given) at depth 1.

    `auth_token` is reserved for the future extension to private repos
    (it would be injected as a credential in the URL or via header);
    today it's unused and this function only supports public repos.
    """
    owner, repo = parse_github_url(url)

    if auth_token:
        raise NotImplementedError(
            "Access to private repos via token isn't implemented in this "
            "version yet. It's reserved as a future extension of the engine."
        )

    if shutil.which("git") is None:
        raise RepoCloneError("git isn't installed on this system; it's required to clone repos.")

    if dest_dir is None:
        dest_dir = Path(tempfile.mkdtemp(prefix="elenk_"))
    else:
        dest_dir.mkdir(parents=True, exist_ok=True)

    clone_url = f"https://github.com/{owner}/{repo}.git"
    result = _run_git(["clone", "--depth", "1", clone_url, str(dest_dir)])
    if result.returncode != 0:
        raise RepoCloneError(
            f"Could not clone {clone_url}: {result.stderr.strip() or result.stdout.strip()}"
        )

    commit_sha: Optional[str] = None
    rev = _run_git(["rev-parse", "HEAD"], cwd=dest_dir)
    if rev.returncode == 0:
        commit_sha = rev.stdout.strip()

    return FetchedRepo(path=dest_dir, owner=owner, repo=repo, commit_sha=commit_sha)


@contextmanager
def cloned_repo(
    url: str,
    keep: bool = False,
    auth_token: Optional[str] = None,
) -> Iterator[FetchedRepo]:
    """Context manager that clones the repo, hands it over for analysis,
    and cleans up the temporary directory on exit (unless `keep=True`)."""
    fetched = fetch_repo(url, auth_token=auth_token)
    try:
        yield fetched
    finally:
        if not keep:
            shutil.rmtree(fetched.path, ignore_errors=True)
