"""
Detects which ecosystems/technologies are present in a repository, to
decide which scanners are worth running.

This avoids, for example, running osv-scanner (dependencies) on a repo
that has no dependency manifest, or spending time on Trivy misconfig
checks when there's no Dockerfile/Terraform.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Set

# Each ecosystem maps to its "indicator" files, which, if present
# anywhere in the repo (not just the root), activate it.
_ECOSYSTEM_INDICATORS: Dict[str, tuple[str, ...]] = {
    "python": ("requirements.txt", "Pipfile", "pyproject.toml", "setup.py"),
    "node": ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"),
    "go": ("go.mod", "go.sum"),
    "java": ("pom.xml", "build.gradle", "build.gradle.kts"),
    "ruby": ("Gemfile", "Gemfile.lock"),
    "php": ("composer.json", "composer.lock"),
    "rust": ("Cargo.toml", "Cargo.lock"),
    "docker": ("Dockerfile", "docker-compose.yml", "docker-compose.yaml"),
    "terraform": ("main.tf", ".tf"),  # ".tf" is treated as a suffix, see below
    "kubernetes": ("k8s", "kustomization.yaml"),
}

# Directories not worth walking (saves time on large repos).
_IGNORED_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".venv",
    "venv",
}

_MAX_FILES_TO_SCAN = 5000  # defensive limit for huge repos


def detect_ecosystems(repo_path: Path) -> Set[str]:
    """Walks the repo (within reasonable limits) and returns the set of
    detected ecosystems, e.g. {"python", "docker"}."""
    found: Set[str] = set()
    files_seen = 0

    for path in repo_path.rglob("*"):
        if files_seen >= _MAX_FILES_TO_SCAN:
            break
        if not path.is_file():
            continue
        if any(part in _IGNORED_DIRS for part in path.parts):
            continue

        files_seen += 1
        name = path.name

        for ecosystem, indicators in _ECOSYSTEM_INDICATORS.items():
            if ecosystem in found:
                continue
            for indicator in indicators:
                if indicator.startswith("."):
                    if name.endswith(indicator):
                        found.add(ecosystem)
                        break
                elif name == indicator:
                    found.add(ecosystem)
                    break

    return found


def has_git_history(repo_path: Path) -> bool:
    return (repo_path / ".git").exists()
