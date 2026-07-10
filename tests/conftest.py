"""Shared fixtures: throwaway git repos and didrun sessions."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=str(repo), capture_output=True, text=True, check=True
    )
    return proc.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A fresh git repo with one committed file."""
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    _git(r, "config", "user.email", "t@t.t")
    _git(r, "config", "user.name", "t")
    _git(r, "config", "commit.gpgsign", "false")
    (r / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    _git(r, "add", "calc.py")
    _git(r, "commit", "-qm", "init")
    return r


@pytest.fixture
def git():
    return _git
