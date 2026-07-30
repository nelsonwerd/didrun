"""Fixtures and guardrails for the compat replay harness.

The corpus leg is OFF unless ``DIDRUN_COMPAT_CORPUS`` points at a copy of an
archive tree, so CI is green by construction and no unattended run can ever
touch a live ledger.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest

from . import synthetic

ENV_VAR = "DIDRUN_COMPAT_CORPUS"

SKIP_UNSET = (
    "set DIDRUN_COMPAT_CORPUS to a COPY of an archive tree to run the corpus replay"
)
SKIP_MISSING = (
    "DIDRUN_COMPAT_CORPUS does not point at a directory; "
    "point it at a COPY of an archive tree to run the corpus replay"
)
SKIP_LIVE = (
    "DIDRUN_COMPAT_CORPUS points at a live repo (it has both a .didrun ledger "
    "and a .git dir); this harness must never read a ledger something else is "
    "writing. Copy the tree WITHOUT its live .didrun directory (the archives "
    "under .didrun-history and the git dir are what the legs need) and point "
    "the variable at the copy"
)
SKIP_REFUSED = (
    "DIDRUN_COMPAT_CORPUS points at (or inside) a tree this harness refuses by "
    "name: it is live, secret-bearing evidence for a running build. Make a copy "
    "on a separate volume and point the variable at the copy"
)

# The refused trees, stored as sha256 digests of their absolute paths rather
# than as literals. Two rules meet here and a digest is the only thing that
# satisfies both: the pack requires these exact paths refused BY NAME, and
# RULES 17 forbids any private absolute path, repo name, or home directory in a
# shipped file. A one-way digest names nothing and still matches exactly.
# A heuristic is not a guardrail when the thing it guards is a running build's
# evidence, so this sits in front of the live-repo heuristic, not instead of it.
_REFUSED_PATH_DIGESTS = frozenset(
    {
        "44b1bd2169fdc4af5ac880330a6917f49456f19ad63efeb79326655e5cd3b4d2",
        "08a945e5d11024bbc32f34f1f5dbf0b57c3590c08177d0391c0e0172a777acf1",
    }
)


def path_digest(path) -> str:
    """sha256 of an absolute path string, trailing separator normalized away."""
    s = str(path).rstrip("/")
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def is_refused(path, digests=_REFUSED_PATH_DIGESTS) -> bool:
    """True if ``path``, its realpath, or any ancestor of either is refused."""
    for candidate in {str(path), os.path.realpath(str(path))}:
        p = Path(candidate)
        for ancestor in (p, *p.parents):
            if path_digest(ancestor) in digests:
                return True
    return False


def resolve_corpus_root(environ, digests=_REFUSED_PATH_DIGESTS) -> tuple:
    """Return ``(root, skip_reason)``. Exactly one of the two is None.

    Pure over its ``environ`` and ``digests`` arguments so both the skip
    behaviour and the refusal branch are testable without depending on what the
    ambient environment holds or on knowing a refused path.
    """
    raw = environ.get(ENV_VAR, "").strip()
    if not raw:
        return None, SKIP_UNSET
    root = Path(raw)
    if is_refused(root, digests):
        return None, SKIP_REFUSED
    if not root.is_dir():
        return None, SKIP_MISSING
    if (root / ".didrun").exists() and (root / ".git").exists():
        return None, SKIP_LIVE
    return root, None


@dataclass(frozen=True)
class ReplaySource:
    """One tree the legs run over. ``expected`` is set only for synthetic."""

    name: str
    root: Path
    expected: Optional[synthetic.Expectations] = None


@pytest.fixture(scope="session")
def synthetic_corpus(tmp_path_factory) -> synthetic.SyntheticCorpus:
    return synthetic.build_corpus(tmp_path_factory.mktemp("synthetic-corpus"))


@pytest.fixture(scope="session")
def known_bad_corpus(tmp_path_factory) -> Path:
    return synthetic.build_known_bad(tmp_path_factory.mktemp("known-bad-corpus"))


@pytest.fixture(scope="session")
def corpus_root() -> Path:
    root, reason = resolve_corpus_root(os.environ)
    if root is None:
        pytest.skip(reason)
    return root


@pytest.fixture(params=["synthetic", "corpus"])
def replay_source(request) -> ReplaySource:
    if request.param == "synthetic":
        fixture = request.getfixturevalue("synthetic_corpus")
        return ReplaySource("synthetic", fixture.root, fixture.expected)
    return ReplaySource("corpus", request.getfixturevalue("corpus_root"))


def has_git_repo(root: Path) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--git-dir"], capture_output=True
    )
    return proc.returncode == 0


# --- the run summary ---------------------------------------------------------
# Counts only. Every line put in here has been through _assert_no_content first.

_SUMMARY: list = []


def record_summary(line: str) -> None:
    _SUMMARY.append(line)


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:
    tr = terminalreporter
    tr.write_sep("-", "compat replay")
    root, _reason = resolve_corpus_root(os.environ)
    if root is None:
        # In these exact words: a green synthetic run is not corpus validation.
        tr.write_line("corpus: SKIPPED (unverified)")
    for line in _SUMMARY:
        tr.write_line(line)
