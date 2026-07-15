"""Deterministic dirty-tree digests and tree deltas via git plumbing.

The mechanism here is not a design choice — it is the one that *survived
measurement* — see docs/MEASUREMENTS.md. The disqualified
alternatives are refused explicitly, with their measured failure reasons, so a
future editor doesn't reintroduce them:

  - ``git stash create``      : returns "clean" when only untracked files exist
                                (agents create files constantly) — blind to real
                                dirt. DISQUALIFIED.
  - status-output hashing     : ``git status --porcelain`` never hashes worktree
                                *content*, so different contents collide.
                                DISQUALIFIED.
  - ``git diff | sha256``     : output varies with user git config
                                (diff.mnemonicPrefix, core.abbrev). DISQUALIFIED.
  - fresh ``read-tree HEAD``   : correct but 3-5x slower than copying the index.
                                Not used.

The kept mechanism: copy the repo's real index to a temp file, ``git add -A``
into it with object writes redirected into the ledger, then ``git write-tree``.
The redirect means digest objects never pollute the user's object DB *and* the
content each command ran against is physically retained in the ledger — which
is what lets ``tree_delta`` compute an exact path+content delta later.

All timings are macOS/APFS/arm64/git-2.50.1 (see docs/MEASUREMENTS.md). A Linux/ext4 rerun of
``capability_probe`` + the benchmark is a documented gate before the envelope is
called normative.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class GitError(Exception):
    """A git plumbing operation failed in a way we refuse to paper over."""


def _run_git(
    args: list[str],
    repo: Path,
    env: Optional[dict] = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    proc = subprocess.run(
        ["git", *args],
        cwd=str(repo),
        env=full_env,
        capture_output=True,
        text=True,
    )
    if check and proc.returncode != 0:
        raise GitError(
            f"git {' '.join(args)} failed ({proc.returncode}): {proc.stderr.strip()}"
        )
    return proc


def is_git_repo(repo: Path) -> bool:
    proc = _run_git(["rev-parse", "--is-inside-work-tree"], repo, check=False)
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def git_dir(repo: Path) -> Path:
    proc = _run_git(["rev-parse", "--git-dir"], repo)
    gd = Path(proc.stdout.strip())
    return gd if gd.is_absolute() else (repo / gd)


def git_common_dir(repo: Path) -> Path:
    """The *shared* git dir — where the real object DB lives.

    Same lesson as ``index_path``: never hardcode ``.git``. In a linked worktree
    ``--git-dir`` is ``.git/worktrees/<name>/``, which has NO ``objects/`` — the
    objects are in the common dir. Pointing the object alternates at
    ``git_dir()/objects`` therefore names a nonexistent directory in a worktree,
    write-tree cannot resolve existing blobs, and the digest silently degrades to
    ``None`` (→ every claim `unknown`). Identical to ``--git-dir`` in a normal
    repo, so this is only ever a no-op or a fix.
    """
    proc = _run_git(["rev-parse", "--git-common-dir"], repo)
    gd = Path(proc.stdout.strip())
    return gd if gd.is_absolute() else (repo / gd)


def objects_dir(repo: Path) -> Path:
    """The real object DB — correct in both normal repos and linked worktrees."""
    return git_common_dir(repo) / "objects"


def index_path(repo: Path) -> Path:
    """Resolve the index via plumbing — never hardcode ``.git/index``.

    Worktrees, ``GIT_INDEX_FILE``, and split index all move it; the measured
    correctness bug was assuming ``.git/index``.
    """
    proc = _run_git(["rev-parse", "--git-path", "index"], repo)
    p = Path(proc.stdout.strip())
    return p if p.is_absolute() else (repo / p)


def head_commit(repo: Path) -> Optional[str]:
    proc = _run_git(["rev-parse", "HEAD"], repo, check=False)
    if proc.returncode != 0:
        return None  # unborn HEAD
    return proc.stdout.strip()


def submodule_dirty(repo: Path) -> bool:
    """True if any submodule has dirty content.

    porcelain-v2 flags this but we do not digest submodule *content*; a claim
    over a dirty-submodule tree is capped at ``stale`` honestly rather than
    silently graded exact.
    """
    proc = _run_git(["status", "--porcelain=v2"], repo, check=False)
    if proc.returncode != 0:
        return False
    for line in proc.stdout.splitlines():
        # v2 submodule state is field 3 of a '1'/'2' record: "S<c><m><u>".
        parts = line.split()
        if len(parts) >= 3 and parts[0] in ("1", "2"):
            sub = parts[2]
            if sub.startswith("S") and sub != "S...":
                return True
    return False


# didrun's own ledger directory. It is tooling state, not reviewed content, so
# it is ALWAYS excluded from tree digests — otherwise the tool would observe its
# own writes and report every tree as "moved" (a self-observation artifact).
# The exclusion is independent of whether the user gitignored it, so the digest
# is stable across repos with different ignore rules.
LEDGER_DIRNAME = ".didrun"


def tree_digest(
    repo: Path,
    ledger_objects: Optional[Path] = None,
    exclude: tuple[str, ...] = (LEDGER_DIRNAME,),
) -> Optional[str]:
    """Digest the current working tree (staged + unstaged + untracked).

    Returns the git tree object id, or ``None`` if the digest could not be taken
    honestly — the caller grades that ``unknown``, never a guess. Digest objects
    are written into ``ledger_objects`` if given (zero pollution of the user's
    object DB) with the repo's real objects available as an alternate so the
    write-tree can reference existing blobs. ``exclude`` pathspecs are kept out
    of the digest (the ledger dir by default).
    """
    if not is_git_repo(repo):
        return None

    src_index = index_path(repo)
    tmp_fd, tmp_index = tempfile.mkstemp(prefix="didrun-index-")
    os.close(tmp_fd)
    try:
        if src_index.exists():
            shutil.copyfile(src_index, tmp_index)
        else:
            # Unborn/indexless repo: start from an empty temp index.
            Path(tmp_index).unlink(missing_ok=True)

        env = {"GIT_INDEX_FILE": tmp_index}
        if ledger_objects is not None:
            ledger_objects = Path(ledger_objects)
            ledger_objects.mkdir(parents=True, exist_ok=True)
            env["GIT_OBJECT_DIRECTORY"] = str(ledger_objects)
            env["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = str(objects_dir(repo))

        # Stage everything into the throwaway index. If this fails, we must NOT
        # write a partial tree — a partial tree would silently under-report dirt.
        #
        # Exclusion is done by the `rm -r --cached` pass below, NOT by an
        # :(exclude,top) pathspec here. git errors out when a pathspec matches a
        # gitignored path, and `.didrun/` gitignored is the config didrun's own
        # docs mandate — naming the ledger in the pathspec made the add fail
        # there, which returned None and graded every claim `unknown`. A bare
        # `add -A -- .` silently skips ignored paths, so the two configs converge:
        # gitignored, the ledger never enters the index; not gitignored, it enters
        # and the rm --cached pass takes it back out. Never use `add -f` to dodge
        # this — that forces *every* ignored path (node_modules, build output)
        # into the digest.
        add = _run_git(["add", "-A", "--", "."], repo, env=env, check=False)
        if add.returncode != 0:
            return None
        # Drop ledger paths that reached the index — staged in this add (ledger
        # not gitignored) or inherited from the copied index (previously staged).
        for spec in exclude:
            _run_git(
                ["rm", "-r", "--cached", "--quiet", "--ignore-unmatch", "--", spec],
                repo,
                env=env,
                check=False,
            )

        wt = _run_git(["write-tree"], repo, env=env, check=False)
        if wt.returncode != 0:
            return None
        return wt.stdout.strip()
    finally:
        Path(tmp_index).unlink(missing_ok=True)


@dataclass(frozen=True)
class PathChange:
    """One path that differs between two trees."""

    status: str  # "A" added, "D" deleted, "M" modified
    path: str


def tree_delta(
    repo: Path, tree_a: str, tree_b: str, ledger_objects: Optional[Path] = None
) -> list[PathChange]:
    """Exact path-level delta between two tree objects.

    Requires that both trees' objects are reachable — the ledger's redirected
    objects plus the repo's own. This is what turns "stale" from a shrug into a
    measured statement ("stale: 1 line changed in src/foo.py").
    """
    env = {}
    if ledger_objects is not None:
        env["GIT_OBJECT_DIRECTORY"] = str(ledger_objects)
        env["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = str(objects_dir(repo))
    proc = _run_git(
        ["diff-tree", "-r", "--no-commit-id", "--name-status", tree_a, tree_b],
        repo,
        env=env,
        check=False,
    )
    if proc.returncode != 0:
        return []
    changes: list[PathChange] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            changes.append(PathChange(status=parts[0].strip()[:1], path=parts[-1]))
    return changes


def commit_tree(repo: Path, commitish: str = "HEAD") -> Optional[str]:
    """The tree id a commit points at (what a claim is graded against at seal)."""
    proc = _run_git(["rev-parse", f"{commitish}^{{tree}}"], repo, check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def capability_probe(repo: Optional[Path] = None) -> dict:
    """Emit the environment matrix for the normative-envelope gate.

    Prints git version and filesystem so a Linux/ext4 rerun can be compared
    against the recorded macOS/APFS numbers (docs/MEASUREMENTS.md).
    """
    repo = Path(repo or ".")
    ver = _run_git(["--version"], repo, check=False).stdout.strip()
    fstype = ""
    try:
        # macOS + Linux both support `df -T`? macOS doesn't; fall back gracefully.
        df = subprocess.run(
            ["df", "-T", str(repo)], capture_output=True, text=True
        )
        if df.returncode != 0:
            df = subprocess.run(["df", str(repo)], capture_output=True, text=True)
        fstype = df.stdout.strip().splitlines()[-1] if df.stdout.strip() else ""
    except Exception:
        fstype = "unknown"
    matrix = {
        "git_version": ver,
        "platform": os.uname().sysname if hasattr(os, "uname") else os.name,
        "machine": os.uname().machine if hasattr(os, "uname") else "unknown",
        "filesystem_line": fstype,
    }
    print("didrun capability matrix:")
    for k, v in matrix.items():
        print(f"  {k}: {v}")
    print(
        "  NOTE: recorded timing envelope is macOS/APFS/arm64/git-2.50.1; "
        "a Linux/ext4 rerun is required before the envelope is normative."
    )
    return matrix
