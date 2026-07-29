"""P1.2 — gitplumbing: copied-index digests, ledger exclusion, isolation, delta."""

from __future__ import annotations

import inspect
import re
from pathlib import Path

from didrun import gitplumbing as gp


def test_clean_tree_digest_stable(repo: Path):
    d1 = gp.tree_digest(repo)
    d2 = gp.tree_digest(repo)
    assert d1 is not None and d1 == d2


def test_untracked_file_changes_digest(repo: Path):
    """The exact case `git stash create` gets wrong: an untracked-only change
    must move the digest."""
    before = gp.tree_digest(repo)
    (repo / "new.py").write_text("x = 1\n")
    after = gp.tree_digest(repo)
    assert before != after


def _loose_objects(repo: Path) -> set:
    """Loose git object files only (``objects/<2-hex>/<38-hex>``).

    Deliberately excludes git's own transient/metadata files (``*.lock`` from
    background auto-maintenance, ``pack/``, ``info/``) — those are git's
    housekeeping, not something didrun writes, and counting them makes the
    isolation check flaky. This measures exactly what pollution would be:
    a new loose object in the user's DB.
    """
    root = repo / ".git" / "objects"
    return {
        p for p in root.rglob("*")
        if p.is_file()
        and re.fullmatch(r"[0-9a-f]{2}", p.parent.name)
        and re.fullmatch(r"[0-9a-f]{38,62}", p.name)
    }


def test_object_isolation(repo: Path, tmp_path: Path):
    """Digest objects land in the ledger dir, never the user's object DB."""
    ledger_obj = tmp_path / "ledger-obj"
    objects_before = _loose_objects(repo)
    (repo / "dirty.py").write_text("y = 2\n")
    digest = gp.tree_digest(repo, ledger_obj)
    objects_after = _loose_objects(repo)
    assert digest is not None
    assert objects_before == objects_after  # zero pollution (no new loose objects)
    assert any(ledger_obj.rglob("*"))  # objects went to the ledger


def test_ledger_dir_excluded_from_digest(repo: Path):
    """didrun's own ledger must not move the tree it measures."""
    clean = gp.tree_digest(repo)
    ledger = repo / ".didrun" / "objects"
    ledger.mkdir(parents=True)
    (ledger / "junk").write_text("noise\n")
    after = gp.tree_digest(repo)
    assert clean == after  # ledger writes are invisible to the digest


def test_digest_survives_gitignored_ledger(repo: Path):
    """The documented default config — `.didrun/` in .gitignore — must digest.

    Regression: the add pathspec used to name the ledger via `:(exclude,top)`,
    and git errors out when a pathspec matches a gitignored path. The add failed,
    tree_digest returned None, and every claim graded `unknown` — so following
    didrun's own "never commit the ledger" rule made didrun unable to receipt
    anything, itself included.
    """
    (repo / ".gitignore").write_text(".didrun/\n")
    (repo / ".didrun" / "objects").mkdir(parents=True)
    (repo / ".didrun" / "objects" / "junk").write_text("noise\n")
    assert gp.tree_digest(repo) is not None


def test_digest_sees_dirt_with_gitignored_ledger(repo: Path):
    """The gitignored-ledger fix must not buy its digest by going blind to dirt."""
    (repo / ".gitignore").write_text(".didrun/\n")
    (repo / ".didrun").mkdir()
    (repo / ".didrun" / "ledger").write_text("noise\n")
    clean = gp.tree_digest(repo)
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b  # edit\n")
    dirty = gp.tree_digest(repo)
    assert clean is not None and dirty is not None
    assert clean != dirty


def test_ledger_excluded_from_digest_when_gitignored(repo: Path):
    """Ledger churn stays invisible in BOTH configs — gitignored or not."""
    (repo / ".gitignore").write_text(".didrun/\n")
    before = gp.tree_digest(repo)
    (repo / ".didrun" / "objects").mkdir(parents=True)
    (repo / ".didrun" / "objects" / "junk").write_text("noise\n")
    after = gp.tree_digest(repo)
    assert before is not None and before == after


def _archive(repo: Path) -> None:
    """A rotated ledger sitting under the archive root, in its usual shape."""
    d = repo / gp.ARCHIVE_DIRNAME / "unit-01" / ".didrun"
    d.mkdir(parents=True)
    (d / "session.log").write_text("rotated\n")


def test_archive_root_is_in_the_default_exclusion():
    """The exclusion is a default, not an opt-in — a caller passing nothing
    still gets the archive root kept out."""
    default = inspect.signature(gp.tree_digest).parameters["exclude"].default
    assert default == (gp.LEDGER_DIRNAME, gp.ARCHIVE_DIRNAME)


def test_archive_gitignored_digest_is_unchanged_by_the_new_exclusion(repo: Path):
    """The compat criterion: where the archive root IS gitignored, v0.2 digests
    a tree to the same id v0.1 did, because `add -A` already skipped it."""
    (repo / ".gitignore").write_text(".didrun/\n.didrun-history/\n")
    _archive(repo)
    v01 = gp.tree_digest(repo, exclude=(gp.LEDGER_DIRNAME,))
    v02 = gp.tree_digest(repo)
    assert v01 is not None and v01 == v02


def test_archive_not_gitignored_is_a_digest_semantics_change(repo: Path):
    """Where the archive root is NOT gitignored, v0.2 and v0.1 disagree — and
    v0.2 is the one that excludes it. Pinned, not hidden: this is the release
    note. Without it, archiving a ledger moves the digest of the tree that
    just archived it and stales the unit that did the archiving."""
    empty = gp.tree_digest(repo)  # no archive root present yet
    _archive(repo)
    v01 = gp.tree_digest(repo, exclude=(gp.LEDGER_DIRNAME,))
    v02 = gp.tree_digest(repo)
    assert v01 is not None and v02 is not None
    assert v01 != v02          # the semantics change, stated
    assert v02 == empty        # and v0.2 is the side that ignores the archive


def test_ledger_dir_still_excluded_in_both_configs_with_the_archive_present(repo: Path):
    """Adding a second exclusion must not weaken the first: `.didrun/` stays
    out regardless of gitignore state, which is the guarantee grading rests on."""
    _archive(repo)
    for ignore in ("", ".didrun/\n.didrun-history/\n"):
        (repo / ".gitignore").write_text(ignore)
        before = gp.tree_digest(repo)
        (repo / ".didrun" / "objects").mkdir(parents=True, exist_ok=True)
        (repo / ".didrun" / "objects" / "junk").write_text("noise\n")
        after = gp.tree_digest(repo)
        assert before is not None and before == after


def test_tree_delta_reports_exact_path(repo: Path, tmp_path: Path):
    ledger_obj = tmp_path / "obj"
    a = gp.tree_digest(repo, ledger_obj)
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b  # edit\n")
    b = gp.tree_digest(repo, ledger_obj)
    delta = gp.tree_delta(repo, a, b, ledger_obj)
    paths = {c.path for c in delta}
    assert "calc.py" in paths


def test_objects_dir_is_the_real_db_in_a_linked_worktree(repo: Path, tmp_path: Path, git):
    """The object alternates must resolve to a REAL directory in a worktree.

    Regression, and the exact trap this asserts: in a linked worktree
    ``--git-dir`` is ``.git/worktrees/<name>/``, which contains NO ``objects/``.
    The alternates were built as ``git_dir()/objects``, so they named a
    directory that does not exist; git then cannot resolve blobs it did not
    re-hash, ``write-tree`` dies ("invalid object ... fatal: git-write-tree"),
    and the digest degrades to None → every claim `unknown`. Agents run in
    worktrees constantly, so this silently disabled didrun there.
    """
    wt = tmp_path / "linked-wt"
    git(repo, "worktree", "add", "-q", "-b", "wt-branch", str(wt))

    # The trap, asserted directly: the old expression names a missing dir...
    assert not (gp.git_dir(wt) / "objects").exists()
    # ...while the common dir is the real, shared object DB.
    assert gp.objects_dir(wt).is_dir()
    assert gp.objects_dir(wt) == gp.objects_dir(repo)


def test_digest_in_linked_worktree(repo: Path, tmp_path: Path, git):
    """Worktree digests work and still see dirt.

    Note: this exercises the worktree path but does NOT by itself reproduce the
    alternates bug — in a small fresh worktree `add -A` re-hashes every blob into
    the ledger, so the alternates are never consulted and a broken path goes
    unnoticed. Reproducing needs a stat-cache hit (an unchanged file whose blob
    lives only in the main DB), which is why the assertion above targets the
    resolved path directly rather than trusting this to fail.
    """
    wt = tmp_path / "dirty-wt"
    git(repo, "worktree", "add", "-q", "-b", "dirty-branch", str(wt))
    ledger_obj = tmp_path / "wt-ledger-obj"

    clean = gp.tree_digest(wt, ledger_obj)
    assert clean is not None
    (wt / "calc.py").write_text("def add(a, b):\n    return a + b  # edit\n")
    dirty = gp.tree_digest(wt, ledger_obj)
    assert dirty is not None and dirty != clean


def test_add_failure_returns_none_not_partial(repo: Path, monkeypatch):
    """A failed `git add` must yield None (→ unknown), never a partial tree."""
    real = gp._run_git

    def fake(args, repo_, env=None, check=True):
        if args[:2] == ["add", "-A"]:
            class R:
                returncode = 1
                stdout = ""
                stderr = "boom"
            return R()
        return real(args, repo_, env=env, check=check)

    monkeypatch.setattr(gp, "_run_git", fake)
    assert gp.tree_digest(repo) is None


def test_commit_tree_resolves(repo: Path):
    assert gp.commit_tree(repo, "HEAD") is not None


def test_capability_probe_runs(repo: Path, capsys):
    m = gp.capability_probe(repo)
    assert "git_version" in m
