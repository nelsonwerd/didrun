"""P1.2 — gitplumbing: copied-index digests, ledger exclusion, isolation, delta."""

from __future__ import annotations

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


def test_object_isolation(repo: Path, tmp_path: Path):
    """Digest objects land in the ledger dir, never the user's object DB."""
    ledger_obj = tmp_path / "ledger-obj"
    objects_before = set((repo / ".git" / "objects").rglob("*"))
    (repo / "dirty.py").write_text("y = 2\n")
    digest = gp.tree_digest(repo, ledger_obj)
    objects_after = set((repo / ".git" / "objects").rglob("*"))
    assert digest is not None
    assert objects_before == objects_after  # zero pollution
    assert any(ledger_obj.rglob("*"))  # objects went to the ledger


def test_ledger_dir_excluded_from_digest(repo: Path):
    """didrun's own ledger must not move the tree it measures."""
    clean = gp.tree_digest(repo)
    ledger = repo / ".didrun" / "objects"
    ledger.mkdir(parents=True)
    (ledger / "junk").write_text("noise\n")
    after = gp.tree_digest(repo)
    assert clean == after  # ledger writes are invisible to the digest


def test_tree_delta_reports_exact_path(repo: Path, tmp_path: Path):
    ledger_obj = tmp_path / "obj"
    a = gp.tree_digest(repo, ledger_obj)
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b  # edit\n")
    b = gp.tree_digest(repo, ledger_obj)
    delta = gp.tree_delta(repo, a, b, ledger_obj)
    paths = {c.path for c in delta}
    assert "calc.py" in paths


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
