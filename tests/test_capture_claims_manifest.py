"""P1.3/P2.1/P2.2 — capture, grading, and the seal/verify round-trip."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from didrun.ledger import Session
from didrun.capture import run_wrapped
from didrun.claims import Claim, ClaimError, grade
from didrun import manifest as M
from didrun import gitplumbing as gp


def _git(repo, *a):
    subprocess.run(["git", *a], cwd=str(repo), capture_output=True, text=True, check=True)


def _session(repo: Path) -> Session:
    return Session(repo / ".didrun")


def test_wrapper_records_true_exit_code(repo: Path):
    """The PTY-misleads case, corrected: a command exiting 3 records exit 3."""
    s = _session(repo)
    ev = run_wrapped([sys.executable, "-c", "import sys; sys.exit(3)"], s, repo)
    assert ev.exit_code == 3
    assert ev.observed_via == "wrapper"
    assert ev.coverage == "complete"


def test_stdout_captured_to_blob(repo: Path):
    s = _session(repo)
    ev = run_wrapped([sys.executable, "-c", "print('hello')"], s, repo)
    assert ev.stdout_blob is not None
    assert s.blobs.get(ev.stdout_blob).strip() == b"hello"


def test_killed_claim_type_refused():
    with pytest.raises(ClaimError) as exc:
        Claim(ctype="diff-exercised", label="x", event_indices=(0,))
    assert "coverage-ingest" in str(exc.value).lower()


def test_grade_tree_exact(repo: Path):
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "print(1)"], s, repo)
    claim = Claim(ctype="tests-pass", label="t", event_indices=(0,), declared_at_index=0)
    tree = gp.commit_tree(repo, "HEAD")
    r = grade(claim, tree, s.events(), repo, s.blobs.root)
    assert r.grade == "tree-exact"


def test_grade_stale_carries_delta(repo: Path):
    """edit -> test(pass) -> edit -> commit grades stale WITH the exact delta."""
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "print(1)"], s, repo)
    claim = Claim(ctype="tests-pass", label="t", event_indices=(0,), declared_at_index=0)
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b  # later\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "edit")
    tree = gp.commit_tree(repo, "HEAD")
    r = grade(claim, tree, s.events(), repo, s.blobs.root)
    assert r.grade == "stale"
    assert r.delta, "stale must carry a concrete delta, never a bare shrug"
    assert any(c.path == "calc.py" for c in r.delta)


def test_grade_scope_exact(repo: Path):
    s = _session(repo)
    (repo / "src").mkdir()
    (repo / "src" / "a.py").write_text("x = 1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "add src")
    run_wrapped([sys.executable, "-c", "print(1)"], s, repo)
    claim = Claim(ctype="tests-pass", label="t", event_indices=(0,),
                  pathspecs=("src",), declared_at_index=0)
    (repo / "src" / "a.py").write_text("x = 2\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "edit src")
    tree = gp.commit_tree(repo, "HEAD")
    r = grade(claim, tree, s.events(), repo, s.blobs.root)
    assert r.grade == "scope-exact"


def test_grade_unknown_on_retroactive_binding(repo: Path):
    """A claim declared at index 0 but bound to a later event (index 1) is a
    retroactive binding under degraded ordering → unknown, with the reason shown."""
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "print(1)"], s, repo)   # event 0
    run_wrapped([sys.executable, "-c", "print(2)"], s, repo)   # event 1
    claim = Claim(ctype="command-succeeded", label="c",
                  event_indices=(1,), declared_at_index=0)
    tree = gp.commit_tree(repo, "HEAD")
    r = grade(claim, tree, s.events(), repo, s.blobs.root)
    assert r.grade == "unknown"
    assert "retroactive" in r.reason


def test_grade_failed_on_witnessed_failure(repo: Path):
    """A success claim bound to a command didrun WATCHED fail grades FAILED
    (a caught lie), distinct from unknown (no evidence)."""
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "import sys; sys.exit(1)"], s, repo)  # event 0, fails
    # Explicitly bind the claim to the failed event.
    claim = Claim(ctype="tests-pass", label="t", event_indices=(0,), declared_at_index=0)
    tree = gp.commit_tree(repo, "HEAD")
    r = grade(claim, tree, s.events(), repo, s.blobs.root)
    assert r.grade == "failed"
    assert r.exit_code == 1
    assert "exited 1" in r.reason


def test_seal_verify_roundtrip_exit_codes(repo: Path):
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "print(1)"], s, repo)
    M.declare_claim(s, Claim(ctype="tests-pass", label="t", event_indices=(0,), declared_at_index=0))
    m = M.seal(s, repo)
    report = M.verify(s, repo)
    assert report.all_verified
    assert report.worst_status == "tree-exact"


def test_verify_survives_amend_via_tree_fallback(repo: Path):
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "print(1)"], s, repo)
    M.declare_claim(s, Claim(ctype="tests-pass", label="t", event_indices=(0,), declared_at_index=0))
    M.seal(s, repo)
    original = gp.head_commit(repo)
    _git(repo, "commit", "--amend", "-qm", "amended message")  # same tree, new commit id
    amended = gp.head_commit(repo)
    assert original != amended
    report = M.verify(s, repo)
    assert report.resolved_by == "tree-fallback"
    assert report.all_verified


def test_fix_loop_converges(repo: Path):
    """The gate loop: a FAILED unit blocks (strict nonzero), the fix is re-run
    through didrun, re-claimed, re-committed, re-sealed — and the gate opens.
    The old commit's manifest still shows its failure (history preserved)."""
    s = _session(repo)
    # Unit 1: buggy — the check fails, the claim is declared anyway.
    run_wrapped([sys.executable, "-c", "import sys; sys.exit(1)"], s, repo)
    M.declare_claim(s, Claim(ctype="tests-pass", label="t", event_indices=(0,), declared_at_index=0))
    M.seal(s, repo)
    first_commit = gp.head_commit(repo)
    report1 = M.verify(s, repo)
    assert not report1.all_verified
    assert report1.worst_status == "failed"          # gate shut

    # Loop back: fix, re-run THROUGH didrun, re-claim, commit, re-seal.
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b  # fixed\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "fix")
    run_wrapped([sys.executable, "-c", "import sys; sys.exit(0)"], s, repo)
    M.declare_claim(s, Claim(ctype="tests-pass", label="t", event_indices=(1,), declared_at_index=1))
    M.seal(s, repo)
    report2 = M.verify(s, repo)
    assert report2.all_verified                       # gate open — loop converged
    assert len(report2.results) == 1                  # only THIS unit's claim

    # History is never rewritten: the first commit's manifest still shows FAILED.
    report_old = M.verify(s, repo, commitish=first_commit)
    assert report_old.worst_status == "failed"


def test_verify_reads_manifest_not_session(repo: Path):
    """Claims declared AFTER a seal must not leak into that seal's verdict —
    the manifest is the only thing verify reads besides the repo."""
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "print(1)"], s, repo)
    M.declare_claim(s, Claim(ctype="tests-pass", label="sealed", event_indices=(0,), declared_at_index=0))
    M.seal(s, repo)
    # A later, unsealed claim (would grade failed if it leaked in).
    run_wrapped([sys.executable, "-c", "import sys; sys.exit(1)"], s, repo)
    M.declare_claim(s, Claim(ctype="tests-pass", label="unsealed", event_indices=(1,), declared_at_index=1))
    report = M.verify(s, repo)
    labels = [r.claim.label for r in report.results]
    assert labels == ["sealed"]
    assert report.all_verified


def test_strict_nonzero_on_stale(repo: Path):
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "print(1)"], s, repo)
    M.declare_claim(s, Claim(ctype="tests-pass", label="t", event_indices=(0,), declared_at_index=0))
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b  # drift\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "drift")
    M.seal(s, repo)
    report = M.verify(s, repo)
    assert not report.all_verified  # → CLI --strict returns nonzero
