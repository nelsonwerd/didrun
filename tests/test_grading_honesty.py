"""P1.1 — the grading ladder must not turn a failed subprocess into a fact.

Two defects are pinned here:

  1. ``tree_delta`` failed open to ``[]``, so when the evidence tree's objects
     were unreachable (the archived-ledger case) ``grade`` rendered one of two
     false sentences — "tree moved since evidence: 0 path(s) differ" (which also
     violates the module's own stale-MUST-carry-the-delta invariant) and
     "evidence tree equals sealed tree but command was not self-stable" (an
     assertion about tree equality derived from a subprocess that failed).
  2. ``grade`` consulted ``_supporting_event`` before ``_witnessed_failure``, so
     a claim bound to [failed, success] graded on the success and the witnessed
     failure was invisible.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from didrun import gitplumbing as gp
from didrun.capture import run_wrapped
from didrun.claims import WIDENING_HINT_CAP, Claim, _widening_hint, grade
from didrun.ledger import Session

# The two sentences the old fail-open path emitted. Neither may ever appear in
# a reason derived from a delta that was not computed.
FORBIDDEN = ("0 path(s) differ", "evidence tree equals sealed tree")


def _git(repo: Path, *a: str) -> None:
    subprocess.run(["git", *a], cwd=str(repo), capture_output=True, text=True, check=True)


def _session(repo: Path) -> Session:
    return Session(repo / ".didrun")


def _uncommitted_evidence(repo: Path) -> tuple[Session, str]:
    """An event whose tree_after lives ONLY in the ledger's object dir.

    The dirt is never committed, so the tree object write-tree produced was
    written under GIT_OBJECT_DIRECTORY into ``.didrun/objects`` and exists
    nowhere else. Pointing a later grade at a different object dir reproduces
    the archived-ledger case exactly: the event is present, the objects are not.
    """
    s = _session(repo)
    (repo / "scratch.py").write_text("x = 1\n")
    run_wrapped([sys.executable, "-c", "print(1)"], s, repo)
    sealed_tree = gp.commit_tree(repo, "HEAD")
    ev = s.events()[0]
    assert ev.tree_after is not None and ev.tree_after != sealed_tree
    return s, sealed_tree


@pytest.mark.parametrize("pathspecs", [(), ("docs",)], ids=["no-pathspecs", "pathspecs"])
def test_uncomputable_delta_grades_unknown_not_a_confident_sentence(
    repo: Path, tmp_path: Path, pathspecs: tuple[str, ...]
):
    """Objects gone -> `unknown`, and neither false sentence is emitted."""
    s, sealed_tree = _uncommitted_evidence(repo)
    claim = Claim(ctype="tests-pass", label="t", event_indices=(0,),
                  pathspecs=pathspecs, declared_at_index=0)

    gone = tmp_path / "empty-objects"
    gone.mkdir()
    assert gp.tree_delta(repo, s.events()[0].tree_after, sealed_tree, gone) is None

    r = grade(claim, sealed_tree, s.events(), repo, gone)
    assert r.grade == "unknown"
    assert "not computable" in r.reason
    for phrase in FORBIDDEN:
        assert phrase not in r.reason
    assert r.delta == []          # an uncomputed delta is never displayed
    assert r.supporting_event_index == 0

    # Control: the SAME claim over the SAME evidence with the objects present
    # still grades stale. That is what proves the unknown above is caused by
    # unavailability and not by the fixture being ungradeable in the first place.
    reachable = grade(claim, sealed_tree, s.events(), repo, s.blobs.root)
    assert reachable.grade == "stale"
    assert "not computable" not in reachable.reason
    assert reachable.delta, "the reachable control must carry a concrete delta"


def test_empty_delta_still_means_the_trees_are_equal(repo: Path):
    """`[]` is "computed, and equal" — collapsing it into `None` breaks this.

    A command that mutates the tree is not self-stable, so it cannot be
    tree-exact even when its resulting tree IS the sealed tree; the delta is
    computed, comes back empty, and the stale-clean branch fires unchanged.
    """
    s = _session(repo)
    run_wrapped(
        [sys.executable, "-c", "open('made.py', 'w').write('y = 2\\n')"], s, repo
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "commit what the command produced")
    sealed_tree = gp.commit_tree(repo, "HEAD")

    ev = s.events()[0]
    assert not ev.self_stable()          # the command moved the tree
    assert ev.tree_after == sealed_tree  # ...and landed exactly on the sealed one

    delta = gp.tree_delta(repo, ev.tree_after, sealed_tree, s.blobs.root)
    assert delta is not None and delta == []

    claim = Claim(ctype="tests-pass", label="t", event_indices=(0,),
                  pathspecs=("src",), declared_at_index=0)
    r = grade(claim, sealed_tree, s.events(), repo, s.blobs.root)
    assert r.grade == "stale"
    # The old sentence survives as the prefix; since the self-stability fix
    # (tests/test_self_stability_delta.py) it also names what the run changed,
    # and the STALE row carries that change as its delta instead of nothing.
    assert r.reason == (
        "evidence tree equals sealed tree but command was not self-stable — the "
        "run itself changed 1 path(s): made.py; add --path made.py to make this "
        "scope-exact"
    )
    assert [c.path for c in r.delta] == ["made.py"]


def test_witnessed_failure_dominates_a_witnessed_success(repo: Path):
    """[failed, success] grades FAILED, on the failure, not on the success.

    Reachable only through the library API today: the CLI's ``--event`` is
    ``type=int``, not ``action="append"``, so every claim the CLI can build
    binds exactly one event (0 of 846 corpus claims are multi-index). This is a
    Low-severity honesty fix, not a headline.
    """
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "import sys; sys.exit(1)"], s, repo)  # 0: fails
    run_wrapped([sys.executable, "-c", "import sys; sys.exit(0)"], s, repo)  # 1: passes
    claim = Claim(ctype="tests-pass", label="t", event_indices=(0, 1), declared_at_index=1)

    r = grade(claim, gp.commit_tree(repo, "HEAD"), s.events(), repo, s.blobs.root)
    assert r.grade == "failed"
    assert r.supporting_event_index == 0
    assert r.exit_code == 1
    assert r.reason == "the recorded command exited 1 — claim is not backed"


# --- every single-event rung of the ladder still fires exactly as before -------


def _case_tree_exact(repo: Path) -> tuple[Session, Claim, str]:
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "print(1)"], s, repo)
    return s, Claim(ctype="tests-pass", label="t", event_indices=(0,),
                    declared_at_index=0), gp.commit_tree(repo, "HEAD")


def _case_scope_exact(repo: Path) -> tuple[Session, Claim, str]:
    s = _session(repo)
    (repo / "src").mkdir()
    (repo / "src" / "a.py").write_text("x = 1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "add src")
    run_wrapped([sys.executable, "-c", "print(1)"], s, repo)
    (repo / "src" / "a.py").write_text("x = 2\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "edit src")
    return s, Claim(ctype="tests-pass", label="t", event_indices=(0,),
                    pathspecs=("src",), declared_at_index=0), gp.commit_tree(repo, "HEAD")


def _case_stale(repo: Path) -> tuple[Session, Claim, str]:
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "print(1)"], s, repo)
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b  # later\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "edit")
    return s, Claim(ctype="tests-pass", label="t", event_indices=(0,),
                    declared_at_index=0), gp.commit_tree(repo, "HEAD")


def _case_unknown(repo: Path) -> tuple[Session, Claim, str]:
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "print(1)"], s, repo)
    run_wrapped([sys.executable, "-c", "print(2)"], s, repo)
    return s, Claim(ctype="command-succeeded", label="c", event_indices=(1,),
                    declared_at_index=0), gp.commit_tree(repo, "HEAD")


def _case_failed(repo: Path) -> tuple[Session, Claim, str]:
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "import sys; sys.exit(1)"], s, repo)
    return s, Claim(ctype="tests-pass", label="t", event_indices=(0,),
                    declared_at_index=0), gp.commit_tree(repo, "HEAD")


LADDER = {
    "tree-exact": (_case_tree_exact, "self-stable command ran against the sealed tree"),
    "scope-exact": (_case_scope_exact, "all 1 change(s) within declared pathspecs"),
    "stale": (_case_stale, "tree moved since evidence: 1 path(s) differ"),
    "unknown": (_case_unknown,
                "retroactive binding: claim declared at index 0 precedes its backing event 1"),
    "failed": (_case_failed, "the recorded command exited 1 — claim is not backed"),
}


@pytest.mark.parametrize("expected_grade", sorted(LADDER))
def test_single_event_claims_are_unaffected(repo: Path, expected_grade: str):
    """The hoist and the fail-closed delta must move no single-event grade.

    Reason strings are asserted verbatim, not by substring: downstream
    validators read them, so a reworded rung is a break even when the grade is
    right.
    """
    build, expected_reason = LADDER[expected_grade]
    s, claim, sealed_tree = build(repo)
    r = grade(claim, sealed_tree, s.events(), repo, s.blobs.root)
    assert r.grade == expected_grade
    assert r.reason == expected_reason


# --- P5.2: a scope miss names the widening set it already measured -----------
#
# Measured over the corpus this tool was built against: 178 of 846 claims
# declared a pathspec and 14 of them lost `scope-exact` because the delta held
# exactly ONE out-of-scope path. The set that would have covered it was already
# in `delta`; the reason reported only how many paths missed, so an operator had
# to re-derive by hand something the tool had computed.


def _out_of_scope_case(
    repo: Path, later: dict, pathspecs: tuple = ("src",)
) -> tuple[Session, Claim, str]:
    """One event, then a commit that edits `later`'s paths only.

    The event's tree is the pre-edit HEAD tree, so grading against the post-edit
    HEAD yields a delta of exactly `later`'s paths — every one of them outside
    ``pathspecs``.
    """
    s = _session(repo)
    (repo / "src").mkdir()
    (repo / "src" / "a.py").write_text("x = 1\n")
    for rel, body in later.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "add tree")
    run_wrapped([sys.executable, "-c", "print(1)"], s, repo)
    for rel in later:
        (repo / rel).write_text("later\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "edit outside src")
    return (
        s,
        Claim(
            ctype="tests-pass",
            label="t",
            event_indices=(0,),
            pathspecs=pathspecs,
            declared_at_index=0,
        ),
        gp.commit_tree(repo, "HEAD"),
    )


def test_one_out_of_scope_path_names_the_pathspec_that_would_cover_it(repo: Path):
    """The 14-claim case. Grade, delta and count prefix are unchanged; the
    reason gains the arithmetic fact of what widening would take."""
    s, claim, sealed = _out_of_scope_case(repo, {"docs/status/X.md": "one\n"})
    r = grade(claim, sealed, s.events(), repo, s.blobs.root)

    assert r.grade == "stale", "the hint must not promote the grade"
    assert r.grade != "scope-exact"
    assert [c.path for c in r.delta] == ["docs/status/X.md"], "delta unchanged"
    assert r.reason == (
        "1 change(s) outside declared pathspecs"
        " — add --path docs/status/ to make this scope-exact"
    )
    # The old prefix is preserved verbatim, which is what a downstream validator
    # matching on it reads.
    assert r.reason.startswith("1 change(s) outside declared pathspecs")


def test_the_named_widening_set_actually_makes_it_scope_exact(repo: Path):
    """The un-gameable half: the hint is a claim about `_within`'s arithmetic, so
    declaring exactly what it names must produce `scope-exact`. A hint that
    printed a plausible-looking directory would pass the assertion above and
    fail here."""
    s, claim, sealed = _out_of_scope_case(repo, {"docs/status/X.md": "one\n"})
    r = grade(claim, sealed, s.events(), repo, s.blobs.root)
    body = r.reason.split(" — ", 1)[1]
    suffix = " to make this scope-exact"
    assert body.startswith("add ") and body.endswith(suffix), body
    named = [
        tok.removeprefix("--path ")
        for tok in body[len("add ") : -len(suffix)].split(", ")
        if tok.startswith("--path ")
    ]
    assert named == ["docs/status/"]

    widened = Claim(
        ctype=claim.ctype,
        label=claim.label,
        event_indices=claim.event_indices,
        pathspecs=claim.pathspecs + tuple(named),
        declared_at_index=claim.declared_at_index,
    )
    r2 = grade(widened, sealed, s.events(), repo, s.blobs.root)
    assert r2.grade == "scope-exact", r2.reason


def test_twelve_out_of_scope_paths_in_three_directories_dedup_to_three(repo: Path):
    """Dedup and sort, with nothing elided.

    Twelve out-of-scope paths across three directories are three prefixes, so
    the hint names three and says nothing about a remainder — there is none. A
    `+0 more` suffix here would be a false statement about what was dropped.
    """
    later = {
        f"{d}/f{i}.md": "one\n"
        for d in ("zeta", "docs/status", "alpha/beta")
        for i in range(4)
    }
    s, claim, sealed = _out_of_scope_case(repo, later)
    r = grade(claim, sealed, s.events(), repo, s.blobs.root)

    assert r.grade == "stale"
    assert len(r.delta) == 12
    assert r.reason == (
        "12 change(s) outside declared pathspecs — add --path alpha/beta/, "
        "--path docs/status/, --path zeta/ to make this scope-exact"
    )
    assert "more)" not in r.reason


def test_more_directories_than_the_cap_are_counted_not_dropped(repo: Path):
    """Above the cap the hint stays readable and stays honest: five prefixes and
    the exact number withheld. Truncating without the count would understate the
    widening the operator was being told about."""
    later = {f"d{i:02d}/f.md": "one\n" for i in range(8)}
    s, claim, sealed = _out_of_scope_case(repo, later)
    r = grade(claim, sealed, s.events(), repo, s.blobs.root)

    assert r.grade == "stale"
    assert r.reason == (
        "8 change(s) outside declared pathspecs — add --path d00/, --path d01/, "
        "--path d02/, --path d03/, --path d04/ (+3 more) to make this scope-exact"
    )
    assert r.reason.count("--path ") == WIDENING_HINT_CAP


def test_a_top_level_file_is_named_by_itself_not_by_the_repository_root(repo: Path):
    """A path with no parent directory is the one case where "use the parent"
    would be a lie with consequences: the parent is the repository root, and
    declaring the root puts EVERY path in scope, so the hint would be advising a
    declaration that stops meaning anything. It names the file instead — the
    smallest prefix that covers it and nothing else."""
    s, claim, sealed = _out_of_scope_case(repo, {"TOPLEVEL.md": "one\n"})
    r = grade(claim, sealed, s.events(), repo, s.blobs.root)
    assert r.reason == (
        "1 change(s) outside declared pathspecs"
        " — add --path TOPLEVEL.md to make this scope-exact"
    )
    assert "--path ." not in r.reason and "--path /" not in r.reason


def test_the_hint_is_deterministic_and_order_independent(repo: Path):
    """Determinism is a hard invariant of the trust path, and the delta's order
    is git's. Sorting is what makes the same scope miss produce the same reason
    twice."""
    paths = ["b/x.md", "a/y.md", "b/z.md", "a/y.md"]
    first = _widening_hint(paths)
    assert first == _widening_hint(reversed(paths))
    assert first == "add --path a/, --path b/ to make this scope-exact"


def test_a_scope_exact_reason_is_byte_identical_to_before(repo: Path):
    """No hint where nothing missed. The in-scope sentence is the one archived
    notes carry for their 163 inert pathspec claims."""
    s, claim, sealed = _case_scope_exact(repo)
    r = grade(claim, sealed, s.events(), repo, s.blobs.root)
    assert r.grade == "scope-exact"
    assert r.reason == "all 1 change(s) within declared pathspecs"
    assert "add --path" not in r.reason


def test_a_stale_claim_with_no_pathspecs_gains_no_hint(repo: Path):
    """The hint belongs to the branch that measured an out-of-scope SET. A claim
    that declared no scope has no widening arithmetic to report, and inventing
    one would be the relevance inference the module forbids."""
    s, claim, sealed = _case_stale(repo)
    r = grade(claim, sealed, s.events(), repo, s.blobs.root)
    assert r.grade == "stale"
    assert r.reason == "tree moved since evidence: 1 path(s) differ"
    assert "--path" not in r.reason
