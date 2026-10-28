"""A command that changes the tree must be graded on what it ran against.

Found dogfooding didrun on a real build: `ant apply` writes a lock file, the
lock file is committed with the rest of the unit, and the claim can never grade
tree-exact. That part is right — tree-exact attests a SELF-STABLE command ran
against exactly the sealed tree, and this one ran against a tree without the
lock file. What was wrong is what the verdict said about it:

    STALE  tree moved since evidence: 0 path(s) differ

which contradicts itself, carries no delta (a STALE row must), and names
nothing a reader could act on. The event already holds both digests, before
and after the run, so the cause is measurable: the run's own changes.

The rule pinned here, for a command that is NOT self-stable:

- the delta is every path at which a tree the command saw (the tree it
  started from, or the tree it left) differs from the sealed tree — so a file
  the run itself wrote IS a change, and is named as one;
- `scope-exact` needs every one of those paths inside the CLAIMANT-declared
  pathspecs. didrun never scopes a claim to the run's own outputs by itself:
  relevance is never inferred (docs/TRUST_MODEL.md);
- never `tree-exact`.

The second point also TIGHTENS one case. Scope used to be judged only from the
tree the run left, so a run that rewrote an undeclared path and was then
followed by an in-scope edit graded scope-exact without the rewrite ever being
in scope. That is pinned below as well.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from didrun import gitplumbing as gp
from didrun import manifest as M
from didrun import render
from didrun.capture import run_wrapped
from didrun.claims import Claim, grade
from didrun.ledger import Session

WRITE_LOCK = "open('ant.lock', 'w').write('locked\\n')"


def _git(repo: Path, *a: str) -> None:
    subprocess.run(["git", *a], cwd=str(repo), capture_output=True, text=True, check=True)


def _commit_all(repo: Path, msg: str = "unit") -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", msg)
    return gp.commit_tree(repo, "HEAD")


def _claim(pathspecs: tuple = ()) -> Claim:
    return Claim(ctype="command-succeeded", label="ant apply", event_indices=(0,),
                 pathspecs=pathspecs, declared_at_index=0)


def _lockfile_case(repo: Path) -> tuple[Session, str]:
    """The dogfood shape: the run writes a file and the unit commits it."""
    s = Session(repo / ".didrun")
    run_wrapped([sys.executable, "-c", WRITE_LOCK], s, repo)
    sealed = _commit_all(repo, "apply")
    ev = s.events()[0]
    assert not ev.self_stable()
    assert ev.tree_after == sealed  # the sealed tree IS the tree the run left
    return s, sealed


def test_the_contradictory_sentence_is_gone_and_the_cause_is_named(repo: Path):
    s, sealed = _lockfile_case(repo)
    r = grade(_claim(), sealed, s.events(), repo, s.blobs.root)
    assert r.grade == "stale"
    assert "0 path(s) differ" not in r.reason
    assert r.reason == (
        "command was not self-stable: the run itself changed 1 path(s): ant.lock, "
        "and the sealed tree is the tree it left — add --path ant.lock to make "
        "this scope-exact"
    )
    # STALE carries the concrete delta, and here it is the run's own write.
    assert [(c.status, c.path) for c in r.delta] == [("A", "ant.lock")]


def test_declaring_the_runs_output_makes_it_scope_exact_never_tree_exact(repo: Path):
    """The claimant says the lock file is in scope; didrun reports exactly that,
    with the file shown and attributed to the run."""
    s, sealed = _lockfile_case(repo)
    r = grade(_claim(("ant.lock",)), sealed, s.events(), repo, s.blobs.root)
    assert r.grade == "scope-exact"
    assert r.reason == (
        "all 1 change(s) within declared pathspecs, 1 of them made by the run itself"
    )
    assert [(c.status, c.path) for c in r.delta] == [("A", "ant.lock")]


def test_the_widening_hint_round_trips(repo: Path):
    """Declaring exactly what the STALE reason names must produce scope-exact."""
    s, sealed = _lockfile_case(repo)
    r = grade(_claim(), sealed, s.events(), repo, s.blobs.root)
    named = r.reason.split("add ", 1)[1].split(" to make", 1)[0]
    specs = tuple(part.removeprefix("--path ") for part in named.split(", "))
    r2 = grade(_claim(specs), sealed, s.events(), repo, s.blobs.root)
    assert r2.grade == "scope-exact", r2.reason


def test_a_pathspec_that_misses_the_runs_output_keeps_its_prefix_and_names_it(repo: Path):
    """The old reason is kept as a prefix (consumers match it) and the cause is
    appended, instead of a bare 'not self-stable'."""
    s, sealed = _lockfile_case(repo)
    r = grade(_claim(("src",)), sealed, s.events(), repo, s.blobs.root)
    assert r.grade == "stale"
    assert r.reason == (
        "evidence tree equals sealed tree but command was not self-stable — the "
        "run itself changed 1 path(s): ant.lock; add --path ant.lock to make "
        "this scope-exact"
    )
    assert [c.path for c in r.delta] == ["ant.lock"]


def test_an_undeclared_rewrite_is_no_longer_hidden_by_a_later_in_scope_edit(repo: Path):
    """The tightening. The run rewrites src/x.py, then docs/ is edited and the
    unit is committed with `--path docs`. Judged only from the tree the run
    LEFT, the delta was docs/ alone and this graded scope-exact; the command
    never ran against the src/x.py that was sealed. Now it is stale and the
    rewrite is named."""
    (repo / "src").mkdir()
    (repo / "src" / "x.py").write_text("x = 1\n")
    (repo / "docs").mkdir()
    (repo / "docs" / "y.md").write_text("one\n")
    _commit_all(repo, "base")
    s = Session(repo / ".didrun")
    run_wrapped(
        [sys.executable, "-c", "open('src/x.py', 'w').write('x = 2\\n')"], s, repo
    )
    (repo / "docs" / "y.md").write_text("two\n")
    sealed = _commit_all(repo, "unit")

    # The pre-fix computation, inline: the delta from the tree the run left.
    left = gp.tree_delta(repo, s.events()[0].tree_after, sealed, s.blobs.root)
    assert [c.path for c in left] == ["docs/y.md"]

    r = grade(_claim(("docs",)), sealed, s.events(), repo, s.blobs.root)
    assert r.grade == "stale"
    assert r.reason == (
        "1 change(s) outside declared pathspecs — add --path src/ to make this "
        "scope-exact; not self-stable: the run itself changed 1 path(s): src/x.py"
    )
    assert sorted(c.path for c in r.delta) == ["docs/y.md", "src/x.py"]


def test_post_run_edits_and_the_runs_own_writes_are_both_counted(repo: Path):
    """No pathspecs, the run writes ant.lock, then calc.py is edited: the
    reason keeps its old count of post-run changes and adds the run's."""
    s = Session(repo / ".didrun")
    run_wrapped([sys.executable, "-c", WRITE_LOCK], s, repo)
    (repo / "calc.py").write_text("def add(a, b):\n    return b + a\n")
    sealed = _commit_all(repo)
    r = grade(_claim(), sealed, s.events(), repo, s.blobs.root)
    assert r.grade == "stale"
    assert r.reason == (
        "tree moved since evidence: 1 path(s) differ; not self-stable: the run "
        "itself changed 1 path(s): ant.lock"
    )
    assert sorted(c.path for c in r.delta) == ["ant.lock", "calc.py"]


def test_the_runs_paths_are_capped_in_the_reason(repo: Path):
    s = Session(repo / ".didrun")
    script = "\n".join(f"open('f{i}.txt', 'w').write('x')" for i in range(7))
    run_wrapped([sys.executable, "-c", script], s, repo)
    sealed = _commit_all(repo)
    r = grade(_claim(), sealed, s.events(), repo, s.blobs.root)
    assert "the run itself changed 7 path(s): f0.txt, f1.txt, f2.txt, f3.txt, " \
           "f4.txt (+2 more)" in r.reason
    assert len(r.delta) == 7


def test_uncomputable_run_delta_grades_unknown(repo: Path, tmp_path: Path):
    """The before-tree's objects gone: no confident sentence about the run."""
    s = Session(repo / ".didrun")
    (repo / "scratch.py").write_text("x = 1\n")  # makes the trees ledger-only
    run_wrapped([sys.executable, "-c", WRITE_LOCK], s, repo)
    sealed = gp.commit_tree(repo, "HEAD")
    gone = tmp_path / "empty-objects"
    gone.mkdir()
    r = grade(_claim(), sealed, s.events(), repo, gone)
    assert r.grade == "unknown"
    assert "not computable" in r.reason
    assert r.delta == []


def test_an_event_with_no_before_digest_is_unknown_not_judged(repo: Path):
    """No digest of the tree the command started from: what it ran against is
    not known, so neither scope nor staleness can be judged from it."""
    from dataclasses import replace

    s, sealed = _lockfile_case(repo)
    ev = replace(s.events()[0], tree_before=None)
    r = grade(_claim(("ant.lock",)), sealed, [ev], repo, s.blobs.root)
    assert r.grade == "unknown"
    assert r.reason == (
        "backing event has no tree digest from before it ran, so what the "
        "command ran against is unknown"
    )


def test_the_verdict_surface_names_the_runs_write(repo: Path):
    """End to end through seal and verify: the row an operator reads."""
    s, _sealed = _lockfile_case(repo)
    M.declare_claim(s, _claim())
    M.seal(s, repo)
    text = render.render_verdict(M.verify(s, repo))
    assert "0 path(s) differ" not in text
    assert "the run itself changed 1 path(s): ant.lock" in text
    assert "A ant.lock" in text
