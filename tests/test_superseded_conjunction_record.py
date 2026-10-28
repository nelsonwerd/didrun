"""A superseded conjunction's record says what it conjoined when it was declared.

Found dogfooding didrun on a real build: a conjunction declared while one of
its gates was red, then re-declared after the gate was fixed and re-claimed,
left a RETIRED row reading TREE-EXACT. The retired attempt had been resolved
against the window as it stood at seal time — the fixed gate — so the record
of the attempt described a different attempt. It never touched the verdict
(a superseded row does not vote), but a record that misstates what was
declared is the one thing a record must not do.

Pinned here:

- a SUPERSEDED conjunction resolves its names against the claims live at the
  point it was declared — the ordinary claims before it in the window, each
  label at its latest declaration up to there — and its reason says so;
- a LIVE conjunction is unchanged: it resolves against the window as sealed,
  so the verdict is exactly what it was;
- seal and verify agree, so the sealed grade regrades to itself.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from didrun import cli
from didrun import manifest as M
from didrun import render
from didrun.capture import run_wrapped
from didrun.claims import CONJUNCTION, Claim
from didrun.ledger import Session


def _session(repo: Path) -> Session:
    return Session(repo / ".didrun")


def _gate(tmp_path: Path) -> tuple[Path, str]:
    """A gate that fails until a flag OUTSIDE the repo exists, so fixing it
    moves no tree and the only variable is which attempt is resolved to."""
    flag = tmp_path / "gate-fixed"
    code = f"import os, sys; sys.exit(0 if os.path.exists({str(flag)!r}) else 1)"
    return flag, code


def _run(s: Session, repo: Path, code: str) -> int:
    run_wrapped([sys.executable, "-c", code], s, repo)
    return len(s.events()) - 1


def _claim(s: Session, label: str, event: int) -> None:
    M.declare_claim(
        s,
        Claim(ctype="tests-pass", label=label, event_indices=(event,),
              declared_at_index=len(s.events()) - 1),
    )


def _conjunction(s: Session, label: str, *names: str) -> None:
    M.declare_claim(
        s,
        Claim(ctype=CONJUNCTION, label=label, event_indices=(),
              declared_at_index=len(s.events()) - 1, conjuncts=tuple(names)),
    )


def _red_then_green(s: Session, repo: Path, tmp_path: Path) -> None:
    """[0] gate FAILED · [1] REL over gate · [2] gate passes · [3] REL again."""
    flag, code = _gate(tmp_path)
    _claim(s, "gate", _run(s, repo, code))       # claim 0: failed attempt
    _conjunction(s, "REL", "gate")               # claim 1: declared while red
    flag.write_text("fixed\n", encoding="ascii")
    _claim(s, "gate", _run(s, repo, code))       # claim 2: the fix
    _conjunction(s, "REL", "gate")               # claim 3: re-declared


def test_the_retired_conjunction_records_the_red_gate_it_was_declared_over(
    repo: Path, tmp_path: Path
):
    s = _session(repo)
    _red_then_green(s, repo, tmp_path)
    m = M.seal(s, repo)
    retired, live = m.claims[1], m.claims[3]

    assert retired["superseded_by"] == 3
    assert retired["grade"] == "failed", "the record must not read TREE-EXACT"
    assert retired["conjunct_grades"] == [{"label": "gate", "grade": "failed"}]
    assert retired["reason"] == (
        "as declared at claim #1: worst of 1 conjunct(s): 'gate' graded failed"
    )
    # The live one is exactly what it always was.
    assert live["grade"] == "tree-exact"
    assert live["reason"] == "worst of 1 conjunct(s): 'gate' graded tree-exact"


def test_the_verdict_is_untouched(repo: Path, tmp_path: Path):
    s = _session(repo)
    _red_then_green(s, repo, tmp_path)
    M.seal(s, repo)
    report = M.verify(s, repo)
    assert report.all_verified is True
    assert report.superseded_count == 2
    assert {r.claim.label: r.grade for r in report.live_results} == {
        "gate": "tree-exact",
        "REL": "tree-exact",
    }
    assert cli.main(["--repo", str(repo), "verify", "--strict"]) == 0


def test_verify_regrades_the_record_to_what_was_sealed(repo: Path, tmp_path: Path):
    s = _session(repo)
    _red_then_green(s, repo, tmp_path)
    m = M.seal(s, repo)
    report = M.verify(s, repo)
    retired = report.results[1]
    assert retired.is_superseded
    assert retired.grade == m.claims[1]["grade"] == "failed"
    assert retired.reason == m.claims[1]["reason"]
    assert retired.conjunct_grades == (("gate", "failed"),)


def test_the_surface_shows_the_retired_row_as_what_it_was(repo: Path, tmp_path: Path):
    s = _session(repo)
    _red_then_green(s, repo, tmp_path)
    M.seal(s, repo)
    text = render.render_verdict(M.verify(s, repo))
    assert (
        "superseded by claim #3 (record, not verdict) — as declared at claim #1: "
        "worst of 1 conjunct(s): 'gate' graded failed"
    ) in text


def test_a_member_retired_after_the_conjunction_was_live_when_it_was_declared(
    repo: Path,
):
    """The as-declared pool is computed within the window prefix: a gate that a
    LATER claim retires was still the live one at declaration, and is what the
    retired conjunction resolves to."""
    s = _session(repo)
    _claim(s, "unit", _run(s, repo, "pass"))
    _conjunction(s, "REL", "unit", "lint")       # claim 1: 'lint' not declared yet
    _claim(s, "lint", _run(s, repo, "pass"))
    _claim(s, "unit", _run(s, repo, "pass"))     # retires claim 0
    _conjunction(s, "REL", "unit", "lint")       # retires claim 1
    m = M.seal(s, repo)

    retired = m.claims[1]
    assert retired["grade"] == "unknown"
    assert retired["conjunct_grades"] == [
        {"label": "unit", "grade": "tree-exact"},
        {"label": "lint", "grade": None},
    ]
    assert retired["reason"] == (
        "as declared at claim #1: unresolved conjunct: 'lint' names no claim "
        "declared before it in this seal window"
    )
    assert m.claims[4]["grade"] == "tree-exact"
    assert M.verify(s, repo).all_verified is True


def test_a_live_conjunction_still_resolves_against_the_sealed_window(
    repo: Path, tmp_path: Path
):
    """Unchanged on purpose: the conjunction that votes is resolved against the
    claims that stand at seal, so a gate fixed after it was declared counts.
    Moving the live rule would change verdicts already published."""
    s = _session(repo)
    flag, code = _gate(tmp_path)
    _claim(s, "gate", _run(s, repo, code))       # failed
    _conjunction(s, "REL", "gate")               # the only REL: live
    flag.write_text("fixed\n", encoding="ascii")
    _claim(s, "gate", _run(s, repo, code))       # passes, retires claim 0
    m = M.seal(s, repo)
    assert "superseded_by" not in m.claims[1]
    assert m.claims[1]["grade"] == "tree-exact"
    assert m.claims[1]["reason"] == "worst of 1 conjunct(s): 'gate' graded tree-exact"
    assert json.loads(m.to_json())["claims"][1]["conjunct_grades"] == [
        {"label": "gate", "grade": "tree-exact"}
    ]
