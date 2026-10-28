"""A claim that belongs to work not in this commit can be set aside — visibly.

Found dogfooding didrun on a real build. A unit was interrupted after it had
run its gate and declared its claim over UNCOMMITTED draft work. The next unit
was unrelated; it committed and sealed, and the seal window — every claim
since the last seal — carried the interrupted unit's claim in with it. Graded
against a commit that does not contain the draft, it was STALE (correctly),
and `verify --strict` stayed red until the claim was re-made against work it
had nothing to do with.

The grade is right; the window is wrong for that one claim. `didrun claim
--defer LABEL --reason TEXT` sets one claim aside from the next seal's verdict
and from nothing else:

- it is RECORD, like a superseded claim: still graded, still published in the
  note with its grade, reason and delta, and marked `deferred` with the
  operator's reason; counted on every verdict surface;
- it is bound to one claim INSTANCE in the unsealed window, never to a label
  going forward, so re-declaring the gate makes a claim that votes;
- it never sets aside a WITNESSED FAILURE. A claim bound to a command that
  exited nonzero is refused at `--defer` time, and a deferral that reaches a
  `failed` grade anyway (a hand-edited record, a forged note mark) is not
  honoured: the claim votes.
- it never carries forward: the claim is in this note's record and in no later
  window.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from didrun import cli
from didrun import manifest as M
from didrun import render
from didrun.capture import run_wrapped
from didrun.claims import CONJUNCTION, Claim
from didrun.ledger import Session

REASON = "draft work for the interrupted unit; not in this commit"


def _session(repo: Path) -> Session:
    return Session(repo / ".didrun")


def _git(repo: Path, *a: str) -> None:
    subprocess.run(["git", *a], cwd=str(repo), capture_output=True, text=True, check=True)


def _cli(repo: Path, *argv: str) -> int:
    return cli.main(["--repo", str(repo), *argv])


def _interrupted_then_unrelated(repo: Path) -> Session:
    """Unit A runs its gate over a draft and claims it, then is abandoned.
    Unit B makes an unrelated change, runs, claims, and commits."""
    s = _session(repo)
    (repo / "draft.py").write_text("WIP = True\n")
    run_wrapped([sys.executable, "-c", "pass"], s, repo)
    assert _cli(repo, "claim", "tests-pass", "--label", "unit A tests") == 0
    (repo / "draft.py").unlink()                     # the draft never lands
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b  # B\n")
    run_wrapped([sys.executable, "-c", "pass"], s, repo)
    assert _cli(repo, "claim", "tests-pass", "--label", "unit B tests") == 0
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "unit B")
    return s


def test_control_without_deferral_the_strict_gate_is_red(repo: Path):
    """The dogfood behaviour, pinned so the fix below is measured against it."""
    s = _interrupted_then_unrelated(repo)
    M.seal(s, repo)
    report = M.verify(s, repo)
    grades = {r.claim.label: r.grade for r in report.live_results}
    assert grades == {"unit A tests": "stale", "unit B tests": "tree-exact"}
    assert _cli(repo, "verify", "--strict") == 1


def test_deferring_the_foreign_claim_opens_the_gate_and_keeps_the_record(
    repo: Path, capsys
):
    s = _interrupted_then_unrelated(repo)
    assert _cli(repo, "claim", "--defer", "unit A tests", "--reason", REASON) == 0
    out = capsys.readouterr().out
    assert "deferred claim #0" in out and REASON in out

    m = M.seal(s, repo)
    entry_a, entry_b = m.claims
    # Record: graded, published, marked — not dropped.
    assert entry_a["grade"] == "stale"
    assert entry_a["delta"], "the stale delta is still published"
    assert entry_a["deferred"] == {"reason": REASON}
    assert "deferred" not in entry_b

    report = M.verify(s, repo)
    assert report.all_verified is True
    assert report.deferred_count == 1
    assert [r.claim.label for r in report.live_results] == ["unit B tests"]
    deferred = report.results[0]
    assert deferred.is_deferred and deferred.grade == "stale"
    assert _cli(repo, "verify", "--strict") == 0


def test_the_surfaces_count_and_label_it(repo: Path, capsys):
    s = _interrupted_then_unrelated(repo)
    _cli(repo, "claim", "--defer", "unit A tests", "--reason", REASON)
    capsys.readouterr()
    assert _cli(repo, "seal") == 0
    assert "1/1 claims recorded-exact  1 deferred" in capsys.readouterr().out

    report = M.verify(s, repo)
    text = render.render_verdict(report)
    assert (
        "1 claim deferred out of this commit (retained in the record, excluded "
        "from the verdict)"
    ) in text
    assert f"deferred (record, not verdict): {REASON} — tree moved" in text
    html = render.render_html(report)
    assert "deferred" in html and REASON in html


def test_a_witnessed_failure_cannot_be_deferred(repo: Path, capsys):
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "import sys; sys.exit(3)"], s, repo)
    run_wrapped([sys.executable, "-c", "pass"], s, repo)
    assert _cli(repo, "claim", "tests-pass", "--label", "gate", "--event", "0") == 0
    capsys.readouterr()
    assert _cli(repo, "claim", "--defer", "gate", "--reason", REASON) == 2
    err = capsys.readouterr().err
    assert "exited 3" in err and "witnessed failure" in err
    assert not M._deferrals_path(s).exists(), "a refused deferral writes nothing"


def test_a_deferral_that_reaches_a_failed_grade_is_not_honoured(repo: Path, capsys):
    """A hand-written record skips the --defer check; the seal re-checks."""
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "import sys; sys.exit(3)"], s, repo)
    M.declare_claim(s, Claim(ctype="tests-pass", label="gate", event_indices=(0,),
                             declared_at_index=0))
    M._deferrals_path(s).write_text(
        json.dumps({"claim_index": 0, "ctype": "tests-pass", "label": "gate",
                    "reason": REASON}) + "\n"
    )
    m = M.seal(s, repo)
    assert "deferred" not in m.claims[0]
    assert "not honoured" in capsys.readouterr().err
    report = M.verify(s, repo)
    assert report.worst_status == "failed"
    assert report.deferred_count == 0


def test_a_forged_note_mark_on_a_failed_claim_still_votes(repo: Path):
    """verify reads the mark the way it reads `superseded_by`: validated."""
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "import sys; sys.exit(3)"], s, repo)
    M.declare_claim(s, Claim(ctype="tests-pass", label="gate", event_indices=(0,),
                             declared_at_index=0))
    m = M.seal(s, repo)
    m.claims[0]["deferred"] = {"reason": "forged"}
    M._attach_note(repo, m.commit, m)
    report = M.verify(s, repo)
    assert report.results[0].is_deferred is False
    assert report.worst_status == "failed"


@pytest.mark.parametrize(
    "mark", [True, "free text", {"reason": ""}, {"reason": 7}, {}],
    ids=["bool", "string", "empty-reason", "non-string-reason", "no-reason"],
)
def test_a_malformed_mark_defers_nothing(repo: Path, mark):
    s = _session(repo)
    (repo / "x.py").write_text("x = 1\n")
    run_wrapped([sys.executable, "-c", "pass"], s, repo)
    M.declare_claim(s, Claim(ctype="tests-pass", label="t", event_indices=(0,),
                             declared_at_index=0))
    (repo / "x.py").unlink()
    m = M.seal(s, repo)
    m.claims[0]["deferred"] = mark
    M._attach_note(repo, m.commit, m)
    report = M.verify(s, repo)
    assert report.deferred_count == 0
    assert report.worst_status == "stale"


def test_the_deferral_binds_the_instance_not_the_label(repo: Path):
    """Re-declaring the gate after deferring it makes a claim that votes."""
    s = _interrupted_then_unrelated(repo)
    _cli(repo, "claim", "--defer", "unit A tests", "--reason", REASON)
    run_wrapped([sys.executable, "-c", "pass"], s, repo)
    assert _cli(repo, "claim", "tests-pass", "--label", "unit A tests") == 0
    m = M.seal(s, repo)
    assert m.claims[0]["superseded_by"] == 2
    assert "deferred" not in m.claims[0], "a retired claim needs no deferral mark"
    report = M.verify(s, repo)
    assert {r.claim.label for r in report.live_results} == {"unit A tests", "unit B tests"}
    assert report.deferred_count == 0


def test_refusals_name_why_and_write_nothing(repo: Path, capsys):
    s = _interrupted_then_unrelated(repo)
    cases = [
        (["claim", "--defer", "unit A tests"], "--reason"),
        (["claim", "--defer", "unit A tests", "--reason", "  "], "--reason"),
        (["claim", "tests-pass", "--reason", REASON], "--reason only"),
        (["claim", "--defer", "unit A tests", "--reason", REASON, "--event", "0"],
         "declares no claim"),
        (["claim", "--defer", "unit A tests", "--reason", REASON, "--path", "src/"],
         "declares no claim"),
        (["claim", "--defer", "unit A tests", "--reason", REASON, "--label", "x"],
         "declares no claim"),
        (["claim", "--defer", "nosuch", "--reason", REASON], "no unsealed claim"),
        (["claim", "lint-clean", "--defer", "unit A tests", "--reason", REASON],
         "no unsealed claim"),
        (["claim"], "claim type is required"),
    ]
    for argv, why in cases:
        capsys.readouterr()
        assert _cli(repo, *argv) == 2, argv
        assert why in capsys.readouterr().err, (argv, why)
    assert not M._deferrals_path(s).exists()


def test_a_claim_already_sealed_cannot_be_deferred(repo: Path, capsys):
    """Its note is published; setting it aside now would rewrite history."""
    s = _interrupted_then_unrelated(repo)
    M.seal(s, repo)
    capsys.readouterr()
    assert _cli(repo, "claim", "--defer", "unit A tests", "--reason", REASON) == 2
    assert "already sealed" in capsys.readouterr().err


def test_deferring_twice_is_refused(repo: Path, capsys):
    _interrupted_then_unrelated(repo)
    assert _cli(repo, "claim", "--defer", "unit A tests", "--reason", REASON) == 0
    capsys.readouterr()
    assert _cli(repo, "claim", "--defer", "unit A tests", "--reason", "again") == 2
    assert "already deferred" in capsys.readouterr().err


def test_an_ambiguous_label_needs_the_type(repo: Path, capsys):
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "pass"], s, repo)
    _cli(repo, "claim", "tests-pass", "--label", "gate")
    _cli(repo, "claim", "lint-clean", "--label", "gate")
    capsys.readouterr()
    assert _cli(repo, "claim", "--defer", "gate", "--reason", REASON) == 2
    assert "pass the claim type" in capsys.readouterr().err
    assert _cli(repo, "claim", "lint-clean", "--defer", "gate", "--reason", REASON) == 0
    (record,) = M._load_deferrals(s)
    assert (record["claim_index"], record["ctype"]) == (1, "lint-clean")


def test_a_window_of_only_deferred_claims_is_never_green(repo: Path):
    s = _interrupted_then_unrelated(repo)
    _cli(repo, "claim", "--defer", "unit A tests", "--reason", REASON)
    _cli(repo, "claim", "--defer", "unit B tests", "--reason", REASON)
    M.seal(s, repo)
    report = M.verify(s, repo)
    assert report.live_results == []
    assert report.all_verified is False
    assert report.worst_status == "unknown"


def test_a_live_conjunction_does_not_resolve_to_a_deferred_claim(repo: Path):
    """A set-aside claim is not part of this commit, so a conjunction naming it
    names nothing here — unknown, never a green it borrowed."""
    s = _interrupted_then_unrelated(repo)
    _cli(repo, "claim", "--defer", "unit A tests", "--reason", REASON)
    M.declare_claim(s, Claim(ctype=CONJUNCTION, label="REL", event_indices=(),
                             declared_at_index=1,
                             conjuncts=("unit A tests", "unit B tests")))
    m = M.seal(s, repo)
    assert m.claims[2]["grade"] == "unknown"
    assert M.verify(s, repo).all_verified is False


def test_the_deferral_reason_is_scanned_and_redacted(repo: Path):
    """Operator-authored text in the note: blocks on a structured secret, and
    is published as a marker on the override."""
    s = _interrupted_then_unrelated(repo)
    token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    _cli(repo, "claim", "--defer", "unit A tests", "--reason", f"see {token}")
    from didrun import redact

    with pytest.raises(redact.SecretsBlocked):
        M.seal(s, repo)
    m = M.seal(s, repo, allow_secrets=True)
    published = m.claims[0]["deferred"]["reason"]
    assert token not in published and "«redacted:github-token»" in published
    assert any(f["field"] == "deferred.reason" for f in m.claims[0]["redaction"]["fields"])


def test_a_deferred_claim_does_not_carry_into_the_next_window(repo: Path):
    s = _interrupted_then_unrelated(repo)
    _cli(repo, "claim", "--defer", "unit A tests", "--reason", REASON)
    M.seal(s, repo)
    run_wrapped([sys.executable, "-c", "pass"], s, repo)
    _cli(repo, "claim", "tests-pass", "--label", "unit C tests")
    (repo / "c.py").write_text("c = 1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "unit C")
    m = M.seal(s, repo)
    assert [c["claim"]["label"] for c in m.claims] == ["unit C tests"]
