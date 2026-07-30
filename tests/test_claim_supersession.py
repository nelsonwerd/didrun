"""P4.1 — supersede a claim inside the window instead of truncating the record.

The pair these pin. Within one seal window a single `failed` or `stale` claim
made `all_verified` false with no in-window way to retire it, and the only two
escapes were seal-early (needs a commit) and re-seal — which force-replaced the
commit's note with `all_claims[watermark:]` and silently destroyed everything
the earlier note held. Discarding the ledger and starting over was the rational
third option, which is what the observed atomicity wall was.

So: a later claim with the same `(ctype, label)` retires an earlier one inside
the window, both stay in the note, and a narrowing re-seal is refused unless the
operator asks for it. The retirement subtracts from the VERDICT, never from the
RECORD — every test here that asserts a green verdict also asserts the retired
claim is still present, with its original grade and reason.

What this does NOT do: prevent claim-until-green. Every attempt is retained and
counted, which makes it visible. That is the honest bound and it is strictly
better than the invisible truncation it replaces.
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
from didrun.claims import Claim, grade
from didrun.ledger import Session
from didrun import gitplumbing as gp


def _git(repo: Path, *a: str) -> None:
    subprocess.run(["git", *a], cwd=str(repo), capture_output=True, text=True, check=True)


def _session(repo: Path) -> Session:
    return Session(repo / ".didrun")


def _run(session: Session, repo: Path, code: str):
    return run_wrapped([sys.executable, "-c", code], session, repo)


def _claim(session: Session, ctype: str, label: str, event_index: int) -> Claim:
    """Declare a claim exactly as the CLI would: one event, declared at the tail."""
    claim = Claim(
        ctype=ctype,
        label=label,
        event_indices=(event_index,),
        declared_at_index=len(session.events()) - 1,
    )
    M.declare_claim(session, claim)
    return claim


def _note_json(repo: Path, commit: str = "HEAD") -> dict:
    """The note body on ``commit``, parsed — read with raw git, not didrun."""
    proc = subprocess.run(
        ["git", "notes", f"--ref={M.NOTES_REF}", "show", commit],
        cwd=str(repo),
        capture_output=True,
    )
    assert proc.returncode == 0, "the commit carries no note"
    body = proc.stdout
    assert body.endswith(b"\n")
    return json.loads(body[:-1])


def _attach_raw_note(repo: Path, commit: str, body: bytes) -> None:
    subprocess.run(
        ["git", "notes", f"--ref={M.NOTES_REF}", "add", "-f", "-F", "-", commit],
        cwd=str(repo),
        input=body,
        capture_output=True,
        check=True,
    )


def _gate_pair(session: Session, repo: Path, tmp_path: Path) -> None:
    """One gate run twice in one window: fails, is fixed, passes. No commit.

    The fix lives OUTSIDE the repo on purpose. A fix that edited a tracked file
    would move the working tree away from HEAD's tree, and the second claim would
    grade `stale` for that reason rather than for anything to do with
    supersession — the test would then be measuring the tree digest. This keeps
    the tree fixed so the only variable is the two attempts at the same gate.
    """
    flag = tmp_path / "gate-fixed"
    code = f"import os, sys; sys.exit(0 if os.path.exists({str(flag)!r}) else 1)"
    _run(session, repo, code)              # event 0 — the gate fails
    _claim(session, "tests-pass", "t", 0)
    flag.write_text("fixed\n", encoding="ascii")
    _run(session, repo, code)              # event 1 — the same gate passes
    _claim(session, "tests-pass", "t", 1)


# --- test 1: the commit-free checkpoint --------------------------------------


def test_a_later_claim_retires_an_earlier_one_with_no_commit(repo: Path, tmp_path: Path):
    """The point of the phase: the gate opens without an intervening commit, and
    the failed attempt is still in the note."""
    s = _session(repo)
    _gate_pair(s, repo, tmp_path)
    head = gp.head_commit(repo)

    m = M.seal(s, repo)

    assert len(m.claims) == 2, "the record must keep both attempts"
    assert m.claims[0]["grade"] == "failed"
    assert m.claims[0]["superseded_by"] == 1
    assert m.claims[1]["grade"] == "tree-exact"
    assert "superseded_by" not in m.claims[1], "the live claim must carry no mark"
    assert (m.claims_from, m.claims_to) == (0, 2)

    report = M.verify(s, repo)
    assert report.all_verified is True, "the gate must open with no commit"
    assert report.worst_status == "tree-exact", "the retired FAILED must not vote"
    assert report.superseded_count == 1
    assert len(report.results) == 2
    assert [r.grade for r in report.live_results] == ["tree-exact"]
    assert gp.head_commit(repo) == head, "no commit may be needed to converge"

    # The CI gate, not just the report object.
    assert cli.main(["--repo", str(repo), "verify", "--strict"]) == 0


def test_the_verdict_line_says_how_many_were_retired(repo: Path, tmp_path: Path, monkeypatch):
    """A green headline over a retained FAILED row has to explain itself."""
    monkeypatch.setenv("NO_COLOR", "1")
    s = _session(repo)
    _gate_pair(s, repo, tmp_path)
    M.seal(s, repo)

    out = render.render_verdict(M.verify(s, repo))
    assert "ALL RECORDED-EXACT" in out
    assert "1/1 claims recorded-exact" in out, "the denominator must be the live set"
    assert "1 claim superseded within this seal window" in out
    # The retired row is still shown, and it says which claim replaced it.
    assert "FAILED" in out
    assert "superseded by claim #1 (record, not verdict)" in out
    # And it is below the live row: the record explains, the verdict is asked about.
    lines = out.splitlines()
    live = next(i for i, ln in enumerate(lines) if "TREE-EXACT" in ln)
    retired = next(i for i, ln in enumerate(lines) if "FAILED" in ln)
    assert live < retired


def test_three_attempts_all_point_at_the_one_that_stands(repo: Path, tmp_path: Path):
    """`superseded_by` names the LIVE entry, not the immediate successor."""
    s = _session(repo)
    _gate_pair(s, repo, tmp_path)
    _run(s, repo, "import sys; sys.exit(0)")
    _claim(s, "tests-pass", "t", 2)

    m = M.seal(s, repo)

    assert len(m.claims) == 3
    assert m.claims[0]["superseded_by"] == 2
    assert m.claims[1]["superseded_by"] == 2
    assert "superseded_by" not in m.claims[2]
    assert M.verify(s, repo).superseded_count == 2
    assert M.verify(s, repo).all_verified is True


# --- test 2: identity is (ctype, label), and nothing wider -------------------


def test_a_different_label_or_ctype_does_not_supersede(repo: Path):
    """Two gates are two gates. Supersession is same-type AND same-label only."""
    s = _session(repo)
    _run(s, repo, "print(1)")
    _claim(s, "tests-pass", "unit", 0)
    _claim(s, "tests-pass", "integration", 0)
    _claim(s, "lint-clean", "unit", 0)

    m = M.seal(s, repo)

    assert len(m.claims) == 3
    assert all("superseded_by" not in c for c in m.claims)
    report = M.verify(s, repo)
    assert report.superseded_count == 0
    assert len(report.live_results) == 3
    assert report.all_verified is True


# --- test 3: the record grows, never shrinks ---------------------------------


def test_the_retired_entry_keeps_its_grade_and_reason_verbatim(repo: Path, tmp_path: Path):
    """Nothing is relabelled, re-graded or dropped — checked against an
    independent grading of the same claim, not against a string in this file."""
    s = _session(repo)
    _gate_pair(s, repo, tmp_path)

    tree = gp.commit_tree(repo, "HEAD")
    declared = M._load_claims(s)
    independent = grade(declared[0], tree, s.events(), repo, s.blobs.root)

    m = M.seal(s, repo)
    retired = m.claims[0]

    assert retired["grade"] == independent.grade == "failed"
    assert retired["reason"] == independent.reason
    assert retired["exit_code"] == independent.exit_code == 1
    assert retired["claim"]["label"] == "t", "the label is not rewritten either"
    assert retired["supporting_event_index"] == 0

    # And verify hands the same values back, marked rather than altered.
    result = M.verify(s, repo).results[0]
    assert result.grade == "failed"
    assert result.reason == independent.reason
    assert result.is_superseded and result.superseded_by == 1


def test_a_retired_stale_claim_keeps_its_delta(repo: Path):
    """`stale` must carry its delta wherever it appears, retired included."""
    s = _session(repo)
    _run(s, repo, "print(1)")                       # event 0, at the old tree
    _claim(s, "tests-pass", "t", 0)
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b  # edited\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "edit")
    _run(s, repo, "print(1)")                       # event 1, at the new tree
    _claim(s, "tests-pass", "t", 1)

    m = M.seal(s, repo)

    assert m.claims[0]["grade"] == "stale"
    assert m.claims[0]["superseded_by"] == 1
    assert [c["path"] for c in m.claims[0]["delta"]] == ["calc.py"]
    assert m.claims[1]["grade"] == "tree-exact"
    assert M.verify(s, repo).all_verified is True


# --- test 4: the window is in the artifact -----------------------------------


def test_the_note_records_the_claim_window(repo: Path):
    """claims_from/claims_to match the watermark arithmetic on every seal."""
    s = _session(repo)
    _run(s, repo, "print(1)")
    _claim(s, "tests-pass", "one", 0)
    first_commit = gp.head_commit(repo)
    M.seal(s, repo)

    body = _note_json(repo, first_commit)
    assert body["claims_from"] == 0
    assert body["claims_to"] == 1
    assert len(body["claims"]) == 1

    (repo / "calc.py").write_text("def add(a, b):\n    return a + b  # two\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "unit two")
    _run(s, repo, "print(2)")
    _claim(s, "tests-pass", "two", 1)
    second = M.seal(s, repo)

    assert (second.claims_from, second.claims_to) == (1, 2)
    body = _note_json(repo, gp.head_commit(repo))
    assert (body["claims_from"], body["claims_to"]) == (1, 2)
    assert len(body["claims"]) == 1, "the window is the note's scope, verbatim"

    # The earlier commit's note is untouched: history is never rewritten.
    assert _note_json(repo, first_commit)["claims_from"] == 0
    assert _note_json(repo, first_commit)["claims_to"] == 1


def test_a_v1_note_reads_back_with_the_window_defaults():
    """Additive with a reading default, so every stored note still parses."""
    body = json.dumps(
        {
            "version": 1,
            "commit": "0" * 40,
            "tree": "1" * 40,
            "claims": [{"grade": "tree-exact"}, {"grade": "tree-exact"}],
            "coverage": {"total_events": 2, "by_coverage": {"complete": 2}},
            "secrets_override": False,
        }
    ).encode("ascii")

    m = M.Manifest.from_json(body)

    assert m.claims_from == 0
    assert m.claims_to == 2, "the default is len(claims), never None"
    assert json.loads(m.to_json())["claims_to"] == 2


# --- test 5: a narrowing re-seal is refused ----------------------------------


def _ten_gates(repo: Path) -> Session:
    s = _session(repo)
    _run(s, repo, "print(1)")
    for i in range(10):
        _claim(s, "tests-pass", f"gate-{i}", 0)
    return s


def test_a_narrowing_reseal_is_refused_and_names_both_windows(repo: Path):
    s = _ten_gates(repo)
    M.seal(s, repo)
    assert _note_json(repo)["claims_to"] == 10

    _claim(s, "tests-pass", "gate-10", 0)
    _claim(s, "tests-pass", "gate-11", 0)

    with pytest.raises(M.ManifestError) as exc:
        M.seal(s, repo)
    message = str(exc.value)
    assert "[0,10)" in message, "the message must name the recorded window"
    assert "[10,12)" in message, "and the window that would replace it"
    assert "--reseal" in message
    # Refused means refused: the note and the watermark are where they were.
    assert _note_json(repo)["claims_to"] == 10
    assert M._last_seal_watermark(s) == 10

    m = M.seal(s, repo, reseal=True)
    assert (m.claims_from, m.claims_to) == (10, 12)
    assert _note_json(repo)["claims_from"] == 10, "the narrowing is now visible"
    assert len(_note_json(repo)["claims"]) == 2


def test_a_superset_reseal_needs_no_flag(repo: Path):
    """Re-covering the recorded window plus more loses nothing, so it is allowed.

    The realistic way to land here is watermark rotation — the gitignored
    seals.jsonl is gone, so the seal covers the whole claim history again.
    """
    s = _ten_gates(repo)
    M.seal(s, repo)
    _claim(s, "tests-pass", "gate-10", 0)
    (s.root / "seals.jsonl").unlink()

    m = M.seal(s, repo)

    assert (m.claims_from, m.claims_to) == (0, 11)
    assert len(_note_json(repo)["claims"]) == 11


def test_the_seal_line_counts_the_same_set_the_verdict_does(repo: Path, tmp_path: Path, capsys):
    """`seal` and `verify` describe the same note, so "1/2 recorded-exact" beside
    an ALL RECORDED-EXACT verdict is one of them being wrong."""
    s = _session(repo)
    _gate_pair(s, repo, tmp_path)
    capsys.readouterr()

    assert cli.main(["--repo", str(repo), "seal"]) == 0

    out = capsys.readouterr().out
    assert "1/1 claims recorded-exact" in out
    assert "1 superseded" in out
    assert "1/2" not in out
    assert cli.main(["--repo", str(repo), "verify", "--strict"]) == 0


def test_the_cli_wires_reseal_and_refuses_without_it(repo: Path, capsys):
    s = _ten_gates(repo)
    assert cli.main(["--repo", str(repo), "seal"]) == 0
    capsys.readouterr()
    _claim(s, "tests-pass", "gate-10", 0)

    assert cli.main(["--repo", str(repo), "seal"]) == 2
    captured = capsys.readouterr()
    assert "refusing to replace the note" in captured.err
    assert "--reseal" in captured.err
    assert "Traceback" not in captured.err

    assert cli.main(["--repo", str(repo), "seal", "--reseal"]) == 0
    assert (_note_json(repo)["claims_from"], _note_json(repo)["claims_to"]) == (10, 11)


# --- test 6: a legacy note carries no window, so it is not overwritten blind --


def test_a_legacy_note_requires_reseal(repo: Path):
    """An absent window is UNKNOWN, not [0,N): the reading default must never
    let the guard conclude a legacy note is containable."""
    s = _session(repo)
    _run(s, repo, "print(1)")
    _claim(s, "tests-pass", "t", 0)
    head = gp.head_commit(repo)
    legacy = json.dumps(
        {
            "version": 1,
            "commit": head,
            "tree": gp.commit_tree(repo, head),
            "claims": [],
            "coverage": {"total_events": 0, "by_coverage": {}},
            "secrets_override": False,
        }
    ).encode("ascii")
    _attach_raw_note(repo, head, legacy)

    with pytest.raises(M.ManifestError) as exc:
        M.seal(s, repo)
    message = str(exc.value)
    assert "records no claim window" in message
    assert "--reseal" in message
    assert "[0,1)" in message, "the seal's own window is still named"

    m = M.seal(s, repo, reseal=True)
    assert (m.claims_from, m.claims_to) == (0, 1)


def test_a_foreign_note_is_not_overwritten_blind(repo: Path):
    """A body that is not a manifest at all reads as no window, for the same
    reason: it is the case where an overwrite destroys the most."""
    s = _session(repo)
    _run(s, repo, "print(1)")
    _claim(s, "tests-pass", "t", 0)
    _attach_raw_note(repo, gp.head_commit(repo), b"someone else's note body")

    with pytest.raises(M.ManifestError) as exc:
        M.seal(s, repo)
    assert "records no claim window" in str(exc.value)
    assert M.seal(s, repo, reseal=True).claims_to == 1


# --- test 7: a missing watermark file is never silent ------------------------


def test_a_missing_watermark_file_warns_and_proceeds(repo: Path, capsys):
    s = _ten_gates(repo)
    M.seal(s, repo)
    capsys.readouterr()
    seals = s.root / "seals.jsonl"
    assert seals.exists()
    seals.unlink()

    m = M.seal(s, repo)

    err = capsys.readouterr().err
    assert "no seal watermark file" in err
    assert "WHOLE claim history" in err
    assert "10 declared claim(s)" in err
    assert m.claims_from == 0, "the watermark really did reset"
    assert seals.exists(), "and the seal proceeded"


def test_the_warning_is_silent_once_the_watermark_exists(repo: Path, capsys):
    """It fires on absence, not on every seal — otherwise it is ignorable noise.

    The first seal of a session also has no watermark file and also warns: the
    two are genuinely indistinguishable from inside `seal`, and the warning text
    says so rather than picking one.
    """
    s = _session(repo)
    _run(s, repo, "print(1)")
    _claim(s, "tests-pass", "one", 0)
    M.seal(s, repo)
    assert "no seal watermark file" in capsys.readouterr().err

    _git(repo, "commit", "-q", "--allow-empty", "-m", "unit two")
    _claim(s, "tests-pass", "two", 0)
    M.seal(s, repo)
    assert "no seal watermark file" not in capsys.readouterr().err


def test_no_claims_no_watermark_warning(repo: Path, capsys):
    """Nothing to re-cover, nothing to warn about."""
    s = _session(repo)
    _run(s, repo, "print(1)")
    M.seal(s, repo)
    assert "no seal watermark file" not in capsys.readouterr().err


# --- test 8: supersession is window-local, so the documented loop is unchanged


def test_the_same_label_in_a_later_window_is_not_superseded(repo: Path):
    """What test_fix_loop_converges encodes, asserted directly: the watermark
    advanced between the two seals, so the second window holds one claim and
    nothing in the first is reachable from it."""
    s = _session(repo)
    _run(s, repo, "import sys; sys.exit(1)")
    _claim(s, "tests-pass", "t", 0)
    M.seal(s, repo)
    first_commit = gp.head_commit(repo)

    (repo / "calc.py").write_text("def add(a, b):\n    return a + b  # fixed\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "fix")
    _run(s, repo, "import sys; sys.exit(0)")
    _claim(s, "tests-pass", "t", 1)
    second = M.seal(s, repo)

    assert (second.claims_from, second.claims_to) == (1, 2)
    assert len(second.claims) == 1
    assert all("superseded_by" not in c for c in second.claims)
    report = M.verify(s, repo)
    assert report.all_verified is True
    assert len(report.results) == 1
    assert report.superseded_count == 0

    # History is never rewritten: the first commit's note still shows FAILED and
    # nothing retired it from the later window.
    old = M.verify(s, repo, commitish=first_commit)
    assert old.worst_status == "failed"
    assert old.superseded_count == 0


# --- the vacuous-green guard ------------------------------------------------


def _result(label: str, grade_name: str, superseded_by=None):
    from didrun.claims import GradeResult

    return GradeResult(
        Claim(ctype="tests-pass", label=label, event_indices=(0,), declared_at_index=0),
        grade_name,
        reason=f"{grade_name} reason",
        supporting_event_index=0,
        superseded_by=superseded_by,
    )


def test_a_window_of_only_superseded_results_is_never_green():
    """`all([])` is True, so filtering the superseded out of `all_verified`
    without re-checking non-emptiness would make a window whose every claim was
    retired verify vacuously green — a green verdict over zero live claims."""
    report = M.VerifyReport(
        commit="a" * 40,
        tree="b" * 40,
        resolved_by="commit",
        results=[
            _result("t", "tree-exact", superseded_by=1),
            _result("t", "tree-exact", superseded_by=1),
        ],
        coverage={},
        chain_status="intact",
    )

    assert report.live_results == []
    assert report.superseded_count == 2
    assert report.all_verified is False
    # And it must not read as an unsealed commit either: there IS a record here.
    assert report.worst_status == "unknown"
    assert report.total == 2
    out = render.render_verdict(report)
    assert "ALL RECORDED-EXACT" not in out
    assert "NO CLAIMS" not in out
    assert "2 claims superseded" in out


def test_an_empty_report_still_reads_as_empty():
    """The complement: no results at all is `empty`, which is a different fact."""
    report = M.VerifyReport(
        commit="a" * 40, tree="b" * 40, resolved_by="none", results=[], coverage={}
    )
    assert report.worst_status == "empty"
    assert report.all_verified is False
    assert report.superseded_count == 0


@pytest.mark.parametrize(
    "mark",
    [
        0,      # itself
        -1,     # backwards
        2,      # out of range
        True,   # a bool is not an index
        "1",    # not an int
        None,   # explicitly null
    ],
)
def test_an_unusable_supersession_mark_counts_the_claim(repo: Path, mark):
    """A mark that is not a forward index into this note's own claims is dropped,
    and dropping it COUNTS the claim — the direction that refuses.

    This is not a forgery barrier and does not pretend to be one: whoever can
    rewrite a note can rewrite a grade directly. It is the same fail-closed
    reading didrun applies to every field it did not compute in this process.
    """
    s = _session(repo)
    _run(s, repo, "import sys; sys.exit(1)")
    _claim(s, "tests-pass", "t", 0)
    _run(s, repo, "import sys; sys.exit(0)")
    _claim(s, "tests-pass", "t", 1)
    m = M.seal(s, repo)
    assert M.verify(s, repo).all_verified is True  # the honest note is green

    body = _note_json(repo)
    body["claims"][0]["superseded_by"] = mark
    _attach_raw_note(
        repo,
        m.commit,
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii"),
    )

    report = M.verify(s, repo)
    assert report.superseded_count == 0, "an unusable mark must not retire a claim"
    assert report.all_verified is False
    assert report.worst_status == "failed"


def test_a_mark_pointing_at_a_different_gate_is_dropped(repo: Path):
    """Supersession is defined by (ctype, label), so a mark across two different
    gates is malformed — it would retire a claim nothing replaced."""
    s = _session(repo)
    _run(s, repo, "import sys; sys.exit(1)")
    _claim(s, "tests-pass", "unit", 0)
    _run(s, repo, "import sys; sys.exit(0)")
    _claim(s, "tests-pass", "integration", 1)
    m = M.seal(s, repo)

    body = _note_json(repo)
    assert all("superseded_by" not in c for c in body["claims"])
    body["claims"][0]["superseded_by"] = 1
    _attach_raw_note(
        repo,
        m.commit,
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii"),
    )

    report = M.verify(s, repo)
    assert report.superseded_count == 0
    assert report.all_verified is False
