"""P1.2 — a sealed claim is bound to the evidence it was sealed against.

The defect these pin: `verify` re-graded every claim from scratch against
whatever ledger was on disk, keyed by integer index, and threw away the grades
it sealed. So an archived ledger made every claim `unknown` with the same reason
string a genuinely unbacked claim gets, and a SUBSTITUTED ledger of unrelated
exit-0 commands on the same tree graded a full set of claims recorded-exact and
exited 0.

What this closes, stated honestly: verify used to silently regrade against
whatever ledger is present, so archival, rebuild or index drift changed a sealed
verdict with no signal. Binding the claim to its entry hash buys ACCIDENT AND
DRIFT DETECTION on a published note. It does not stop a forger — whoever can
substitute a ledger can regenerate its chain and re-run claim+seal to mint fresh
hash-bound claims (ledger.py's declared non-guarantee).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from didrun import cli
from didrun import gitplumbing as gp
from didrun import manifest as M
from didrun import render
from didrun.capture import run_wrapped
from didrun.claims import Claim, GradeResult
from didrun.ledger import Session, canonical_json


def _git(repo: Path, *a: str) -> None:
    subprocess.run(["git", *a], cwd=str(repo), capture_output=True, text=True, check=True)


def _session(repo: Path) -> Session:
    return Session(repo / ".didrun")


def _ok(repo: Path, session: Session, text: str):
    return run_wrapped([sys.executable, "-c", f"print({text!r})"], session, repo)


def _sealed_green(repo: Path, label: str = "suite") -> Session:
    """One recorded success, one claim over it, sealed on a clean tree."""
    s = _session(repo)
    _ok(repo, s, "the unit under test")
    M.declare_claim(
        s, Claim(ctype="tests-pass", label=label, event_indices=(0,), declared_at_index=0)
    )
    M.seal(s, repo)
    return s


def _substitute_log(repo: Path, session: Session, tmp_path: Path, texts) -> None:
    """Replace session.log with a ledger of DIFFERENT commands on the same tree.

    Built by running real commands into a fresh Session, never by splicing log
    lines: a spliced log has broken prev_hash linkage, so it reports a broken
    chain, which dominates and fails --strict regardless of whether the evidence
    binding works at all. The test would then pass for the wrong reason and stop
    testing this unit.

    The substitute ledger lives OUTSIDE the repo. A ledger directory inside it
    under any name but `.didrun` would enter the tree digest, moving tree_after
    away from the sealed tree — and the whole point of this fixture is a
    substitute whose events still look tree-exact.
    """
    alt = Session(tmp_path / "alt-ledger")
    for text in texts:
        _ok(repo, alt, text)
    shutil.copyfile(alt.log_path, session.log_path)


# --- test 1: the falsification test (criterion per red-team §3.3) ------------


def test_substituted_ledger_of_the_same_length_is_caught(repo: Path, tmp_path: Path):
    """A same-length ledger of different commands on the same tree.

    This fails on pre-P1.2 code, which grades it `tree-exact` and exits 0 — the
    substitute's events are self-stable against the sealed tree, which is all
    the index-keyed regrade ever looked at. It would ALSO fail with only the
    witness-unavailable half: `supporting_event_index >= len(events)` is false
    here, because the substitute ledger is exactly as long as the one it
    replaced. Only the hash binding detects it.
    """
    s = _sealed_green(repo)
    sealed_tree = gp.commit_tree(repo, "HEAD")
    _substitute_log(repo, s, tmp_path, ["something else entirely"])

    live = list(s.entries())
    assert len(live) == 1, "the substitute must be the SAME LENGTH, or test 2 covers it"
    assert live[0].event.tree_after == sealed_tree, (
        "the substitute must still look tree-exact, or the tree check catches it "
        "and the hash binding is never exercised"
    )
    assert s.verify_chain_detail().status == "intact", (
        "a spliced log would report a broken chain and dominate the verdict; "
        "evidence binding must be the only thing detecting this"
    )

    report = M.verify(s, repo)
    assert [r.grade for r in report.results] == ["witness-unavailable"]
    assert "hash mismatch" in report.results[0].reason
    assert report.results[0].sealed_grade == "tree-exact"
    assert not report.all_verified            # → --strict exits non-zero
    assert report.evidence_bound_count == 0
    assert "hash mismatch" in render.render_verdict(report)
    assert cli.main(["--repo", str(repo), "verify", "--strict"]) == 1


# --- test 2: a ledger that is merely short ------------------------------------


def test_truncated_ledger_names_the_out_of_range_index(repo: Path, tmp_path: Path):
    s = _session(repo)
    _ok(repo, s, "first")
    _ok(repo, s, "second")
    M.declare_claim(
        s, Claim(ctype="tests-pass", label="late", event_indices=(1,), declared_at_index=1)
    )
    M.seal(s, repo)

    lines = s.log_path.read_bytes().splitlines(keepends=True)
    assert len(lines) == 2
    s.log_path.write_bytes(lines[0])          # drop the backing entry

    report = M.verify(s, repo)
    assert [r.grade for r in report.results] == ["witness-unavailable"]
    reason = report.results[0].reason
    assert "index 1" in reason and "out of range" in reason
    assert "1 event(s)" in reason
    assert not report.all_verified
    assert cli.main(["--repo", str(repo), "verify", "--strict"]) == 1


# --- test 3: the archived ledger ----------------------------------------------


# The exact sentence a genuinely unbacked claim gets. An archived ledger used to
# produce this byte-for-byte, which made "the evidence is elsewhere" and "there
# never was any evidence" indistinguishable in the report.
_UNBACKED_REASON = "no witnessed successful command backs this claim"


def test_archived_ledger_reports_the_sealed_grade_not_a_bare_unknown(
    repo: Path, tmp_path: Path
):
    s = _sealed_green(repo)
    shutil.move(str(repo / ".didrun"), str(tmp_path / "archived-ledger"))

    report = M.verify(_session(repo), repo)
    assert [r.grade for r in report.results] == ["witness-unavailable"]
    reason = report.results[0].reason
    assert "sealed as tree-exact" in reason
    assert _UNBACKED_REASON not in reason
    assert report.results[0].sealed_grade == "tree-exact"
    assert not report.all_verified
    assert report.evidence_bound_count == 0


# --- test 4: a genuinely unbacked claim is still `unknown` --------------------


def test_unbacked_claim_stays_unknown_with_the_original_reason(repo: Path):
    """The two states must remain distinguishable — that is the whole point.

    A claim bound to an index that never had an event has nothing to bind to, so
    the seal writes no evidence block and verify says what it has always said.
    """
    s = _session(repo)
    _ok(repo, s, "unrelated")
    M.declare_claim(
        s,
        Claim(ctype="tests-pass", label="phantom", event_indices=(7,), declared_at_index=0),
    )
    M.seal(s, repo)

    body = json.loads(_note_bytes(repo))
    assert "evidence" not in body["claims"][0], "nothing backed it; nothing to bind"

    report = M.verify(s, repo)
    assert [r.grade for r in report.results] == ["unknown"]
    assert report.results[0].reason == _UNBACKED_REASON
    assert report.evidence_bound_count == 0


# --- test 5: a legacy v1 note verifies exactly as it did before ---------------

# Generated by running this fixture against the code as it stood BEFORE P1.2
# (see the unit's report), then pasted in. Hard-coded on purpose: computing them
# from the code under test would make "identical to pre-change behaviour" a
# claim this test cannot actually make.
_LEGACY_EXPECTED = [
    ("fresh", "tree-exact", "self-stable command ran against the sealed tree", []),
    ("drifted", "stale", "tree moved since evidence: 1 path(s) differ", [("M", "calc.py")]),
    ("unbacked", "unknown", "no witnessed successful command backs this claim", []),
    ("caught", "failed", "the recorded command exited 1 — claim is not backed", []),
]


def _v1_claim_entry(ctype, label, indices, declared_at, grade, supporting, exit_code):
    """A claim entry in the shape a v1 note carried — no `evidence` key."""
    return {
        "claim": {
            "ctype": ctype,
            "label": label,
            "event_indices": list(indices),
            "pathspecs": [],
            "declared_at_index": declared_at,
            "argv_preview": [],
        },
        "grade": grade,
        "reason": "sealed",
        "delta": [],
        "supporting_event_index": supporting,
        "exit_code": exit_code,
    }


def _attach_raw_note(repo: Path, commit: str, body: bytes) -> None:
    subprocess.run(
        ["git", "notes", f"--ref={M.NOTES_REF}", "add", "-f", "-F", "-", commit],
        cwd=str(repo),
        input=body,
        capture_output=True,
        check=True,
    )


def _note_bytes(repo: Path, commit: str = "HEAD") -> bytes:
    proc = subprocess.run(
        ["git", "notes", f"--ref={M.NOTES_REF}", "show", commit],
        cwd=str(repo),
        capture_output=True,
        check=True,
    )
    return proc.stdout


def test_legacy_v1_note_verifies_byte_for_byte_as_before(repo: Path):
    """The corpus-protection test: 65 published notes are all version 1.

    Every one of them carries no evidence block, so every one of them must take
    the unbound path and produce the grades, reasons and deltas it produced
    before this unit existed — down to the string.
    """
    s = _session(repo)
    _ok(repo, s, "1")                                                    # event 0 @T0
    run_wrapped([sys.executable, "-c", "import sys; sys.exit(1)"], s, repo)  # event 1 @T0
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b  # edit\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "edit")
    _ok(repo, s, "2")                                                    # event 2 @T1

    commit = gp.head_commit(repo)
    body = canonical_json(
        {
            "version": 1,
            "commit": commit,
            "tree": gp.commit_tree(repo, commit),
            "claims": [
                _v1_claim_entry("tests-pass", "fresh", (2,), 2, "tree-exact", 2, 0),
                _v1_claim_entry("command-succeeded", "drifted", (0,), 0, "stale", 0, 0),
                _v1_claim_entry("lint-clean", "unbacked", (7,), 2, "unknown", None, None),
                _v1_claim_entry("tests-pass", "caught", (1,), 1, "failed", 1, 1),
            ],
            "coverage": {"total_events": 3, "by_coverage": {"complete": 3}},
            "secrets_override": False,
        }
    )
    _attach_raw_note(repo, commit, body)

    report = M.verify(s, repo)
    observed = [
        (r.claim.label, r.grade, r.reason, [(c.status, c.path) for c in r.delta])
        for r in report.results
    ]
    assert observed == _LEGACY_EXPECTED
    assert report.worst_status == "failed"
    assert not report.all_verified
    assert report.evidence_bound_count == 0
    assert report.total == 4
    assert all(r.sealed_grade is None for r in report.results)


# --- test 6: the happy path ---------------------------------------------------


def test_happy_path_is_evidence_bound_and_strict_clean(repo: Path):
    s = _session(repo)
    _ok(repo, s, "one")
    _ok(repo, s, "two")
    M.declare_claim(
        s, Claim(ctype="tests-pass", label="a", event_indices=(0,), declared_at_index=1)
    )
    M.declare_claim(
        s, Claim(ctype="lint-clean", label="b", event_indices=(1,), declared_at_index=1)
    )
    M.seal(s, repo)

    report = M.verify(s, repo)
    assert [r.grade for r in report.results] == ["tree-exact", "tree-exact"]
    assert all(r.evidence_bound for r in report.results)
    assert report.evidence_bound_count == 2 and report.total == 2
    assert report.all_verified
    assert cli.main(["--repo", str(repo), "verify", "--strict"]) == 0


def test_seal_records_the_entry_hash_of_the_backing_event(repo: Path):
    """The binding is the recorded entry's own chain hash, taken from the ledger."""
    s = _sealed_green(repo)
    entry = list(s.entries())[0]
    evidence = json.loads(_note_bytes(repo))["claims"][0]["evidence"]
    assert evidence["event_index"] == 0
    assert evidence["entry_hash"] == entry.entry_hash
    assert evidence["tree_after"] == entry.event.tree_after
    assert evidence["env_fingerprint"] == entry.event.env_fingerprint


def test_amend_tree_fallback_still_resolves_and_stays_bound(repo: Path):
    """The durable anchor keeps working: same tree, new commit id, still bound."""
    s = _sealed_green(repo)
    original = gp.head_commit(repo)
    _git(repo, "commit", "--amend", "-qm", "amended message")
    assert gp.head_commit(repo) != original

    report = M.verify(s, repo)
    assert report.resolved_by == "tree-fallback"
    assert report.all_verified
    assert report.evidence_bound_count == 1


# --- test 7: the state is registered on the human surfaces -------------------


def test_witness_unavailable_is_registered_in_both_render_tables():
    """Both tables are read through `.get(…, UNKNOWN)`, so an unregistered grade
    renders as UNKNOWN — a silent lie rather than a loud error."""
    assert "witness-unavailable" in render._GRADE_DISPLAY
    assert "witness-unavailable" in render._SORT_RANK
    assert render._GRADE_DISPLAY["witness-unavailable"][0] == "WITNESS-UNAVAIL"
    # Worse than stale, better than unknown — the order the verdict sorts by.
    assert (
        render._SORT_RANK["unknown"]
        < render._SORT_RANK["witness-unavailable"]
        < render._SORT_RANK["stale"]
    )


def test_verdict_never_calls_a_witness_unavailable_report_recorded_exact(
    repo: Path, tmp_path: Path, monkeypatch
):
    monkeypatch.setenv("NO_COLOR", "1")
    s = _sealed_green(repo)
    _substitute_log(repo, s, tmp_path, ["something else entirely"])

    out = render.render_verdict(M.verify(s, repo))
    assert "WITNESS-UNAVAIL" in out
    assert "ALL RECORDED-EXACT" not in out
    assert "0/1 claims evidence-bound" in out
    for overclaim in ("VERIFIED", "PASSED", " OK"):
        assert overclaim not in out


def test_html_report_shows_the_state_and_never_reads_as_passed(
    repo: Path, tmp_path: Path
):
    s = _sealed_green(repo)
    _substitute_log(repo, s, tmp_path, ["something else entirely"])

    html_out = render.render_html(M.verify(s, repo))
    assert "WITNESS-UNAVAIL" in html_out
    assert "badge witness_unavailable" in html_out   # styled, not bare ink
    assert "ALL RECORDED-EXACT" not in html_out
    assert "0/1 claims evidence-bound" in html_out
    assert "VERIFIED" not in html_out and "PROVEN" not in html_out.upper()


def test_strict_never_accepts_witness_unavailable():
    """`all_verified`'s membership set is the one thing --strict rests on.

    Widening it to admit this state would make --strict pass on a claim whose
    evidence nobody has seen, which is the exact lie the state exists to stop.
    """
    report = M.VerifyReport(
        commit="c" * 40,
        tree="t" * 40,
        resolved_by="commit",
        results=[
            GradeResult(
                Claim(ctype="tests-pass", label="x", event_indices=(0,)),
                "witness-unavailable",
                reason="sealed as tree-exact at commit cccccccccccc; "
                "witness ledger unavailable (entry hash mismatch at index 0)",
                sealed_grade="tree-exact",
            )
        ],
        coverage={},
    )
    assert not report.all_verified
    assert report.worst_status == "witness-unavailable"
