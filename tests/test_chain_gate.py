"""P1.3 — `verify` consults the ledger hash chain and fails closed.

The defect these pin: `verify_chain` had exactly one caller in the whole
package and it was `show --session`. `didrun verify --strict` — the command an
entire discipline gates on — never recomputed the chain, so a forked ledger
(duplicate indices) or a mid-file rewrite certified green and exited 0.

What a chain check buys, stated as narrowly as it deserves: accident and drift
detection on the ledger the verdict was read out of. It is not a forger
barrier — whoever can rewrite a record can recompute every hash after it
(ledger.py's declared non-guarantee). A `broken` chain says an entry did not
recompute; it does not say who moved it.

Two states that are deliberately NOT faults: `absent` (the ledger is elsewhere,
which P1.2 already reports per claim as witness-unavailable) and `empty`.
Treating either as tamper would make every verify against an archived ledger
read like an attack, which is the failure mode this file's tests 4 and 5 exist
to stop.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from didrun import cli
from didrun import manifest as M
from didrun import render
from didrun.capture import run_wrapped
from didrun.claims import Claim
from didrun.ledger import ChainVerdict, Session, canonical_json


def _session(repo: Path) -> Session:
    return Session(repo / ".didrun")


def _sealed(repo: Path, events: int = 3) -> Session:
    """`events` recorded successes, one claim over event 0, sealed clean.

    The claim binds event 0 on purpose: every corruption below lands on a LATER
    record, so the claim's own evidence stays intact and gradeable. A test whose
    claim went witness-unavailable would fail for the wrong reason and stop
    testing the chain gate.
    """
    s = _session(repo)
    for i in range(events):
        run_wrapped([sys.executable, "-c", f"print({i!r})"], s, repo)
    M.declare_claim(
        s, Claim(ctype="tests-pass", label="suite", event_indices=(0,), declared_at_index=0)
    )
    M.seal(s, repo)
    return s


def _records(s: Session) -> list[dict]:
    return [
        json.loads(line)
        for line in s.log_path.read_text(encoding="ascii").splitlines()
        if line.strip()
    ]


def _rewrite(s: Session, mutate) -> None:
    """Round-trip the log through canonical JSON, mutating it via ``mutate``.

    The assertion is the load-bearing part: it proves the round-trip is
    byte-stable on the records nobody touched, so a corruption test can never
    pass merely because re-serializing the log moved a byte somewhere else.
    """
    original = s.log_path.read_bytes()
    recs = _records(s)
    assert b"".join(canonical_json(r) + b"\n" for r in recs) == original, (
        "the canonical round-trip is not byte-stable; every corruption test in "
        "this file would then be testing the round-trip, not the corruption"
    )
    mutate(recs)
    s.log_path.write_bytes(b"".join(canonical_json(r) + b"\n" for r in recs))


def _flip(h: str) -> str:
    return ("0" if h[0] != "0" else "1") + h[1:]


def _corrupt_middle_hash(s: Session) -> None:
    """Flip a byte of the STORED hash of a middle record.

    Chosen over corrupting the event body so the events themselves are
    untouched: every claim still grades exactly as it did, and the only thing
    that changed in the whole report is the chain. That is what makes the
    falsification test below a clean control.
    """
    _rewrite(s, lambda recs: recs[1].__setitem__("entry_hash", _flip(recs[1]["entry_hash"])))


# --- test 1: a broken chain fails --strict -----------------------------------


def test_broken_chain_dominates_the_verdict_and_fails_strict(repo: Path, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    s = _sealed(repo)
    _corrupt_middle_hash(s)

    report = M.verify(_session(repo), repo)
    assert report.chain_status == "broken"
    assert report.chain_broken_index == 1
    assert report.worst_status == "chain-broken"
    assert not report.all_verified

    out = render.render_verdict(report)
    assert "ledger chain BROKEN at index 1" in out
    assert "every grade below is unreliable" in out
    assert "ALL RECORDED-EXACT" not in out

    assert cli.main(["--repo", str(repo), "verify", "--strict"]) == 1


def test_the_chain_check_is_the_only_thing_failing_that_report(repo: Path, monkeypatch):
    """The falsification half of test 1, on the SAME corrupted fixture.

    Neutralize only the chain check and the identical corrupted ledger goes
    green — which is the proof that the chain gate, and nothing else in the
    report, is what test 1 detected. If this test ever fails, test 1 has started
    passing for some other reason and is no longer evidence of anything.
    """
    s = _sealed(repo)
    _corrupt_middle_hash(s)

    monkeypatch.setattr(
        Session, "verify_chain_detail", lambda self: ChainVerdict("intact")
    )
    report = M.verify(_session(repo), repo)
    assert report.chain_status == "intact"
    assert report.all_verified, (
        "with the chain check neutralized this corrupted ledger must grade "
        "green; if it does not, test 1's red came from somewhere else"
    )
    assert report.worst_status == "tree-exact"
    assert "ledger chain" not in render.render_verdict(report)


# --- test 2: a fork (duplicate index) ----------------------------------------


def test_duplicate_index_reads_as_a_broken_chain(repo: Path, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    s = _sealed(repo)
    # Re-append the last record verbatim: same index, same prev_hash, same
    # stored hash. Every hash in the file still recomputes -- only the SEQUENCE
    # is wrong, which is the shape a forked ledger actually has.
    _rewrite(s, lambda recs: recs.append(dict(recs[-1])))

    report = M.verify(_session(repo), repo)
    assert report.chain_status == "broken"
    assert report.chain_broken_index == 2
    assert not report.all_verified
    assert "ledger chain BROKEN at index 2" in render.render_verdict(report)
    assert cli.main(["--repo", str(repo), "verify", "--strict"]) == 1


# --- test 3: unverifiable is not "intact", and is not "broken" either --------


def test_unknown_preimage_version_is_unverifiable_not_broken(repo: Path, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    s = _sealed(repo)
    _rewrite(s, lambda recs: recs[1].__setitem__("preimage_version", 2))

    report = M.verify(_session(repo), repo)
    assert report.chain_status == "unverifiable"
    assert report.chain_broken_index is None  # nothing was shown not to recompute
    assert report.worst_status == "chain-broken"
    assert not report.all_verified

    # The verdict TOKEN is CHAIN-BROKEN for both fault states — one registered
    # verdict, per the pack. The distinction lives in the banner, which is the
    # line that says what actually happened, and it must not say BROKEN: a
    # record this binary cannot recompute is not evidence of mutation, and
    # saying so would accuse a future writer of tampering.
    banner = render.chain_banner_text(report)
    assert "unverifiable" in banner
    assert "BROKEN" not in banner
    assert "unknown chain preimage version: 2" in banner  # the reason, named

    out = render.render_verdict(report)
    assert banner in out
    assert "ALL RECORDED-EXACT" not in out
    assert cli.main(["--repo", str(repo), "verify", "--strict"]) == 1


# --- test 4: an absent ledger is not tamper ----------------------------------


def test_absent_ledger_is_witness_unavailable_not_a_broken_chain(
    repo: Path, tmp_path: Path, monkeypatch
):
    monkeypatch.setenv("NO_COLOR", "1")
    _sealed(repo)
    shutil.move(str(repo / ".didrun"), str(tmp_path / "archived-ledger"))

    report = M.verify(_session(repo), repo)
    assert report.chain_status == "absent"
    assert report.worst_status == "witness-unavailable"  # the claims, not the chain
    assert [r.grade for r in report.results] == ["witness-unavailable"]
    assert not report.all_verified

    out = render.render_verdict(report)
    assert "ledger chain" not in out, "a ledger that is elsewhere has not been tampered with"
    assert "BROKEN" not in out
    assert "witness ledger unavailable" in out

    # --strict still refuses, for the honest reason: nobody has seen the evidence.
    assert cli.main(["--repo", str(repo), "verify", "--strict"]) == 1


def test_empty_log_is_not_a_chain_fault(repo: Path, monkeypatch):
    """`empty` is a present-but-zero-length log, and it is not tamper either.

    Distinct from `absent` (no file at all) so the two stay tellable apart, and
    excluded from the fault set for the same reason: nothing failed to
    recompute. The claims still refuse --strict on their own.
    """
    monkeypatch.setenv("NO_COLOR", "1")
    s = _sealed(repo)
    s.log_path.write_bytes(b"")

    report = M.verify(_session(repo), repo)
    assert report.chain_status == "empty"
    assert report.worst_status == "witness-unavailable"
    assert not report.all_verified
    assert "ledger chain" not in render.render_verdict(report)


def test_unreadable_log_refuses_instead_of_crashing_a_commit_with_no_note(repo: Path):
    """An unreadable ledger must not start crashing verify on an unsealed commit.

    The chain check runs before the manifest is resolved, so it reads a ledger
    on a path that previously never touched one. Nothing is sealed here: before
    P1.3 this returned a clean "no claims" report, and it still must — as a
    refusal that names the problem, not a traceback.

    The damage used here is corruption in the MIDDLE of the log. P2.3 gave the
    reader a narrow tolerance for a torn FINAL record — a lost event, not
    tamper, pinned by the test below — and that tolerance stops at the last
    line on purpose: a hole with records after it is still unreadable, and
    still a graded refusal rather than a crash.
    """
    s = _session(repo)
    for i in range(3):
        run_wrapped([sys.executable, "-c", f"print({i!r})"], s, repo)
    lines = s.log_path.read_bytes().splitlines(keepends=True)
    assert len(lines) == 3
    s.log_path.write_bytes(lines[0] + lines[1][:40] + b"\n" + lines[2])

    report = M.verify(_session(repo), repo)
    assert report.chain_status == "unverifiable"
    assert report.results == []
    assert "could not be read" in report.chain_reason
    assert "ledger chain unverifiable" in render.render_verdict(report)


def test_a_torn_final_record_is_a_lost_event_not_a_chain_fault(repo: Path):
    """P2.3: the tail an interrupted append leaves must not read as tamper.

    Before P2.3 this was `unverifiable` — the log could not be read at all, so
    the ledger's last word on an interrupted session was "this binary cannot
    recompute me". It is now the honest thing: every link that survives does
    recompute, the chain is `intact` over that prefix, and the truncation
    travels in the reason. The fault this file exists to make dominant must NOT
    fire here, because nothing failed to recompute.
    """
    s = _session(repo)
    for i in range(2):
        run_wrapped([sys.executable, "-c", f"print({i!r})"], s, repo)
    lines = s.log_path.read_bytes().splitlines(keepends=True)
    assert len(lines) == 2
    # A partial final record: the shape a crash mid-append leaves behind. Cut at
    # a byte offset, not a line boundary, or the log is merely SHORT and parses.
    s.log_path.write_bytes(lines[0] + lines[1][:40])

    report = M.verify(_session(repo), repo)
    assert report.chain_status == "intact"
    assert report.results == []
    assert "torn at byte" in report.chain_reason
    # Surfaced, but never as a chain fault: no banner, no tamper sentence.
    assert "ledger chain" not in render.render_verdict(report)


# --- test 5: the happy path is untouched -------------------------------------


def test_intact_chain_adds_nothing_to_the_verdict(repo: Path, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    _sealed(repo)

    report = M.verify(_session(repo), repo)
    assert report.chain_status == "intact"
    assert report.chain_broken_index is None
    assert report.worst_status == "tree-exact"
    assert report.all_verified

    out = render.render_verdict(report)
    assert "ALL RECORDED-EXACT" in out
    assert "chain" not in out.lower(), "an intact chain is not news; it prints nothing"
    # The class is always in the stylesheet; the block must not be in the body.
    assert '<div class="chainbanner">' not in render.render_html(report)
    assert cli.main(["--repo", str(repo), "verify", "--strict"]) == 0


def test_show_session_is_unchanged(repo: Path, capsys):
    """`show --session` was the sole caller of verify_chain and keeps its shape."""
    s = _sealed(repo)
    assert cli.main(["--repo", str(repo), "show", "--session"]) == 0
    assert "chain intact" in capsys.readouterr().out

    _corrupt_middle_hash(s)
    assert cli.main(["--repo", str(repo), "show", "--session"]) == 1
    assert "BROKEN at index 1" in capsys.readouterr().out


# --- test 6: the render surfaces cannot silently drop it ---------------------


def test_chain_broken_is_registered_in_both_render_tables():
    """An unregistered verdict renders as UNKNOWN through `.get(…, UNKNOWN)`.

    That is the silent lie render.py's own comment warns about, and it would
    turn the strongest statement didrun can make about a ledger into its
    weakest.
    """
    assert "chain-broken" in render._GRADE_DISPLAY
    assert "chain-broken" in render._SORT_RANK
    assert render._SORT_RANK["chain-broken"] < render._SORT_RANK["failed"]
    assert render._GRADE_DISPLAY["chain-broken"][0] == "CHAIN-BROKEN"


def test_neither_surface_reads_as_passed_when_the_chain_is_broken(
    repo: Path, monkeypatch
):
    monkeypatch.setenv("NO_COLOR", "1")
    s = _sealed(repo)
    _corrupt_middle_hash(s)
    report = M.verify(_session(repo), repo)

    out = render.render_verdict(report)
    assert "CHAIN-BROKEN" in out
    assert "ALL RECORDED-EXACT" not in out
    assert "UNKNOWN" not in out, "the verdict must not fall back to UNKNOWN"
    for overclaim in ("VERIFIED", "PASSED", "PROVEN"):
        assert overclaim not in out.upper()

    html_out = render.render_html(report)
    assert "CHAIN-BROKEN" in html_out
    assert '<div class="chainbanner">' in html_out
    assert "ledger chain BROKEN at index 1" in html_out
    assert "ALL RECORDED-EXACT" not in html_out


def test_quiet_html_still_prints_the_chain_banner(repo: Path, tmp_path: Path, capsys, monkeypatch):
    """--quiet suppresses the verdict, never the ledger's integrity."""
    monkeypatch.setenv("NO_COLOR", "1")
    s = _sealed(repo)
    _corrupt_middle_hash(s)
    out_html = tmp_path / "report.html"

    rc = cli.main(
        ["--repo", str(repo), "verify", "--strict", "--html", str(out_html), "--quiet"]
    )
    printed = capsys.readouterr().out
    assert rc == 1
    assert "ledger chain BROKEN at index 1" in printed
    assert "STATUS" not in printed, "--quiet still suppresses the per-claim table"


def test_no_claims_report_still_reports_a_broken_chain(repo: Path, monkeypatch):
    """A commit with nothing sealed still gets the sentence.

    The ledger is what every other command reads; "nothing sealed here" is not a
    reason to stay quiet about it not recomputing.
    """
    monkeypatch.setenv("NO_COLOR", "1")
    s = _session(repo)
    for i in range(3):
        run_wrapped([sys.executable, "-c", f"print({i!r})"], s, repo)
    _corrupt_middle_hash(s)

    report = M.verify(_session(repo), repo)
    assert report.results == []
    assert report.chain_status == "broken"
    assert report.worst_status == "chain-broken"
    out = render.render_verdict(report)
    assert "NO CLAIMS" in out
    assert "ledger chain BROKEN at index 1" in out
