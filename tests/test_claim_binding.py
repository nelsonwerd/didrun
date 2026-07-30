"""P5.2 — `didrun claim` must not receipt an older passing run.

The defect, reachable through the documented happy path and nothing more
exotic: `cmd_claim` with no `--event` bound to the last event whose
``exit_code == 0`` rather than to the last event. So

    didrun run -- pytest -q      # passes, event 0
    <edit>
    didrun run -- pytest -q      # FAILS, event 1
    didrun claim tests-pass      # bound event 0

produced a claim backed by the older passing run. ``declared_at_index`` stayed
at ``len(events) - 1``, so the retroactive-binding rule (which fires only when
the claim was declared BEFORE its backing event) did not catch it, and if the
tree had not moved between the two runs the claim graded ``tree-exact``. The
only signal was the index printed in a success line.

The fix is a refusal, not a better heuristic: bind to the last event, and if the
last event did not exit 0, refuse and say so. Binding an earlier event stays
available through an explicit ``--event N``, which now warns about the gap.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from didrun import cli
from didrun import manifest as _manifest
from didrun.capture import run_wrapped
from didrun.ledger import Event, Session

PASS = [sys.executable, "-c", "print('ok')"]
FAIL = [sys.executable, "-c", "import sys; sys.exit(3)"]


def _session(repo: Path) -> Session:
    return Session(repo / ".didrun")


def _claims(repo: Path) -> list:
    return _manifest._load_claims(_session(repo))


def _claim(repo: Path, *args: str) -> int:
    return cli.main(["--repo", str(repo), "claim", *args])


# --- 1. the headline case -----------------------------------------------------


def test_a_failing_last_event_refuses_instead_of_receipting_the_older_pass(
    repo: Path, capsys
):
    """Pass, then fail, then claim with no --event.

    On pre-change code this SILENTLY receipted the older passing event 0 and
    exited 0. The test therefore asserts three separate things, because "exit 2"
    alone would still pass on a version that wrote the claim and then failed for
    an unrelated reason: the exit code, that the message names the failing index
    and its real exit code, and that claims.jsonl gained nothing at all.
    """
    s = _session(repo)
    run_wrapped(PASS, s, repo)
    run_wrapped(FAIL, s, repo)
    assert [ev.exit_code for ev in s.events()] == [0, 3]
    capsys.readouterr()

    assert _claim(repo, "tests-pass", "--label", "unit") == 2
    err = capsys.readouterr().err
    assert "index 1" in err, err
    assert "exited 3" in err, err
    assert _claims(repo) == [], "a refused claim must write nothing"
    assert not (repo / ".didrun" / "claims.jsonl").exists() or (
        repo / ".didrun" / "claims.jsonl"
    ).read_bytes() == b""


def test_the_refusal_names_the_deliberate_escape(repo: Path, capsys):
    """A refusal that does not say what to do instead gets worked around.

    The escape is `--event N`, and it must be named in the refusal itself: an
    operator who really does mean the earlier run has a supported way to say so.
    """
    s = _session(repo)
    run_wrapped(PASS, s, repo)
    run_wrapped(FAIL, s, repo)
    capsys.readouterr()
    assert _claim(repo, "tests-pass") == 2
    assert "--event" in capsys.readouterr().err


def test_a_last_event_that_witnessed_no_exit_refuses_too(repo: Path, capsys):
    """``exit_code is None`` is not a pass either.

    An interrupted flight and a PTY transcript both record an event that
    witnesses no exit code, and the old backwards search skipped straight over
    them to an earlier success. "Not 0" includes "unknown", and the message says
    which of the two it is rather than printing "exited None".
    """
    s = _session(repo)
    run_wrapped(PASS, s, repo)
    s.append(
        Event(
            argv=("some-command",),
            cwd=str(repo),
            env_fingerprint="0" * 16,
            observed_via="transcript",
            coverage="display-only",
        )
    )
    assert s.events()[-1].exit_code is None
    capsys.readouterr()

    assert _claim(repo, "tests-pass") == 2
    err = capsys.readouterr().err
    assert "index 1" in err, err
    assert "no exit code" in err, err
    assert "None" not in err, err
    assert _claims(repo) == []


# --- 2. the happy path is still the happy path -------------------------------


def test_a_passing_last_event_binds_to_it(repo: Path, capsys):
    s = _session(repo)
    run_wrapped(FAIL, s, repo)
    run_wrapped(PASS, s, repo)
    capsys.readouterr()

    assert _claim(repo, "tests-pass", "--label", "unit") == 0
    (claim,) = _claims(repo)
    assert claim.event_indices == (1,), "binds the LAST event, not the first pass"
    assert capsys.readouterr().err == "", "the happy path warns about nothing"


def test_the_single_event_case_binds_event_zero(repo: Path):
    """The documented one-run flow, unchanged: run something, claim it."""
    s = _session(repo)
    run_wrapped(PASS, s, repo)
    assert _claim(repo, "tests-pass") == 0
    (claim,) = _claims(repo)
    assert claim.event_indices == (0,)


# --- 3. an explicit older binding warns but succeeds -------------------------


def test_explicit_event_zero_of_four_warns_and_still_writes_the_claim(
    repo: Path, capsys
):
    """`--event` is a deliberate act, so it succeeds — but not silently.

    197 of 846 claims in the corpus this tool was built against bound a
    non-terminal event. Whether any of those gaps spanned a FAILURE is unknown
    (it needs a read of archived logs). The warning is what makes the next one
    visible at the moment it is created.
    """
    s = _session(repo)
    for _ in range(4):
        run_wrapped(PASS, s, repo)
    assert len(s.events()) == 4
    capsys.readouterr()

    assert _claim(repo, "tests-pass", "--event", "0") == 0
    err = capsys.readouterr().err
    assert "event 0" in err, err
    assert "3 event(s) before the most recent" in err, err
    (claim,) = _claims(repo)
    assert claim.event_indices == (0,), "the claim is written, not refused"


def test_explicit_binding_to_the_most_recent_event_does_not_warn(repo: Path, capsys):
    """There is no gap, so there is nothing to say. A warning on every explicit
    `--event` would be noise, and noise is how a real warning gets filtered."""
    s = _session(repo)
    for _ in range(3):
        run_wrapped(PASS, s, repo)
    capsys.readouterr()
    assert _claim(repo, "tests-pass", "--event", "2") == 0
    assert capsys.readouterr().err == ""


def test_an_explicit_binding_to_a_failing_event_is_not_refused_here(
    repo: Path, capsys
):
    """The refusal is about the DEFAULT, not about `--event`.

    Binding a claim to an event that failed is allowed and is not a lie: the
    grading ladder witnesses the failure and grades it `failed`, which is the
    honest record. Refusing at declare time would hide a failure instead of
    recording one.
    """
    s = _session(repo)
    run_wrapped(FAIL, s, repo)
    run_wrapped(PASS, s, repo)
    capsys.readouterr()
    assert _claim(repo, "tests-pass", "--event", "0") == 0
    (claim,) = _claims(repo)
    assert claim.event_indices == (0,)


# --- 4. no events at all -----------------------------------------------------


def test_no_events_at_all_keeps_the_existing_refusal_verbatim(repo: Path, capsys):
    """Asserted verbatim: docs/COMPAT.md quotes this sentence."""
    capsys.readouterr()
    assert _claim(repo, "tests-pass") == 2
    assert capsys.readouterr().err == (
        "didrun claim: no recorded events to bind to (run something first)\n"
    )


# --- 5. declared_at_index is untouched in every path -------------------------


@pytest.mark.parametrize(
    "extra,events,expected_indices",
    [
        ([], 3, (2,)),
        (["--event", "0"], 3, (0,)),
        (["--event", "1"], 2, (1,)),
    ],
    ids=["default", "explicit-older", "explicit-latest"],
)
def test_declared_at_index_is_always_the_last_index(
    repo: Path, extra, events, expected_indices
):
    """The retroactive-binding rule reads this field, and P5.2 changes which
    event is BOUND, never where the declaration sits. If this drifted, a claim
    bound to the last event would start grading `unknown`.
    """
    s = _session(repo)
    for _ in range(events):
        run_wrapped(PASS, s, repo)
    assert _claim(repo, "tests-pass", *extra) == 0
    (claim,) = _claims(repo)
    assert claim.event_indices == expected_indices
    assert claim.declared_at_index == events - 1


# --- 6. end to end through the real binary -----------------------------------

_CLI_BOOT = "import sys; from didrun.cli import main; sys.exit(main(sys.argv[1:]))"


def test_the_refusal_holds_in_a_subprocess_too(repo: Path):
    """In-process `cli.main` shares this interpreter's state; a separate process
    is the shape an agent actually invokes, and the exit code is what a shell
    gate reads."""
    for argv in ([*PASS], [*FAIL]):
        subprocess.run(
            [sys.executable, "-c", _CLI_BOOT, "--repo", str(repo), "run", "--", *argv],
            cwd=str(repo),
            capture_output=True,
        )
    proc = subprocess.run(
        [sys.executable, "-c", _CLI_BOOT, "--repo", str(repo), "claim", "tests-pass"],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 2, proc.stderr
    assert "exited 3" in proc.stderr
    assert _claims(repo) == []
