"""P2.3 — the recorder records the flight when the flight is interrupted.

Two halves, and they meet at the same sentence: a lost event must cost one
event, never the ledger.

  - capture/CLI: SIGINT or SIGTERM during a wrapped command appends an event
    that says what was NOT witnessed (no exit code, coverage "unobserved")
    instead of guessing, keeps the output drained so far, and exits on the
    conventional code with no traceback.
  - ledger: an append is fsynced, a torn FINAL record is readable as a lost
    event rather than as tamper, and `append` refuses to write past the tear
    rather than burying it mid-log where it would break the chain forever.

The signal legs drive the real CLI in a real process. Calling a handler
directly would test the handler, not the delivery; the delivery is the part
v0.1 got wrong.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from didrun import gitplumbing
from didrun.capture import CaptureInterrupted, run_wrapped
from didrun.claims import Claim, grade
from didrun.ledger import Event, LedgerError, Session, canonical_json

# POSIX signal semantics. Windows has no SIGKILL and no process-group Ctrl-C
# with these mechanics; docs/COMPAT.md already scopes Tier-0 capture there.
pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="POSIX signal delivery semantics"
)


def _session(repo: Path, readonly: bool = False) -> Session:
    return Session(repo / ".didrun", readonly=readonly)


def _wrapper_event(argv=("echo", "hi"), exit_code=0, **kw) -> Event:
    return Event(
        argv=tuple(argv),
        cwd="/tmp",
        env_fingerprint="abc123",
        observed_via="wrapper",
        coverage="complete",
        exit_code=exit_code,
        **kw,
    )


_CLI_BOOT = "import sys; from didrun.cli import main; sys.exit(main(sys.argv[1:]))"

# Prints a marker, flushes, publishes its pid, then blocks. The pid file is
# written LAST and via a rename, so its existence proves both that the child is
# running and that the marker has already been handed to the pipe: the test
# never sends a signal into a race with the child's startup.
_STARTED_THEN_SLEEP = (
    "import os, sys, time\n"
    "sys.stdout.write('MARKER-STARTED\\n')\n"
    "sys.stdout.flush()\n"
    "tmp = sys.argv[1] + '.tmp'\n"
    "open(tmp, 'w').write(str(os.getpid()))\n"
    "os.replace(tmp, sys.argv[1])\n"
    "time.sleep(120)\n"
)


def _wait_for(predicate, timeout: float, interval: float = 0.02) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def _start_wrapped_sleeper(repo: Path, tmp_path: Path):
    """Spawn `didrun run -- <a child that blocks>` and wait until it is running.

    Returns ``(proc, pid_file, child_argv)``. The child script lives outside the
    repo so it cannot move a tree digest, and its source carries the marker text
    so no assertion about the marker can pass off didrun's own summary line.
    """
    script = tmp_path / "started_then_sleep.py"
    script.write_text(_STARTED_THEN_SLEEP, encoding="utf-8")
    pid_file = tmp_path / "child.pid"
    child_argv = [sys.executable, str(script), str(pid_file)]
    proc = subprocess.Popen(
        [sys.executable, "-c", _CLI_BOOT, "--repo", str(repo), "run", "--", *child_argv],
        cwd=str(repo),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if not _wait_for(pid_file.exists, 60):
        proc.kill()
        proc.communicate(timeout=30)
        pytest.fail("the wrapped child never started")
    return proc, pid_file, child_argv


def _interrupt(repo: Path, tmp_path: Path, signum: int):
    """Run a blocking child under didrun, signal DIDRUN, collect the outcome."""
    proc, _pid_file, child_argv = _start_wrapped_sleeper(repo, tmp_path)
    proc.send_signal(signum)
    out, err = proc.communicate(timeout=120)
    return proc.returncode, out, err, child_argv


# --- 1 + 4: the event is recorded, and the exit code is conventional ----------


@pytest.mark.parametrize(
    "signame,expected_code",
    [("SIGINT", 130), ("SIGTERM", 143)],
)
def test_an_interrupt_records_an_unobserved_event_and_exits_cleanly(
    repo: Path, tmp_path: Path, signame: str, expected_code: int
):
    signum = getattr(signal, signame)
    code, out, err, child_argv = _interrupt(repo, tmp_path, signum)

    assert code == expected_code, err.decode("utf-8", "replace")
    # v0.1's whole report was a traceback. The line that replaces it has to be
    # both present and machine-greppable.
    assert b"Traceback" not in err
    assert b"KeyboardInterrupt" not in err
    assert f"interrupted by {signame}".encode("ascii") in err

    entries = list(_session(repo, readonly=True).entries())
    assert len(entries) == 1, "the flight recorder lost the flight"
    ev = entries[0].event
    assert ev.observed_via == "wrapper"
    assert ev.coverage == "unobserved"
    assert ev.exit_code is None, "nobody witnessed an exit; recording one is a lie"
    assert ev.argv == tuple(child_argv), "the in-flight argv is what was recorded"
    # The recorded index is what the operator was told to look at.
    assert f"recorded event {entries[0].index}".encode("ascii") in err

    ok, broken = _session(repo, readonly=True).verify_chain()
    assert (ok, broken) == (True, None)


# --- 2: partial output survives (this is what P2.2 unlocked) ------------------


def test_partial_output_survives_the_interrupt(repo: Path, tmp_path: Path):
    """subprocess.run structurally could not do this.

    Its bare `except:` kills the child and re-raises with the buffers still
    bound inside communicate(), where nothing can reach them. The pump drains
    into a caller-owned accumulator, so the bytes the child had already written
    are still there after the signal.
    """
    _code, _out, _err, _argv = _interrupt(repo, tmp_path, signal.SIGINT)

    s = _session(repo, readonly=True)
    ev = list(s.entries())[0].event
    assert ev.stdout_blob is not None
    assert b"MARKER-STARTED" in s.blobs.get(ev.stdout_blob)


# --- 3: it grades `unknown`, with no ladder change ---------------------------


def test_a_claim_bound_to_an_interrupted_event_grades_unknown(
    repo: Path, tmp_path: Path
):
    """The design criterion for the schema-free shape.

    `_supporting_event` skips the event (exit_code != 0) and `_witnessed_failure`
    skips it (exit_code is None), so the correct grade falls out of the existing
    ladder. The other half of this test — that claims.py was not edited — is a
    `git diff --name-only` check in the unit's verification, because a comment
    is not a check.
    """
    _code, _out, _err, _argv = _interrupt(repo, tmp_path, signal.SIGINT)

    s = _session(repo, readonly=True)
    events = [e.event for e in s.entries()]
    claim = Claim(
        ctype="command-succeeded",
        label="the interrupted command",
        event_indices=(0,),
        declared_at_index=0,
    )
    result = grade(
        claim,
        gitplumbing.commit_tree(repo, "HEAD"),
        events,
        repo,
        s.blobs.root,
    )
    assert result.grade == "unknown"
    assert result.exit_code is None
    # Never `failed`: an interrupted command was not caught lying.
    assert "no witnessed successful command" in result.reason


# --- 5: the child dies, the parent lives — the normal path is untouched ------


def test_killing_the_child_still_takes_the_normal_path(repo: Path, tmp_path: Path):
    """A SIGKILLed child is a witnessed (negative) exit, not an interrupt.

    The interrupt path must not widen to swallow it: `-9` is evidence about the
    command, and downgrading it to `unobserved` would lose a real observation.
    """
    proc, pid_file, _argv = _start_wrapped_sleeper(repo, tmp_path)
    os.kill(int(pid_file.read_text()), signal.SIGKILL)
    _out, err = proc.communicate(timeout=120)

    assert b"interrupted by" not in err
    ev = list(_session(repo, readonly=True).entries())[0].event
    assert ev.coverage == "complete"
    assert ev.exit_code == -signal.SIGKILL


# --- 6: a torn tail costs one event, not the ledger --------------------------


def _torn_log(tmp_path: Path, records: int = 3, keep: int = 2) -> tuple:
    """A log of ``records`` events truncated mid-way through record ``keep``.

    Returns ``(session, prefix_len, surviving_hashes)``.
    """
    s = Session(tmp_path / ".didrun")
    for i in range(records):
        s.append(_wrapper_event(argv=("cmd", str(i))))
    lines = s.log_path.read_bytes().splitlines(keepends=True)
    prefix = b"".join(lines[:keep])
    hashes = [json.loads(line)["entry_hash"] for line in lines[:keep]]
    # Cut at a byte offset inside the record, not at a line boundary, or the
    # log is merely SHORT and parses cleanly.
    s.log_path.write_bytes(prefix + lines[keep][:37])
    return Session(tmp_path / ".didrun"), len(prefix), hashes


def test_a_torn_final_record_is_readable_and_is_not_tamper(tmp_path: Path):
    s, prefix_len, hashes = _torn_log(tmp_path)

    entries = list(s.entries())
    assert [e.index for e in entries] == [0, 1]
    assert [e.entry_hash for e in entries] == hashes
    assert s.tail_truncated is True
    assert s.tail_truncated_offset == prefix_len

    verdict = s.verify_chain_detail()
    assert verdict.status == "intact"
    assert verdict.first_broken_index is None
    assert "torn at byte" in verdict.reason
    assert str(prefix_len) in verdict.reason
    assert s.verify_chain() == (True, None)


def test_a_malformed_middle_record_is_still_a_hard_error(tmp_path: Path):
    """The tolerance is for the LAST line only.

    A hole with records after it is corruption, not an interrupted write, and
    quietly skipping it would let a reader present a log with a missing middle
    as a whole one.
    """
    s = Session(tmp_path / ".didrun")
    for i in range(3):
        s.append(_wrapper_event(argv=("cmd", str(i))))
    lines = s.log_path.read_bytes().splitlines(keepends=True)
    s.log_path.write_bytes(lines[0] + b"{not json at all}\n" + lines[2])

    reader = Session(tmp_path / ".didrun")
    with pytest.raises(LedgerError) as exc:
        list(reader.entries())
    assert "corruption inside the log" in str(exc.value)
    assert reader.tail_truncated is False


# --- 6b: the recorder survives the tear, and never writes past it ------------


def test_a_torn_tail_does_not_kill_the_recorder_and_is_never_written_past(
    tmp_path: Path,
):
    """Change 7 without change 8 fixes the reader and leaves the writer dead.

    `_last()` must read past the tear (or every subsequent append raises, and
    one lost event still kills the ledger); `append()` must refuse to WRITE
    past it (or the partial bytes end up mid-log, unparseable forever, and one
    lost event becomes a permanently broken chain).
    """
    s, prefix_len, hashes = _torn_log(tmp_path)
    before = s.log_path.read_bytes()

    assert s._last() == (1, hashes[1])

    with pytest.raises(LedgerError) as exc:
        s.append(_wrapper_event(argv=("cmd", "after")))
    assert "torn final record" in str(exc.value)
    assert str(prefix_len) in str(exc.value), "the operator needs the byte offset"
    assert s.log_path.read_bytes() == before, "a refusal must not mutate evidence"

    # The operator's recovery, at the offset the refusal named.
    with s.log_path.open("r+b") as fh:
        fh.truncate(prefix_len)

    fresh = Session(tmp_path / ".didrun")
    entry = fresh.append(_wrapper_event(argv=("cmd", "after")))
    assert entry.index == 2
    assert fresh.tail_truncated is False
    # No unparseable line anywhere, in the middle or at the end.
    for line in fresh.log_path.read_bytes().splitlines():
        json.loads(line)
    assert fresh.verify_chain() == (True, None)
    assert [e.index for e in fresh.entries()] == [0, 1, 2]


# --- 7: fsync changes durability, not bytes ----------------------------------


def test_append_fsyncs_the_record_before_returning(tmp_path: Path, monkeypatch):
    """The durability half of the change, pinned by the call.

    The byte-identity test below is a regression guard: it passes on the
    unfixed code by construction, because the point of fsync is that it changes
    nothing on disk. Only this one fails when the fsync goes away, so both are
    here and they are not the same test.
    """
    real_fsync = os.fsync
    fsynced: list = []

    def spy(fd):
        fsynced.append(fd)
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", spy)
    s = Session(tmp_path / ".didrun")
    s.append(_wrapper_event())

    assert fsynced, "append returned before the record was durable"
    assert list(s.entries())[0].event.argv == ("echo", "hi")


def test_fsync_adds_no_bytes_to_the_log(tmp_path: Path):
    """The on-disk line is exactly what every previous release wrote.

    Pinned against a reconstruction rather than a golden file so it fails if the
    record's SHAPE moves, not only if fsync appended something.
    """
    s = Session(tmp_path / ".didrun")
    events = [_wrapper_event(argv=("cmd", str(i))) for i in range(3)]
    entries = [s.append(ev) for ev in events]

    expected = b"".join(
        canonical_json(
            {
                "index": entry.index,
                "prev_hash": entry.prev_hash,
                "entry_hash": entry.entry_hash,
                "event": ev.to_dict(),
            }
        )
        + b"\n"
        for entry, ev in zip(entries, events)
    )
    assert s.log_path.read_bytes() == expected


# --- 8: handlers are borrowed, never kept ------------------------------------


def test_signal_handlers_are_restored_after_a_normal_run(repo: Path):
    before = {
        sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)
    }
    ev = run_wrapped([sys.executable, "-c", "pass"], _session(repo), repo)
    assert ev.exit_code == 0
    after = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    assert after == before


def test_run_wrapped_from_a_worker_thread_records_normally(repo: Path):
    """`signal.signal` raises off the main thread, and run_wrapped is a library
    entry point an embedder may call from a worker. The guard makes that a
    silent skip, not a ValueError — and the recorded event is unchanged."""
    outcome: dict = {}

    def work() -> None:
        try:
            outcome["event"] = run_wrapped(
                [sys.executable, "-c", "print('hi')"], _session(repo), repo
            )
        except BaseException as exc:  # recorded, never swallowed
            outcome["error"] = exc

    worker = threading.Thread(target=work)
    worker.start()
    worker.join(120)
    assert not worker.is_alive()
    assert "error" not in outcome, repr(outcome.get("error"))

    ev = outcome["event"]
    assert (ev.observed_via, ev.coverage, ev.exit_code) == ("wrapper", "complete", 0)
    assert not isinstance(outcome.get("error"), CaptureInterrupted)
