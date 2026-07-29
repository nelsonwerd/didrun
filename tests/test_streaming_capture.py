"""P2.2 — the Tier-0 capture pump streams instead of buffering to completion.

The criterion is byte-identity of what is RECORDED: the drained blobs must equal
what ``subprocess.run(capture_output=True)`` would have returned, for every shape
of output. Everything else here (tee, heartbeat, ``show --output``) is display,
and the tests pin that display never becomes the default and never carries the
child's bytes into a place the buffered path did not.
"""

from __future__ import annotations

import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from didrun.capture import run_wrapped
from didrun.ledger import Session, sha256_hex


def _session(repo: Path) -> Session:
    return Session(repo / ".didrun")


# Spawning the CLI as a real process is the only way to see what a caller's
# terminal sees; `-c` is used rather than a path so no absolute path is embedded.
_CLI_BOOT = "import sys; from didrun.cli import main; sys.exit(main(sys.argv[1:]))"


def _cli_argv(repo: Path, *args: str) -> list:
    return [sys.executable, "-c", _CLI_BOOT, "--repo", str(repo), *args]


def _run_cli(repo: Path, *args: str, timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        _cli_argv(repo, *args), cwd=str(repo), capture_output=True, timeout=timeout
    )


def _child_script(tmp_path: Path, name: str, source: str) -> list:
    """A child whose ARGV carries none of the text it prints.

    ``didrun run``'s summary line echoes argv, so a `-c` child whose source
    contains the marker would let a marker-absence assertion pass (or fail) for
    the wrong reason. The script lives outside the repo so it cannot move a tree
    digest either.
    """
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return [sys.executable, str(path)]


def _wait_for(predicate, timeout: float, interval: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


# --- 1. the criterion: recorded blobs are byte-identical ----------------------

_NOTHING = "pass"
_LARGE = (
    "import sys\n"
    "for _ in range(1024):\n"
    "    sys.stdout.buffer.write(b'y' * 1024)\n"
    "sys.stdout.buffer.flush()\n"
)
_INTERLEAVED = (
    "import sys\n"
    "for i in range(200):\n"
    "    sys.stdout.buffer.write(b'out-%d\\n' % i)\n"
    "    sys.stdout.buffer.flush()\n"
    "    sys.stderr.buffer.write(b'err-%d\\n' % i)\n"
    "    sys.stderr.buffer.flush()\n"
)
# NULs and lone 0xfe/0xff: bytes no text decoder round-trips.
_BINARY = (
    "import sys\n"
    "sys.stdout.buffer.write(bytes(range(256)) * 8)\n"
    "sys.stdout.buffer.flush()\n"
)
_STDERR_ONLY = (
    "import sys\n"
    "sys.stderr.buffer.write(b'only stderr, repeatedly\\n' * 500)\n"
    "sys.stderr.buffer.flush()\n"
)


@pytest.mark.parametrize(
    "name,script",
    [
        ("empty", _NOTHING),
        ("large", _LARGE),
        ("interleaved", _INTERLEAVED),
        ("binary", _BINARY),
        ("stderr-only", _STDERR_ONLY),
    ],
)
def test_streamed_blobs_are_byte_identical_to_the_buffered_path(
    repo: Path, name: str, script: str
):
    """The pump changes WHEN bytes are seen, never WHICH bytes are recorded."""
    argv = [sys.executable, "-c", script]
    reference = subprocess.run(argv, cwd=str(repo), capture_output=True)

    s = _session(repo)
    ev = run_wrapped(argv, s, repo)

    assert ev.stdout_blob == sha256_hex(reference.stdout), f"{name}: stdout digest"
    assert ev.stderr_blob == sha256_hex(reference.stderr), f"{name}: stderr digest"
    assert s.blobs.get(ev.stdout_blob) == reference.stdout
    assert s.blobs.get(ev.stderr_blob) == reference.stderr
    assert ev.exit_code == reference.returncode
    # The persisted shape is unchanged: this is still a complete wrapper event.
    assert (ev.observed_via, ev.coverage) == ("wrapper", "complete")


# --- 2. liveness --------------------------------------------------------------

_EARLY_THEN_SLEEP = (
    "import sys, time\n"
    "sys.stdout.write('MARKER-EARLY\\n')\n"
    "sys.stdout.flush()\n"
    "time.sleep(5)\n"
)


def test_tee_surfaces_output_before_the_child_exits(repo: Path, tmp_path: Path):
    """--tee is progressive, not a replay at the end: the marker is readable
    while the child is still running."""
    sink = tmp_path / "tee.out"
    child = _child_script(tmp_path, "early_then_sleep.py", _EARLY_THEN_SLEEP)
    with sink.open("wb") as fh:
        proc = subprocess.Popen(
            _cli_argv(repo, "run", "--tee", "--", *child),
            cwd=str(repo),
            stdout=fh,
            stderr=subprocess.DEVNULL,
        )
        try:
            seen = _wait_for(lambda: b"MARKER-EARLY" in sink.read_bytes(), timeout=3.0)
            # Read the liveness fact at the same instant, not after the wait.
            still_running = proc.poll() is None
        finally:
            rc = proc.wait(timeout=60)

    assert seen, "the child's output never reached the terminal while it ran"
    assert still_running, "the marker only appeared after the child had exited"
    assert rc == 0


def test_default_run_tees_nothing_and_prints_only_the_summary(repo: Path, tmp_path: Path):
    """No flags: stdout carries the summary line and not one child byte.
    External gates parse this stream."""
    child = _child_script(
        tmp_path,
        "noisy.py",
        "import sys\nprint('MARKER-CHILD')\nprint('MARKER-ERR', file=sys.stderr)\n",
    )
    proc = _run_cli(repo, "run", "--", *child)

    assert proc.returncode == 0
    lines = [ln for ln in proc.stdout.decode().splitlines() if ln.strip()]
    assert len(lines) == 1, f"expected only the summary line, got {lines!r}"
    assert lines[0].startswith("recorded wrapper event")
    assert b"MARKER-CHILD" not in proc.stdout
    assert b"MARKER-CHILD" not in proc.stderr
    assert b"MARKER-ERR" not in proc.stdout
    assert b"MARKER-ERR" not in proc.stderr


# --- 3. no deadlock -----------------------------------------------------------

_BOTH_PIPES_BIG = (
    "import sys\n"
    "for _ in range(16):\n"
    "    sys.stdout.buffer.write(b'o' * 65536)\n"
    "    sys.stderr.buffer.write(b'e' * 65536)\n"
    "sys.stdout.buffer.flush()\n"
    "sys.stderr.buffer.flush()\n"
)


def test_pump_does_not_deadlock_when_both_pipes_fill(repo: Path):
    """1 MiB down each pipe before the child exits — far past the OS pipe buffer.
    A pump that drained one stream to EOF first would hang here forever, so the
    join timeout is the assertion."""
    s = _session(repo)
    argv = [sys.executable, "-c", _BOTH_PIPES_BIG]
    box: dict = {}

    def go() -> None:
        box["event"] = run_wrapped(argv, s, repo)

    worker = threading.Thread(target=go, daemon=True)
    worker.start()
    worker.join(120)

    assert not worker.is_alive(), "the capture pump deadlocked on a full pipe"
    ev = box["event"]
    assert s.blobs.get(ev.stdout_blob) == b"o" * 65536 * 16
    assert s.blobs.get(ev.stderr_blob) == b"e" * 65536 * 16


# --- 4. heartbeat -------------------------------------------------------------

_HEARTBEAT_RE = re.compile(
    r"^didrun: \d+s  \S+ \(\d+ args\)  stdout=\d+B stderr=\d+B$"
)

_NOISY_THEN_SLEEP = (
    "import sys, time\n"
    "sys.stdout.write('MARKER-CONTENT-OUT\\n')\n"
    "sys.stderr.write('MARKER-CONTENT-ERR\\n')\n"
    "sys.stdout.flush(); sys.stderr.flush()\n"
    "time.sleep(3)\n"
)


def test_heartbeat_is_bounded_and_carries_no_content(repo: Path, tmp_path: Path):
    child = _child_script(tmp_path, "noisy_then_sleep.py", _NOISY_THEN_SLEEP)
    proc = _run_cli(repo, "run", "--heartbeat", "1", "--", *child)

    assert proc.returncode == 0
    err = proc.stderr.decode()
    beats = [ln for ln in err.splitlines() if ln.startswith("didrun: ")]
    assert len(beats) >= 2, f"expected repeated heartbeats over a 3s child, got {beats!r}"
    for line in beats:
        assert _HEARTBEAT_RE.match(line), f"heartbeat off-shape: {line!r}"
    # Not one byte of what the child printed may ride out on the progress line.
    assert "MARKER-CONTENT-OUT" not in err
    assert "MARKER-CONTENT-ERR" not in err
    assert b"MARKER-CONTENT-OUT" not in proc.stdout
    # And the heartbeat stays off stdout, which external gates parse.
    assert "didrun: " not in proc.stdout.decode()


def test_heartbeat_is_off_by_default(repo: Path):
    child = [sys.executable, "-c", "import time; time.sleep(2)"]
    proc = _run_cli(repo, "run", "--", *child)
    assert proc.returncode == 0
    assert proc.stderr == b"", f"unrequested output on stderr: {proc.stderr!r}"


# --- 5. show --event N --output ----------------------------------------------

# Synthetic, structurally identical to a real AWS key; matches redact's
# aws-access-key pattern. Never a live credential.
_FAKE_KEY = "AKIAZZ7EXAMPLE9QTEST"


def test_show_output_round_trips_the_recorded_bytes(repo: Path):
    s = _session(repo)
    ev = run_wrapped([sys.executable, "-c", _BINARY], s, repo)
    recorded = s.blobs.get(ev.stdout_blob)

    proc = _run_cli(repo, "show", "--event", "0", "--output")
    assert proc.returncode == 0
    assert proc.stdout == recorded


def test_show_output_reads_the_stderr_stream(repo: Path):
    s = _session(repo)
    ev = run_wrapped([sys.executable, "-c", _STDERR_ONLY], s, repo)

    proc = _run_cli(repo, "show", "--event", "0", "--output", "--stream", "stderr")
    assert proc.returncode == 0
    assert proc.stdout == s.blobs.get(ev.stderr_blob)


def test_show_output_redacted_applies_the_redactor(repo: Path):
    s = _session(repo)
    run_wrapped([sys.executable, "-c", f"print({_FAKE_KEY!r})"], s, repo)

    raw = _run_cli(repo, "show", "--event", "0", "--output")
    assert _FAKE_KEY.encode() in raw.stdout

    red = _run_cli(repo, "show", "--event", "0", "--output", "--redacted")
    assert red.returncode == 0
    assert _FAKE_KEY.encode() not in red.stdout
    assert "«redacted:aws-access-key»" in red.stdout.decode("utf-8")


def test_show_output_refuses_a_missing_blob_without_a_traceback(repo: Path):
    s = _session(repo)
    ev = run_wrapped([sys.executable, "-c", "print('gone')"], s, repo)
    (s.blobs.root / ev.stdout_blob).unlink()

    proc = _run_cli(repo, "show", "--event", "0", "--output")
    assert proc.returncode == 2
    assert b"Traceback" not in proc.stderr
    assert b"didrun show:" in proc.stderr


def test_show_output_refuses_an_out_of_range_event(repo: Path):
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "print('one')"], s, repo)

    proc = _run_cli(repo, "show", "--event", "7", "--output")
    assert proc.returncode == 2
    assert b"Traceback" not in proc.stderr

    proc = _run_cli(repo, "show", "--output")
    assert proc.returncode == 2
    assert b"--event" in proc.stderr


def test_show_output_does_not_create_a_ledger(repo: Path, tmp_path: Path):
    """--output is a read-only command and stays one (P2.1's seam)."""
    empty = tmp_path / "empty"
    empty.mkdir()
    proc = _run_cli(empty, "show", "--event", "0", "--output")
    assert proc.returncode == 2
    # didrun's own refusal, not argparse's: a 2 from an unrecognised flag would
    # satisfy the returncode and the missing directory for the wrong reason.
    assert b"didrun show:" in proc.stderr
    assert not (empty / ".didrun").exists()


# --- 6. exit-code fidelity ----------------------------------------------------


@pytest.mark.parametrize("code", [0, 1, 42])
def test_exit_codes_match_the_buffered_path(repo: Path, code: int):
    argv = [sys.executable, "-c", f"import sys; sys.exit({code})"]
    reference = subprocess.run(argv, cwd=str(repo), capture_output=True)
    s = _session(repo)
    ev = run_wrapped(argv, s, repo)
    assert ev.exit_code == reference.returncode == code


def test_signal_death_records_the_same_code_as_the_buffered_path(repo: Path):
    argv = [
        sys.executable,
        "-c",
        "import os, signal; os.kill(os.getpid(), signal.SIGTERM)",
    ]
    reference = subprocess.run(argv, cwd=str(repo), capture_output=True)
    s = _session(repo)
    ev = run_wrapped(argv, s, repo)
    assert ev.exit_code == reference.returncode
    assert ev.exit_code < 0, "a signal death must not be recorded as a clean exit"
