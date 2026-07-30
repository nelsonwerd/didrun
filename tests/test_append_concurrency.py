"""P2.4 — the read-tail-and-append pair is atomic between didrun processes.

The hazard being closed is corruption, not wall-clock. ``Session.append`` reads
the tail, derives ``(index, prev_hash)`` from it, then writes; two processes
that interleave those three steps both write the same index chained from the
same predecessor, and ``verify_chain`` reports a break that cannot be repaired
without rewriting the log — the one edit an evidence store must never make.

Two things make the positive leg here mean something.

  - **The negative leg runs the identical harness.** ``test_1`` and ``test_2``
    drive the same child script with the same contention profile; the only
    difference between them is whether ``ledger._append_lock`` is the real
    context manager or ``contextlib.nullcontext``. A green positive leg that
    could not fail is worth nothing, so the negative leg proves the harness
    races.
  - **The lock's extent is asserted, not assumed.** Test 4 pins that it is not
    held across the wrapped child (the failure mode that would trade a rare
    recoverable break for a routine hang), and test 3 pins that a read-only
    verify never waits on it.

Honest scope: the deployment class this protects — concurrent didrun
invocations against one ledger — has zero observed instances in the corpus this
work was measured against. The two preserved incidents behind it come from the
evidence documents, not from a race reproduced here.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from didrun import gitplumbing as gp
from didrun import ledger as ledger_mod
from didrun import manifest as manifest_mod
from didrun.claims import Claim
from didrun.ledger import Event, Session

# flock is the whole mechanism. Off POSIX the manager is a declared no-op and
# there is nothing here to assert but the degradation (test 11).
fcntl = ledger_mod.fcntl

ECHO = "/bin/echo"
SH = "/bin/sh"

pytestmark = pytest.mark.skipif(
    not ledger_mod.APPEND_LOCK_AVAILABLE
    or not (os.path.exists(ECHO) and os.path.exists(SH)),
    reason="POSIX flock semantics and a POSIX /bin layout",
)

# How many writers race for one ledger. Eight is the figure the design was
# specified against and is enough to make a fork overwhelming rather than
# marginal when the lock is removed.
RACERS = 8

# Seconds each racer spends between reading the tail and writing the line,
# injected identically into both legs. See _race() for why this is here and why
# it does not weaken the positive leg.
WIDEN_SECONDS = 0.05


# The racer. It drives the REAL CLI in a real process — the corruption this
# guards against is between processes, so an in-process thread test would not
# reach it. Everything it does is switched by environment variable so the
# locked and unlocked legs run byte-identical code.
_RACER = '''
import contextlib
import os
import sys
import time

import didrun.ledger as ledger
from didrun.ledger import Session

if os.environ.get("DIDRUN_TEST_NO_LOCK") == "1":
    # The negative leg. contextlib.nullcontext accepts and ignores the root, so
    # this is exactly Session.append with no mutual exclusion: v0.1's behaviour.
    ledger._append_lock = contextlib.nullcontext

WIDEN = float(os.environ.get("DIDRUN_TEST_WIDEN") or 0.0)
RENDEZVOUS = os.environ.get("DIDRUN_TEST_RENDEZVOUS") or ""
PEERS = int(os.environ.get("DIDRUN_TEST_PEERS") or 0)


def _rendezvous(path, peers, timeout=120.0):
    """Block until `peers` processes have arrived. Single-byte O_APPEND writes."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, b"x")
    finally:
        os.close(fd)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if os.path.getsize(path) >= peers:
                return
        except OSError:
            pass
        time.sleep(0.005)
    raise SystemExit("rendezvous timed out")


_real_last = Session._last
_real_append = Session.append


def _last(self):
    out = _real_last(self)
    if WIDEN:
        # Between reading the tail and writing the line. Under the lock this is
        # inside the critical section and merely slows the run down; without it
        # this is the window every racer reads the same tail through.
        time.sleep(WIDEN)
    return out


def _append(self, event):
    if RENDEZVOUS:
        # BEFORE the lock, never inside it: a barrier inside the critical
        # section would deadlock the locked leg by construction.
        _rendezvous(RENDEZVOUS, PEERS)
    return _real_append(self, event)


Session._last = _last
Session.append = _append

from didrun.cli import main

sys.exit(main(sys.argv[1:]))
'''

_CLI_BOOT = "import sys; from didrun.cli import main; sys.exit(main(sys.argv[1:]))"

# Acquires the ledger's append lock, publishes readiness, then blocks forever.
# Used to prove the lock is really held (test 3, test 6) and that the kernel
# releases it when the holder is killed (test 6).
_HOLDER = '''
import os
import sys
import time

from didrun.ledger import _append_lock

root, ready = sys.argv[1], sys.argv[2]
with _append_lock(root):
    tmp = ready + ".tmp"
    open(tmp, "w").write(str(os.getpid()))
    os.replace(tmp, ready)
    time.sleep(600)
'''


def _wait_for(predicate, timeout: float, interval: float = 0.01) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def _lock_is_held(root: Path) -> bool:
    """True when some open file description holds the ledger's exclusive flock.

    A real probe even from the process that holds the lock: flock conflicts are
    per open-file-description, so a second os.open in this process is refused
    the same way another process would be. Test 7 pins that this probe
    discriminates, so a False here is a measurement and not a tautology.
    """
    path = Path(root) / ledger_mod.LOCK_FILENAME
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return True
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


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


def _read_session(repo: Path) -> Session:
    """A read-only view of the ledger — the reader must never create anything."""
    return Session(repo / ".didrun", readonly=True)


def _race(repo: Path, tmp_path: Path, tag: str, *, no_lock: bool):
    """Run RACERS concurrent `didrun run` invocations against one ledger.

    Returns ``(returncodes, verdict, indices)`` read back through a read-only
    session. The contention profile is IDENTICAL in both legs — a start
    rendezvous immediately before ``append`` plus WIDEN_SECONDS between the tail
    read and the write — so the only variable across test 1 and test 2 is the
    lock itself.
    """
    script = tmp_path / "racer.py"
    script.write_text(_RACER, encoding="utf-8")
    env = dict(os.environ)
    env["DIDRUN_TEST_WIDEN"] = str(WIDEN_SECONDS)
    env["DIDRUN_TEST_RENDEZVOUS"] = str(tmp_path / f"rendezvous-{tag}")
    env["DIDRUN_TEST_PEERS"] = str(RACERS)
    if no_lock:
        env["DIDRUN_TEST_NO_LOCK"] = "1"
    procs = [
        subprocess.Popen(
            [
                sys.executable,
                str(script),
                "--repo",
                str(repo),
                "run",
                "--",
                ECHO,
                str(i),
            ],
            cwd=str(repo),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for i in range(RACERS)
    ]
    codes = []
    for proc in procs:
        try:
            proc.communicate(timeout=180)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate(timeout=30)
            pytest.fail("a racer never finished — the lock is wider than the append")
        codes.append(proc.returncode)
    session = _read_session(repo)
    verdict = session.verify_chain_detail()
    indices = [e.index for e in session.entries()]
    return codes, verdict, indices


# --- 1. the race, with the lock ----------------------------------------------


def test_eight_concurrent_runs_leave_one_intact_chain(repo: Path, tmp_path: Path):
    codes, verdict, indices = _race(repo, tmp_path, "locked", no_lock=False)

    assert codes == [0] * RACERS
    assert verdict.status == "intact", verdict.reason
    assert len(indices) == RACERS
    assert set(indices) == set(range(RACERS))
    # Sequence, not just membership: a fork that happened to land on a complete
    # set would still be out of order on disk.
    assert indices == list(range(RACERS))


# --- 2. the negative leg: the same harness, no lock --------------------------


def test_the_same_race_forks_the_chain_without_the_lock(repo: Path, tmp_path: Path):
    """The control. Without the lock this harness must actually corrupt.

    **What the harness had to do to make this fail** — recorded because a
    negative leg that needed help is only honest if the help is named, and
    because both helpers are applied to the LOCKED leg too:

      1. A start rendezvous immediately before ``Session.append``, outside the
         lock. Eight ``didrun run`` invocations otherwise finish their tree
         digests at scattered times and mostly do not overlap at all; the
         barrier makes them arrive together, which is the situation the lock
         exists for and not one it gets to dodge.
      2. ``WIDEN_SECONDS`` of sleep between the tail read and the write. The
         unlocked window is a few hundred microseconds of local I/O, so without
         widening the outcome is a coin toss per attempt rather than a
         demonstration.

    Neither weakens test 1: the identical profile runs there, and the lock has
    to hold the chain together through it.

    Measured on the machine this was written on: 3 of 3 unlocked attempts forked
    (duplicate indices, chain reported broken at index 0). The assertion stays
    at "at least one" so a slower or busier machine cannot turn a real
    demonstration into a red suite.
    """
    attempts = 3
    forks = 0
    for attempt in range(attempts):
        shutil.rmtree(repo / ".didrun", ignore_errors=True)
        _codes, verdict, indices = _race(
            repo, tmp_path, f"unlocked-{attempt}", no_lock=True
        )
        duplicated = len(indices) != len(set(indices))
        if duplicated or verdict.status != "intact":
            forks += 1

    assert forks > 0, (
        "the unlocked race never forked the chain, so test 1 proves nothing — "
        "raise RACERS or WIDEN_SECONDS until it does"
    )


# --- 3. the read path takes no lock ------------------------------------------


def test_a_read_only_verify_does_not_wait_on_the_append_lock(
    repo: Path, tmp_path: Path, git
):
    """A held write lock must not stall a reader. Verification is the hot path
    in CI and a reader that contends turns a corruption fix into an outage."""
    subprocess.run(
        [sys.executable, "-c", _CLI_BOOT, "--repo", str(repo), "run", "--", ECHO, "hi"],
        cwd=str(repo),
        capture_output=True,
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            "-c",
            _CLI_BOOT,
            "--repo",
            str(repo),
            "claim",
            "tests-pass",
            "--label",
            "reader",
        ],
        cwd=str(repo),
        capture_output=True,
        check=True,
    )
    git(repo, "commit", "-qm", "seal point", "--allow-empty")
    subprocess.run(
        [sys.executable, "-c", _CLI_BOOT, "--repo", str(repo), "seal"],
        cwd=str(repo),
        capture_output=True,
        check=True,
    )

    root = repo / ".didrun"
    with ledger_mod._append_lock(root):
        assert _lock_is_held(root), "the fixture did not actually hold the lock"
        # No timeout= fallback: a reader that needs one has already failed.
        proc = subprocess.run(
            [sys.executable, "-c", _CLI_BOOT, "--repo", str(repo), "verify"],
            cwd=str(repo),
            capture_output=True,
            timeout=60,
        )
        assert proc.returncode in (0, 1), proc.stderr.decode()
        show = subprocess.run(
            [sys.executable, "-c", _CLI_BOOT, "--repo", str(repo), "show", "--session"],
            cwd=str(repo),
            capture_output=True,
            timeout=60,
        )
        assert show.returncode == 0, show.stderr.decode()


# --- 4. the lock is never held across the wrapped child ----------------------


def test_the_lock_is_not_held_across_the_wrapped_child(repo: Path, tmp_path: Path):
    """The failure this prompt was specified to avoid.

    Acquiring for the duration of `cli.main` would be trivially correct and
    would make a second `didrun run` block for as long as the first command
    takes — hours, in the workload this tool was built for.
    """
    marker = tmp_path / "child-running"
    slow = subprocess.Popen(
        [
            sys.executable,
            "-c",
            _CLI_BOOT,
            "--repo",
            str(repo),
            "run",
            "--",
            SH,
            "-c",
            f"touch {marker}; sleep 5",
        ],
        cwd=str(repo),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert _wait_for(marker.exists, 60), "the wrapped child never started"
        started = time.monotonic()
        quick = subprocess.run(
            [
                sys.executable,
                "-c",
                _CLI_BOOT,
                "--repo",
                str(repo),
                "run",
                "--",
                ECHO,
                "x",
            ],
            cwd=str(repo),
            capture_output=True,
            timeout=60,
        )
        elapsed = time.monotonic() - started
        assert quick.returncode == 0, quick.stderr.decode()
        # The wrapped child sleeps 5s and has barely started. Anything near that
        # means the lock covered it.
        assert elapsed < 3.0, f"the second run took {elapsed:.2f}s"
    finally:
        slow.kill()
        slow.communicate(timeout=30)


# --- 5. lock file hygiene ----------------------------------------------------


def test_lock_file_is_private_ignored_and_outside_every_tree_digest(
    repo: Path, git
):
    root = repo / ".didrun"
    session = Session(root)
    before = gp.tree_digest(repo, ledger_objects=session.blobs.root)
    assert before is not None

    with ledger_mod._append_lock(root):
        pass

    lock = root / ledger_mod.LOCK_FILENAME
    assert lock.exists()
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600

    # Ignored by the ledger's own "*" rule, so no `git add -A` can stage it.
    ignored = subprocess.run(
        ["git", "check-ignore", "-v", str(lock.relative_to(repo))],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    assert ignored.returncode == 0, ignored.stdout + ignored.stderr

    # And excluded from the digest unconditionally, not merely by being ignored.
    after = gp.tree_digest(repo, ledger_objects=session.blobs.root)
    assert after == before
    listing = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", after],
        cwd=str(repo),
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "GIT_OBJECT_DIRECTORY": str(session.blobs.root),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(gp.objects_dir(repo)),
        },
    )
    assert listing.returncode == 0, listing.stderr
    assert ".didrun" not in listing.stdout


# --- 6. a killed holder leaves no stale lock ---------------------------------


def test_a_sigkilled_holder_leaves_no_stale_lock(repo: Path, tmp_path: Path):
    """flock is the reason this test is short. A PID file or an O_EXCL sentinel
    would need liveness checks and a recovery path; the kernel drops an flock
    when the holder dies, however it dies."""
    root = repo / ".didrun"
    session = Session(root)
    script = tmp_path / "holder.py"
    script.write_text(_HOLDER, encoding="utf-8")
    ready = tmp_path / "holder.ready"

    holder = subprocess.Popen(
        [sys.executable, str(script), str(root), str(ready)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert _wait_for(ready.exists, 60), "the holder never acquired the lock"
        assert _lock_is_held(root), "the holder claimed the lock but does not hold it"
    finally:
        holder.kill()
        holder.communicate(timeout=30)

    assert _wait_for(lambda: not _lock_is_held(root), 10), "the lock outlived its holder"
    started = time.monotonic()
    entry = session.append(_wrapper_event())
    assert time.monotonic() - started < 5.0
    assert entry.index == 0


# --- 7. the probe discriminates (so tests 3 and 6 are measurements) ----------


def test_the_lock_probe_reports_false_when_nothing_holds_the_lock(repo: Path):
    root = repo / ".didrun"
    Session(root)
    assert _lock_is_held(root) is False
    with ledger_mod._append_lock(root):
        assert _lock_is_held(root) is True
    assert _lock_is_held(root) is False


# --- 8. a read-only session never touches the lock file ----------------------


def test_a_read_only_session_never_creates_the_lock_file(tmp_path: Path):
    root = tmp_path / ".didrun"
    session = Session(root, readonly=True)
    with pytest.raises(ledger_mod.LedgerError):
        session.append(_wrapper_event())
    assert not root.exists()
    assert not (root / ledger_mod.LOCK_FILENAME).exists()


# --- 9 + 10. the claim and seal appends take the same lock -------------------


def _asserting_lock(recorded: list, real):
    @contextlib.contextmanager
    def probing(root):
        with real(root):
            recorded.append(_lock_is_held(Path(root)))
            yield

    return probing


def test_declare_claim_holds_the_lock_while_it_writes(repo: Path, monkeypatch):
    """A claims.jsonl line is not bounded by PIPE_BUF once a claim declares
    pathspecs, so O_APPEND atomicity is not a guarantee here."""
    session = Session(repo / ".didrun")
    session.append(_wrapper_event())
    held: list = []
    monkeypatch.setattr(
        manifest_mod, "_append_lock", _asserting_lock(held, ledger_mod._append_lock)
    )

    manifest_mod.declare_claim(
        session,
        Claim(
            ctype="tests-pass",
            label="locked",
            event_indices=(0,),
            pathspecs=("src/", "tests/"),
            declared_at_index=0,
        ),
    )

    assert held == [True]
    assert len(manifest_mod._load_claims(session)) == 1
    assert _lock_is_held(session.root) is False


def test_record_seal_holds_the_lock_while_it_writes(repo: Path, monkeypatch):
    session = Session(repo / ".didrun")
    held: list = []
    monkeypatch.setattr(
        manifest_mod, "_append_lock", _asserting_lock(held, ledger_mod._append_lock)
    )

    manifest_mod._record_seal(session, "c" * 40, "t" * 40, 1)

    assert held == [True]
    assert manifest_mod._last_seal_watermark(session) == 1
    assert _lock_is_held(session.root) is False


# --- 11. the platform degradation is recorded, not asserted away -------------


def test_without_fcntl_the_manager_is_a_declared_no_op(tmp_path: Path, monkeypatch):
    """docs/COMPAT.md states that append serialization is POSIX-only. That
    sentence has to be backed by behaviour: no invented fallback, no lock file,
    and appends that still work."""
    root = tmp_path / ".didrun"
    monkeypatch.setattr(ledger_mod, "fcntl", None)
    monkeypatch.setattr(ledger_mod, "APPEND_LOCK_AVAILABLE", False)

    session = Session(root)
    assert session.append_serialized is False
    with ledger_mod._append_lock(root):
        pass
    assert not (root / ledger_mod.LOCK_FILENAME).exists()

    entry = session.append(_wrapper_event())
    assert entry.index == 0
    assert not (root / ledger_mod.LOCK_FILENAME).exists()
    assert session.verify_chain_detail().status == "intact"
