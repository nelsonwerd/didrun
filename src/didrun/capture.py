"""Tiered, vendor-neutral session capture.

Only Tier 0 — ``didrun run -- <cmd>`` — guarantees complete capture, and it is
the trust core. The other tiers are enrichment with honest coverage grades; the
measured reason invisible/universal capture is impossible is in
docs/MEASUREMENTS.md (absolute-path execs escape a
PATH shim 100% of the time; a PTY transcript yields no argv/exit).

  Tier 0  didrun run -- <cmd>   complete argv/exit/output/timing        (this file)
  Tier 1  PATH shim             bare-name execs only (structural misses) (generator here)
  Tier 2  per-shell trap        bash BASH_ENV / zsh ~/.zshenv, env-gated  (installers here)
  Tier 3  native adapter        enrichment only                          (adapters/)

The PTY transcript is a *human-facing* artifact, graded ``display-only``: it can
read "tests: 5 passed" for a command that exited 3, so it must never carry an
exit code. That invariant is enforced in ledger.Event.
"""

from __future__ import annotations

import hashlib
import os
import selectors
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from .ledger import Event, Session
from . import gitplumbing

# The GATE: the environment facts whose identity is allowed to change a verdict.
# We hash a declared allowlist rather than the raw environment so the
# fingerprint never leaks a secret (redaction of captured *output* is a separate
# pass; see redact.py) — every value here is digested, never stored.
#
# IN, because each of them changes what a build produces: the locale (LANG), the
# shell a recipe may re-enter (SHELL), the active virtualenv (VIRTUAL_ENV), the
# timezone (TZ, which moves every date a build stamps), and the process umask
# (below — not an environment variable, but the same kind of fact, and the one
# whose absence made two green wrapper events under different umasks
# indistinguishable in the receipt).
#
# OUT, deliberately, and both were in v0.1's key set:
#
#   PATH  varies with terminal tab, direnv, `nix develop`, tmux and homebrew
#         shellenv ordering, and flips on any venv activation VIRTUAL_ENV
#         already records. A gate that refuses in a new shell is ignored within
#         a week. It is recorded as its own digest instead (see
#         env_fingerprint), so PATH drift stays inspectable without gating.
#
#   PWD   is NOT the child's cwd. run_wrapped always spawns with cwd=str(repo)
#         and Event.cwd records that same resolved path; PWD is the caller's
#         shell-maintained variable, which can be stale and can be absent when
#         didrun is spawned by a launcher. While nothing read the fingerprint
#         this was inert. The moment it is compared, PWD is a false-drift
#         source: two byte-identical executions of the same command against the
#         same repo, invoked from different directories, would disagree.
_ENV_FINGERPRINT_KEYS = ("LANG", "SHELL", "TZ", "VIRTUAL_ENV")

# The fingerprint's preimage is versioned IN BAND, because the digest's shape
# does not change when its key set does: two 16-hex strings over different key
# sets are silently incomparable, which reads as "the environment drifted" when
# the truth is "these were produced by different didrun versions". A bare digest
# with no prefix was produced by v0.1 and is incomparable, not drifted.
#
# 2: the key set changed (umask and TZ in, PATH and PWD out) AND the string
# grew a `:path=` suffix. A v1 and a v2 value are never compared — see
# manifest._env_comparison and docs/COMPAT.md.
FINGERPRINT_VERSION = 2

# The marker introducing the non-gated PATH digest in a v2 fingerprint.
_PATH_MARKER = "path="

_UMASK: Optional[int] = None

# The env var that gates Tier-2 traps. The trap does nothing unless this is set,
# and it is set ONLY by `didrun run`, so an installed trap never records an
# unrelated shell session on the machine (the privacy gate).
DIDRUN_ACTIVE_ENV = "DIDRUN_SESSION"


def process_umask() -> int:
    """This process's umask, read ONCE and reused for every event.

    There is no read-only way to read a umask: the read is a read-modify-write
    (``os.umask(0)`` then restore), and between the two calls this process's
    umask is 0 — process-global state, not thread-local, so a sibling thread
    forking in that window hands its child the wrong one. Reading once per
    process opens that window once, before the first child is spawned, instead
    of once per wrapped command. The umask is a property of the process, not of
    the command, so re-reading it per event would buy nothing anyway.

    ``run_wrapped`` primes this before spawning, so the value recorded on an
    event is the umask the child actually inherited.
    """
    global _UMASK
    if _UMASK is None:
        old = os.umask(0)
        os.umask(old)
        _UMASK = old
    return _UMASK


def env_fingerprint(env: Optional[dict] = None, umask: Optional[int] = None) -> str:
    """Digest the environment facts that can change what a build produces.

    Returns ``v2:<16 hex gate>:path=<8 hex>``. The GATE is the only part a
    comparison may read (``fingerprint_gate``); the ``path=`` digest records
    PATH so its drift stays INSPECTABLE without becoming a gate — see
    ``_ENV_FINGERPRINT_KEYS`` for why, and docs/COMPAT.md for why a digest and
    not the raw string.

    Every input is hashed and none is stored: the fingerprint must never become
    the place where a secret-bearing environment variable lands verbatim in a
    note. That is also why the whole environment is not fingerprinted, and it is
    the reason an inherited-environment false green (``GOFLAGS=-exec=…``) is a
    documented NON-guarantee rather than something this closes.
    """
    env = env if env is not None else os.environ
    umask = process_umask() if umask is None else umask
    parts = [f"{key}={env.get(key, '')}" for key in _ENV_FINGERPRINT_KEYS]
    # Named like the env parts, so the preimage stays one readable list and a
    # future key called "umask" could not collide with it silently.
    parts.append(f"umask={umask:04o}")
    gate = hashlib.sha256("\n".join(parts).encode("utf-8", "replace")).hexdigest()[:16]
    path_digest = hashlib.sha256(
        env.get("PATH", "").encode("utf-8", "replace")
    ).hexdigest()[:8]
    return f"v{FINGERPRINT_VERSION}:{gate}:{_PATH_MARKER}{path_digest}"


def fingerprint_version(value: str) -> Optional[int]:
    """The in-band version of a fingerprint, or None if it carries no prefix.

    ``None`` means the value came from a didrun that predates the prefix, so it
    is INCOMPARABLE with a versioned one — a consumer must not read a mismatch
    between the two as environment drift.

    A v2 value carries a second colon (the ``:path=`` suffix); only the leading
    ``v<N>`` field is read here, so both shapes parse.
    """
    prefix, sep, _rest = value.partition(":")
    if not sep or not prefix.startswith("v"):
        return None
    digits = prefix[1:]
    if not (digits.isascii() and digits.isdigit()):
        return None
    return int(digits)


def fingerprint_gate(value: str) -> Optional[str]:
    """The comparable portion of a fingerprint, or None when there is none.

    ``None`` is INCOMPARABLE and a consumer must never report it as drift: it
    means a bare v0.1 digest with no version prefix, or a value whose gate field
    is empty. The ``:path=`` suffix is excluded on purpose — PATH is recorded to
    be looked at, never to be gated on.
    """
    if fingerprint_version(value) is None:
        return None
    _prefix, _sep, rest = value.partition(":")
    gate, _sep2, _suffix = rest.partition(":")
    return gate or None


def fingerprint_path_digest(value: str) -> Optional[str]:
    """The non-gated PATH digest carried by a v2 fingerprint, or None.

    Advisory only, in every consumer. A v1 fingerprint carries none, and a
    difference here is reported as PATH drift, never as environment drift.
    """
    if fingerprint_version(value) is None:
        return None
    _prefix, _sep, rest = value.partition(":")
    _gate, sep, suffix = rest.partition(":")
    if not sep or not suffix.startswith(_PATH_MARKER):
        return None
    return suffix[len(_PATH_MARKER):] or None


# --- Tier 0: the output pump --------------------------------------------------
#
# v0.1 ran the child through subprocess.run(capture_output=True), which buffers
# both pipes to completion inside communicate(). The child's output therefore
# reached the terminal not progressively and not at the end but *never*: the
# whole operator-visible record of a 14.6-hour chain was one summary line per
# command. It is also why an interrupted command had no partial output to keep —
# subprocess.run's except clause kills the child and re-raises with the buffers
# still bound inside communicate(), where nothing can reach them.
#
# The pump below drains both pipes incrementally instead. What is *recorded* is
# unchanged, byte for byte; only when the bytes become visible changes.

_PUMP_CHUNK = 65536


class CaptureBuffers:
    """The accumulating stdout/stderr of one wrapped child.

    Owned by the caller rather than hidden inside the pump so that whatever was
    drained before an exception is still reachable afterwards. Byte counts are
    kept alongside the chunks so a progress line can report volume without ever
    touching content.
    """

    def __init__(self) -> None:
        self._chunks: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
        self._counts: dict[str, int] = {"stdout": 0, "stderr": 0}
        # The threaded drain has two writers; the selector drain has one. The
        # lock costs nothing measurable and keeps one implementation of feed().
        self._lock = threading.Lock()

    def feed(self, stream: str, data: bytes) -> None:
        with self._lock:
            self._chunks[stream].append(data)
            self._counts[stream] += len(data)

    def bytes_drained(self, stream: str) -> int:
        with self._lock:
            return self._counts[stream]

    @property
    def stdout(self) -> bytes:
        with self._lock:
            return b"".join(self._chunks["stdout"])

    @property
    def stderr(self) -> bytes:
        with self._lock:
            return b"".join(self._chunks["stderr"])


def _tee_chunk(stream: str, data: bytes) -> None:
    """Write one drained chunk straight to this process's terminal.

    RAW BYTES, deliberately unredacted. Redaction is whole-buffer: a _TOKENISH
    match can straddle a chunk boundary, so a streaming redactor would emit half
    a secret and call it covered. ``--tee`` is local terminal output — the same
    exposure as running the command directly — and is never an export. Every
    export path (note, bundle, HTML, ``show --output --redacted``) still runs
    through redact.
    """
    out = sys.stdout if stream == "stdout" else sys.stderr
    buf = getattr(out, "buffer", None)
    if buf is not None:
        buf.write(data)
        buf.flush()
    else:  # a text-only stream (a test harness's capture object, say)
        out.write(data.decode("utf-8", "replace"))
        out.flush()


def _heartbeat_line(argv: list[str], elapsed: float, buffers: CaptureBuffers) -> str:
    """One progress line: elapsed, command identity, volume. No content.

    The command identity is argv[0]'s basename and an argument count, not the
    argv itself: argv is the carrier redact.scrub_argv exists for (``FOO_TOKEN=…``
    is a measured shape), and a heartbeat that pasted it into a build log would
    be a leak this file introduced. Byte counts are volume, never a digest of
    the output text — a rolling digest of content is content.
    """
    name = os.path.basename(argv[0]) if argv else "?"
    return (
        f"didrun: {int(elapsed)}s  {name} ({max(len(argv) - 1, 0)} args)  "
        f"stdout={buffers.bytes_drained('stdout')}B "
        f"stderr={buffers.bytes_drained('stderr')}B"
    )


def _emit_heartbeat(argv: list[str], elapsed: float, buffers: CaptureBuffers) -> None:
    # stderr, so a caller parsing didrun's stdout is unaffected even with the
    # flag on.
    print(_heartbeat_line(argv, elapsed, buffers), file=sys.stderr, flush=True)


def _selector_for(proc: "subprocess.Popen") -> Optional[selectors.BaseSelector]:
    """A selector with both pipes registered, or None if they cannot be.

    ``selectors.DefaultSelector`` on Windows is a select() over sockets and
    cannot take an anonymous pipe. Registration fails before a single byte is
    read, so returning None here is a clean handover to the threaded drain
    rather than a partial one.
    """
    sel = selectors.DefaultSelector()
    try:
        sel.register(proc.stdout, selectors.EVENT_READ, "stdout")
        sel.register(proc.stderr, selectors.EVENT_READ, "stderr")
    except (ValueError, OSError, NotImplementedError):
        sel.close()
        return None
    return sel


def _drain_via_selector(
    sel: selectors.BaseSelector,
    buffers: CaptureBuffers,
    tee: bool,
    heartbeat: Optional[float],
    argv: list[str],
    origin: float,
) -> None:
    # One chunk per ready stream per pass: neither pipe is ever read to
    # completion while the other fills, which is the deadlock the buffered path
    # avoided by using communicate().
    next_beat = origin + heartbeat if heartbeat else None
    while sel.get_map():
        timeout = None
        if next_beat is not None:
            timeout = max(0.0, next_beat - time.monotonic())
        for key, _mask in sel.select(timeout):
            data = os.read(key.fd, _PUMP_CHUNK)
            if not data:  # EOF on this pipe
                sel.unregister(key.fileobj)
                key.fileobj.close()
                continue
            buffers.feed(key.data, data)
            if tee:
                _tee_chunk(key.data, data)
        if next_beat is not None and time.monotonic() >= next_beat:
            _emit_heartbeat(argv, time.monotonic() - origin, buffers)
            next_beat = time.monotonic() + heartbeat


def _drain_via_threads(
    proc: "subprocess.Popen",
    buffers: CaptureBuffers,
    tee: bool,
    heartbeat: Optional[float],
    argv: list[str],
    origin: float,
) -> None:
    """Fallback drain: one blocking reader thread per pipe.

    Same no-starvation property as the selector pump (neither stream waits on
    the other) at the cost of two threads per wrapped command. stdlib only —
    this is the alternative to declaring Tier-0 capture POSIX-only, and adding
    a dependency to pump a pipe is not on the table.
    """
    tee_lock = threading.Lock()

    def reader(stream: str, pipe) -> None:
        try:
            while True:
                data = pipe.read1(_PUMP_CHUNK)
                if not data:
                    break
                buffers.feed(stream, data)
                if tee:
                    with tee_lock:
                        _tee_chunk(stream, data)
        finally:
            pipe.close()

    threads = [
        threading.Thread(target=reader, args=("stdout", proc.stdout), daemon=True),
        threading.Thread(target=reader, args=("stderr", proc.stderr), daemon=True),
    ]
    for t in threads:
        t.start()
    next_beat = origin + heartbeat if heartbeat else None
    while True:
        alive = [t for t in threads if t.is_alive()]
        if not alive:
            return
        timeout = None
        if next_beat is not None:
            timeout = max(0.0, next_beat - time.monotonic())
        alive[0].join(timeout)
        if next_beat is not None and time.monotonic() >= next_beat:
            _emit_heartbeat(argv, time.monotonic() - origin, buffers)
            next_beat = time.monotonic() + heartbeat


# --- Tier 0: interruption -----------------------------------------------------
#
# An operator SIGINT reaches the whole foreground process group, so the child
# takes it too. v0.1 let the resulting KeyboardInterrupt propagate out of
# subprocess.run: the child was killed, the buffers were discarded inside
# communicate(), and CPython exited 130 with a traceback BEFORE session.append
# ran. The flight recorder lost the flight — the exact failure it exists to
# prevent, and a silent one, because absence of evidence stopped being visible.
#
# What replaces it records the same event the normal path would, minus the two
# facts nobody witnessed: no exit code, and coverage "unobserved". Both are
# EXISTING vocabulary (ledger.COVERAGE), so no Event field moves and no archived
# entry_hash changes. The grading ladder needs no edit either: _supporting_event
# skips the event (exit_code != 0) and _witnessed_failure skips it (exit_code is
# None), so a claim bound to it grades `unknown` — the correct answer, for free.

_INTERRUPT_SIGNALS = ("SIGINT", "SIGTERM")

# How long the child gets after the signal is forwarded before it is killed.
# The wait is a timer rather than a sleep because the handler runs on the main
# thread, which is the thread draining the pipes — sleeping there would stall
# the drain that keeps the child from blocking on a full pipe.
_CHILD_GRACE_SECONDS = 2.0


def signal_name(signum: int) -> str:
    """``SIGINT`` for 2, and a readable fallback for anything unnamed."""
    try:
        return signal.Signals(signum).name
    except ValueError:
        return f"signal {signum}"


class CaptureInterrupted(Exception):
    """A wrapped command was interrupted AND its event has been recorded.

    Raised only after ``session.append`` returns, so the exception means "the
    flight is on the record", never "the record was lost". It carries the
    signal number so the CLI can exit on the conventional code without a
    traceback, and the appended event's index so an operator is told where the
    partial record is.
    """

    def __init__(self, signum: int, event_index: Optional[int] = None) -> None:
        self.signum = signum
        self.event_index = event_index
        super().__init__(
            f"interrupted by {signal_name(signum)}; "
            f"recorded event {event_index} as unobserved"
        )

    @property
    def exit_code(self) -> int:
        # 128 + N, the shell convention: 130 for SIGINT, 143 for SIGTERM.
        return 128 + self.signum


def _kill_quietly(proc: "subprocess.Popen") -> None:
    try:
        proc.kill()
    except (OSError, ValueError):
        pass


def _install_interrupt_handlers(
    proc: "subprocess.Popen", caught: dict
) -> Callable[[], None]:
    """Forward SIGINT/SIGTERM to the child, remember the first one that arrived.

    Returns a callable that restores the previous handlers. The caller MUST run
    it in a ``finally``: leaving didrun's handlers installed would change the
    interrupt behaviour of an embedder's entire process, long after the child
    it was installed for is gone.

    MAIN THREAD ONLY. ``signal.signal`` raises ``ValueError: signal only works
    in main thread`` anywhere else, and ``run_wrapped`` is a library entry point
    a harness or an embedder may legitimately call from a worker. Off the main
    thread this installs nothing and records nothing new — the uninterrupted
    path is byte-for-byte what it was.
    """
    if threading.current_thread() is not threading.main_thread():
        return lambda: None

    timers: list = []
    previous: dict = {}

    def handler(signum, _frame):
        if caught["signum"] is None:
            caught["signum"] = signum
        # Forward first. A terminal Ctrl-C already delivered the signal to the
        # whole foreground process group, in which case this is a harmless
        # no-op; a signal sent to didrun alone (a supervisor, a test) reaches
        # the child only here.
        try:
            proc.send_signal(signum)
        except (OSError, ValueError):
            pass
        # Then escalate, so a child that ignores the signal cannot hang the
        # recorder. The kill closes the pipes, which ends the drain.
        timer = threading.Timer(_CHILD_GRACE_SECONDS, _kill_quietly, args=(proc,))
        timer.daemon = True
        timer.start()
        timers.append(timer)

    for name in _INTERRUPT_SIGNALS:
        signum = getattr(signal, name, None)
        if signum is None:  # not every platform defines both
            continue
        try:
            previous[signum] = signal.signal(signum, handler)
        except (ValueError, OSError, RuntimeError):
            continue

    def restore() -> None:
        for timer in timers:
            timer.cancel()
        for signum, prev in previous.items():
            try:
                signal.signal(signum, prev)
            except (ValueError, OSError, RuntimeError):
                pass

    return restore


def _defer_interrupts(caught: dict) -> Callable[[], None]:
    """Hold SIGINT/SIGTERM until the flight is on the record.

    The child is already reaped by the time this is installed, so there is
    nothing left to forward to and nothing to escalate against — the only job
    is to stop a signal from unwinding the recorder between the drain and
    ``session.append``. Without it a second Ctrl-C lands in the digest/append
    window and raises ``KeyboardInterrupt`` out of ``run_wrapped``, losing the
    event for a command that actually ran and, on the drain path, discarding
    the interrupt evidence the drain went to the trouble of collecting.

    The signal is recorded, not dropped: the caller re-raises it as
    ``CaptureInterrupted`` once the entry is durable, so the operator still
    gets the interrupt they asked for and the conventional 130 exit.

    MAIN THREAD ONLY, for the same reason as ``_install_interrupt_handlers``.
    """
    if threading.current_thread() is not threading.main_thread():
        return lambda: None

    previous: dict = {}

    def handler(signum, _frame):
        if caught.get("deferred") is None:
            caught["deferred"] = signum

    for name in _INTERRUPT_SIGNALS:
        signum = getattr(signal, name, None)
        if signum is None:
            continue
        try:
            previous[signum] = signal.signal(signum, handler)
        except (ValueError, OSError, RuntimeError):
            continue

    def restore() -> None:
        for signum, prev in previous.items():
            try:
                signal.signal(signum, prev)
            except (ValueError, OSError, RuntimeError):
                pass

    return restore


def _spawn_and_drain(
    argv: list[str],
    cwd: str,
    buffers: CaptureBuffers,
    tee: bool = False,
    heartbeat: Optional[float] = None,
) -> tuple:
    """Run ``argv``, draining both pipes as they fill.

    Returns ``(exit_code, signum)``, where ``signum`` is the interrupting signal
    or ``None``. On interruption the exit code is still read — the child is dead
    by then — but the caller must not record it: nobody witnessed the command
    finish, and a kill-induced ``-2`` is not the command's verdict.

    The bytes fed into ``buffers`` are the bytes ``capture_output=True`` would
    have returned — that equality is the criterion this change is held to, and
    it is tested per stream over empty, large, interleaved and non-UTF-8 output
    rather than asserted here.
    """
    caught: dict = {"signum": None}
    with subprocess.Popen(
        argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as proc:
        origin = time.monotonic()
        restore = _install_interrupt_handlers(proc, caught)
        try:
            sel = _selector_for(proc)
            if sel is None:
                _drain_via_threads(proc, buffers, tee, heartbeat, argv, origin)
            else:
                with sel:
                    _drain_via_selector(sel, buffers, tee, heartbeat, argv, origin)
            # Reaped inside the handlers' lifetime on purpose: a second signal
            # arriving here is forwarded to an already-dead child instead of
            # raising KeyboardInterrupt through the recording that follows.
            exit_code = proc.wait()
        except BaseException:
            # Same disposition as the buffered path: kill the child and let
            # Popen.__exit__ reap it. Unlike the buffered path, the caller's
            # buffers hold everything drained up to this point.
            proc.kill()
            raise
        finally:
            restore()
    return exit_code, caught["signum"]


def _tree_digest_or_none(repo: Path, ledger_objects: Path) -> Optional[str]:
    """``tree_digest``, with a failure recorded as ``None`` instead of raised.

    The interrupt path only. The signal went to the whole foreground process
    group, so git may have taken it too and the digest can fail in ways the
    normal path never sees. ``None`` is the honest answer — the claim grades
    ``unknown`` — and taking the digest must never cost the event being
    recorded, which is the whole point of this path.
    """
    try:
        return gitplumbing.tree_digest(repo, ledger_objects)
    except Exception:
        return None


def run_wrapped(
    argv: list[str],
    session: Session,
    repo: Optional[Path] = None,
    tee: bool = False,
    heartbeat: Optional[float] = None,
    buffers: Optional[CaptureBuffers] = None,
) -> Event:
    """Tier 0: run a command under direct capture and record a complete Event.

    Captures argv, cwd, an env fingerprint, exit code, stdout/stderr as blobs,
    and git tree digests before and after. This is the only path that witnesses
    a real exit code, so its events are ``coverage="complete"``,
    ``observed_via="wrapper"``.

    ``tee`` mirrors the child's raw output to this terminal as it arrives, and
    ``heartbeat`` prints a content-free progress line to stderr at most every N
    seconds. Both are local display, both default off, and neither changes one
    byte of what is recorded. ``buffers`` lets a caller own the accumulator and
    read partial output back after an interrupt.

    On SIGINT/SIGTERM the event is still recorded — argv, cwd, fingerprint, both
    tree digests and whatever output was drained before the signal — and then
    ``CaptureInterrupted`` is raised. The event says what was not witnessed
    rather than guessing it: no exit code, ``coverage="unobserved"``.
    """
    repo = Path(repo or os.getcwd())
    ledger_objects = session.blobs.root  # digest objects live beside blobs

    # Read the umask BEFORE the child is spawned, so the value the event records
    # is the one the child inherited, and so the read-modify-write window this
    # opens (see process_umask) is never concurrent with a fork. Cached from
    # here on: the fingerprint below reuses it rather than re-reading.
    process_umask()

    tree_before = gitplumbing.tree_digest(repo, ledger_objects)
    submod = gitplumbing.submodule_dirty(repo)

    if buffers is None:
        buffers = CaptureBuffers()
    started = time.time()
    exit_code, signum = _spawn_and_drain(
        list(argv), str(repo), buffers, tee=tee, heartbeat=heartbeat
    )
    ended = time.time()
    interrupted = signum is not None

    # The child is reaped, but the flight is not on the record until append
    # returns. Digesting a large worktree and writing two blobs is a real
    # window, and it is exactly where a second Ctrl-C lands. Hold interrupts
    # across it; honour them immediately afterwards.
    deferred: dict = {"deferred": None}
    stop_deferring = _defer_interrupts(deferred)
    try:
        # The after-digest never costs the event, on ANY path. A terminal
        # Ctrl-C reaches the whole foreground process group, so the git the
        # digest shells out to can be killed even when the child had already
        # exited cleanly and the drain saw no signal at all. Losing a witnessed
        # command over a failed digest is the worse trade every time: `None`
        # grades `unknown`, which is the honest answer, while no event at all
        # says the command never ran.
        tree_after = _tree_digest_or_none(repo, ledger_objects)
        digest_lost = tree_after is None and not interrupted

        stdout_digest = session.blobs.put(buffers.stdout)
        stderr_digest = session.blobs.put(buffers.stderr)

        if interrupted:
            coverage = "unobserved"
        elif digest_lost:
            # argv, streams and exit code were all witnessed; the resulting
            # tree was not. Say exactly that rather than claiming "complete".
            coverage = "observed-text-only"
        else:
            coverage = "complete"

        event = Event(
            argv=tuple(argv),
            cwd=str(repo),
            env_fingerprint=env_fingerprint(),
            observed_via="wrapper",
            coverage=coverage,
            exit_code=None if interrupted else exit_code,
            started_at=started,
            ended_at=ended,
            stdout_blob=stdout_digest,
            stderr_blob=stderr_digest,
            tree_before=tree_before,
            tree_after=tree_after,
            submodule_dirty=submod,
        )
        entry = session.append(event)
    finally:
        stop_deferring()

    if interrupted:
        raise CaptureInterrupted(signum, entry.index)
    # The command itself completed and is fully recorded; the operator
    # interrupted the recorder afterwards. Report the interrupt, not a
    # fabricated clean return.
    if deferred["deferred"] is not None:
        raise CaptureInterrupted(deferred["deferred"], entry.index)
    return event


def pty_transcript(argv: list[str], session: Session, repo: Optional[Path] = None) -> Event:
    """Capture a PTY transcript as a human-facing artifact (display-only).

    The raw terminal byte stream is stored as a blob. Per the measured PTY
    limit, we do NOT recover argv semantics or an exit code from the stream, so
    the event is ``coverage="display-only"``, ``observed_via="transcript"`` and
    carries no exit code — enforced by ledger.Event.
    """
    import pty

    # Before pty.spawn, for the same reason run_wrapped primes it before Popen:
    # the recorded umask must be the one the child inherited.
    process_umask()

    repo = Path(repo or os.getcwd())
    chunks: list[bytes] = []

    def _read(fd: int) -> bytes:
        try:
            data = os.read(fd, 65536)
        except OSError:
            return b""
        chunks.append(data)
        return data

    # pty.spawn echoes to our stdout and pumps the child through a pty; the
    # read callback tees the bytes into `chunks` for the transcript blob.
    pty.spawn(argv, _read)

    transcript = b"".join(chunks)
    digest = session.blobs.put(transcript)

    event = Event(
        argv=tuple(argv),
        cwd=str(repo),
        env_fingerprint=env_fingerprint(),
        observed_via="transcript",
        coverage="display-only",
        exit_code=None,  # invariant: a transcript never claims an exit code
        transcript_blob=digest,
        tree_before=None,
        tree_after=None,
    )
    session.append(event)
    return event


# --- Tier 1: PATH shim generator ---------------------------------------------
#
# Honest scope (measured): a PATH shim observes only bare-name, PATH-resolved
# execs. Absolute-path invocations and shell builtins escape 100% of the time.
# The shim re-dispatches a bare-name command through Tier 0 so it is captured
# completely; anything it cannot see is graded as a structural miss, never
# silently dropped.

_SHIM_TEMPLATE = """#!/bin/sh
# didrun Tier-1 shim for `{name}`. Generated — do not edit.
# Re-dispatches through `didrun run` ONLY when a didrun session is active,
# so an installed shim never records unrelated shell activity (privacy gate).
if [ -n "${active_env}" ] && [ -x "{didrun_bin}" ]; then
  exec "{didrun_bin}" run --shim -- "{real}" "$@"
fi
exec "{real}" "$@"
"""


def generate_shim(name: str, real_path: str, didrun_bin: str, out_dir: Path) -> Path:
    """Write a PATH shim for a bare command name. Returns the shim path.

    The shim is inert unless ``DIDRUN_SESSION`` is set (the privacy gate) and
    the real binary is resolved by absolute path so the shim never recurses.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    shim = out_dir / name
    shim.write_text(
        _SHIM_TEMPLATE.format(
            name=name,
            real=real_path,
            didrun_bin=didrun_bin,
            active_env=DIDRUN_ACTIVE_ENV,
        )
    )
    shim.chmod(0o755)
    return shim


# --- Tier 2: per-shell trap installers ---------------------------------------
#
# Measured (docs/MEASUREMENTS.md): Claude Code spawns the user's $SHELL per
# command. bash honors BASH_ENV non-interactively; zsh sources ~/.zshenv and a
# DEBUG trap there fires (preexec does not, non-interactively). Both are gated
# on DIDRUN_SESSION so they are dead unless `didrun run` set it — otherwise the
# trap would observe every shell session on the machine (a privacy incident for
# a trust tool). fish/dash/`/bin/sh` are unsupported and reported as gaps.

_BASH_TRAP = """# didrun Tier-2 bash trap (generated). Inert unless DIDRUN_SESSION is set.
if [ -n "${DIDRUN_SESSION:-}" ] && [ -n "${DIDRUN_LOG:-}" ]; then
  trap 'printf "%s\\t%s\\n" "$?" "$BASH_COMMAND" >> "$DIDRUN_LOG" 2>/dev/null' DEBUG
fi
"""

_ZSH_TRAP = """# didrun Tier-2 zsh trap (generated). Inert unless DIDRUN_SESSION is set.
if [[ -n "${DIDRUN_SESSION:-}" && -n "${DIDRUN_LOG:-}" ]]; then
  trap 'print -r -- "$ZSH_DEBUG_CMD" >> "$DIDRUN_LOG" 2>/dev/null' DEBUG
fi
"""


def tier2_snippet(shell: str) -> str:
    """Return the gated trap snippet for a shell, or raise for unsupported ones."""
    shell = os.path.basename(shell)
    if shell == "bash":
        return _BASH_TRAP
    if shell == "zsh":
        return _ZSH_TRAP
    raise ValueError(
        f"Tier-2 capture unsupported for shell {shell!r} "
        "(bash and zsh only; fish/dash/sh are honest gaps)"
    )
