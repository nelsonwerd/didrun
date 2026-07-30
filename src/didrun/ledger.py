"""The ledger: content-addressed blob store + hash-chained append-only event log.

This is the tamper-evidence substrate. Every captured execution writes an
``Event`` into a ``Session`` whose entries are chained by SHA-256. What the
chain provides (and, honestly, what it does not) is spelled out in
docs/TRUST_MODEL.md:

  - It DETECTS accidental mutation and out-of-order/partial edits, and gives a
    cheap self-consistency check.
  - It does NOT resist a determined local forger, who can regenerate the whole
    chain in milliseconds. The chain is a self-consistency check, not a forger
    barrier. Cross-party trust needs signing (deferred).

Determinism is a hard invariant: canonical JSON is byte-stable across processes
and platforms, and no timestamp is ever used for ordering — the chain is the
order.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sys
import tempfile
from dataclasses import dataclass, field, asdict, fields as dataclass_fields
from pathlib import Path
from typing import IO, Any, Iterator, Optional

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised only off POSIX
    fcntl = None  # type: ignore[assignment]

# True when this platform can serialize appends between processes. False means
# the degradation documented in docs/COMPAT.md is live: concurrent writers can
# fork the chain, exactly as v0.1 did everywhere. No portable fallback is
# invented here — a fallback that does not actually exclude would be worse than
# a declared gap, because callers would stop treating concurrency as a hazard.
APPEND_LOCK_AVAILABLE = fcntl is not None

# The ledger is secret-bearing by the tool's own account (docs/TRUST_MODEL.md):
# it holds argv verbatim, full stdout/stderr, and a content-addressed snapshot of
# every non-ignored file in the tree. 0700 on the root is the durable control —
# see Session.harden for what it does and does not cover.
LEDGER_DIR_MODE = 0o700
LEDGER_FILE_MODE = 0o600

# The append mutex. It lives INSIDE the ledger directory, which is excluded from
# every tree digest unconditionally and self-ignored by the "*" rule __init__
# writes — so it moves no digest and can never be committed.
LOCK_FILENAME = ".lock"

# The genesis link. The first entry chains from this fixed, well-known value so
# an empty vs tampered-truncated log are distinguishable.
GENESIS_HASH = "0" * 64

# The chain preimage this binary writes. Every entry_hash ever recorded was
# computed over version 1, so version 1's field list is frozen forever: a name
# added to or removed from it stops every archived entry_hash reproducing.
# A future schema adds a *new* version here and leaves 1 untouched.
PREIMAGE_VERSION = 1

# canonical_json sorts keys, so the order within each tuple does not affect the
# digest — only membership does.
_PREIMAGE_FIELDS: dict[int, tuple[str, ...]] = {
    1: (
        "argv",
        "cwd",
        "env_fingerprint",
        "observed_via",
        "coverage",
        "exit_code",
        "started_at",
        "ended_at",
        "stdout_blob",
        "stderr_blob",
        "transcript_blob",
        "tree_before",
        "tree_after",
        "submodule_dirty",
    ),
}

# Observation provenance. Only wrapper/shim events witnessed an actual exit code;
# a transcript only saw bytes on a terminal and must never claim an exit code.
OBSERVED_VIA = ("wrapper", "shim", "trap", "transcript")

# Per-item capture coverage, honest about what was actually observed.
COVERAGE = ("complete", "observed-text-only", "display-only", "unobserved")

_EXIT_BEARING = ("wrapper", "shim")


def sha256_hex(data: bytes) -> str:
    """SHA-256 of bytes as lowercase hex. The one hashing primitive."""
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON encoding used for both hashing and on-disk storage.

    Sorted keys, no insignificant whitespace, ``ensure_ascii`` so the byte
    stream is identical regardless of locale or platform. This byte-stability
    is what makes the chain reproducible across processes — it is tested, not
    assumed.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


class LedgerError(Exception):
    """Raised on a structural violation of a ledger invariant."""


def _open_private_append(path: Path) -> IO[bytes]:
    """Open ``path`` for binary append, creating it 0600 rather than 0666&~umask.

    The mode argument to ``os.open`` applies at CREATION only: a file an older
    binary already created at 0644 keeps 0644. That bound is deliberate and is
    documented on ``Session.harden`` — the root's 0700 is what makes it
    acceptable, and it is not the same statement as "the files are 0600".
    """
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, LEDGER_FILE_MODE)
    return os.fdopen(fd, "ab")


@contextlib.contextmanager
def _append_lock(root: Path) -> Iterator[None]:
    """Serialize a read-tail-and-append pair against other didrun processes.

    The hazard is corruption, not throughput. ``Session.append`` reads the tail,
    derives ``(index, prev_hash)`` from it, then writes; two processes that
    interleave those steps both write the SAME index chained from the SAME
    predecessor, and the fork is permanent — repairing it means rewriting the
    log, the one thing an evidence store must not do.

    ``flock`` is the right primitive precisely because it is owned by the kernel
    and released when the holder dies, however it dies. A PID-file or
    ``O_EXCL`` sentinel would introduce a stale-lock class that a SIGKILLed
    process leaves behind forever; this introduces none.

    Two bounds, stated rather than glossed:

      - Without ``fcntl`` this is a no-op and concurrent writers can fork the
        chain exactly as they could in v0.1. See ``APPEND_LOCK_AVAILABLE``.
      - ``flock`` over NFS and some network filesystems is emulated or ignored.
        The exclusion is as good as the filesystem's, and no better.

    The critical section is microseconds of local I/O. It is never held across a
    wrapped child process: the child has already exited by the time an event
    exists to append.
    """
    if fcntl is None:
        yield
        return
    path = Path(root) / LOCK_FILENAME
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, LEDGER_FILE_MODE)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class Event:
    """One observed execution.

    Fields are deliberately explicit rather than a free-form dict so the schema
    is auditable and the exit-code invariant is enforceable. ``tree_before`` /
    ``tree_after`` are git tree digests (see gitplumbing); ``None`` means the
    digest could not be taken honestly (→ the claim grades ``unknown``), never
    a guess.
    """

    argv: tuple[str, ...]
    cwd: str
    env_fingerprint: str
    observed_via: str
    coverage: str
    exit_code: Optional[int] = None
    started_at: Optional[float] = None
    ended_at: Optional[float] = None
    stdout_blob: Optional[str] = None
    stderr_blob: Optional[str] = None
    transcript_blob: Optional[str] = None
    tree_before: Optional[str] = None
    tree_after: Optional[str] = None
    submodule_dirty: bool = False

    def __post_init__(self) -> None:
        if self.observed_via not in OBSERVED_VIA:
            raise LedgerError(f"unknown observed_via: {self.observed_via!r}")
        if self.coverage not in COVERAGE:
            raise LedgerError(f"unknown coverage: {self.coverage!r}")
        # The honesty invariant that a PTY transcript can violate: it displays
        # "tests: 5 passed" for a command that exited 3 (measured — see
        # docs/MEASUREMENTS.md). Only wrapper/shim events witnessed a real exit.
        if self.exit_code is not None and self.observed_via not in _EXIT_BEARING:
            raise LedgerError(
                f"event observed_via={self.observed_via!r} cannot carry an "
                f"exit_code (only {_EXIT_BEARING} witness real exits)"
            )

    def self_stable(self) -> bool:
        """True if the working tree did not change across the command.

        Self-stability is the precondition for any *exact* grade: if the tree
        moved while the command ran, the evidence cannot be tree-exact.
        """
        return (
            self.tree_before is not None
            and self.tree_after is not None
            and self.tree_before == self.tree_after
        )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["argv"] = list(self.argv)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Event":
        # Unknown keys are dropped rather than fatal: a ledger written by a
        # newer binary must stay *readable* by this one. What is dropped is not
        # discarded silently — unknown_event_keys_of() reports it, and an entry
        # carrying any is graded unverifiable rather than recomputed.
        known = {k: v for k, v in d.items() if k in _EVENT_FIELD_NAMES}
        known["argv"] = tuple(known.get("argv", ()))
        return cls(**known)


_EVENT_FIELD_NAMES = frozenset(f.name for f in dataclass_fields(Event))


def unknown_event_keys_of(d: dict) -> tuple[str, ...]:
    """Keys in a stored event body that this binary's Event schema lacks."""
    return tuple(sorted(k for k in d if k not in _EVENT_FIELD_NAMES))


@dataclass
class ChainEntry:
    """One line of the session log: an event plus its chaining hashes."""

    index: int
    prev_hash: str
    event: Event
    entry_hash: str = ""
    # Neither of these is serialized into the event body or hashed; ChainEntry
    # is built by hand, never via asdict, so they are free.
    preimage_version: int = PREIMAGE_VERSION
    unknown_event_keys: tuple[str, ...] = ()

    def compute_hash(self) -> str:
        # The hash binds the previous link, the position, and the canonical
        # event body, projected onto the field list declared for this preimage
        # version. Reordering, truncation, or mutation all break it. At version
        # 1 the projection is byte-identical to the whole to_dict(), which is
        # what keeps every archived entry_hash reproducing.
        field_names = _PREIMAGE_FIELDS.get(self.preimage_version)
        if field_names is None:
            raise LedgerError(
                f"unknown chain preimage version: {self.preimage_version}"
            )
        d = self.event.to_dict()
        body = canonical_json(
            {
                "index": self.index,
                "prev": self.prev_hash,
                "event": {k: d[k] for k in field_names},
            }
        )
        return sha256_hex(self.prev_hash.encode("ascii") + body)


@dataclass(frozen=True)
class ChainVerdict:
    """The honest three-way answer about a chain, not a boolean.

    ``unverifiable`` is the state the boolean could not express: the entry was
    written by something this binary does not fully understand, so its hash
    cannot be recomputed. That is never the same statement as tamper.
    """

    status: str  # "intact" | "broken" | "unverifiable" | "empty"
    first_broken_index: Optional[int] = None
    unverifiable_index: Optional[int] = None
    reason: str = ""


class BlobStore:
    """Content-addressed byte store.

    Keyed by SHA-256 of content, so identical output across events is stored
    once (dedup). The directory can be redirected to a git object directory by
    the seal step; here it is a plain directory of ``<digest>`` files.
    """

    def __init__(self, root: Path, readonly: bool = False) -> None:
        self.root = Path(root)
        self.readonly = readonly
        # A read-only store creates nothing: it is opened by commands that only
        # read a ledger, and a directory conjured by `verify` is the same defect
        # as a world-readable one.
        if not readonly:
            self.root.mkdir(parents=True, exist_ok=True)

    def put(self, data: bytes) -> str:
        if self.readonly:
            raise LedgerError("read-only blob store: refusing to write a blob")
        digest = sha256_hex(data)
        path = self.root / digest
        if not path.exists():
            # Write-once. Atomic via a temp file + rename so a crash mid-write
            # never leaves a partial blob under a valid-looking digest.
            #
            # The temp name is unique PER WRITER, not `<digest>.tmp`. Two didrun
            # processes recording concurrently store the same blob constantly —
            # an empty stderr is one digest shared by every event — and with a
            # shared temp name the second writer's rename deletes the first
            # writer's temp out from under it, so the first dies on chmod or
            # replace with FileNotFoundError. Measured, not theorised: 2 of 6
            # eight-way concurrent `didrun run` attempts crashed that way. Both
            # writers producing the same bytes is exactly what content
            # addressing guarantees, so the last rename winning is correct.
            tmp_fd, tmp_name = tempfile.mkstemp(
                prefix=digest + ".", suffix=".tmp", dir=str(self.root)
            )
            tmp = Path(tmp_name)
            with os.fdopen(tmp_fd, "wb") as fh:
                fh.write(data)
            # os.replace preserves the SOURCE file's mode, so the blob inherits
            # whatever the temp had. mkstemp creates 0600, but state it rather
            # than depend on it: the blob is the one durable artifact here.
            os.chmod(tmp, LEDGER_FILE_MODE)
            os.replace(tmp, path)
        return digest

    def get(self, digest: str) -> bytes:
        path = self.root / digest
        if not path.exists():
            raise LedgerError(f"blob not found: {digest}")
        data = path.read_bytes()
        # Verify on read — a corrupted/edited blob is a tamper signal.
        if sha256_hex(data) != digest:
            raise LedgerError(f"blob digest mismatch (corruption): {digest}")
        return data

    def has(self, digest: str) -> bool:
        return (self.root / digest).exists()


class Session:
    """Append-only, hash-chained event log persisted as JSONL.

    Each line is a ``ChainEntry`` serialized with ``canonical_json``. Appends
    are the only mutation; ``verify_chain`` recomputes every link and reports
    the first break.
    """

    def __init__(self, root: Path, readonly: bool = False) -> None:
        self.root = Path(root)
        self.readonly = readonly
        # Set by every full read of the log (see _iter_records). A torn final
        # record is a lost event, never tamper, so it is reported rather than
        # raised — but it is never silent either.
        self.tail_truncated = False
        self.tail_truncated_offset: Optional[int] = None
        # Recorded, not asserted: on a platform without fcntl the append is not
        # serialized and two writers can fork the chain. A caller that wants to
        # say so can read this; nothing in the trust path branches on it, because
        # a lock is not evidence.
        self.append_serialized = APPEND_LOCK_AVAILABLE
        self.lock_path = Path(root) / LOCK_FILENAME
        if not readonly:
            self.root.mkdir(parents=True, exist_ok=True)
            self.harden()
            # The ledger is secret-bearing by construction (it records
            # everything a session printed). Self-ignore the whole directory so
            # a user's `git add -A` can never stage it — even if they forgot a
            # root-level rule. A `*` here ignores every path in the ledger,
            # including itself.
            gitignore = self.root / ".gitignore"
            if not gitignore.exists():
                with _open_private_append(gitignore) as fh:
                    fh.write(b"*\n")
        self.log_path = self.root / "session.log"
        self.blobs = BlobStore(self.root / "objects", readonly=readonly)

    def harden(self) -> None:
        """Force the ledger ROOT to 0700, repairing a ledger already on disk.

        The chmod is the load-bearing half: ``mkdir(exist_ok=True)`` never
        re-tightens an existing directory, so a ledger a v0.1 binary created at
        0755 would stay 0755 forever without this. It therefore runs on every
        writable open, not only on creation.

        **The bound, stated because a rounded-up version of it would be a lie.**
        This repairs the root and only the root. A ``session.log``,
        ``claims.jsonl`` or ``.gitignore`` an older binary created at 0644 keeps
        0644 — ``__init__`` writes ``.gitignore`` only when it is absent, so it
        is never re-created. 0700 on the root is what makes that acceptable:
        another uid cannot reach those files through the directory. It is NOT
        the same guarantee as "the files are 0600".

        ``objects/`` is deliberately not walked. git populates it directly via
        ``GIT_OBJECT_DIRECTORY``, twice per ``didrun run``, at git's own modes,
        so chmod-ing it would be undone by the next command.

        Never chmods a directory this process does not own: warns once on stderr
        and continues. ``os.geteuid`` does not exist on Windows, where the check
        is skipped (and where ``os.chmod`` is close to a no-op anyway — see
        docs/COMPAT.md).
        """
        geteuid = getattr(os, "geteuid", None)
        if geteuid is not None:
            try:
                owner = self.root.stat().st_uid
            except OSError as exc:
                print(f"didrun: cannot stat {self.root}: {exc}", file=sys.stderr)
                return
            if owner != geteuid():
                print(
                    f"didrun: not tightening {self.root} to 0700 — it is owned "
                    f"by uid {owner}, not this process",
                    file=sys.stderr,
                )
                return
        try:
            os.chmod(self.root, LEDGER_DIR_MODE)
        except OSError as exc:
            print(
                f"didrun: could not set {self.root} to 0700: {exc}",
                file=sys.stderr,
            )

    # --- reading the raw log --------------------------------------------------

    def _iter_records(self) -> Iterator[dict]:
        """Yield each stored record, tolerating a torn FINAL line.

        A process killed mid-append leaves a partial last line. ``json.loads``
        on it used to raise, and every reader called it, so one lost event
        killed the entire ledger — reads AND writes. The tolerance here is
        deliberately narrow: only the last line may fail to parse, the fact is
        recorded on ``tail_truncated`` rather than swallowed, and an
        unparseable line with data after it is corruption in the middle of the
        log, which stays a hard error.

        Read in binary so a tear that split a multi-byte sequence is a parse
        failure like any other rather than a decode error from the reader.
        """
        self.tail_truncated = False
        self.tail_truncated_offset = None
        if not self.log_path.exists():
            return
        torn_at: Optional[int] = None
        with self.log_path.open("rb") as fh:
            offset = 0
            for raw in fh:
                start = offset
                offset += len(raw)
                if torn_at is not None:
                    raise LedgerError(
                        f"session.log has an unparseable record at byte "
                        f"{torn_at} with {offset - torn_at} bytes of data after "
                        f"it: that is corruption inside the log, not an "
                        f"interrupted final write"
                    )
                line = raw.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    torn_at = start
                    continue
                yield rec
        if torn_at is not None:
            self.tail_truncated = True
            self.tail_truncated_offset = torn_at

    # --- writing -------------------------------------------------------------

    def _last(self) -> tuple[int, str]:
        """Return (last_index, last_hash) from the last PARSEABLE record.

        Shares ``_iter_records``' torn-tail tolerance deliberately. Giving it
        only to ``entries()`` would leave every subsequent ``append`` raising
        after an interrupted write: the reader would recover and the recorder
        would stay dead, which is the failure this is here to prevent. Reading
        past the tear is not the same as writing past it — ``append`` still
        refuses that.
        """
        last: Optional[dict] = None
        for rec in self._iter_records():
            last = rec
        if last is None:
            return -1, GENESIS_HASH
        return last["index"], last["entry_hash"]

    def append(self, event: Event) -> ChainEntry:
        # Checked BEFORE the lock so a read-only session never creates or opens
        # the lock file: `verify` and `show` must leave no trace in a ledger and
        # must never contend with a writer.
        if self.readonly:
            raise LedgerError("read-only session: refusing to append to the ledger")
        with _append_lock(self.root):
            return self._append_locked(event)

    def _append_locked(self, event: Event) -> ChainEntry:
        """The critical section: read the tail, derive the link, write the line.

        Split out only so the lock's extent is legible. Everything here must be
        cheap and local — a wrapped child has long since exited by the time an
        event exists to append, and the lock must never be widened to cover one.
        """
        last_index, last_hash = self._last()
        if self.tail_truncated:
            # Refuse; never truncate. Two reasons, and the second is the sharp
            # one. The ledger is evidence, so a writer that edits it to make
            # room is the one thing it must not do. And appending past the tear
            # would leave those partial bytes in the MIDDLE of the log, where
            # they are unparseable forever — a permanently broken chain, which
            # turns one lost event into a dead ledger. The offset is named so
            # an operator can decide.
            raise LedgerError(
                f"session.log has a torn final record at byte "
                f"{self.tail_truncated_offset}; refusing to append. One event "
                f"was lost to an interrupted write. Recover deliberately: "
                f"truncate the file to {self.tail_truncated_offset} bytes, or "
                f"archive this ledger and start a new one."
            )
        entry = ChainEntry(index=last_index + 1, prev_hash=last_hash, event=event)
        entry.entry_hash = entry.compute_hash()
        rec = {
            "index": entry.index,
            "prev_hash": entry.prev_hash,
            "entry_hash": entry.entry_hash,
            "event": event.to_dict(),
        }
        # Omitted at version 1 so a v1 record on disk stays byte-identical to
        # what every previous release wrote, and an older binary keeps reading it.
        if entry.preimage_version != 1:
            rec["preimage_version"] = entry.preimage_version
        # Append one canonical line. Newline-delimited so the tail read is cheap.
        with _open_private_append(self.log_path) as fh:
            fh.write(canonical_json(rec) + b"\n")
            # The line is evidence the moment append() returns: a crash between
            # here and the kernel's own flush would lose an event this process
            # already reported as recorded. fsync changes durability, never
            # bytes.
            fh.flush()
            os.fsync(fh.fileno())
        return entry

    # --- reading / verifying -------------------------------------------------

    def entries(self) -> Iterator[ChainEntry]:
        for rec in self._iter_records():
            body = rec["event"]
            entry = ChainEntry(
                index=rec["index"],
                prev_hash=rec["prev_hash"],
                event=Event.from_dict(body),
                entry_hash=rec["entry_hash"],
                # Absent means version 1: that is what every archived
                # record looks like and it must keep meaning v1.
                preimage_version=rec.get("preimage_version", 1),
                unknown_event_keys=unknown_event_keys_of(body),
            )
            yield entry

    def events(self) -> list[Event]:
        return [e.event for e in self.entries()]

    def verify_chain_detail(self) -> ChainVerdict:
        """Recompute the chain and report which of the four states it is in.

        Stops at the first entry that is broken or that cannot be recomputed.
        An entry this binary cannot recompute — an unknown preimage version, or
        event keys outside the version's declared-exhaustive field list — is
        ``unverifiable``: the projection would quietly hash a subset and
        reproduce the stored digest, so reporting ``intact`` there would be a
        lie and reporting ``broken`` would be a different one.

        A torn final record is none of those three. Every link that IS present
        recomputes, so the status is ``intact`` over the surviving prefix and
        the truncation travels in the reason. Calling it ``broken`` would read
        as tamper for what is only a lost event, and that is the one
        mistranslation this tool cannot afford.
        """
        prev = GENESIS_HASH
        expected_index = 0
        seen = False
        for entry in self.entries():
            seen = True
            if entry.index != expected_index:
                return ChainVerdict(
                    "broken",
                    first_broken_index=entry.index,
                    reason=(
                        f"entry index {entry.index} out of sequence "
                        f"(expected {expected_index})"
                    ),
                )
            if entry.prev_hash != prev:
                return ChainVerdict(
                    "broken",
                    first_broken_index=entry.index,
                    reason=f"entry {entry.index} does not link to the previous entry",
                )
            if entry.unknown_event_keys:
                return ChainVerdict(
                    "unverifiable",
                    unverifiable_index=entry.index,
                    reason=(
                        f"entry {entry.index} carries event keys this binary does "
                        f"not know ({', '.join(entry.unknown_event_keys)}); its "
                        f"preimage cannot be recomputed"
                    ),
                )
            try:
                recomputed = entry.compute_hash()
            except LedgerError as exc:
                return ChainVerdict(
                    "unverifiable",
                    unverifiable_index=entry.index,
                    reason=f"entry {entry.index}: {exc}",
                )
            if recomputed != entry.entry_hash:
                return ChainVerdict(
                    "broken",
                    first_broken_index=entry.index,
                    reason=f"entry {entry.index} does not recompute to its stored hash",
                )
            prev = entry.entry_hash
            expected_index += 1
        # Only reachable once the iteration finished, which is exactly when the
        # torn-tail flag is known: every early return above stopped at a fault
        # that dominates this one.
        tail = ""
        if self.tail_truncated:
            tail = (
                f"the log's final record is torn at byte "
                f"{self.tail_truncated_offset} — one event was lost to an "
                f"interrupted write; this verdict covers the surviving prefix"
            )
        if not seen:
            return ChainVerdict("empty", reason=tail)
        return ChainVerdict("intact", reason=tail)

    def verify_chain(self) -> tuple[bool, Optional[int]]:
        """Recompute the chain. Returns (ok, first_broken_index).

        ``first_broken_index`` is the index whose stored hash or linkage does
        not recompute — the earliest point tamper is detectable. ``None`` when
        the chain is intact.

        A thin wrapper over ``verify_chain_detail``; anything other than intact
        or empty is ``ok=False``, including ``unverifiable``, which collapses to
        the same boolean but is never the same fact. Callers that need to tell
        "cannot recompute" from "tamper" must use ``verify_chain_detail``. This
        signature is depended on and does not change.
        """
        verdict = self.verify_chain_detail()
        if verdict.status in ("intact", "empty"):
            return True, None
        if verdict.status == "broken":
            return False, verdict.first_broken_index
        return False, verdict.unverifiable_index
