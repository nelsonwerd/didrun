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

import hashlib
import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterator, Optional

# The genesis link. The first entry chains from this fixed, well-known value so
# an empty vs tampered-truncated log are distinguishable.
GENESIS_HASH = "0" * 64

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
        d = dict(d)
        d["argv"] = tuple(d.get("argv", ()))
        return cls(**d)


@dataclass
class ChainEntry:
    """One line of the session log: an event plus its chaining hashes."""

    index: int
    prev_hash: str
    event: Event
    entry_hash: str = ""

    def compute_hash(self) -> str:
        # The hash binds the previous link, the position, and the canonical
        # event body. Reordering, truncation, or mutation all break it.
        body = canonical_json(
            {"index": self.index, "prev": self.prev_hash, "event": self.event.to_dict()}
        )
        return sha256_hex(self.prev_hash.encode("ascii") + body)


class BlobStore:
    """Content-addressed byte store.

    Keyed by SHA-256 of content, so identical output across events is stored
    once (dedup). The directory can be redirected to a git object directory by
    the seal step; here it is a plain directory of ``<digest>`` files.
    """

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, data: bytes) -> str:
        digest = sha256_hex(data)
        path = self.root / digest
        if not path.exists():
            # Write-once. Atomic via a temp file + rename so a crash mid-write
            # never leaves a partial blob under a valid-looking digest.
            tmp = self.root / (digest + ".tmp")
            tmp.write_bytes(data)
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

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        # The ledger is secret-bearing by construction (it records everything a
        # session printed). Self-ignore the whole directory so a user's
        # `git add -A` can never stage it — even if they forgot a root-level
        # rule. A `*` here ignores every path in the ledger, including itself.
        gitignore = self.root / ".gitignore"
        if not gitignore.exists():
            gitignore.write_text("*\n", encoding="ascii")
        self.log_path = self.root / "session.log"
        self.blobs = BlobStore(self.root / "objects")

    # --- writing -------------------------------------------------------------

    def _last(self) -> tuple[int, str]:
        """Return (last_index, last_hash) by reading the tail of the log."""
        if not self.log_path.exists():
            return -1, GENESIS_HASH
        last_line = None
        with self.log_path.open("r", encoding="ascii") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last_line = line
        if last_line is None:
            return -1, GENESIS_HASH
        rec = json.loads(last_line)
        return rec["index"], rec["entry_hash"]

    def append(self, event: Event) -> ChainEntry:
        last_index, last_hash = self._last()
        entry = ChainEntry(index=last_index + 1, prev_hash=last_hash, event=event)
        entry.entry_hash = entry.compute_hash()
        rec = {
            "index": entry.index,
            "prev_hash": entry.prev_hash,
            "entry_hash": entry.entry_hash,
            "event": event.to_dict(),
        }
        # Append one canonical line. Newline-delimited so the tail read is cheap.
        with self.log_path.open("ab") as fh:
            fh.write(canonical_json(rec) + b"\n")
        return entry

    # --- reading / verifying -------------------------------------------------

    def entries(self) -> Iterator[ChainEntry]:
        if not self.log_path.exists():
            return
        with self.log_path.open("r", encoding="ascii") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                entry = ChainEntry(
                    index=rec["index"],
                    prev_hash=rec["prev_hash"],
                    event=Event.from_dict(rec["event"]),
                    entry_hash=rec["entry_hash"],
                )
                yield entry

    def events(self) -> list[Event]:
        return [e.event for e in self.entries()]

    def verify_chain(self) -> tuple[bool, Optional[int]]:
        """Recompute the chain. Returns (ok, first_broken_index).

        ``first_broken_index`` is the index whose stored hash or linkage does
        not recompute — the earliest point tamper is detectable. ``None`` when
        the chain is intact.
        """
        prev = GENESIS_HASH
        expected_index = 0
        for entry in self.entries():
            if entry.index != expected_index:
                return False, entry.index
            if entry.prev_hash != prev:
                return False, entry.index
            if entry.compute_hash() != entry.entry_hash:
                return False, entry.index
            prev = entry.entry_hash
            expected_index += 1
        return True, None
