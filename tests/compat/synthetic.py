"""A deterministic, archive-shaped synthetic corpus.

The real corpus cannot ship: it is secret-bearing, it is 174 MB, and it belongs
to a running build. So CI gets this instead — a tree with the same *shapes* the
real archives have, generated from literals with no randomness and no wall
clock, carrying one instance of every outcome the replay legs are supposed to
detect.

Nothing in here is real. Paths, digests, argv and labels are invented; the only
product code used is the code under test (``Event``, ``ChainEntry``,
``Manifest``), so the fixture's shape follows the schema instead of drifting
from it.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from didrun.claims import Claim, GradeResult
from didrun.ledger import (
    GENESIS_HASH,
    ChainEntry,
    Event,
    canonical_json,
    sha256_hex,
)
from didrun.manifest import MANIFEST_VERSION, Manifest

# Fixed identities and timestamps: the fixture must be byte-identical on every
# machine and every run, so nothing here may read the clock or the environment.
_GIT_ENV = {
    "GIT_AUTHOR_NAME": "compat fixture",
    "GIT_AUTHOR_EMAIL": "fixture@invalid",
    "GIT_COMMITTER_NAME": "compat fixture",
    "GIT_COMMITTER_EMAIL": "fixture@invalid",
    "GIT_AUTHOR_DATE": "2020-01-01T00:00:00+00:00",
    "GIT_COMMITTER_DATE": "2020-01-01T00:00:00+00:00",
}

_SYNTHETIC_CWD = "/w/repo"
_SYNTHETIC_FINGERPRINT = "v1:0123456789abcdef"
_SYNTHETIC_TREE = "3" * 40


@dataclass(frozen=True)
class Expectations:
    """What the legs must report for this fixture. Declared, never derived."""

    # Ordered by sorted ledger-directory path, which is the order the harness
    # walks. See build_corpus for which unit is which.
    log_statuses: tuple
    log_entries: tuple
    objects: dict
    notes: int
    claim_shape: dict


@dataclass(frozen=True)
class SyntheticCorpus:
    root: Path
    expected: Expectations


def _git(root: Path, *args: str, stdin: Optional[bytes] = None) -> bytes:
    """Run git in ``root``. Never echoes git's output — it can carry paths."""
    proc = subprocess.run(
        ["git", "-C", str(root), *args],
        input=stdin,
        capture_output=True,
        env={**os.environ, **_GIT_ENV},
    )
    if proc.returncode != 0:
        raise RuntimeError(f"synthetic fixture: git {args[0]} failed")
    return proc.stdout


def _init_repo(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "fixture@invalid")
    _git(root, "config", "user.name", "compat fixture")
    _git(root, "config", "commit.gpgsign", "false")
    # Git's background maintenance can repack while a test walks objects.
    _git(root, "config", "gc.auto", "0")
    _git(root, "config", "maintenance.auto", "false")


def _commit(root: Path, name: str, body: str) -> str:
    (root / name).write_text(body, encoding="ascii")
    _git(root, "add", name)
    _git(root, "commit", "-qm", f"fixture {name}")
    return _git(root, "rev-parse", "HEAD").decode("ascii").strip()


def _attach_note(root: Path, commit: str, body: bytes) -> None:
    _git(
        root,
        "notes",
        "--ref=refs/notes/didrun",
        "add",
        "-f",
        "-F",
        "-",
        commit,
        stdin=body,
    )


# --- the ledger side ---------------------------------------------------------


def _event(i: int) -> Event:
    return Event(
        argv=("pytest", "-q"),
        cwd=_SYNTHETIC_CWD,
        env_fingerprint=_SYNTHETIC_FINGERPRINT,
        observed_via="wrapper",
        coverage="complete",
        exit_code=0,
        started_at=1000000.0 + i,
        ended_at=1000001.0 + i,
        stdout_blob=sha256_hex(f"synthetic-stdout-{i}".encode("ascii")),
        stderr_blob=None,
        transcript_blob=None,
        tree_before=_SYNTHETIC_TREE,
        tree_after=_SYNTHETIC_TREE,
        submodule_dirty=False,
    )


def _chain(count: int) -> list:
    """``count`` well-formed, correctly chained records."""
    records = []
    prev = GENESIS_HASH
    for i in range(count):
        entry = ChainEntry(index=i, prev_hash=prev, event=_event(i))
        entry.entry_hash = entry.compute_hash()
        records.append(
            {
                "index": i,
                "prev_hash": prev,
                "entry_hash": entry.entry_hash,
                "event": entry.event.to_dict(),
            }
        )
        prev = entry.entry_hash
    return records


def _write_log(path: Path, records: list, torn_tail: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        for rec in records:
            fh.write(canonical_json(rec) + b"\n")
        if torn_tail:
            # A process killed mid-append: a partial line, no newline. This is
            # the commonest real-world damage and it must not read as tamper.
            fh.write(canonical_json(_chain(1)[0])[:37])


def _write_objects(objects: Path, flat: int, fanout: int) -> None:
    """An objects/ dir carrying both namespaces, like 113 of the real archives."""
    objects.mkdir(parents=True, exist_ok=True)
    for i in range(flat):
        digest = sha256_hex(f"synthetic-blob-{i}".encode("ascii"))
        (objects / digest).write_bytes(b"synthetic blob\n")
    for i in range(fanout):
        loose = sha256_hex(f"synthetic-loose-{i}".encode("ascii"))[:40]
        d = objects / loose[:2]
        d.mkdir(exist_ok=True)
        (d / loose[2:]).write_bytes(b"synthetic loose object\n")


# --- the note side -----------------------------------------------------------


def _claim_entry(
    ctype: str,
    label: str,
    grade: str,
    supporting: Optional[int],
    declared_at: int,
    pathspecs: tuple = (),
    exit_code: Optional[int] = 0,
) -> dict:
    """One graded claim in the shape seal() writes into a note."""
    result = GradeResult(
        claim=Claim(
            ctype=ctype,
            label=label,
            event_indices=(supporting,) if supporting is not None else (),
            pathspecs=pathspecs,
            declared_at_index=declared_at,
        ),
        grade=grade,
        reason="synthetic fixture",
        delta=[],
        supporting_event_index=supporting,
        exit_code=exit_code,
    )
    d = result.to_dict()
    d["claim"]["argv_preview"] = ["pytest", "-q"]
    return d


def _conjunction_entry(
    label: str,
    grade: str,
    conjunct_grades: tuple,
    declared_at: int,
) -> dict:
    """One graded conjunction, in the shape seal() writes into a v3 note.

    ``grade`` is declared, not derived: every value in this fixture is a literal
    so the legs measure the instrument against a shape whose every field is
    stated. It binds no event and declares no pathspec, so its `argv_preview` is
    empty — the same thing seal() writes for a claim with no supporting event.
    """
    result = GradeResult(
        claim=Claim(
            ctype="conjunction",
            label=label,
            event_indices=(),
            declared_at_index=declared_at,
            conjuncts=tuple(name for name, _g in conjunct_grades),
        ),
        grade=grade,
        reason="synthetic fixture",
        conjunct_grades=conjunct_grades,
    )
    d = result.to_dict()
    d["claim"]["argv_preview"] = []
    return d


def _strip_post_v2_claim_keys(body: dict) -> None:
    """Remove the claim keys no note before v3 carried.

    ``Claim.to_dict`` emits ``conjuncts`` for every claim, so a body built from
    the current dataclass carries it whatever version number the fixture stamps
    on the manifest. A note that says version 1 and holds a v3 claim shape would
    make the older legs read as passing on a shape they never see in an archive.
    """
    for entry in body.get("claims", []):
        entry.get("claim", {}).pop("conjuncts", None)


def _coverage() -> dict:
    return {"events": 3, "complete": 3, "observed_text_only": 0, "display_only": 0}


def build_corpus(root: Path) -> SyntheticCorpus:
    """Build the good-path fixture and return it with its declared expectations.

    Ledger directories, in the sorted order the harness walks them:

      0  unit-01-good-nested      nested <name>/.didrun/, 3 entries, intact
      1  unit-02-good-flat        flat <name>/, 1 entry, intact
      2  unit-03-torn-tail        2 entries + a partial final line
      3  unit-04-unknown-key      an event key this binary does not know
      4  unit-05-unknown-preimage a preimage version this binary does not know
      5  unit-06-empty            a zero-byte log
      6  unit-07-broken-hash      3 entries, entry 1's stored hash mutated
    """
    root = Path(root)
    _init_repo(root)
    history = root / ".didrun-history"

    nested = history / "unit-01-good-nested" / ".didrun"
    _write_log(nested / "session.log", _chain(3))
    _write_objects(nested / "objects", flat=2, fanout=2)
    # Present in 94 / 62 of the real archives; the legs only stat their shape.
    (nested / "claims.jsonl").write_bytes(b"")
    (nested / "seals.jsonl").write_bytes(b"")

    flat = history / "unit-02-good-flat"
    _write_log(flat / "session.log", _chain(1))
    _write_objects(flat / "objects", flat=1, fanout=1)

    _write_log(
        history / "unit-03-torn-tail" / ".didrun" / "session.log",
        _chain(2),
        torn_tail=True,
    )

    unknown_key = _chain(1)
    unknown_key[0]["event"]["signal"] = 9
    _write_log(history / "unit-04-unknown-key" / ".didrun" / "session.log", unknown_key)

    unknown_preimage = _chain(1)
    unknown_preimage[0]["preimage_version"] = 2
    _write_log(
        history / "unit-05-unknown-preimage" / ".didrun" / "session.log",
        unknown_preimage,
    )

    empty = history / "unit-06-empty" / ".didrun" / "session.log"
    empty.parent.mkdir(parents=True, exist_ok=True)
    empty.write_bytes(b"")

    broken = _chain(3)
    stored = broken[1]["entry_hash"]
    broken[1]["entry_hash"] = ("0" if stored[0] != "0" else "1") + stored[1:]
    _write_log(history / "unit-07-broken-hash" / ".didrun" / "session.log", broken)

    # Four notes, one per manifest version this binary must read plus one that
    # exercises the additive-key allowlist. The second deliberately omits
    # `secrets_override` — the one key from_json already reads with a
    # v1-reproducing default — so the allowlist is exercised by the good path and
    # not only by a meta-test. The version ladder is covered on purpose: v3 is
    # what this build writes, and a leg that only ever reads the version it wrote
    # would say nothing about the 65 v1 notes already published.
    commit_a = _commit(root, "work-a.txt", "one\n")
    manifest_a = Manifest(
        version=MANIFEST_VERSION,
        commit=commit_a,
        tree=_SYNTHETIC_TREE,
        claims=[
            _claim_entry("tests-pass", "suite", "tree-exact", 0, 0),
            _claim_entry(
                "lint-clean", "lint", "scope-exact", 1, 2, pathspecs=("src/",)
            ),
            _claim_entry("command-succeeded", "build", "stale", 0, 6),
        ],
        coverage=_coverage(),
        secrets_override=False,
    )
    _attach_note(root, commit_a, manifest_a.to_json())

    # A v2 note: the version before the claim vocabulary gained `conjunction`.
    # Pinned to the literal 2 rather than MANIFEST_VERSION so this leg keeps
    # reading a note one version behind whatever this build writes.
    commit_b = _commit(root, "work-b.txt", "two\n")
    body_b = json.loads(
        Manifest(
            version=2,
            commit=commit_b,
            tree=_SYNTHETIC_TREE,
            claims=[_claim_entry("tests-pass", "suite", "failed", 0, 0, exit_code=1)],
            coverage=_coverage(),
            secrets_override=False,
        ).to_json()
    )
    del body_b["secrets_override"]
    _strip_post_v2_claim_keys(body_b)
    _attach_note(root, commit_b, canonical_json(body_b))

    # A v3 note carrying a conjunction: the claim shape the vocabulary extension
    # added. It binds no event and names its members by label, and the note holds
    # what each member earned beside the grade the conjunction took from them.
    commit_c = _commit(root, "work-c.txt", "three\n")
    manifest_c = Manifest(
        version=MANIFEST_VERSION,
        commit=commit_c,
        tree=_SYNTHETIC_TREE,
        claims=[
            _claim_entry("tests-pass", "unit", "tree-exact", 0, 0),
            _claim_entry("lint-clean", "lint", "tree-exact", 1, 1),
            _conjunction_entry(
                "release",
                "tree-exact",
                (("unit", "tree-exact"), ("lint", "tree-exact")),
                2,
            ),
        ],
        coverage=_coverage(),
        secrets_override=False,
    )
    _attach_note(root, commit_c, manifest_c.to_json())

    # A v1 note, in the shape the archives actually hold one: none of the keys
    # any later version added. Every one of them is on v1's additive allowlist,
    # so this is the leg's statement that a note published before v0.2 still
    # round-trips under a reader three versions later.
    commit_d = _commit(root, "work-d.txt", "four\n")
    body_d = json.loads(
        Manifest(
            version=1,
            commit=commit_d,
            tree=_SYNTHETIC_TREE,
            claims=[_claim_entry("tests-pass", "suite", "tree-exact", 0, 0)],
            coverage=_coverage(),
        ).to_json()
    )
    for added_after_v1 in (
        "secrets_override",
        "secrets",
        "claims_from",
        "claims_to",
        "authority",
    ):
        del body_d[added_after_v1]
    _strip_post_v2_claim_keys(body_d)
    _attach_note(root, commit_d, canonical_json(body_d))

    expected = Expectations(
        log_statuses=(
            "intact",
            "intact",
            "torn-tail",
            "unverifiable@0",
            "unverifiable@0",
            "empty",
            "broken@1",
        ),
        log_entries=(3, 1, 2, 1, 1, 0, 3),
        objects={"dirs": 2, "flat-64hex": 3, "git-fanout": 3},
        notes=4,
        claim_shape={
            "notes": 4,
            "claims": 8,
            # The conjunction binds no event, so it is not a multi-index claim
            # and never becomes one: that shape is what the design review ruled
            # out, and this counter is the leg that would catch it arriving.
            "multi-index": 0,
            "max-pathspecs": 1,
            "pathspecs": {0: 7, 1: 1},
            "gap-ge-1": 2,
            "gap-ge-5": 1,
            "grades": {"failed": 1, "scope-exact": 1, "stale": 1, "tree-exact": 5},
        },
    )
    return SyntheticCorpus(root=root, expected=expected)


def build_known_bad(root: Path) -> Path:
    """A second tree whose *note* and *objects* legs must come back red.

    Kept separate from build_corpus so the good fixture stays green: a leg that
    is red for a reason that is actually correct behaviour is a leg nobody will
    trust.
    """
    root = Path(root)
    _init_repo(root)
    history = root / ".didrun-history"

    # A third path shape in objects/: neither a flat 64-hex blob nor a git
    # fan-out dir. The classifier must fail closed on it rather than ignore it.
    residue = history / "unit-bad-objects" / ".didrun" / "objects"
    _write_objects(residue, flat=1, fanout=1)
    (residue / "pack").mkdir()
    (residue / "notes.txt").write_bytes(b"third shape\n")
    _write_log(history / "unit-bad-objects" / ".didrun" / "session.log", _chain(1))

    commit = _commit(root, "work.txt", "bad\n")
    # A note from a manifest version this binary must refuse, not coerce.
    too_new = json.loads(
        Manifest(
            version=MANIFEST_VERSION,
            commit=commit,
            tree=_SYNTHETIC_TREE,
            claims=[],
            coverage=_coverage(),
        ).to_json()
    )
    too_new["version"] = MANIFEST_VERSION + 1
    _attach_note(root, commit, canonical_json(too_new))
    return root


def multi_index_note_body(commit: str = "a" * 40) -> bytes:
    """A note carrying the claim shape the corpus says does not exist.

    0 of 846 real claims bind more than one event; two of the audit's blocker
    findings turned on that. This is the counter-example the leg must catch.
    """
    entry = _claim_entry("tests-pass", "suite", "tree-exact", 0, 0)
    entry["claim"]["event_indices"] = [0, 1]
    two_specs = _claim_entry(
        "lint-clean", "lint", "scope-exact", 1, 1, pathspecs=("src/", "tests/")
    )
    return Manifest(
        version=MANIFEST_VERSION,
        commit=commit,
        tree=_SYNTHETIC_TREE,
        claims=[entry, two_specs],
        coverage=_coverage(),
    ).to_json()
