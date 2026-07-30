"""P0.1 — seal publishes fail-closed, on stdin, atomically with the watermark.

The defect these pin: `_attach_note` discarded git's exit status, so a denied
write to refs/notes/didrun produced a silent half-seal — no note, watermark
advanced, exit 0. The pair (note published, watermark advanced) is now atomic
in both directions, and the rollback RESTORES a note it overwrote rather than
removing it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from didrun import cli
from didrun import manifest as M
from didrun.capture import run_wrapped
from didrun.claims import Claim
from didrun.ledger import Session

# Captured at import so a selective patch can delegate without recursing.
_REAL_RUN = subprocess.run

# Keys `to_json()` emits that a note of this manifest version never carried.
# Additive fields land here as a DELIBERATE one-line diff, never silently.
# v2 adds no TOP-LEVEL key: the evidence binding lives inside each claim entry,
# so the manifest's own key set is unchanged from v1.
# `claims_from`/`claims_to` are P4.1's: the claim window the seal covered. Both
# are additive with a reading default (0 / len(claims)), so a stored note of
# EITHER version legitimately lacks them, and both rows carry them.
# v3 is P4.2's `conjunction` claim type, which adds no top-level key either: the
# conjunct list and the per-conjunct grades live inside a claim entry. The row
# exists so the version this build writes has a DECLARED allowlist instead of a
# KeyError, and so a v3-only top-level field would still have to land here on
# purpose.
_ADDITIVE_KEYS_BY_MANIFEST_VERSION = {
    1: frozenset({"claims_from", "claims_to"}),
    2: frozenset({"claims_from", "claims_to"}),
    3: frozenset({"claims_from", "claims_to"}),
}


def _session(repo: Path) -> Session:
    return Session(repo / ".didrun")


def _seeded(repo: Path, labels=("t",)) -> Session:
    """One recorded event plus one claim per label, ready to seal."""
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "print(1)"], s, repo)
    for label in labels:
        M.declare_claim(
            s, Claim(ctype="tests-pass", label=label, event_indices=(0,), declared_at_index=0)
        )
    return s


def _seal_lines(repo: Path) -> int:
    path = repo / ".didrun" / "seals.jsonl"
    if not path.exists():
        return 0
    return len([ln for ln in path.read_text(encoding="ascii").splitlines() if ln.strip()])


def _note_bytes(repo: Path, commit: str = "HEAD"):
    """The raw note body, or None when the commit carries no note."""
    proc = _REAL_RUN(
        ["git", "notes", f"--ref={M.NOTES_REF}", "show", commit],
        cwd=str(repo),
        capture_output=True,
    )
    return proc.stdout if proc.returncode == 0 else None


def _is_notes_add(argv) -> bool:
    argv = list(argv)
    return argv[:2] == ["git", "notes"] and "add" in argv


def _patch_notes_add(monkeypatch, returncode: int, seen: list):
    """Fail (or merely observe) ONLY `git notes … add`.

    A blanket patch of `manifest.subprocess.run` is wrong: the same symbol
    serves `_rev` and `_resolve_manifest`, so a blanket failure aborts the seal
    before it ever reaches `_attach_note` and the test passes for the wrong
    reason. A failing `git` shim on PATH has the same defect.
    """

    def fake(argv, *args, **kwargs):
        if _is_notes_add(argv):
            seen.append((list(argv), kwargs.get("input")))
            if returncode != 0:
                return subprocess.CompletedProcess(
                    list(argv), returncode, b"", b"fatal: could not write note object"
                )
        return _REAL_RUN(argv, *args, **kwargs)

    monkeypatch.setattr(M.subprocess, "run", fake)


def _round_trip(body: bytes) -> M.Manifest:
    """The note round-trip criterion: newline discipline, key-superset semantic
    equality, serialization idempotence. Deliberately NOT byte equality —
    `git notes` appends a trailing newline to every body, so that assertion is
    false on every real note.
    """
    # (a) strip at most one trailing newline, and prove at most one was there.
    assert body.endswith(b"\n"), "note body does not end in a newline"
    stripped = body[:-1]
    assert not stripped.endswith(b"\n"), "note body carries more than one trailing newline"

    manifest = M.Manifest.from_json(stripped)
    source = json.loads(stripped)
    emitted = json.loads(manifest.to_json())

    # (b) every source key survives with an equal value; extras are allowlisted.
    for key, value in source.items():
        assert key in emitted, f"round-trip dropped manifest key {key!r}"
        assert emitted[key] == value, f"round-trip changed manifest key {key!r}"
    # The allowlist is the BOUND on what may be missing, not an exact set: every
    # body this helper sees was written by the seal under test, so it already
    # carries every key `to_json` emits and the extra set is empty. Exact
    # equality here asserted that a note this binary just published must LACK a
    # key it declares, which stopped being true the moment an additive field
    # landed. The leg that actually exercises a key-lacking note is
    # tests/compat's leg 2 (over stored v1 bodies), plus the byte pin below.
    extra = frozenset(emitted) - frozenset(source)
    allowed = _ADDITIVE_KEYS_BY_MANIFEST_VERSION[source["version"]]
    assert extra <= allowed, (
        f"unexpected extra manifest keys {sorted(extra - allowed)} — a field was "
        "added without updating the per-version allowlist"
    )

    # (c) serialization is idempotent; this is where canonical_json is pinned.
    once = manifest.to_json()
    assert M.Manifest.from_json(once).to_json() == once
    return manifest


def test_note_publication_failure_is_fatal(repo: Path, monkeypatch):
    """git refuses the note -> seal raises, nothing is recorded, no note exists."""
    s = _seeded(repo)
    seen: list = []
    _patch_notes_add(monkeypatch, 1, seen)

    with pytest.raises(M.ManifestError) as exc:
        M.seal(s, repo)

    assert "could not publish note" in str(exc.value)
    assert "fatal: could not write note object" in str(exc.value)
    assert seen, "the selective patch never saw a `git notes add` — wrong seam"
    assert _seal_lines(repo) == 0
    assert _note_bytes(repo) is None


def test_watermark_failure_rolls_back_and_leaves_no_note(repo: Path, monkeypatch):
    """No prior note: a failed watermark write must leave the commit noteless."""
    s = _seeded(repo)

    def boom(*args, **kwargs):
        raise OSError("read-only file system: seals.jsonl")

    monkeypatch.setattr(M, "_record_seal", boom)

    with pytest.raises(M.ManifestError) as exc:
        M.seal(s, repo)

    message = str(exc.value)
    assert "no watermark was recorded" in message
    assert "rolled back" in message
    assert "noteless" in message
    assert "read-only file system" in message
    assert _seal_lines(repo) == 0
    assert _note_bytes(repo) is None


def test_watermark_failure_restores_a_prior_note(repo: Path, monkeypatch):
    """The rollback may never destroy evidence the commit already carried.

    This is the leg a `git notes remove` rollback fails: `_attach_note` forces,
    so the seal overwrote a real prior note.
    """
    s = _seeded(repo)
    subprocess.run(
        ["git", "notes", f"--ref={M.NOTES_REF}", "add", "-f", "-m", "prior evidence body"],
        cwd=str(repo),
        capture_output=True,
        check=True,
    )
    prior = _note_bytes(repo)
    assert prior == b"prior evidence body\n"

    def boom(*args, **kwargs):
        raise OSError("read-only file system: seals.jsonl")

    monkeypatch.setattr(M, "_record_seal", boom)

    # `reseal=True` because the prior note here is deliberately NOT a didrun
    # manifest, so it records no claim window and P4.1 refuses to replace it
    # blind. This test's subject is the rollback restoring the overwritten body
    # byte-for-byte, which needs the seal to reach `_record_seal` at all.
    with pytest.raises(M.ManifestError) as exc:
        M.seal(s, repo, reseal=True)

    message = str(exc.value)
    assert "no watermark was recorded" in message
    assert "prior note was restored" in message
    assert _seal_lines(repo) == 0
    assert _note_bytes(repo) == prior  # byte-restored, not removed


def test_body_travels_on_stdin_not_argv(repo: Path, monkeypatch):
    """The real criterion: `-F -` with the body on `input=`, and no `-m`."""
    s = _seeded(repo)
    seen: list = []
    _patch_notes_add(monkeypatch, 0, seen)

    m = M.seal(s, repo)

    assert len(seen) == 1
    argv, stdin = seen[0]
    assert "-F" in argv
    assert "-" in argv
    assert "-m" not in argv
    body = m.to_json()
    assert body not in [el.encode("ascii") if isinstance(el, str) else el for el in argv]
    assert all(body.decode("ascii") != el for el in argv)
    assert stdin == body


def test_note_larger_than_arg_max_publishes_and_resolves(repo: Path):
    """A body over 1.5 MB — past Linux's 131,072-byte MAX_ARG_STRLEN per argument
    and past macOS's 1,048,576-byte kern.argmax — publishes and re-resolves.

    256 KB is the wrong number: it succeeds under `-m` on macOS and fails under
    `-m` on Linux, so it proves nothing and diverges by platform.
    """
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "print(1)"], s, repo)
    M.declare_claim(
        s,
        Claim(
            ctype="tests-pass",
            label="x" * 1_600_000,
            event_indices=(0,),
            declared_at_index=0,
        ),
    )

    m = M.seal(s, repo)
    body = _note_bytes(repo)
    assert body is not None
    assert len(body) >= 1_572_864, f"body is only {len(body)} bytes — too small to bind"

    resolved = _round_trip(body)
    assert resolved == m
    assert M.verify(s, repo).all_verified


def test_happy_path_publishes_exactly_what_it_returns(repo: Path):
    s = _seeded(repo)

    m = M.seal(s, repo)

    assert _seal_lines(repo) == 1
    body = _note_bytes(repo)
    assert body is not None
    assert _round_trip(body) == m


def test_happy_path_cli_still_exits_zero(repo: Path):
    _seeded(repo)

    assert cli.main(["--repo", str(repo), "seal"]) == 0
    assert _seal_lines(repo) == 1
    assert _note_bytes(repo) is not None


def test_manifest_json_bytes_are_pinned():
    """The manifest's on-the-wire bytes are compat surface across every sealed
    note. A `to_json` tidy-up would move them silently; this pin makes any move
    a deliberate diff.

    P3.2 adds exactly one key, `secrets`, whose default is `{}`. Every key a
    stored note carries still comes back with an equal value, so the addition
    is additive with a v1-reproducing default — which is why this is a one-line
    diff here plus a one-line diff in the compat allowlist, and not a
    MANIFEST_VERSION bump.

    P4.1 adds `claims_from`/`claims_to`, the claim window the seal covered, on
    the same terms: reading defaults of 0 and `len(claims)`, so no stored note
    changes meaning and this stays a deliberate diff rather than a version bump.

    P5.1 adds `authority`, the cited authorization artifacts, with a reading
    default of `[]` — and it sorts FIRST, so the pinned bytes move at the front.
    Same terms again: additive, no version bump, one deliberate diff here and one
    in the compat allowlist. It is a manifest key and not an `Event` field
    precisely so it can be exactly this: a change no stored note notices.
    """
    m = M.Manifest(
        version=1,
        commit="0" * 40,
        tree="1" * 40,
        claims=[
            {
                "claim": {
                    "argv_preview": ["pytest", "-q"],
                    "ctype": "tests-pass",
                    "declared_at_index": 0,
                    "event_indices": [0],
                    "label": "t",
                    "pathspecs": [],
                },
                "delta": [],
                "exit_code": 0,
                "grade": "tree-exact",
                "reason": "r",
                "supporting_event_index": 0,
            }
        ],
        coverage={"by_coverage": {"complete": 1}, "total_events": 1},
    )
    assert m.to_json() == (
        b'{"authority":[],'
        b'"claims":[{"claim":{"argv_preview":["pytest","-q"],"ctype":"tests-pass",'
        b'"declared_at_index":0,"event_indices":[0],"label":"t","pathspecs":[]},'
        b'"delta":[],"exit_code":0,"grade":"tree-exact","reason":"r",'
        b'"supporting_event_index":0}],'
        b'"claims_from":0,"claims_to":1,'
        b'"commit":"0000000000000000000000000000000000000000",'
        b'"coverage":{"by_coverage":{"complete":1},"total_events":1},'
        b'"secrets":{},"secrets_override":false,'
        b'"tree":"1111111111111111111111111111111111111111","version":1}'
    )
