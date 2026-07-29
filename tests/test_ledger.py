"""P1.1 — ledger: blobs, chain integrity, determinism, the exit-code invariant."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from didrun.ledger import (
    GENESIS_HASH,
    Event,
    Session,
    BlobStore,
    LedgerError,
    canonical_json,
    sha256_hex,
    unknown_event_keys_of,
)


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


def test_blob_roundtrip_and_dedup(tmp_path: Path):
    store = BlobStore(tmp_path / "obj")
    d1 = store.put(b"hello")
    d2 = store.put(b"hello")
    assert d1 == d2 == sha256_hex(b"hello")  # identical content -> one digest
    assert store.get(d1) == b"hello"


def test_two_writers_of_one_blob_do_not_collide_on_a_temp_name(
    tmp_path: Path, monkeypatch
):
    """P2.4 — concurrent recorders store the same blob constantly.

    An empty stderr is one digest every event shares, so two `didrun run`
    processes writing at once is the normal case, not the exotic one. This is
    the crash, driven deterministically instead of hoped for: writer A is
    suspended at its rename, writer B completes the SAME blob inside that
    window, and A resumes. With a shared ``<digest>.tmp`` name B's rename has
    already consumed A's temp and A dies with FileNotFoundError.

    Measured before the fix on an eight-way concurrent `didrun run`: 2 of 6
    attempts lost a process to exactly this traceback.
    """
    root = tmp_path / "obj"
    store = BlobStore(root)
    data = b"identical bytes from both writers"
    real_replace = os.replace
    interleaved = []

    def replace_with_a_second_writer_inside(src, dst):
        if not interleaved:
            interleaved.append(True)
            BlobStore(root).put(data)
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", replace_with_a_second_writer_inside)

    assert store.put(data) == sha256_hex(data)
    assert interleaved == [True], "the second writer never ran; the test is vacuous"
    assert store.get(sha256_hex(data)) == data
    # No temp residue survives a completed pair of writes.
    assert [p.name for p in root.iterdir()] == [sha256_hex(data)]


def test_blob_corruption_detected(tmp_path: Path):
    store = BlobStore(tmp_path / "obj")
    d = store.put(b"payload")
    (tmp_path / "obj" / d).write_bytes(b"tampered")
    with pytest.raises(LedgerError):
        store.get(d)


def test_chain_intact(tmp_path: Path):
    s = Session(tmp_path / ".didrun")
    for i in range(5):
        s.append(_wrapper_event(argv=("cmd", str(i))))
    ok, broke = s.verify_chain()
    assert ok and broke is None


def test_chain_tamper_detected(tmp_path: Path):
    s = Session(tmp_path / ".didrun")
    for i in range(5):
        s.append(_wrapper_event(argv=("cmd", str(i))))
    # Flip one byte in the middle of the log.
    log = s.log_path
    lines = log.read_text().splitlines()
    lines[2] = lines[2].replace("cmd", "xxx", 1)
    log.write_text("\n".join(lines) + "\n")
    ok, broke = s.verify_chain()
    assert not ok
    assert broke == 2


def test_transcript_event_cannot_carry_exit_code():
    with pytest.raises(LedgerError):
        Event(
            argv=("x",),
            cwd="/tmp",
            env_fingerprint="f",
            observed_via="transcript",
            coverage="display-only",
            exit_code=0,  # illegal: a transcript never witnesses an exit
        )


def test_canonical_json_is_byte_stable():
    a = canonical_json({"b": 1, "a": 2})
    b = canonical_json({"a": 2, "b": 1})
    assert a == b  # key order independent


def test_chain_hash_reproducible_cross_process(tmp_path: Path):
    """The strongest determinism check: an identical session built in a *separate*
    process must produce the identical final entry hash. Non-deterministic JSON
    key order or float formatting would break this."""
    script = textwrap.dedent(
        """
        import sys
        from didrun.ledger import Session, Event
        s = Session(sys.argv[1] + '/.didrun')
        for i in range(3):
            s.append(Event(argv=('cmd', str(i)), cwd='/tmp',
                           env_fingerprint='f', observed_via='wrapper',
                           coverage='complete', exit_code=0,
                           started_at=None, ended_at=None))
        entries = list(s.entries())
        print(entries[-1].entry_hash)
        """
    )
    out = []
    for _ in range(2):
        d = tmp_path / f"run{_}"
        d.mkdir()
        proc = subprocess.run(
            [sys.executable, "-c", script, str(d)],
            capture_output=True,
            text=True,
            check=True,
        )
        out.append(proc.stdout.strip())
    assert out[0] == out[1]


def test_self_stability_precondition():
    ev = _wrapper_event(tree_before="aaa", tree_after="aaa")
    assert ev.self_stable()
    ev2 = _wrapper_event(tree_before="aaa", tree_after="bbb")
    assert not ev2.self_stable()


# --- P0.2 — the frozen v1 preimage, unknown keys, unknown versions -----------


def _records(session: Session) -> list[dict]:
    return [json.loads(l) for l in session.log_path.read_text().splitlines() if l.strip()]


def _rewrite(session: Session, records: list[dict]) -> None:
    session.log_path.write_bytes(b"".join(canonical_json(r) + b"\n" for r in records))


def test_v1_record_on_disk_carries_no_preimage_version_key(tmp_path: Path):
    """A v1 record must stay byte-shaped exactly as every previous release
    wrote it, so an older binary keeps reading a ledger this one produced."""
    s = Session(tmp_path / ".didrun")
    s.append(_wrapper_event())
    rec = _records(s)[0]
    assert set(rec) == {"index", "prev_hash", "entry_hash", "event"}


def test_archived_shape_record_round_trips(tmp_path: Path):
    """A record with no preimage_version key — i.e. every archived record —
    reads back, recomputes, and grades intact.

    The expected hash is spelled out here with the pre-P0.2 preimage rather
    than borrowed from compute_hash(), so this fails if the projection ever
    stops being byte-identical to the whole event body at version 1.
    """
    s = Session(tmp_path / ".didrun")
    body = _wrapper_event(argv=("cmd", "0")).to_dict()
    stored = sha256_hex(
        GENESIS_HASH.encode("ascii")
        + canonical_json({"index": 0, "prev": GENESIS_HASH, "event": body})
    )
    _rewrite(
        s,
        [{"index": 0, "prev_hash": GENESIS_HASH, "entry_hash": stored, "event": body}],
    )

    entries = list(s.entries())
    assert len(entries) == 1
    assert entries[0].preimage_version == 1
    assert entries[0].unknown_event_keys == ()
    assert entries[0].event.argv == ("cmd", "0")  # argv tuple-ization survives
    assert entries[0].compute_hash() == stored
    assert s.verify_chain_detail().status == "intact"
    assert s.verify_chain() == (True, None)


def test_unknown_event_key_is_readable_but_unverifiable(tmp_path: Path):
    """A ledger written by a newer binary must stay readable, and must not be
    reported as tamper — but must never be reported as intact either."""
    s = Session(tmp_path / ".didrun")
    s.append(_wrapper_event())
    recs = _records(s)
    recs[0]["event"]["umask"] = "0022"
    _rewrite(s, recs)

    # Readable, not fatal: no TypeError out of cls(**d).
    ev = Event.from_dict(recs[0]["event"])
    assert ev.argv == ("echo", "hi")
    assert unknown_event_keys_of(recs[0]["event"]) == ("umask",)

    entries = list(s.entries())
    assert entries[0].unknown_event_keys == ("umask",)
    # This is exactly why unverifiable has to exist: the projection cannot see
    # the extra key, so the recomputed hash still matches and a hash check
    # alone would call this chain intact.
    assert entries[0].compute_hash() == entries[0].entry_hash

    verdict = s.verify_chain_detail()
    assert verdict.status == "unverifiable"
    assert verdict.unverifiable_index == 0
    assert verdict.first_broken_index is None
    assert "umask" in verdict.reason

    ok, idx = s.verify_chain()
    assert ok is False
    assert idx == 0


def test_unknown_preimage_version_fails_closed(tmp_path: Path):
    s = Session(tmp_path / ".didrun")
    for i in range(3):
        s.append(_wrapper_event(argv=("cmd", str(i))))
    recs = _records(s)
    recs[1]["preimage_version"] = 2
    _rewrite(s, recs)

    entries = list(s.entries())
    assert entries[1].preimage_version == 2
    with pytest.raises(LedgerError):
        entries[1].compute_hash()

    verdict = s.verify_chain_detail()
    assert verdict.status == "unverifiable"
    assert verdict.unverifiable_index == 1
    assert verdict.first_broken_index is None
    assert "2" in verdict.reason


def test_verify_chain_reports_rather_than_raises_on_unknown_version(tmp_path: Path):
    """compute_hash now raises on an unknown version. A reader that crashes is
    worse than one that reports, so the boolean wrapper must still return."""
    s = Session(tmp_path / ".didrun")
    for i in range(3):
        s.append(_wrapper_event(argv=("cmd", str(i))))
    recs = _records(s)
    recs[1]["preimage_version"] = 2
    _rewrite(s, recs)

    ok, idx = s.verify_chain()  # must not raise
    assert ok is False
    assert idx == 1


def test_mutated_event_body_is_broken_not_unverifiable(tmp_path: Path):
    """Tamper inside a known field is still tamper — unverifiable must not
    become a laundering route for a mutated body."""
    s = Session(tmp_path / ".didrun")
    for i in range(5):
        s.append(_wrapper_event(argv=("cmd", str(i))))
    recs = _records(s)
    recs[1]["event"]["argv"] = ["cmd", "tampered"]
    _rewrite(s, recs)

    verdict = s.verify_chain_detail()
    assert verdict.status == "broken"
    assert verdict.first_broken_index == 1
    assert verdict.unverifiable_index is None

    ok, idx = s.verify_chain()
    assert ok is False
    assert idx == 1


def test_empty_chain_verdict(tmp_path: Path):
    s = Session(tmp_path / ".didrun")
    assert s.verify_chain_detail().status == "empty"
    assert s.verify_chain() == (True, None)
