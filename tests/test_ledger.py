"""P1.1 — ledger: blobs, chain integrity, determinism, the exit-code invariant."""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from didrun.ledger import (
    Event,
    Session,
    BlobStore,
    LedgerError,
    canonical_json,
    sha256_hex,
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
