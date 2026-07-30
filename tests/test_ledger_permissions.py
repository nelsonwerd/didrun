"""P2.1 — the ledger root is private, and read-only commands do not create one.

The criterion here is deliberately about the ROOT, not about files. The ledger's
``objects/`` directory is populated by git, twice per ``didrun run``, through the
``GIT_OBJECT_DIRECTORY`` redirect, at git's own modes — so "every file is 0600"
is not a property this package can hold. 0700 on the root is, and it is what
makes another uid unable to reach the files through the directory.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from didrun import gitplumbing
from didrun.cli import main
from didrun.ledger import Event, LedgerError, Session


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


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


@pytest.fixture
def umask(request):
    """Run a test under a specific umask and restore it afterwards."""
    previous = os.umask(request.param)
    try:
        yield request.param
    finally:
        os.umask(previous)


# --- 1. the criterion: an existing 0755 ledger is re-tightened ---------------

def test_existing_0755_ledger_is_retightened_on_open(tmp_path: Path):
    # A ledger a v0.1 binary created: the directory already exists at 0755.
    root = tmp_path / ".didrun"
    root.mkdir()
    os.chmod(root, 0o755)
    assert _mode(root) == 0o755

    Session(root)

    # mkdir(mode=0o700, exist_ok=True) does NOT re-tighten an existing
    # directory, so an implementation that only passes mode= fails here.
    assert _mode(root) == 0o700


def test_fresh_ledger_root_is_private(tmp_path: Path):
    root = tmp_path / ".didrun"
    Session(root)
    assert _mode(root) == 0o700


# --- 2. umask independence, and the files this version creates ---------------

@pytest.mark.parametrize("umask", [0o022, 0o002, 0o077], indirect=True)
def test_root_and_own_files_are_private_under_any_umask(
    tmp_path: Path, umask: int, monkeypatch
):
    from didrun import manifest as _manifest
    from didrun.claims import Claim

    root = tmp_path / f".didrun-{umask:03o}"
    session = Session(root)
    session.append(_wrapper_event())
    _manifest.declare_claim(
        session,
        Claim(ctype="tests-pass", label="t", event_indices=(0,), declared_at_index=0),
    )
    _manifest._record_seal(session, "c" * 40, "t" * 40, 1)

    assert _mode(root) == 0o700
    for name in ("session.log", "claims.jsonl", "seals.jsonl", ".gitignore"):
        assert _mode(root / name) == 0o600, name

    # Deliberately NOT asserted: modes under objects/. git writes into that
    # directory itself via GIT_OBJECT_DIRECTORY (gitplumbing.tree_digest), at
    # git's modes, on every recorded command — so any assertion here would be
    # about git's umask handling, not didrun's, and would be repaired-then-undone
    # by the next `didrun run`. The root's 0700 is the control (red-team A2.4).


# --- 2b. the inherited-file bound, pinned rather than assumed ----------------

def test_inherited_v01_files_keep_their_modes_only_the_root_is_repaired(
    tmp_path: Path,
):
    root = tmp_path / ".didrun"
    root.mkdir()
    log = root / "session.log"
    gitignore = root / ".gitignore"
    log.write_bytes(b"")
    gitignore.write_text("*\n", encoding="ascii")
    os.chmod(log, 0o644)
    os.chmod(gitignore, 0o644)
    os.chmod(root, 0o755)
    gitignore_before = gitignore.read_bytes()
    mtime_before = gitignore.stat().st_mtime_ns

    Session(root)

    # This is the DELIBERATE BOUND of Session.harden, not an oversight: the
    # root is the control, the files are not retro-fixed. O_CREAT's mode
    # applies at creation only, and .gitignore is written only when absent, so
    # a ledger an older binary created keeps 0644 on those files forever.
    # Nobody may read the 0600 assertions in the test above as a general
    # "the files are 0600" guarantee.
    assert _mode(root) == 0o700
    assert _mode(log) == 0o644
    assert _mode(gitignore) == 0o644
    assert gitignore.read_bytes() == gitignore_before
    assert gitignore.stat().st_mtime_ns == mtime_before


# --- the two guards on the chmod --------------------------------------------

def test_a_ledger_owned_by_another_uid_is_warned_about_not_chmodded(
    tmp_path: Path, monkeypatch, capsys
):
    root = tmp_path / ".didrun"
    root.mkdir()
    os.chmod(root, 0o755)
    # Cannot create a foreign-owned directory without root, so move the OTHER
    # side of the comparison: this process reports a euid the directory is not
    # owned by. The branch under test is identical.
    monkeypatch.setattr(os, "geteuid", lambda: root.stat().st_uid + 1)

    Session(root)

    assert _mode(root) == 0o755, "chmodded a directory this process does not own"
    err = capsys.readouterr().err
    assert "not tightening" in err and "0700" in err


def test_missing_geteuid_does_not_crash_the_windows_path(tmp_path: Path, monkeypatch):
    # os.geteuid does not exist on Windows. The ownership check is skipped
    # there rather than raising AttributeError on every Session open.
    root = tmp_path / ".didrun"
    root.mkdir()
    os.chmod(root, 0o755)
    monkeypatch.delattr(os, "geteuid", raising=False)

    Session(root)

    # POSIX chmod still works here, so the mode moves; the point of the test is
    # that the absent attribute is a skipped check, not an exception.
    assert _mode(root) == 0o700


# --- 3. a read-only open creates nothing ------------------------------------

def test_readonly_session_creates_no_ledger(tmp_path: Path):
    root = tmp_path / ".didrun"
    session = Session(root, readonly=True)
    assert not root.exists()
    # And it still answers read questions about the ledger that is not there.
    assert list(session.entries()) == []
    assert session.events() == []
    assert session.verify_chain() == (True, None)
    assert not root.exists()


def test_readonly_session_refuses_to_write(tmp_path: Path):
    session = Session(tmp_path / ".didrun", readonly=True)
    with pytest.raises(LedgerError):
        session.append(_wrapper_event())
    with pytest.raises(LedgerError):
        session.blobs.put(b"payload")
    assert not (tmp_path / ".didrun").exists()


def test_cmd_verify_on_a_repo_with_no_ledger_creates_nothing(repo: Path, capsys):
    ledger = repo / ".didrun"
    assert not ledger.exists()

    rc = main(["--repo", str(repo), "verify"])

    assert rc == 0
    assert not ledger.exists(), "a read-only verify manufactured a ledger"
    assert sorted(p.name for p in repo.iterdir()) == [".git", "calc.py"]


def test_cmd_show_session_on_a_repo_with_no_ledger_creates_nothing(repo: Path):
    rc = main(["--repo", str(repo), "show", "--session"])
    assert rc == 0
    assert not (repo / ".didrun").exists()


# --- 4. a read-only open re-modes nothing -----------------------------------

def test_readonly_verify_does_not_remode_an_existing_ledger(repo: Path):
    ledger = repo / ".didrun"
    ledger.mkdir()
    os.chmod(ledger, 0o755)

    rc = main(["--repo", str(repo), "verify"])

    assert rc == 0
    # Pointing a read-only command at someone else's archive must not touch it.
    assert _mode(ledger) == 0o755


# --- 5. the chmod moves no tree digest --------------------------------------

def test_chmod_is_digest_neutral(repo: Path):
    ledger = repo / ".didrun"
    ledger.mkdir()
    os.chmod(ledger, 0o755)
    before = gitplumbing.tree_digest(repo)
    assert before is not None

    Session(ledger)

    assert _mode(ledger) == 0o700
    after = gitplumbing.tree_digest(repo)
    assert after == before


# --- 6. the new file-open path still appends a verifiable chain --------------

def test_append_and_chain_survive_the_private_open(tmp_path: Path):
    root = tmp_path / ".didrun"
    session = Session(root)
    for i in range(4):
        session.append(_wrapper_event(argv=("cmd", str(i))))
    ok, broke = session.verify_chain()
    assert ok and broke is None
    assert [e.index for e in session.entries()] == [0, 1, 2, 3]

    # Re-opening an existing ledger appends, never truncates.
    reopened = Session(root)
    reopened.append(_wrapper_event(argv=("cmd", "4")))
    assert len(list(reopened.entries())) == 5
    assert reopened.verify_chain() == (True, None)
    assert _mode(root / "session.log") == 0o600


def test_blob_temp_mode_does_not_leak_through_the_rename(tmp_path: Path):
    # os.replace preserves the SOURCE mode, so a loose 0644 temp would become a
    # 0644 blob. Under a permissive umask that is exactly what a plain
    # write_bytes produced.
    previous = os.umask(0o000)
    try:
        session = Session(tmp_path / ".didrun")
        digest = session.blobs.put(b"secret output")
    finally:
        os.umask(previous)
    assert _mode(session.blobs.root / digest) == 0o600
    assert session.blobs.get(digest) == b"secret output"
