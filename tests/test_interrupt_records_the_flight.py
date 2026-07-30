"""A signal must never cost the event for a command that actually ran.

Regression cover for the lost-flight window between the drain and the append.
Two distinct mechanisms put an event at risk once the child is reaped:

1. A second interrupt landing while didrun is digesting the tree and appending
   (the recorder's own Python signal handling).
2. A terminal Ctrl-C reaching the whole foreground process group, which kills
   the ``git`` the after-digest shells out to -- even when the child had
   already exited cleanly and the drain saw no signal at all.

Both used to end the process with no record of a command whose side effects
are on disk. The event is worth more than the after-digest: `None` grades
`unknown`, which is honest, while no event at all says the command never ran.
"""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from didrun import gitplumbing
from didrun.capture import run_wrapped
from didrun.ledger import Session


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture()
def repo(tmp_path):
    _git(tmp_path, "init", "-q", ".")
    _git(tmp_path, "config", "user.email", "t@t.test")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "f.txt").write_text("x\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "init")
    return tmp_path


def test_a_failing_after_digest_still_records_the_event(repo, monkeypatch):
    """The mechanism behind the process-group kill, made deterministic.

    Rather than racing a real signal, fail the digest the way a killed git
    fails it. The event must still land, tree_after must be None, and coverage
    must say the tree was not witnessed instead of claiming "complete".
    """
    session = Session(repo / ".didrun")

    real = gitplumbing.tree_digest
    calls = {"n": 0}

    def flaky(*a, **kw):
        calls["n"] += 1
        if calls["n"] > 1:  # tree_before succeeds, tree_after dies
            raise gitplumbing.GitError("git rev-parse --git-path index failed (-2): ")
        return real(*a, **kw)

    monkeypatch.setattr(gitplumbing, "tree_digest", flaky)

    event = run_wrapped([sys.executable, "-c", "print('ran')"], session, repo=repo)

    entries = list(session.entries())
    assert len(entries) == 1, "a witnessed command left no event"
    assert event.exit_code == 0, "the command completed; its exit code is known"
    assert event.tree_after is None, "an unwitnessed tree must be None, not a guess"
    assert event.coverage == "observed-text-only", (
        "claiming 'complete' would assert the tree was witnessed when it was not"
    )
    assert session.verify_chain()[0], "the chain must stay intact"


def test_second_interrupt_during_the_record_phase_does_not_lose_the_flight(repo):
    """End to end, through the CLI, against the real double-Ctrl-C window.

    The first signal ends the child; the second lands while didrun is
    digesting and appending. Before the fix this window ran ~30-140ms wide and
    lost the event outright.
    """
    didrun = Path(sys.executable).parent / "didrun"
    if not didrun.exists():  # pragma: no cover - depends on install layout
        pytest.skip("didrun console script not present in this environment")

    (repo / "child.py").write_text(
        "import time\n"
        "for i in range(40):\n"
        "    print(i, flush=True)\n"
        "    time.sleep(0.05)\n"
    )

    lost = []
    for gap_ms in (30, 60, 90, 120):
        for stale in repo.glob(".didrun/session.log"):
            stale.unlink()
        proc = subprocess.Popen(
            [str(didrun), "run", "--", sys.executable, "child.py"],
            cwd=repo,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(0.6)
        for delay in (0.0, gap_ms / 1000.0):
            time.sleep(delay)
            try:
                os.killpg(proc.pid, signal.SIGINT)
            except (ProcessLookupError, PermissionError):  # pragma: no cover
                pass
        proc.wait(timeout=60)

        log = repo / ".didrun" / "session.log"
        lines = [l for l in log.read_text().splitlines() if l.strip()] if log.exists() else []
        if not lines:
            lost.append(gap_ms)

    assert not lost, f"interrupt lost the flight at gaps (ms): {lost}"
