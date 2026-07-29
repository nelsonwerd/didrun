"""P3.3 — the environment fingerprint is bound to something and read by someone.

Before this unit the fingerprint was written twice and read nowhere: two green
wrapper events recorded under different umasks were indistinguishable in the
receipt, and the key set gated on the two worst false-drift sources on a
developer machine (PATH, PWD) while omitting the one that voided real chains
(umask).

The comparison that makes it load-bearing is ACROSS TIME — sealed fingerprint
versus this process's. Comparing the fingerprints inside a single claim would be
vacuous: every claim didrun's CLI can declare binds exactly one event, and one
event trivially agrees with itself, so ``return False`` would pass such a test on
100% of real claims.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

from didrun import capture
from didrun import cli
from didrun import gitplumbing as gp
from didrun import manifest as M
from didrun import render
from didrun.claims import (
    ENV_DRIFT,
    ENV_INCOMPARABLE,
    ENV_MATCH,
    ENV_NOT_RECORDED,
    Claim,
)
from didrun.ledger import Event, Session

# A structurally equivalent stand-in for a real environment, so no test here
# depends on the machine it runs on.
_ENV = {
    "LANG": "en_US.UTF-8",
    "SHELL": "/bin/zsh",
    "TZ": "UTC",
    "VIRTUAL_ENV": "/opt/envs/example",
    "PATH": "/usr/bin:/bin",
}


def _session(repo: Path) -> Session:
    return Session(repo / ".didrun")


def _ok(repo: Path, session: Session):
    return capture.run_wrapped([sys.executable, "-c", "print(1)"], session, repo)


def _sealed_green(repo: Path) -> Session:
    """One recorded success, one claim over it, sealed on a clean tree."""
    s = _session(repo)
    _ok(repo, s)
    M.declare_claim(
        s, Claim(ctype="tests-pass", label="suite", event_indices=(0,), declared_at_index=0)
    )
    M.seal(s, repo)
    return s


def _seal_with_fingerprint(repo: Path, fingerprint: str) -> Session:
    """Seal a green claim over an event carrying ``fingerprint`` verbatim.

    The event is constructed rather than recorded because the point is a
    fingerprint THIS didrun would never produce — a bare v0.1 digest, or a v1
    value from before the key set changed. It is appended through the real
    ``Session.append`` so the chain covers it exactly as it covers a captured
    event; nothing here edits a log.
    """
    s = _session(repo)
    tree = gp.tree_digest(repo, s.blobs.root)
    s.append(
        Event(
            argv=("example-suite", "--quiet"),
            cwd=str(repo),
            env_fingerprint=fingerprint,
            observed_via="wrapper",
            coverage="complete",
            exit_code=0,
            started_at=1.0,
            ended_at=2.0,
            tree_before=tree,
            tree_after=tree,
        )
    )
    M.declare_claim(
        s, Claim(ctype="tests-pass", label="suite", event_indices=(0,), declared_at_index=0)
    )
    M.seal(s, repo)
    return s


def _run_child(script: str, *args: str, env=None, cwd=None) -> str:
    proc = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script), *args],
        capture_output=True,
        text=True,
        check=True,
        env=env,
        cwd=cwd,
    )
    return proc.stdout.strip()


# --- test 1: the falsification test (criterion per red-team §3.1(3)) ---------

def test_a_changed_TZ_drifts_the_verdict_and_refuses_under_require_env_match(
    repo: Path, monkeypatch, capsys
):
    """Seal green, verify under a different TZ, and the verdict must move.

    THE FALSIFICATION: a no-op implementation fails BOTH halves. If nothing
    compares the fingerprint across time (the pre-P3.3 state, or a reader that
    always answers "match"), the two verdict texts are identical and
    --require-env-match --strict still exits 0. Passing requires the comparison
    to exist AND to be able to refuse.

    TZ is the mover on purpose: it is in the gate, it is trivially settable, and
    it is not PATH or PWD — both of which are now deliberately unable to do
    this.
    """
    monkeypatch.setenv("TZ", "UTC")
    s = _sealed_green(repo)

    before = render.render_verdict(M.verify(s, repo))
    assert "1/1 claims recorded-exact" in before
    assert f"env: 1 {ENV_MATCH} / 0 drifted / 0 {ENV_INCOMPARABLE}" in before
    assert ENV_DRIFT not in before

    monkeypatch.setenv("TZ", "Asia/Tokyo")
    after = render.render_verdict(M.verify(s, repo))
    assert after != before
    assert ENV_DRIFT in after
    assert "0 match / 1 drifted" in after
    # Drift did not un-record the command: the grade is untouched.
    assert "1/1 claims recorded-exact" in after

    # Advisory by default...
    assert cli.main(["--repo", str(repo), "verify", "--strict"]) == 0
    capsys.readouterr()
    # ...and a refusal on request.
    assert cli.main(["--repo", str(repo), "verify", "--require-env-match", "--strict"]) == 1
    out = capsys.readouterr().out
    assert ENV_DRIFT in out


def test_drift_alone_does_not_change_the_grade_or_the_default_verdict(
    repo: Path, monkeypatch
):
    """`all_verified` keeps its default membership. Drift is a fact about this
    machine now, not about whether the recorded command ran."""
    monkeypatch.setenv("TZ", "UTC")
    s = _sealed_green(repo)
    monkeypatch.setenv("TZ", "Asia/Tokyo")

    drifted = M.verify(s, repo)
    assert drifted.env_drift_count == 1
    assert [r.grade for r in drifted.results] == ["tree-exact"]
    assert drifted.all_verified is True
    assert drifted.worst_status == "tree-exact"

    gated = M.verify(s, repo, require_env_match=True)
    assert gated.all_verified is False
    # Still not a grade: the claim is recorded-exact and says so.
    assert [r.grade for r in gated.results] == ["tree-exact"]


# --- test 2: umask is bound --------------------------------------------------

_RECORD_UNDER_UMASK = """
    import os, sys
    os.umask(int(sys.argv[3], 8))
    from pathlib import Path
    from didrun.capture import run_wrapped
    from didrun.ledger import Session
    ev = run_wrapped(
        [sys.executable, "-c", "pass"], Session(Path(sys.argv[2])), Path(sys.argv[1])
    )
    print(ev.env_fingerprint)
"""


def test_umask_is_bound_into_the_gate(repo: Path, tmp_path: Path):
    """Two events recorded under umask 022 and 077 must differ in the gate.

    This is the case that voided three chains and was invisible in the receipt:
    same argv, same tree, same exit code, two different file-permission
    outcomes, one indistinguishable pair of green events.

    Recorded in child processes because the umask is read once per process and
    reused (capture.process_umask) — which is itself the property under test:
    the value must reach the ledger, not merely the helper's return value.
    """
    prints = [
        _run_child(
            _RECORD_UNDER_UMASK, str(repo), str(tmp_path / f"ledger-{mask}"), mask
        )
        for mask in ("022", "077")
    ]
    assert all(capture.fingerprint_version(p) == 2 for p in prints)
    assert capture.fingerprint_gate(prints[0]) != capture.fingerprint_gate(prints[1])
    # Only the umask moved: the non-gated PATH digest is unchanged.
    assert capture.fingerprint_path_digest(prints[0]) == capture.fingerprint_path_digest(
        prints[1]
    )


def test_umask_reaches_the_fingerprint_directly_too():
    """The same fact without a subprocess, so a failure localizes."""
    a = capture.env_fingerprint(_ENV, umask=0o022)
    b = capture.env_fingerprint(_ENV, umask=0o077)
    assert capture.fingerprint_gate(a) != capture.fingerprint_gate(b)
    assert capture.env_fingerprint(_ENV, umask=0o022) == a


# --- test 3: PWD no longer drifts --------------------------------------------

_RECORD_FROM_CWD = """
    import sys
    from pathlib import Path
    from didrun.capture import run_wrapped
    from didrun.ledger import Session
    ev = run_wrapped(
        [sys.executable, "-c", "pass"], Session(Path(sys.argv[2])), Path(sys.argv[1])
    )
    print(ev.env_fingerprint)
"""


def test_the_invocation_directory_does_not_drift_the_gate(repo: Path, tmp_path: Path):
    """The same command against the same repo, invoked from two directories.

    PWD was in v0.1's key set and is NOT the child's cwd — run_wrapped always
    spawns with cwd=str(repo). Gating on it would mean two byte-identical
    executions disagree because the operator was standing somewhere else.

    Both the real child cwd and the PWD variable are moved, because a shell sets
    the second and a launcher may not set it at all.
    """
    here = tmp_path / "here"
    there = tmp_path / "there"
    here.mkdir()
    there.mkdir()
    prints = [
        _run_child(
            _RECORD_FROM_CWD,
            str(repo),
            str(tmp_path / f"ledger-{d.name}"),
            env={**os.environ, "PWD": str(d)},
            cwd=str(d),
        )
        for d in (here, there)
    ]
    assert capture.fingerprint_gate(prints[0]) == capture.fingerprint_gate(prints[1])
    assert prints[0] == prints[1]


def test_PWD_is_not_in_the_preimage_at_all():
    assert "PWD" not in capture._ENV_FINGERPRINT_KEYS
    a = capture.env_fingerprint({**_ENV, "PWD": "/home/example/one"}, umask=0o022)
    b = capture.env_fingerprint({**_ENV, "PWD": "/home/example/two"}, umask=0o022)
    assert a == b


# --- test 4: PATH is visible but not a gate ----------------------------------

def test_PATH_moves_the_recorded_digest_but_never_the_gate():
    """Two different PATHs: same gate, different `path=` suffix.

    PATH varies with terminal tab, direnv, `nix develop`, tmux and homebrew
    shellenv ordering. Gating on it produces a refusal that fires on a new shell
    and is ignored within a week — but dropping it entirely would lose a real
    signal, so it is recorded beside the gate instead of inside it.
    """
    assert "PATH" not in capture._ENV_FINGERPRINT_KEYS
    a = capture.env_fingerprint({**_ENV, "PATH": "/usr/bin:/bin"}, umask=0o022)
    b = capture.env_fingerprint({**_ENV, "PATH": "/opt/example/bin:/bin"}, umask=0o022)
    assert capture.fingerprint_gate(a) == capture.fingerprint_gate(b)
    assert capture.fingerprint_path_digest(a) != capture.fingerprint_path_digest(b)


def test_a_PATH_difference_is_an_advisory_and_never_drift(repo: Path, monkeypatch):
    """A verdict must not call a PATH change environment drift."""
    monkeypatch.setenv("PATH", os.environ.get("PATH", "/usr/bin:/bin"))
    s = _sealed_green(repo)
    monkeypatch.setenv("PATH", "/opt/example/bin:" + os.environ.get("PATH", ""))

    report = M.verify(s, repo)
    assert [r.env_status for r in report.results] == [ENV_MATCH]
    assert report.env_drift_count == 0
    assert "PATH differs" in report.results[0].env_reason
    assert "recorded, not gated" in report.results[0].env_reason
    assert M.verify(s, repo, require_env_match=True).all_verified is True


# --- test 5: legacy is incomparable, not drifted -----------------------------

def test_a_bare_v0_1_fingerprint_is_incomparable_and_never_renders_as_drift(
    repo: Path,
):
    """The archived-evidence case, and the reason this unit is compat-safe.

    A v0.1 digest carries no version prefix, so it is not a measurement of the
    same key set. Reporting a mismatch against it as drift would make every note
    published before v0.2 look like the environment moved.
    """
    s = _seal_with_fingerprint(repo, "0123456789abcdef")
    report = M.verify(s, repo)

    assert [r.env_status for r in report.results] == [ENV_INCOMPARABLE]
    assert "unversioned v0.1 digest" in report.results[0].env_reason
    assert "not evidence that anything drifted" in report.results[0].env_reason

    text = render.render_verdict(report)
    assert ENV_DRIFT not in text
    assert f"0 drifted / 1 {ENV_INCOMPARABLE}" in text
    assert ENV_DRIFT not in render.render_html(report)

    # Incomparable never refuses, under either mode. This is the assertion that
    # would break the corpus if it stopped holding.
    assert report.all_verified is True
    assert M.verify(s, repo, require_env_match=True).all_verified is True


def test_a_v1_fingerprint_from_an_older_didrun_is_incomparable_too(repo: Path):
    """Sealed evidence from P0.3-era didrun (versioned, older key set).

    The version prefix exists precisely so this case is legible: v1 and v2 are
    digests of different key sets, so they are incomparable by construction
    rather than by luck.
    """
    s = _seal_with_fingerprint(repo, "v1:0123456789abcdef")
    report = M.verify(s, repo)
    assert [r.env_status for r in report.results] == [ENV_INCOMPARABLE]
    assert "version 1" in report.results[0].env_reason
    assert "incomparable, not drifted" in report.results[0].env_reason
    assert M.verify(s, repo, require_env_match=True).all_verified is True


def test_a_note_that_bound_no_fingerprint_is_not_recorded_not_drifted(repo: Path):
    """A v0.1-shaped note has no evidence block at all — a third distinct fact.

    Reported separately from `incomparable` because "the seal never recorded
    one" and "it recorded one this binary cannot compare" are different, and
    collapsing them would hide which notes could start being compared.
    """
    s = _sealed_green(repo)
    head = gp.head_commit(repo)
    body = subprocess.run(
        ["git", "notes", f"--ref={M.NOTES_REF}", "show", head],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    stripped = body.replace('"evidence"', '"evidence_removed"')
    subprocess.run(
        ["git", "notes", f"--ref={M.NOTES_REF}", "add", "-f", "-F", "-", head],
        cwd=str(repo),
        input=stripped.encode("ascii"),
        capture_output=True,
        check=True,
    )

    report = M.verify(s, repo)
    assert [r.env_status for r in report.results] == [ENV_NOT_RECORDED]
    assert "bound no environment fingerprint" in report.results[0].env_reason
    text = render.render_verdict(report)
    assert f"1 {ENV_NOT_RECORDED}" in text
    assert ENV_DRIFT not in text
    assert M.verify(s, repo, require_env_match=True).all_verified is True


# --- test 6: determinism -----------------------------------------------------

_FINGERPRINT_IN_CHILD = """
    import json, sys
    from didrun import capture
    env = json.loads(sys.argv[1])
    print(capture.env_fingerprint(env, umask=int(sys.argv[2], 8)))
"""


def test_fingerprint_is_reproducible_across_processes(tmp_path: Path):
    """Determinism is a trust-path invariant (no wall clock, no randomness).

    Mirrors the cross-process chain-hash check in tests/test_ledger.py: a
    same-process comparison cannot catch hash randomization or key-order
    instability, because both are fixed for a process's lifetime.
    """
    import json

    out = [
        _run_child(_FINGERPRINT_IN_CHILD, json.dumps(_ENV, sort_keys=True), "022")
        for _ in range(2)
    ]
    assert out[0] == out[1]
    assert out[0] == capture.env_fingerprint(_ENV, umask=0o022)


def test_the_umask_read_is_cached_not_repeated(monkeypatch):
    """Read once, reuse. The read is a read-modify-write on process-global
    state, so doing it per event would open that window on every wrapped
    command."""
    monkeypatch.setattr(capture, "_UMASK", None)
    reads = []
    real_umask = os.umask

    def counting_umask(mask):
        reads.append(mask)
        return real_umask(mask)

    monkeypatch.setattr(capture.os, "umask", counting_umask)
    first = capture.process_umask()
    assert reads == [0, first]  # set to 0, then restored
    for _ in range(5):
        assert capture.process_umask() == first
    assert reads == [0, first]  # and never touched again


# --- test 7: no leak ---------------------------------------------------------

def test_the_fingerprint_leaks_no_input_value():
    """Values are digested, never stored. The fingerprint must never become the
    place a secret-bearing environment variable lands verbatim in a note."""
    inputs = {
        "LANG": "xq_ZZ.KOI8-R",
        "SHELL": "/opt/quixotic/bin/wobbleshell",
        "TZ": "Antarctica/South_Pole",
        "VIRTUAL_ENV": "/opt/envs/zephyrous-marmoset-3141",
        "PATH": "/opt/quixotic/bin:/usr/lib/kumquat/sbin",
    }
    value = capture.env_fingerprint(inputs, umask=0o022)
    assert re.fullmatch(r"v2:[0-9a-f]{16}:path=[0-9a-f]{8}", value)
    for raw in inputs.values():
        assert raw not in value
        for i in range(len(raw) - 3):
            assert raw[i : i + 4] not in value


def test_the_drift_reason_carries_digests_not_environment_values(
    repo: Path, monkeypatch
):
    """The reason names both gates. They are 16-hex digests, so naming them
    leaks nothing — which is what makes the message safe to print."""
    monkeypatch.setenv("TZ", "UTC")
    s = _sealed_green(repo)
    monkeypatch.setenv("TZ", "Antarctica/South_Pole")
    reason = M.verify(s, repo).results[0].env_reason
    assert "Antarctica" not in reason
    assert len(re.findall(r"\b[0-9a-f]{16}\b", reason)) == 2


# --- the parsers -------------------------------------------------------------

def test_fingerprint_accessors_refuse_rather_than_guess():
    value = capture.env_fingerprint(_ENV, umask=0o022)
    assert capture.fingerprint_version(value) == 2
    assert capture.fingerprint_gate(value) == value.split(":")[1]
    assert capture.fingerprint_path_digest(value) == value.split("path=")[1]

    # A bare v0.1 digest: no version, no gate, no path digest — INCOMPARABLE at
    # every accessor, so no consumer can accidentally compare one.
    assert capture.fingerprint_version("0123456789abcdef") is None
    assert capture.fingerprint_gate("0123456789abcdef") is None
    assert capture.fingerprint_path_digest("0123456789abcdef") is None

    # A v1 value: comparable within v1, and carries no path digest.
    assert capture.fingerprint_version("v1:0123456789abcdef") == 1
    assert capture.fingerprint_gate("v1:0123456789abcdef") == "0123456789abcdef"
    assert capture.fingerprint_path_digest("v1:0123456789abcdef") is None

    # Malformed shapes are refusals, never empty-string matches.
    assert capture.fingerprint_gate("v2:") is None
    assert capture.fingerprint_path_digest("v2:0123456789abcdef:") is None
    assert capture.fingerprint_path_digest("v2:0123456789abcdef:other=aa") is None
