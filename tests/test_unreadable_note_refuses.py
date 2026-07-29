"""A note this binary cannot read is a graded refusal — never a crash, never a pass.

The invariant is stated in `cli.cmd_verify` itself: "Evidence this binary cannot
read is a graded refusal, not a crash. 2, not --strict's 1: 'could not read the
manifest' is a different fact from 'the manifest graded badly'." It was not
holding. Measured on the pre-fix tree, over 22 malformed note shapes:

  - 11 shapes left an uncaught traceback (`KeyError`, `TypeError`,
    `JSONDecodeError`, `ClaimError`) and exited **1** — colliding with the exit
    code `--strict` uses for a note that graded badly, so a corrupt note was
    indistinguishable from an honest failure by exit code alone;
  - 4 shapes were **ACCEPTED**. `{"version": true}` verified green at exit 0,
    because `bool` is an `int` subclass and `True > 3` is False. So did `2.5`,
    `0` and `-1`.

The accepted set is the one that matters. docs/COMPAT.md's "Version 3" section
rests the whole forward-compatibility story on the version guard — the
MANIFEST_VERSION bump exists so an older reader refuses a v3 note *on its
version* before it reaches the claim vocabulary it cannot parse. A guard a
malformed field walks past is not a guard.

Test 1 is the gate: over every malformed shape, `didrun verify --strict` must
exit 2 with no traceback. Not "must not crash" — must not PASS either, and the
two failures need one test that cannot be satisfied by fixing only one of them.
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


# --- helpers -----------------------------------------------------------------


def _session(repo: Path) -> Session:
    return Session(repo / ".didrun")


def _seal_one(repo: Path) -> M.Manifest:
    """A repo carrying one honest sealed claim, so every mutation below starts
    from a note that verifies green."""
    session = _session(repo)
    run_wrapped([sys.executable, "-c", "print('ok')"], session, repo)
    M.declare_claim(
        session,
        Claim(
            ctype="tests-pass",
            label="unit",
            event_indices=(0,),
            declared_at_index=0,
        ),
    )
    return M.seal(session, repo)


def _note_text(repo: Path, commit: str = "HEAD") -> str:
    proc = subprocess.run(
        ["git", "notes", f"--ref={M.NOTES_REF}", "show", commit],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, "the commit carries no note"
    return proc.stdout


def _put_note(repo: Path, raw: str, commit: str = "HEAD") -> None:
    subprocess.run(
        ["git", "notes", f"--ref={M.NOTES_REF}", "add", "-f", "-m", raw, commit],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=True,
    )


def _mutated(raw: str, fn) -> str:
    d = json.loads(raw)
    fn(d)
    return json.dumps(d, sort_keys=True, separators=(",", ":")) + "\n"


def _set_ctype(d, value) -> None:
    d["claims"][0]["claim"]["ctype"] = value


# Every shape measured as broken on the pre-fix tree, plus the four that were
# accepted. Keyed by name so a failure says which shape regressed.
#
# The `version` cases are split into two groups on purpose. A NON-INTEGER
# version is a malformed field (ManifestFormatError). An integer version above
# MANIFEST_VERSION is the documented forward-compat refusal and keeps its own
# message and its own exception — the distinction is load-bearing on the
# tree-fallback scan, where one is skipped and the other propagates.
MALFORMED = {
    # -- the fail-OPEN set: these verified green before the fix ---------------
    "version true": lambda raw: _mutated(raw, lambda d: d.__setitem__("version", True)),
    "version 2.5": lambda raw: _mutated(raw, lambda d: d.__setitem__("version", 2.5)),
    "version 0": lambda raw: _mutated(raw, lambda d: d.__setitem__("version", 0)),
    "version -1": lambda raw: _mutated(raw, lambda d: d.__setitem__("version", -1)),
    # -- the crash set --------------------------------------------------------
    "version string": lambda raw: _mutated(raw, lambda d: d.__setitem__("version", "3")),
    "version null": lambda raw: _mutated(raw, lambda d: d.__setitem__("version", None)),
    "version list": lambda raw: _mutated(raw, lambda d: d.__setitem__("version", [3])),
    "version absent": lambda raw: _mutated(raw, lambda d: d.pop("version")),
    "not json": lambda raw: "this is not json\n",
    "json list": lambda raw: "[1,2,3]\n",
    "json string": lambda raw: '"hello"\n',
    "no commit": lambda raw: _mutated(raw, lambda d: d.pop("commit")),
    "no tree": lambda raw: _mutated(raw, lambda d: d.pop("tree")),
    "no claims": lambda raw: _mutated(raw, lambda d: d.pop("claims")),
    "no coverage": lambda raw: _mutated(raw, lambda d: d.pop("coverage")),
    "claims not a list": lambda raw: _mutated(
        raw, lambda d: d.__setitem__("claims", "x")
    ),
    "claim entry not a dict": lambda raw: _mutated(
        raw, lambda d: d["claims"].__setitem__(0, 7)
    ),
    "claim object missing": lambda raw: _mutated(
        raw, lambda d: d["claims"][0].pop("claim")
    ),
    "ctype unknown": lambda raw: _mutated(raw, lambda d: _set_ctype(d, "nonsense")),
    "ctype killed": lambda raw: _mutated(raw, lambda d: _set_ctype(d, "diff-exercised")),
    "ctype null": lambda raw: _mutated(raw, lambda d: _set_ctype(d, None)),
    "event_indices not iterable": lambda raw: _mutated(
        raw, lambda d: d["claims"][0]["claim"].__setitem__("event_indices", 7)
    ),
}


# --- test 1: the gate --------------------------------------------------------


@pytest.mark.parametrize("shape", sorted(MALFORMED))
def test_an_unreadable_note_refuses_with_exit_2_and_no_traceback(
    repo: Path, capsys, shape: str
):
    """THE criterion, over every malformed shape, through the real CLI.

    Three assertions, because the two pre-fix failure modes are opposites and a
    one-sided test would pass on half a fix:

      1. exit 2 — not 0 (accepted), and not 1 (which is `--strict`'s "graded
         badly" and would make a corrupt note look like an honest failure);
      2. the refusal is on stderr, prefixed like every other refusal;
      3. nothing raised out of the command.
    """
    _seal_one(repo)
    _put_note(repo, MALFORMED[shape](_note_text(repo)))
    capsys.readouterr()

    # Any exception escaping cli.main IS the traceback this test is about, so it
    # is not caught here — pytest reporting it as an error is the correct
    # outcome for a regression.
    rc = cli.main(["--repo", str(repo), "verify", "--strict"])
    captured = capsys.readouterr()

    assert rc == 2, (
        f"{shape!r}: expected the graded refusal (2), got {rc}. "
        f"0 means the malformed note was ACCEPTED; 1 means it was reported as a "
        f"grading failure rather than an unreadable one."
    )
    assert "didrun verify:" in captured.err
    assert "Traceback" not in captured.err


def test_the_malformed_set_covers_both_pre_fix_failure_modes():
    """A guard on test 1's fixture: it must keep testing both directions.

    If the fail-open cases were ever dropped from MALFORMED, test 1 would still
    pass over a build that only stopped crashing — and the accepted-green shapes
    are the ones that could put a false verdict in front of a reviewer.
    """
    assert {"version true", "version 2.5", "version 0", "version -1"} <= set(MALFORMED)
    assert {"not json", "ctype unknown", "no commit"} <= set(MALFORMED)


# --- test 2: the fail-open shape, stated on its own ---------------------------


def test_a_boolean_version_is_not_version_one(repo: Path):
    """The measured false green, isolated.

    `bool` is an `int` subclass: `True > 3` is False, so the pre-fix guard let
    `{"version": true}` through and graded the note under v1 semantics. It
    verified at exit 0. This is the same reading rule `_superseded_by` already
    applied via `_is_index`, and the reason is identical — a field that arrived
    from a file is not a field this process computed.
    """
    _seal_one(repo)
    body = json.loads(_note_text(repo))
    body["version"] = True
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")

    with pytest.raises(M.ManifestFormatError) as exc:
        M.Manifest.from_json(raw)
    assert "True" in str(exc.value)
    # And it must NOT be reported as the forward-compat refusal, which would
    # tell an operator to upgrade over a note that is simply corrupt.
    assert "upgrade didrun" not in str(exc.value)


# --- test 3: the two refusals stay distinguishable ---------------------------


def test_a_format_refusal_is_a_manifest_error_but_a_version_refusal_is_not_a_format_one(
    repo: Path,
):
    """The type split the tree-fallback scan depends on.

    `ManifestFormatError` subclasses `ManifestError` so the CLI's existing
    handler catches it and exits 2. But a version this binary cannot read must
    NOT be a format error: on the scan path a format error is skipped and
    counted, and a too-new version propagates. Collapsing the two would make a
    v4 note skippable, and the scan would report some older note's verdict as if
    it were current.
    """
    assert issubclass(M.ManifestFormatError, M.ManifestError)

    _seal_one(repo)
    body = json.loads(_note_text(repo))
    body["version"] = M.MANIFEST_VERSION + 1
    too_new = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")

    with pytest.raises(M.ManifestError) as exc:
        M.Manifest.from_json(too_new)
    assert not isinstance(exc.value, M.ManifestFormatError)
    assert "upgrade didrun" in str(exc.value)


# --- test 4: the scan path still skips rather than dying ---------------------


def test_the_tree_fallback_still_skips_a_corrupt_note_and_counts_it(
    repo: Path, git
):
    """Preserved behaviour, pinned because the fix could plausibly break it.

    A foreign or corrupt note under the same ref must not hide every good one —
    it is skipped and COUNTED. Before the fix that happened by accident, because
    the scan caught bare `Exception` and `json` raised something that was not a
    `ManifestError`. Now `ManifestFormatError` IS a `ManifestError`, so the skip
    clause has to come first by type. If it did not, this verify would raise
    instead of resolving the good note.
    """
    _seal_one(repo)
    good_tree = M.gitplumbing.commit_tree(repo, M.gitplumbing.head_commit(repo))

    # A second commit carrying an unreadable note under the same ref.
    (repo / "other.py").write_text("x = 1\n")
    git(repo, "add", "other.py")
    git(repo, "commit", "-qm", "other")
    _put_note(repo, "not a manifest at all\n", "HEAD")

    # Ask for a tree no note carries, so the scan is forced to walk PAST the
    # corrupt note instead of stopping at the good one. `git notes list` order is
    # by object id, so a test that relied on the corrupt note being reached first
    # would pass or fail on a hash — this reaches it every time.
    m, resolved_by, skipped = M._resolve_manifest(repo, None, "f" * 40)
    assert m is None
    assert resolved_by == "none"
    assert skipped == 1, "the corrupt note was not skipped and counted"

    # And the good note is still resolvable with the corrupt one in the ref.
    m, resolved_by, _ = M._resolve_manifest(repo, None, good_tree)
    assert m is not None, "the corrupt note hid the good one"
    assert resolved_by == "tree-fallback"


# --- test 5: no false refusal of an honest note ------------------------------


@pytest.mark.parametrize("version", [1, 2, M.MANIFEST_VERSION])
def test_every_version_this_binary_writes_or_must_read_still_parses(
    repo: Path, version: int
):
    """The fix must refuse nothing that was legitimately published.

    Every note in the world carries an integer version of 1, 2 or 3, and the
    compat corpus replays all three. A guard that tightened onto them would be a
    worse defect than the one it closed.
    """
    _seal_one(repo)
    body = json.loads(_note_text(repo))
    body["version"] = version
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")
    assert M.Manifest.from_json(raw).version == version


def test_an_honest_note_still_verifies_green(repo: Path, capsys):
    """The end-to-end control for test 1: the same path, unmutated, exits 0."""
    _seal_one(repo)
    capsys.readouterr()
    assert cli.main(["--repo", str(repo), "verify", "--strict"]) == 0
