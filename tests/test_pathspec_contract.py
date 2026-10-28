"""`claim --path` takes plain path prefixes, says what they mean, and refuses
the rest.

Found dogfooding didrun on a real build. The help said only "declare a
pathspec for scope-exact grading", which reads like a git pathspec, so an
operator passed one:

    didrun claim tests-pass --path ':(exclude)docs/x.md'

`_within` is a PATH-PREFIX test. It has never interpreted git pathspec magic,
so that declaration covered exactly nothing — every change graded stale, with
no word about why. The same silent nothing happens to a glob (`src/*.py`), to
`./src` (the leading `./` is never stripped), and to `.`.

The design call: refuse, do not interpret. Supporting `:(exclude)` would mean
"every path but this one is in scope", which turns scope-exact into a grade
that excuses almost any change; it is the most generous possible reading of a
flag that exists to be narrow. So the CLI refuses every form `_within` cannot
honour, names why, and writes nothing. A note that ALREADY carries such a
pathspec is not refused on read: it keeps grading exactly as it did, because
refusing it would make published evidence unreadable.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from didrun import cli
from didrun import gitplumbing as gp
from didrun import manifest as M
from didrun.capture import run_wrapped
from didrun.claims import Claim, grade, pathspec_problem
from didrun.ledger import Session


def _session(repo: Path) -> Session:
    return Session(repo / ".didrun")


def _ran(repo: Path) -> Session:
    s = _session(repo)
    run_wrapped([sys.executable, "-c", "pass"], s, repo)
    return s


def _claim(repo: Path, *paths: str) -> int:
    argv = ["--repo", str(repo), "claim", "tests-pass", "--label", "t"]
    for p in paths:
        argv += ["--path", p]
    return cli.main(argv)


@pytest.mark.parametrize(
    "spec, why",
    [
        (":(exclude)docs/x.md", "pathspec magic"),
        (":!docs/x.md", "pathspec magic"),
        (":/src", "pathspec magic"),
        ("src/*.py", "glob"),
        ("src/?.py", "glob"),
        ("src/[ab].py", "glob"),
        ("", "whole repository"),
        (".", "whole repository"),
        ("/", "whole repository"),
        ("./", "whole repository"),
        ("./src", "leading ./"),
        ("src/../docs", "'.' or '..'"),
        ("src/./a.py", "'.' or '..'"),
    ],
)
def test_a_pathspec_didrun_cannot_honour_is_refused_and_nothing_is_declared(
    repo: Path, capsys, spec: str, why: str
):
    s = _ran(repo)
    assert _claim(repo, "src/", spec) == 2
    err = capsys.readouterr().err
    assert why in err
    assert repr(spec) in err, "the refusal names the offending value"
    assert M._load_claims(s) == [], "a refused claim writes nothing"


def test_plain_prefixes_are_accepted_repeated_and_kept_in_order(repo: Path):
    s = _ran(repo)
    assert _claim(repo, "src/", "docs/status/X.md", "/abs/like") == 0
    (declared,) = M._load_claims(s)
    assert declared.pathspecs == ("src/", "docs/status/X.md", "/abs/like")


def test_the_help_says_what_a_path_means(capsys):
    """The help is the contract an operator reads: what the prefix covers,
    that it is repeatable, and what is refused."""
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["claim", "--help"])
    text = " ".join(capsys.readouterr().out.split())
    for phrase in (
        "--path PREFIX",
        "may differ from the tree this claim's evidence was recorded against",
        "files the claimed run itself wrote",
        "grades stale",
        "Repeat --path",
        "':(exclude)",
        "refused",
    ):
        assert phrase in text, phrase


def test_the_library_validator_matches_the_cli():
    assert pathspec_problem("src/") is None
    assert pathspec_problem("calc.py") is None
    assert "pathspec magic" in pathspec_problem(":(exclude)x")


def test_a_note_already_holding_a_magic_pathspec_still_reads_and_grades(repo: Path):
    """Refusing at declaration must not make published evidence unreadable: a
    Claim carrying one still constructs, and grades as it always did — the
    magic covers nothing, so a change is out of scope."""
    s = _ran(repo)
    claim = Claim(ctype="tests-pass", label="t", event_indices=(0,),
                  pathspecs=(":(exclude)docs/x.md",), declared_at_index=0)
    (repo / "calc.py").write_text("x = 1\n")
    import subprocess

    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "edit"], cwd=repo, check=True)
    r = grade(claim, gp.commit_tree(repo, "HEAD"), s.events(), repo, s.blobs.root)
    assert r.grade == "stale"
    M.declare_claim(s, claim)
    M.seal(s, repo)
    assert M.verify(s, repo).results[0].grade == "stale"
