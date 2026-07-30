"""P3 remediation — the two directions the tokenizer change was measured in.

The P3.2 work removed `/` from the entropy sweep's token class because an
absolute filesystem path was tokenizing as one 90-character token and scoring
like a credential. That fixed the false positives and was measured. What was
not measured is the other direction: `/` is also 1 of the 64 characters of
base64, so dropping it stopped scoring a real credential class as well as
paths. A base64 secret whose slash-free runs are all shorter than the
24-character floor became invisible — and because replacement is driven off
`scan`'s findings, invisible means UNREDACTED, published verbatim into a note
under a seal line reading "0 findings".

So this file pins BOTH directions, and each fixture asserts the structural
property that makes it a faithful witness rather than a convenient one:

* the credential fixtures assert that every one of their `/`-delimited
  segments is under the floor, which is exactly the class that went missing —
  a fixture with a 24-character segment would pass on segment scoring alone and
  prove nothing;
* the path fixtures assert they fired under the pre-P3.2 sweep, so "still
  silent" is a statement about a real false positive and not about a string
  that was always quiet.

`_looks_like_path` is what tells the two apart, and it is deliberately biased:
one name-like segment is enough to call a run a path. That direction can only
move a run back to the segment scoring that P3.2 ships, so it cannot introduce
a false positive P3.2 does not already have — measured at 0 new ones over
46,403 real paths — and it pays for that in recall instead.

Every credential-shaped string here is synthetic and structural. Every path is
synthetic too, for the reason the P3.2 file gives: the strings this was
measured against are a home directory and a private project name, and a test
fixture is a shipped file.
"""

from __future__ import annotations

import json
import math
import re
import subprocess
import sys
from pathlib import Path

import pytest

from didrun import manifest as M
from didrun import redact
from didrun.capture import run_wrapped
from didrun.claims import Claim
from didrun.ledger import Session


# --- the P3.2 sweep, reimplemented so before/after is checkable here ----------

# The token class exactly as P3.2 shipped it: `/` removed, so a run is only
# ever scored in segments. Written out rather than imported, so a change to
# redact.py cannot make these before/after assertions agree with it.
_P32_TOKENISH = re.compile(r"[A-Za-z0-9_\-+=]{24,}")
_PRE_P32_TOKENISH = re.compile(r"[A-Za-z0-9_\-+/=]{24,}")
_HEXISH = re.compile(r"^[0-9a-fA-F]+$")


def _bits_per_char(s: str) -> float:
    counts: dict = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _sweep(text: str, tokenizer) -> list:
    """The entropy sweep under an arbitrary tokenizer, structured hits removed."""
    covered = []
    for _kind, pat in redact._PATTERNS:
        covered.extend(m.span() for m in pat.finditer(text))
    hits = []
    for m in tokenizer.finditer(text):
        tok = m.group(0)
        if _HEXISH.match(tok):
            continue
        if any(s <= m.start() < e for s, e in covered):
            continue
        if _bits_per_char(tok) >= redact._ENTROPY_MIN_BITS_PER_CHAR:
            hits.append(m.span())
    return hits


def _entropy_hits(text: str) -> list:
    return [f for f in redact.scan(text) if f.kind == redact._ENTROPY_KIND]


# --- direction 1: base64 credentials with a separator in them ----------------

# Synthetic base64-alphabet credentials. Each one carries `/` at an offset that
# chops it into pieces that are ALL under the 24-character floor, which is the
# precise shape that stopped being a candidate at all.
SEPARATED_CREDENTIALS = [
    "Kq7Xm2Bv9Rt4Wn6Zc/8Yd3Fj5Hg1Lp0Qs",
    "Zr4Nb8Kw2Vt6Mx1Qy/Jd7Fs3Gh5Lc9Pn0Rv2Bt6Wq",
    "Tj5Hn9Cw3Xq7Bz1Mv/Ld4Fp8Gs2Kr6Yt0Nx/Vb3Zc7Qw",
]


@pytest.mark.parametrize("cred", SEPARATED_CREDENTIALS)
def test_credential_fixtures_are_faithful_witnesses(cred):
    """Every segment under the floor — otherwise the fixture proves nothing.

    A fixture with one 24-character slash-free segment is caught by segment
    scoring alone, so it would pass against the very code that lost this
    class. The whole run must clear the bar and no segment may reach it.
    """
    segments = cred.split("/")
    assert len(segments) > 1, "fixture must contain a separator"
    assert max(len(s) for s in segments) < redact._ENTROPY_MIN_LEN, (
        "fixture is caught by segment scoring and cannot witness the defect"
    )
    assert len(cred) >= redact._ENTROPY_MIN_LEN
    assert _bits_per_char(cred) >= redact._ENTROPY_MIN_BITS_PER_CHAR


@pytest.mark.parametrize("cred", SEPARATED_CREDENTIALS)
def test_separated_credentials_were_lost_by_p32_and_are_found_again(cred):
    """The regression, stated as a before/after on each fixture."""
    assert _sweep(cred, _PRE_P32_TOKENISH), "fixture did not fire before P3.2"
    assert not _sweep(cred, _P32_TOKENISH), (
        "fixture is not in the class P3.2 lost, so it cannot witness the fix"
    )
    assert _entropy_hits(cred), "the credential class is still invisible"


@pytest.mark.parametrize("cred", SEPARATED_CREDENTIALS)
def test_a_found_credential_is_actually_replaced(cred):
    """Detection is not the point; removal is.

    `redact` drives replacement off `scan`'s findings, so a class that stops
    being a candidate stops being scrubbed too. This asserts the consequence
    rather than the mechanism.
    """
    result = redact.redact(cred)
    assert cred not in result.text
    assert result.text == redact._mask(redact._ENTROPY_KIND)
    # And the projection still reconstructs, so nothing was mangled.
    assert redact.reconstruct(cred, result) == cred


def test_a_separated_credential_inside_a_command_line_is_replaced():
    """The shape that actually leaks: a secret sitting in a recorded argv."""
    cred = SEPARATED_CREDENTIALS[1]
    text = f"deploy --token {cred} --region eu-west-1"
    scrubbed = redact.redact(text).text
    assert cred not in scrubbed
    assert "deploy --token" in scrubbed and "--region eu-west-1" in scrubbed


# --- direction 2: the paths P3.2 silenced stay silent ------------------------

# The same class the P3.2 measurement was taken over: ordinary build, cache and
# toolchain paths, every one of them a false positive under the pre-P3.2 sweep.
PATHS_THAT_FIRED_BEFORE_P32 = [
    "/opt/homebrew/Cellar/go/1.24.0/libexec/pkg/tool/darwin_arm64",
    "/var/folders/qs/tmpbuild/example-service/cmd/gateway/internal/transport/grpc_handler.go",
    "/Users/exampleuser/Library/Caches/build-tool/artifacts/darwin_arm64/release/binary",
    "/home/runner/_work/pipeline-Qz4/artifacts/Linux_x64/Release/bin/toolchain",
    "/opt/build/Jenkins/workspace/Nightly_x64/out/Release/obj/gen/protoc_wrapper",
]

# Paths whose segments are CamelCase or capitalised rather than lower case —
# the shape that a naive "a path segment is lower case" rule misreads as a
# credential. They must stay quiet too.
MIXED_CASE_PATHS = [
    "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks",
    "/opt/toolchain/PrivateFrameworks/CoreFoundation/Modules/Darwin/Headers",
]


@pytest.mark.parametrize("path", PATHS_THAT_FIRED_BEFORE_P32 + MIXED_CASE_PATHS)
def test_paths_silenced_by_p32_are_still_silent(path):
    assert _entropy_hits(path) == [], "a path is being scored as a credential again"
    assert redact.redact(path).text == path, "a path was rewritten in an export"


@pytest.mark.parametrize("path", PATHS_THAT_FIRED_BEFORE_P32)
def test_path_fixtures_are_faithful_witnesses(path):
    """These fired before P3.2, so "still silent" is about a real false positive."""
    assert _sweep(path, _PRE_P32_TOKENISH), (
        "fixture did not fire under the pre-P3.2 sweep and proves nothing"
    )


def test_the_separator_is_classified_not_tokenized_away():
    """The actual mechanism, pinned directly.

    P3.2 answered "is this `/` a separator?" in the character class, which
    answers it the same way for every string. It is answered per run now: a
    path is scored in segments, a base64 blob whole. The segment tokenizer
    still admits no separator, which is what keeps a path from re-merging.
    """
    assert "/" not in redact._TOKENISH.pattern
    assert "/" in redact._RUNISH.pattern
    assert redact._looks_like_path(PATHS_THAT_FIRED_BEFORE_P32[0])
    assert redact._looks_like_path(MIXED_CASE_PATHS[0])
    for cred in SEPARATED_CREDENTIALS:
        assert not redact._looks_like_path(cred)


def test_the_threshold_and_the_length_floor_still_did_not_move():
    """The candidate moved; the test applied to it did not."""
    assert redact._ENTROPY_MIN_BITS_PER_CHAR == 4.2
    assert redact._ENTROPY_MIN_LEN == 24


def test_a_low_entropy_prefix_cannot_hide_a_high_entropy_tail():
    """Whole-run scoring must not become a way to dilute a secret below the bar.

    A long repetitive prefix drags the whole run's per-character entropy under
    the threshold. Scoring only the run would miss the tail that segment
    scoring catches, so a run that does not clear the bar whole is still
    scored in segments.
    """
    run = "a" * 40 + "/" + "Kq7Xm2Bv9Rt4Wn6Zc8Yd3Fj5Hg1Lp0Qs"
    assert _bits_per_char(run) < redact._ENTROPY_MIN_BITS_PER_CHAR, (
        "fixture does not dilute the run and cannot witness the fallback"
    )
    assert _entropy_hits(run), "the high-entropy tail was diluted away"


def test_a_git_hash_is_still_not_a_secret():
    """The hex exclusion survives whole-run scoring."""
    assert _entropy_hits("a" * 0 + "0123456789abcdef0123456789abcdef01234567") == []


# --- the exported claim fields are redacted, not just blocked on -------------

_GHP = "ghp_" + "G" * 36


def _one_event(session: Session, repo: Path, code: str):
    return run_wrapped([sys.executable, "-c", code], session, repo)


def _note_text(repo: Path) -> str:
    proc = subprocess.run(
        ["git", "notes", f"--ref={M.NOTES_REF}", "show", "HEAD"],
        cwd=str(repo), capture_output=True, text=True,
    )
    assert proc.returncode == 0, "no note was published"
    return proc.stdout


def test_a_secret_in_a_claim_label_is_redacted_in_the_published_note(repo: Path):
    """The gate and the publication used to disagree.

    A token in a claim label blocked the seal — and the refusal says "re-run
    with --allow-secrets to export a REDACTED artifact anyway". On the
    override the label went into refs/notes/didrun verbatim: a ref that gets
    pushed. Blocking is not redacting, and the message promised both.
    """
    s = Session(repo / ".didrun")
    _one_event(s, repo, "print('ok')")
    M.declare_claim(
        s,
        Claim(
            ctype="tests-pass",
            label=f"suite green with {_GHP}",
            event_indices=(0,),
            declared_at_index=0,
        ),
    )
    # Still blocks: this fix does not open the gate, it makes the override honest.
    with pytest.raises(redact.SecretsBlocked):
        M.seal(s, repo)

    m = M.seal(s, repo, allow_secrets=True)
    assert m.secrets_override is True

    published = _note_text(repo)
    assert _GHP not in published, "the token was published verbatim"
    assert json.loads(published)["claims"][0]["claim"]["label"] == (
        f"suite green with {redact._mask('github-token')}"
    )


def test_the_label_redaction_declares_its_projection(repo: Path):
    """A marker is plain text; the projection is what a consumer can check."""
    s = Session(repo / ".didrun")
    _one_event(s, repo, "print('ok')")
    label = f"suite green with {_GHP}"
    M.declare_claim(
        s,
        Claim(ctype="tests-pass", label=label, event_indices=(0,), declared_at_index=0),
    )
    m = M.seal(s, repo, allow_secrets=True)
    fields = m.claims[0]["redaction"]["fields"]
    entry = next(f for f in fields if f["field"] == "claim.label")
    assert entry["detector_id"] == "github-token"
    assert entry["withheld"] is False
    # The declared span names the source coordinates that were replaced.
    assert label[entry["start"]:entry["end"]] == _GHP


def test_a_secret_in_a_pathspec_is_redacted_in_the_published_note(repo: Path):
    """Pathspecs are operator-authored too, and they are exported."""
    s = Session(repo / ".didrun")
    _one_event(s, repo, "print('ok')")
    M.declare_claim(
        s,
        Claim(
            ctype="tests-pass",
            label="scoped",
            event_indices=(0,),
            pathspecs=(f"src/{_GHP}",),
            declared_at_index=0,
        ),
    )
    m = M.seal(s, repo, allow_secrets=True)
    published = _note_text(repo)
    assert _GHP not in published
    assert redact._mask("github-token") in m.claims[0]["claim"]["pathspecs"][0]


def test_a_secret_in_a_changed_path_is_redacted_in_the_published_note(repo: Path):
    """A changed path is repository-authored text and rides in every stale grade."""
    s = Session(repo / ".didrun")
    _one_event(s, repo, "print('ok')")
    M.declare_claim(
        s,
        Claim(ctype="tests-pass", label="t", event_indices=(0,), declared_at_index=0),
    )
    # Move the tree after the evidence, with a filename that carries a secret.
    (repo / f"{_GHP}.txt").write_text("x\n")
    subprocess.run(["git", "add", "-A"], cwd=str(repo), capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-qm", "add file"], cwd=str(repo), capture_output=True, check=True
    )

    m = M.seal(s, repo, allow_secrets=True)
    result = m.claims[0]
    assert result["delta"], "fixture did not produce a delta and proves nothing"
    published = _note_text(repo)
    assert _GHP not in published, "a changed path was published verbatim"
    assert any(
        redact._mask("github-token") in change["path"] for change in result["delta"]
    )


def test_every_exported_claim_string_field_is_scrubbed(repo: Path):
    """The invariant, not the four instances.

    Anything in the published claim entry that carries operator- or
    repository-authored text goes through the redaction pass. This walks the
    serialized note rather than naming fields, so a field added later that
    forgets the pass fails here.
    """
    s = Session(repo / ".didrun")
    _one_event(s, repo, "print('ok')")
    M.declare_claim(
        s,
        Claim(
            ctype="tests-pass",
            label=f"label {_GHP}",
            event_indices=(0,),
            pathspecs=(f"spec/{_GHP}",),
            declared_at_index=0,
        ),
    )
    (repo / f"{_GHP}.txt").write_text("x\n")
    subprocess.run(["git", "add", "-A"], cwd=str(repo), capture_output=True, check=True)
    subprocess.run(
        ["git", "commit", "-qm", "add file"], cwd=str(repo), capture_output=True, check=True
    )
    M.seal(s, repo, allow_secrets=True)
    assert _GHP not in _note_text(repo)


def test_the_scan_still_blocks_on_a_field_it_redacts(repo: Path):
    """Redacting a field must not quietly stop it blocking.

    Scrubbing the label before the manifest bytes are serialized removes it
    from the whole-blob scan. If the field pass did not report what it removed,
    this seal would succeed silently — the opposite failure, and just as bad.
    """
    s = Session(repo / ".didrun")
    _one_event(s, repo, "print('ok')")
    M.declare_claim(
        s,
        Claim(
            ctype="tests-pass",
            label=f"label {_GHP}",
            event_indices=(0,),
            declared_at_index=0,
        ),
    )
    with pytest.raises(redact.SecretsBlocked) as exc:
        M.seal(s, repo)
    message = str(exc.value)
    assert "github-token" in message
    # And it says WHERE, in claim coordinates: a label has no event and no line.
    assert "label of claim 0" in message
