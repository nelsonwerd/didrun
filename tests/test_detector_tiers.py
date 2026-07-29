"""P3.2 — detector tiers, finding locality, and the export-domain block.

Three things are pinned here, and they pull against each other on purpose.

1. The tokenizer stops treating a whole filesystem path as one token. The
   entropy sweep's token class used to include `/`, and a path accumulates
   distinct characters far faster than any one of its segments does, so an
   ordinary build path scored like a credential. `_old_entropy_findings` below
   is a deliberate reimplementation of the pre-P3.2 sweep, so every "this no
   longer fires" assertion is a measured BEFORE/AFTER inside one file rather
   than a claim about code that no longer exists.

2. Nothing in (1) may cost structured recall. The six shape-based detectors are
   unchanged and every one of them is pinned firing at `block`, and the entropy
   sweep is pinned still firing on a genuinely high-entropy token — it was
   demoted to `notice`, never deleted. Deleting it would pass every "paths stop
   firing" test in this file while removing the only detector that catches an
   unstructured credential.

3. Blocking follows the bytes that leave the machine. A secret in a claim label
   is published and now blocks; a secret in a stdout blob stays in a gitignored
   local ledger and now warns instead.

Every credential-shaped string below is synthetic and structural — a shape the
detectors match, never a real token. Every path below is synthetic too: the
strings this work was measured against are a home directory and a private
project name, and a test fixture is a shipped file. The substitution is not
taken on faith — each synthetic path's entropy is asserted into the band its
group is supposed to occupy, so swapping the fixture for a differently-shaped
string fails here instead of quietly changing what is being tested.
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


def _session(repo: Path) -> Session:
    return Session(repo / ".didrun")


# --- the pre-P3.2 detector, reimplemented so before/after is checkable --------

# The token class as it stood before this prompt: `/` included, which is the
# entire defect. Written out rather than imported, so restoring the old class
# in redact.py cannot make these tests agree with it.
_OLD_TOKENISH = re.compile(r"[A-Za-z0-9_\-+/=]{24,}")
_HEXISH = re.compile(r"^[0-9a-fA-F]+$")


def _bits_per_char(s: str) -> float:
    counts: dict = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _old_entropy_findings(text: str) -> list:
    """The entropy sweep exactly as it behaved before the tokenizer change."""
    covered = []
    for _kind, pat in redact._PATTERNS:
        covered.extend(m.span() for m in pat.finditer(text))
    hits = []
    for m in _OLD_TOKENISH.finditer(text):
        tok = m.group(0)
        if _HEXISH.match(tok):
            continue
        if any(s <= m.start() < e for s, e in covered):
            continue
        if _bits_per_char(tok) >= redact._ENTROPY_MIN_BITS_PER_CHAR:
            hits.append(m.span())
    return hits


def _max_token_bits(text: str, tokenizer=_OLD_TOKENISH) -> float:
    toks = [m.group(0) for m in tokenizer.finditer(text) if not _HEXISH.match(m.group(0))]
    return max((_bits_per_char(t) for t in toks), default=0.0)


# --- test 1: paths no longer tokenize whole ----------------------------------

# The band ordinary repository paths were measured to occupy. Paths in it were
# never the problem — they are the control group, and asserting the synthetics
# land in it is what makes the substitution faithful rather than convenient.
_ORDINARY_BAND = (3.94, 4.12)

ORDINARY_PATHS = [
    "/home/runner/work/project-name/project-name/src/backend/services/authentication/handlers.py",
    "/Users/exampleuser/src/example-project/pkg/adapters/outbound/persistence/migrations",
]

# The knife edge: paths that scored between the ordinary band and the threshold.
# They did not fire, but a hair more variety in a directory name and they would
# have — which is the mechanism behind the observed 1-to-346 finding swing on
# runs that differed only in where the repo was checked out.
KNIFE_EDGE_PATHS = [
    "/Users/exampleuser/Documents/billing-reconciler/internal/messagebus/http/connection_lifecycle_test.go",
]

# And the paths that actually fired: ordinary build and cache paths, every one
# of them a false positive, every one of them silent after the change. The
# homebrew path is used verbatim — it names no user and no private project.
DEEP_PATHS_THAT_FIRED = [
    "/opt/homebrew/Cellar/go/1.24.0/libexec/pkg/tool/darwin_arm64",
    "/var/folders/qs/tmpbuild/example-service/cmd/gateway/internal/transport/grpc_handler.go",
    "/Users/exampleuser/Library/Caches/build-tool/artifacts/darwin_arm64/release/binary",
    "/Users/exampleuser/Documents/widget-platform-Qz4/internal/servicelayer/http/connection_lifecycle_test.go",
]


@pytest.mark.parametrize("path", ORDINARY_PATHS)
def test_ordinary_paths_are_faithful_substitutes_and_stay_quiet(path):
    """The control group: in the measured band, silent before and after."""
    low, high = _ORDINARY_BAND
    bits = _max_token_bits(path)
    assert low <= bits <= high, (
        f"synthetic path is not a faithful substitute: {bits:.4f} bits/char is "
        f"outside the measured ordinary-path band {_ORDINARY_BAND}"
    )
    assert _old_entropy_findings(path) == []
    assert redact.scan(path) == []


@pytest.mark.parametrize("path", KNIFE_EDGE_PATHS)
def test_knife_edge_paths_sit_between_the_band_and_the_threshold(path):
    """Faithful to the near-miss class: above ordinary, still under the line."""
    bits = _max_token_bits(path)
    assert _ORDINARY_BAND[1] < bits < redact._ENTROPY_MIN_BITS_PER_CHAR, (
        f"synthetic path is not a faithful knife-edge substitute: {bits:.4f}"
    )
    assert _old_entropy_findings(path) == []
    assert redact.scan(path) == []


@pytest.mark.parametrize("path", DEEP_PATHS_THAT_FIRED)
def test_deep_paths_fired_before_and_are_silent_after(path):
    """The before/after difference, stated explicitly on each fixture."""
    bits = _max_token_bits(path)
    assert bits >= redact._ENTROPY_MIN_BITS_PER_CHAR, (
        f"synthetic path is not a faithful substitute for a FIRING path: {bits:.4f}"
    )
    before = _old_entropy_findings(path)
    assert before, "fixture must fire under the old tokenizer or it proves nothing"
    assert redact.scan(path) == [], "path still tokenizes whole"


def test_tokenizer_no_longer_admits_a_path_separator():
    """The one-character change, pinned directly.

    A path is now several tokens, not one, and the count is what changes the
    entropy: the same characters spread over segments never reach the
    threshold that the concatenation did.
    """
    assert "/" not in redact._TOKENISH.pattern
    path = DEEP_PATHS_THAT_FIRED[1]
    old = _OLD_TOKENISH.findall(path)
    new = redact._TOKENISH.findall(path)
    assert any("/" in tok for tok in old), "fixture must span separators"
    assert all("/" not in tok for tok in new)
    # A path's segments are individually short, so the whole path no longer
    # reaches the 24-character floor at all: it is not merely re-scored, it
    # stops being a candidate.
    assert max(len(t) for t in old) > max((len(t) for t in new), default=0)


def test_the_threshold_and_the_length_floor_did_not_move():
    """One variable at a time. If these move, the measurement above is void."""
    assert redact._ENTROPY_MIN_BITS_PER_CHAR == 4.2
    assert redact._ENTROPY_MIN_LEN == 24


# --- test 2: structured recall is unchanged, and entropy still exists --------

STRUCTURED_SAMPLES = [
    ("aws-access-key", "AKIAIOSFODNN7EXAMPLE"),
    ("github-token", "ghp_" + "A" * 36),
    ("slack-token", "xoxb-1234567890-ABCDEFGHIJ"),
    ("openai-key", "sk-AbCdEf0123456789XyZwVuTsQq"),
    ("pem-private-key", "-----BEGIN RSA PRIVATE KEY-----"),
    ("env-secret-assignment", "MY_SECRET=hunter2taffylongvalue"),
]


@pytest.mark.parametrize("kind,sample", STRUCTURED_SAMPLES)
def test_every_structured_detector_fires_at_block_tier(kind, sample):
    findings = [f for f in redact.scan(sample) if f.kind == kind]
    assert findings, f"{kind} lost recall"
    assert all(f.tier == redact.TIER_BLOCK for f in findings)
    assert all(f.detector_id == kind for f in findings)


def test_structured_detectors_all_declare_block_tier():
    """No structured pattern may quietly arrive at notice tier."""
    for kind, _pat in redact._PATTERNS:
        assert redact._tier(kind) == redact.TIER_BLOCK


def test_entropy_sweep_still_fires_on_a_genuine_high_entropy_token():
    """DEMOTED, NOT DELETED.

    Deleting the sweep would satisfy every path assertion in this file while
    removing the only detector that catches an unstructured credential. A
    24-character token drawn from a wide alphabet, with no `/` to be blamed on
    the tokenizer, must still be reported.
    """
    token = "aZ3kQ9mB7xT2vL5nR8wY4cF6"
    assert "/" not in token and len(token) == redact._ENTROPY_MIN_LEN
    findings = [f for f in redact.scan(token) if f.kind == "high-entropy"]
    assert findings, "the entropy sweep was deleted, not demoted"
    assert findings[0].tier == redact.TIER_NOTICE


def test_entropy_sweep_fires_inside_ordinary_surrounding_text():
    """The same token embedded in a command line is still found."""
    text = "curl -H 'X-Api: aZ3kQ9mB7xT2vL5nR8wY4cF6' https://example.invalid/v1"
    assert any(f.kind == "high-entropy" for f in redact.scan(text))


# --- test 3: locality --------------------------------------------------------

_BLOB = (
    "starting run\n"
    "no secrets on this line\n"
    "leaked ghp_" + "B" * 36 + " in output\n"
    "done\n"
)


def test_findings_in_a_blob_carry_source_line_and_offset():
    source = redact.FindingSource("stdout", event_index=4)
    findings = redact.scan(_BLOB, source)
    hit = next(f for f in findings if f.kind == "github-token")
    assert hit.source.kind == "stdout"
    assert hit.source.event_index == 4
    assert hit.source.argv_index is None
    assert hit.line == 3, "line must be 1-based within the scanned text"
    # The offset indexes the text that was scanned, so a reader can go get it.
    start = hit.source.byte_offset
    assert _BLOB[start:start + (hit.span[1] - hit.span[0])] == _BLOB[hit.span[0]:hit.span[1]]
    assert hit.fingerprint


def test_argv_findings_carry_an_argv_index_and_no_line():
    source = redact.FindingSource("argv", event_index=2, argv_index=3)
    hit = redact.scan("MY_TOKEN=ghp_" + "C" * 36, source)[0]
    assert hit.source.kind == "argv"
    assert hit.source.argv_index == 3
    assert hit.line is None, "an argv element has no lines"


def test_findings_scanned_without_a_source_are_unlocated_not_wrong():
    """Back-compat: the original three-field call still works and lies about nothing."""
    hit = redact.scan("AKIAIOSFODNN7EXAMPLE")[0]
    assert hit.source is None
    assert hit.fingerprint == ""
    assert redact.Finding(kind="k", span=(0, 1), preview="p").tier == redact.TIER_NOTICE


def test_fingerprint_is_stable_across_runs_over_identical_input():
    source = redact.FindingSource("stdout", event_index=4)
    first = [f.fingerprint for f in redact.scan(_BLOB, source)]
    second = [f.fingerprint for f in redact.scan(_BLOB, source)]
    assert first == second
    assert all(len(fp) == 16 for fp in first)


def test_fingerprint_locates_and_does_not_digest_the_token():
    """It is a LOCALITY digest, and that is a security property, not a shortcut.

    Digesting the token would publish an unkeyed hash of a short high-entropy
    string next to the redaction that removed it — a brute-force oracle for the
    thing just protected. So: two different secrets at the same location share a
    fingerprint, and the same secret at two locations does not.
    """
    source = redact.FindingSource("stdout", event_index=1)
    a = redact.scan("ghp_" + "D" * 36, source)[0]
    b = redact.scan("ghp_" + "E" * 36, source)[0]
    assert a.fingerprint == b.fingerprint  # same place, different token

    elsewhere = redact.FindingSource("stdout", event_index=2)
    c = redact.scan("ghp_" + "D" * 36, elsewhere)[0]
    assert a.fingerprint != c.fingerprint  # same token, different place


def test_unknown_source_kind_is_refused():
    with pytest.raises(ValueError):
        redact.FindingSource("stdin")


# --- test 4: the scope inversion is fixed ------------------------------------

_LABEL_TOKEN = "ghp_" + "F" * 36


def _one_event(session: Session, repo: Path, code: str):
    return run_wrapped([sys.executable, "-c", code], session, repo)


def _note_bytes(repo: Path):
    proc = subprocess.run(
        ["git", "notes", f"--ref={M.NOTES_REF}", "show", "HEAD"],
        cwd=str(repo), capture_output=True,
    )
    return proc.stdout if proc.returncode == 0 else None


def test_a_secret_in_a_claim_label_blocks_the_seal(repo: Path):
    """The exported field that was never scanned.

    A claim label is operator-authored text that travels in the note to
    wherever the note travels. Until now the gate never looked at it.
    """
    s = _session(repo)
    _one_event(s, repo, "print('ok')")
    M.declare_claim(
        s,
        Claim(
            ctype="tests-pass",
            label=f"suite green with {_LABEL_TOKEN}",
            event_indices=(0,),
            declared_at_index=0,
        ),
    )
    with pytest.raises(redact.SecretsBlocked) as exc:
        M.seal(s, repo)
    assert "github-token" in str(exc.value)


def test_a_secret_in_a_local_output_blob_warns_but_does_not_block(repo, capsys):
    """The bytes that never leave: reported loudly, not a work stoppage.

    The token is assembled inside the child so it never appears in argv — argv
    IS exported (as a redacted preview) and blocking on it is unchanged.
    """
    s = _session(repo)
    _one_event(s, repo, "print('gh' + 'p_' + 'B' * 36)")
    M.declare_claim(
        s,
        Claim(ctype="tests-pass", label="clean label", event_indices=(0,),
              declared_at_index=0),
    )
    m = M.seal(s, repo)
    assert m.secrets["blocked"] is False
    assert m.secrets_override is False
    err = capsys.readouterr().err
    assert "did not block" in err
    assert "github-token" in err
    assert "stdout of event 0" in err


def test_a_secret_in_argv_still_blocks_and_says_where(repo: Path):
    """argv is exported, so argv still blocks — with an address this time."""
    s = _session(repo)
    _one_event(s, repo, f"x = 'MY_TOKEN={_LABEL_TOKEN}'")
    M.declare_claim(
        s,
        Claim(ctype="tests-pass", label="clean", event_indices=(0,), declared_at_index=0),
    )
    with pytest.raises(redact.SecretsBlocked) as exc:
        M.seal(s, repo)
    message = str(exc.value)
    assert "at argv of event 0 arg 2" in message
    assert _LABEL_TOKEN not in message, "a refusal must not reprint the secret"


def test_a_deep_path_in_stdout_does_not_block_and_seals(repo, capsys):
    """The regression the tokenizer change is for: a build path is not a secret."""
    s = _session(repo)
    _one_event(s, repo, f"print({DEEP_PATHS_THAT_FIRED[0]!r})")
    M.declare_claim(
        s,
        Claim(ctype="tests-pass", label="build ok", event_indices=(0,),
              declared_at_index=0),
    )
    m = M.seal(s, repo)
    assert m.secrets["findings_by_tier"] == {"block": 0, "notice": 0}
    assert m.secrets["blocked"] is False


def test_allow_secrets_overrides_a_blocking_label(repo: Path):
    s = _session(repo)
    _one_event(s, repo, "print('ok')")
    M.declare_claim(
        s,
        Claim(ctype="tests-pass", label=f"green {_LABEL_TOKEN}", event_indices=(0,),
              declared_at_index=0),
    )
    m = M.seal(s, repo, allow_secrets=True)
    assert m.secrets_override is True
    assert m.secrets["blocked"] is True
    assert m.secrets["overridden"] is True


def test_allow_secrets_on_a_clean_seal_still_records_false(repo: Path):
    """`secrets_override` keeps its exact meaning: an override actually happened."""
    s = _session(repo)
    _one_event(s, repo, "print('ok')")
    M.declare_claim(
        s,
        Claim(ctype="tests-pass", label="clean", event_indices=(0,), declared_at_index=0),
    )
    m = M.seal(s, repo, allow_secrets=True)
    assert m.secrets_override is False
    assert m.secrets["overridden"] is False


# --- test 5: the scan domain is recorded -------------------------------------

def test_seal_records_what_was_actually_scanned(repo: Path):
    """`secrets_override: false` used to be unfalsifiable — it was the same word
    for "nothing was found" and "almost nothing was looked at"."""
    s = _session(repo)
    _one_event(s, repo, "print('one')")
    _one_event(s, repo, "print('two')")
    _one_event(s, repo, "print('three')")
    M.declare_claim(
        s,
        Claim(ctype="tests-pass", label="first", event_indices=(0,), declared_at_index=0),
    )
    m = M.seal(s, repo)
    secrets = m.secrets
    # `claim-fields` is load-bearing in this string, not decoration: the label,
    # the pathspecs and the changed paths are scanned as fields by the same
    # pass that redacts them. Before that they reached the scan only inside the
    # serialized manifest, which blocked a seal over a label and then published
    # that label verbatim on --allow-secrets.
    assert secrets["scan_domain"] == "claim-bound-events+claim-fields+manifest"
    assert secrets["events_total"] == 3
    assert secrets["events_scanned"] == 1
    assert secrets["events_scanned"] <= secrets["events_total"]
    assert secrets["bytes_scanned"] > 0
    assert secrets["detector_set_version"] == redact.DETECTOR_SET_VERSION


def test_the_secrets_block_survives_the_note_round_trip(repo: Path):
    s = _session(repo)
    _one_event(s, repo, "print('ok')")
    M.declare_claim(
        s,
        Claim(ctype="tests-pass", label="ok", event_indices=(0,), declared_at_index=0),
    )
    m = M.seal(s, repo)
    body = _note_bytes(repo)
    assert body is not None
    parsed = M.Manifest.from_json(body.rstrip(b"\n"))
    assert parsed.secrets == m.secrets


def test_a_note_without_a_secrets_block_reads_back_additively():
    """A stored v1/v2 note has no `secrets` key and must not become an error."""
    body = json.dumps(
        {
            "version": 1,
            "commit": "0" * 40,
            "tree": "1" * 40,
            "claims": [],
            "coverage": {"total_events": 0, "by_coverage": {}},
            "secrets_override": False,
        }
    ).encode("ascii")
    assert M.Manifest.from_json(body).secrets == {}


# --- change 4b: the detector-set version is declared, not inferred -----------

def test_detector_set_version_is_two_and_the_projection_version_is_not(repo: Path):
    """Re-tiering every detector and changing what the entropy sweep matches IS
    a detector-set change. The span-partition algorithm is untouched.
    """
    assert redact.DETECTOR_SET_VERSION == 2
    assert redact.PROJECTION_VERSION == 1
    s = _session(repo)
    _one_event(s, repo, "print('ok')")
    M.declare_claim(
        s,
        Claim(ctype="tests-pass", label="ok", event_indices=(0,), declared_at_index=0),
    )
    m = M.seal(s, repo)
    assert m.claims[0]["redaction"]["detector_set_version"] == 2
    assert m.claims[0]["redaction"]["projection_version"] == 1
    assert m.secrets["detector_set_version"] == 2


def test_a_v1_projection_is_distinguishable_from_a_v2_one(repo: Path):
    """A consumer reads the declared version instead of inferring didrun's era."""
    s = _session(repo)
    _one_event(s, repo, "print('ok')")
    M.declare_claim(
        s,
        Claim(ctype="tests-pass", label="ok", event_indices=(0,), declared_at_index=0),
    )
    fresh = M.seal(s, repo).claims[0]["redaction"]

    stored_v1 = dict(fresh, detector_set_version=1)
    assert stored_v1["projection_version"] == fresh["projection_version"]
    assert stored_v1["detector_set_version"] != fresh["detector_set_version"]


# --- test 6: the refusal enumerates ------------------------------------------

def test_secrets_blocked_names_detector_source_and_line():
    source = redact.FindingSource("stdout", event_index=7)
    findings = [f for f in redact.scan(_BLOB, source) if f.tier == redact.TIER_BLOCK]
    message = str(redact.SecretsBlocked(findings))
    assert "github-token" in message
    assert "stdout of event 7" in message
    assert "line 3" in message
    assert "fingerprint" in message


def test_secrets_blocked_caps_the_enumeration_and_counts_the_rest():
    """A refusal that prints 19,900 lines is as unusable as one that prints none."""
    text = "\n".join(f"line {i} ghp_" + "G" * 36 for i in range(50))
    findings = redact.scan(text, redact.FindingSource("manifest"))
    assert len(findings) == 50
    message = str(redact.SecretsBlocked(findings))
    listed = [ln for ln in message.splitlines() if ln.startswith("  - ")]
    assert len(listed) == redact.ENUMERATION_CAP
    assert "and 30 more finding(s) not listed" in message
    assert message.splitlines()[0].startswith("export blocked: 50 likely secret(s)")


# --- test 7: a blocked seal is free ------------------------------------------

def test_a_blocked_seal_advances_nothing(repo: Path):
    """Currently unguarded, and it is what makes attempting a seal cheap: the
    refusal must happen before the note is published and before the watermark
    moves, or a blocked seal silently consumes the claims it refused.
    """
    s = _session(repo)
    _one_event(s, repo, "print('ok')")
    M.declare_claim(
        s,
        Claim(ctype="tests-pass", label="clean unit", event_indices=(0,),
              declared_at_index=0),
    )
    M.seal(s, repo)

    seals = s.root / "seals.jsonl"
    seals_before = seals.read_bytes()
    note_before = _note_bytes(repo)
    assert note_before is not None

    M.declare_claim(
        s,
        Claim(ctype="tests-pass", label=f"second unit {_LABEL_TOKEN}",
              event_indices=(0,), declared_at_index=0),
    )
    with pytest.raises(redact.SecretsBlocked):
        M.seal(s, repo)

    assert seals.read_bytes() == seals_before, "the watermark moved on a refused seal"
    assert _note_bytes(repo) == note_before, "a refused seal republished the note"

    # And the refusal is genuinely free: fixing the label and re-sealing works,
    # with the refused claim still in scope rather than swallowed.
    (s.root / "claims.jsonl").write_bytes(
        b"\n".join(
            line for line in (s.root / "claims.jsonl").read_bytes().splitlines()
            if _LABEL_TOKEN.encode("ascii") not in line
        )
        + b"\n"
    )
    M.declare_claim(
        s,
        Claim(ctype="tests-pass", label="second unit", event_indices=(0,),
              declared_at_index=0),
    )
    # `reseal=True` because this seals the SAME commit a second time with a
    # narrower window ([1,2) over a note that records [0,1)), which P4.1 refuses
    # by default — that narrowing is the data-loss path it closes. What this test
    # is about is a blocked seal advancing nothing, so the flag keeps its subject
    # intact rather than the assertion below being softened.
    m = M.seal(s, repo, reseal=True)
    assert [c["claim"]["label"] for c in m.claims] == ["second unit"]


# --- test 8: the false-positive pin ------------------------------------------

# Realistic developer strings and the tier each is expected to reach. This is a
# table so that any future tuning of the detectors shows up as a diff on a
# reviewed list rather than as a number nobody looked at. `notice` entries are
# not endorsements — they are the entropy sweep's remaining reach, recorded so
# that a change to it is visible.
DEVELOPER_STRINGS = [
    ("commit 356a192b7913b04c54574d18c28d46e6395428ab passed", set()),
    ("sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", set()),
    ("https://example.invalid/example-org/example-repo/pull/1284#issuecomment-2098765432", set()),
    ("npm WARN deprecated request@2.88.2: request has been deprecated", set()),
    ("registry.invalid/library/postgres@sha256:1a2b3c4d5e6f70819a2b3c4d5e6f7081", set()),
    ("pytest -q tests/test_capture_claims_manifest.py::test_grade_tree_exact", set()),
    ("go test ./internal/servicelayer/... -run TestServiceLifecycle -count=1", set()),
    ("--define=GOFLAGS=-mod=readonly -trimpath", set()),
    ("cargo build --release --target aarch64-apple-darwin", set()),
    ("kubectl -n production get pods -l app.kubernetes.io/name=gateway", set()),
    ("registry.invalid/example-org/example-service:v1.24.0-rc3", set()),
    ("uuid 3f2504e0-4f89-11d3-9a0c-0305e82c3301 assigned", set()),
    ("git rebase --onto origin/main feature/long-running-branch-name", set()),
    ("Traceback (most recent call last):\n  File \"app/main.py\", line 42", set()),
    ("ruff check --select E,F,W --ignore E501 src/ tests/", set()),
    ("terraform plan -var-file=environments/production/main.tfvars", set()),
    ("ORDINARY_PATH " + ORDINARY_PATHS[0], set()),
    ("DEEP_PATH " + DEEP_PATHS_THAT_FIRED[0], set()),
    # Still reported, and deliberately so: these are the shapes an unstructured
    # credential actually takes, and the sweep is the only detector that sees them.
    ("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", {"notice"}),
    ("integrity sha512-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP==", {"notice"}),
    # And the six that must never be demoted.
    ("AKIAIOSFODNN7EXAMPLE", {"block"}),
    ("ghp_" + "A" * 36, {"block"}),
    ("xoxb-1234567890-ABCDEFGHIJ", {"block"}),
    ("sk-AbCdEf0123456789XyZwVuTsQq", {"block"}),
    ("-----BEGIN OPENSSH PRIVATE KEY-----", {"block"}),
    ("DEPLOY_TOKEN=hunter2taffylongvalue", {"block"}),
]


@pytest.mark.parametrize("text,expected", DEVELOPER_STRINGS)
def test_developer_string_tiers_are_pinned(text, expected):
    assert {f.tier for f in redact.scan(text)} == expected


def test_the_false_positive_table_covers_both_outcomes():
    """A table that only contained clean strings would pass if scan() returned []."""
    tiers = {t for _s, expected in DEVELOPER_STRINGS for t in expected}
    assert tiers == {"block", "notice"}
