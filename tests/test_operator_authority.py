"""P5.1 — operator authority, and the exact size of what it buys.

Every test here is written against one sentence, which is also the constant the
source prints on every surface: a `cited` authority records that a file with this
digest was cited for this scope. It is NOT a signature and NOT approval, because
**an agent can author its own authorization artifact in one line** — nothing in
this file, and nothing in didrun, distinguishes that from a human writing one.

So the tests are deliberately asymmetric. The mechanism tests (bind, scope,
expiry, refusal) pin plumbing. The two that matter are the honesty ones:
``test_the_limitation_string_is_in_the_output``, which fails if any surface shows
a citation without the sentence that bounds it or reaches for a stronger word,
and ``test_retroactive_fabrication_is_detectable_and_only_that``, whose docstring
exists to stop a later reader from mistaking this feature for tamper-proofing.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from didrun import cli
from didrun import manifest as M
from didrun import redact
from didrun import render
from didrun.capture import run_wrapped
from didrun.claims import Claim
from didrun.ledger import Session

# Neutral, low-entropy, and spaced so the tokenizer cannot see one long run: this
# string exists to be searched for in the published note, not to trip a detector.
_ARTIFACT_BODY = "body of the cited artifact\n"

# Structurally a github token, and synthetic: the shape the detectors match, never
# a real credential. Same construction as tests/test_detector_tiers.py.
_LABEL_TOKEN = "ghp_" + "F" * 36


def _session(repo: Path) -> Session:
    return Session(repo / ".didrun")


def _one_event(session: Session, repo: Path):
    return run_wrapped([sys.executable, "-c", "print('ok')"], session, repo)


def _claim(session: Session, label: str = "suite") -> None:
    M.declare_claim(
        session,
        Claim(ctype="tests-pass", label=label, event_indices=(0,), declared_at_index=0),
    )


def _artifact(repo: Path, name: str = "APPROVAL.md", body: str = _ARTIFACT_BODY) -> Path:
    path = repo / name
    path.write_text(body, encoding="utf-8")
    return path


def _authority_lines(repo: Path) -> list:
    path = repo / ".didrun" / "authority.jsonl"
    if not path.exists():
        return []
    return [ln for ln in path.read_text(encoding="ascii").splitlines() if ln.strip()]


def _commit(repo: Path, name: str, body: str) -> None:
    (repo / name).write_text(body, encoding="utf-8")
    for args in (["add", name], ["commit", "-qm", f"add {name}"]):
        subprocess.run(["git", *args], cwd=str(repo), check=True, capture_output=True)


def _ready(repo: Path) -> Session:
    """A session with one recorded event and one claim bound to it."""
    s = _session(repo)
    _one_event(s, repo)
    _claim(s)
    return s


# --- test 1: record and bind -------------------------------------------------

def test_authorize_records_one_line_and_the_seal_binds_it(repo: Path):
    """The digest travels into the note. The artifact's bytes never do.

    An authorization artifact is exactly the kind of file that carries a
    credential in passing, and the note is the one artifact that leaves the
    machine — so the absence of the body is asserted directly, not inferred from
    the fact that nothing in the code writes it.
    """
    s = _ready(repo)
    artifact = _artifact(repo)
    record = M.declare_authority(
        s, artifact, scope=M.AUTHORITY_ALLOW_SECRETS, label="drew ok"
    )

    assert len(_authority_lines(repo)) == 1
    stored = json.loads(_authority_lines(repo)[0])
    assert stored == record
    assert "artifact_bytes" in stored and stored["artifact_bytes"] == len(
        _ARTIFACT_BODY.encode("utf-8")
    )

    m = M.seal(s, repo, allow_secrets=True)
    assert len(m.authority) == 1
    bound = m.authority[0]
    real = hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert bound["artifact_sha256"] == real
    assert bound["grade"] == M.AUTHORITY_GRADE == "cited"
    assert bound["principal_basis"] == "self-asserted"

    note = m.to_json().decode("ascii")
    # The body, and every word of it long enough to be recognisable, is absent.
    assert _ARTIFACT_BODY.strip() not in note
    assert "cited artifact" not in note
    assert real in note


def test_an_ordinary_seal_cites_nothing_even_when_an_authority_exists(repo: Path):
    """The regression case, and the anti-rubber-stamp invariant in one.

    An authority on disk must not attach itself to a seal that performs no
    exceptional transition. If it did, `cited` would appear on every note, which
    is the routine-isation this design is shaped to avoid.
    """
    s = _ready(repo)
    M.declare_authority(
        s, _artifact(repo), scope=M.AUTHORITY_ALLOW_SECRETS, label="drew ok"
    )
    m = M.seal(s, repo)
    assert m.authority == []
    report = M.verify(s, repo)
    assert report.authority == []
    assert render.authority_lines(report) == []
    assert M.AUTHORITY_LIMITATION not in render.render_verdict(report)


# --- test 2: the limitation string is in the output --------------------------

_STRONGER_WORDS = ("signed", "approved", "authorized by", "verified")


def _stronger_word_in(surface: str) -> list:
    """Which upgrade words appear in a surface, matched as WORDS.

    Word boundaries and not substrings: the HTML carries a CSS comment about the
    "MOST-designed states", and a substring search would report `signed` inside
    `designed` — a false hit that would either fail this test forever or, worse,
    get it weakened to a scoped search that stops covering the header line.
    """
    lowered = surface.lower()
    return [
        word
        for word in _STRONGER_WORDS
        if re.search(rf"\b{re.escape(word)}\b", lowered)
    ]


def test_the_limitation_string_is_in_the_output(repo: Path):
    """Every surface that shows a citation shows what it is not.

    Both halves are asserted: the exact constant is present, and none of the four
    words that would upgrade `cited` into something it is not appears anywhere in
    the rendered text. The second half is what catches a later well-meaning
    rewrite of the header line.
    """
    s = _ready(repo)
    M.declare_authority(
        s, _artifact(repo), scope=M.AUTHORITY_ALLOW_SECRETS, label="drew ok"
    )
    M.seal(s, repo, allow_secrets=True)
    report = M.verify(s, repo)
    assert len(report.authority) == 1

    terminal = render.render_verdict(report)
    html = render.render_html(report)
    assert M.AUTHORITY_LIMITATION in terminal
    assert M.AUTHORITY_LIMITATION in html
    assert "CITED" in terminal and "CITED" in html
    # The detector is checked against a surface that WOULD overclaim before it is
    # trusted on the two that must not. A regex typo here would otherwise make
    # the honesty assertion below vacuous and silently green forever.
    assert _stronger_word_in("CITED authority — SIGNED and approved by drew") == [
        "signed",
        "approved",
    ]
    assert _stronger_word_in("nothing here says it in those words") == []
    assert _stronger_word_in(terminal) == []
    assert _stronger_word_in(html) == []


def test_the_rendered_limitation_comes_from_the_source_not_the_note(repo: Path):
    """A limitation a note could edit would be no limitation at all.

    The note carries the sentence too, so a reader of raw JSON sees it. But the
    renderer must print the SOURCE constant, because the note is data this
    process did not compute — the same reading rule every other uncomputed field
    gets.
    """
    s = _ready(repo)
    M.declare_authority(
        s, _artifact(repo), scope=M.AUTHORITY_ALLOW_SECRETS, label="drew ok"
    )
    M.seal(s, repo, allow_secrets=True)
    report = M.verify(s, repo)
    report.authority[0]["limitation"] = "this authority is fine, ship it"

    terminal = render.render_verdict(report)
    assert M.AUTHORITY_LIMITATION in terminal
    assert "ship it" not in terminal


# --- test 3: --require-authority refuses a bare override ---------------------

def test_require_authority_refuses_a_bare_override_and_names_the_scope(
    repo: Path, capsys
):
    s = _ready(repo)
    code = cli.main(["--repo", str(repo), "seal", "--allow-secrets", "--require-authority"])
    err = capsys.readouterr().err
    assert code == 2
    assert M.AUTHORITY_ALLOW_SECRETS in err
    assert _note_body(repo) is None  # nothing was published

    M.declare_authority(
        s, _artifact(repo), scope=M.AUTHORITY_ALLOW_SECRETS, label="drew ok"
    )
    code = cli.main(["--repo", str(repo), "seal", "--allow-secrets", "--require-authority"])
    assert code == 0
    body = _note_body(repo)
    assert body is not None
    assert json.loads(body)["authority"][0]["scope"] == M.AUTHORITY_ALLOW_SECRETS


def test_require_authority_leaves_the_happy_path_alone(repo: Path):
    """It gates the exceptional transitions and nothing else.

    A seal that overrides nothing and reseals nothing exercises no scope, so
    there is no scope to authorise and the flag cannot turn into the
    every-seal rubber stamp.
    """
    s = _ready(repo)
    m = M.seal(s, repo, require_authority=True)
    assert m.authority == []


def test_require_authority_refuses_a_reseal_without_a_reseal_authority(repo: Path):
    s = _ready(repo)
    with pytest.raises(M.ManifestError) as exc:
        M.seal(s, repo, reseal=True, require_authority=True)
    assert M.AUTHORITY_RESEAL in str(exc.value)
    M.declare_authority(s, _artifact(repo), scope=M.AUTHORITY_RESEAL, label="replace it")
    m = M.seal(s, repo, reseal=True, require_authority=True)
    assert [a["scope"] for a in m.authority] == [M.AUTHORITY_RESEAL]


# --- test 4: scope isolation -------------------------------------------------

def test_a_reseal_authority_does_not_satisfy_allow_secrets(repo: Path):
    """One scope, one boundary. A citation is not a general permission."""
    s = _ready(repo)
    M.declare_authority(s, _artifact(repo), scope=M.AUTHORITY_RESEAL, label="replace it")

    m = M.seal(s, repo, allow_secrets=True)
    assert m.authority == []  # the wrong scope binds to nothing

    with pytest.raises(M.ManifestError) as exc:
        M.seal(s, repo, allow_secrets=True, require_authority=True)
    assert M.AUTHORITY_ALLOW_SECRETS in str(exc.value)
    assert M.AUTHORITY_RESEAL not in str(exc.value).split("scope", 1)[1].split(".", 1)[0]


# --- test 5: expiry ----------------------------------------------------------

def test_an_authority_expires_after_the_seals_it_declared(repo: Path):
    """`--expires-after-seals 1` covers the next seal and not the one after.

    The clock is seals, not wall time: a wall clock in the trust path is not
    allowed here, and it would make a citation's liveness depend on how long a
    build took.
    """
    s = _ready(repo)
    M.declare_authority(
        s,
        _artifact(repo),
        scope=M.AUTHORITY_ALLOW_SECRETS,
        label="drew ok",
        expires_after_seals=1,
    )

    first = M.seal(s, repo, allow_secrets=True)
    assert len(first.authority) == 1

    # A second commit, so the second seal gets its own note and the narrowing
    # guard is not what this test is measuring.
    _commit(repo, "next.py", "x = 1\n")
    _claim(s, label="second unit")
    second = M.seal(s, repo, allow_secrets=True)
    assert second.authority == []

    with pytest.raises(M.ManifestError) as exc:
        M.seal(s, repo, allow_secrets=True, require_authority=True, reseal=True)
    assert M.AUTHORITY_ALLOW_SECRETS in str(exc.value)


def test_a_wider_ttl_covers_the_seals_it_says_it_does(repo: Path):
    """The complement of the test above: expiry counts, it does not just fire."""
    s = _ready(repo)
    M.declare_authority(
        s,
        _artifact(repo),
        scope=M.AUTHORITY_ALLOW_SECRETS,
        label="drew ok",
        expires_after_seals=2,
    )
    assert len(M.seal(s, repo, allow_secrets=True).authority) == 1
    _commit(repo, "next.py", "x = 1\n")
    _claim(s, label="second unit")
    assert len(M.seal(s, repo, allow_secrets=True).authority) == 1
    _commit(repo, "third.py", "y = 2\n")
    _claim(s, label="third unit")
    assert M.seal(s, repo, allow_secrets=True).authority == []


# --- test 6: never standing --------------------------------------------------

@pytest.mark.parametrize("scope", ["", "everything", "seal", "allow_secrets", None])
def test_an_unscoped_or_unknown_authority_is_refused_at_authorize_time(repo, scope):
    """There is no standing grant and no scope for an ordinary seal.

    `allow_secrets` (underscored) is in the parameter list on purpose: a
    near-miss of a real scope must be refused rather than helpfully coerced,
    because coercing it would silently widen what was authorised.
    """
    s = _ready(repo)
    with pytest.raises(M.ManifestError) as exc:
        M.declare_authority(s, _artifact(repo), scope=scope, label="drew ok")
    assert "scope" in str(exc.value)
    assert _authority_lines(repo) == []


def test_the_cli_refuses_an_unknown_scope_with_exit_2(repo: Path):
    """And it refuses it BECAUSE the scope is unknown, not because it cannot parse.

    The good invocation is asserted first on purpose. argparse exits 2 for any
    unrecognised argument, including an `authorize` subcommand that does not
    exist at all — so a bare "unknown scope exits 2" assertion passes on a
    binary with no operator authority in it, which measured green on exactly
    that during this unit's falsification pass. Pinning the accepted case first
    is what makes the refusal below a statement about the SCOPE.
    """
    _ready(repo)
    artifact = _artifact(repo)
    assert (
        cli.main(
            [
                "--repo", str(repo), "authorize",
                "--artifact", str(artifact),
                "--scope", M.AUTHORITY_ALLOW_SECRETS,
                "--label", "drew ok",
            ]
        )
        == 0
    )
    assert len(_authority_lines(repo)) == 1

    with pytest.raises(SystemExit) as exc:
        cli.main(
            [
                "--repo", str(repo), "authorize",
                "--artifact", str(artifact),
                "--scope", "everything",
                "--label", "drew ok",
            ]
        )
    assert exc.value.code == 2
    assert len(_authority_lines(repo)) == 1  # the refusal recorded nothing


def test_the_authorize_command_prints_the_digest_and_the_limitation(repo, capsys):
    """`authorize`'s own output is where an operator forms their idea of this."""
    _ready(repo)
    artifact = _artifact(repo)
    assert (
        cli.main(
            [
                "--repo", str(repo), "authorize",
                "--artifact", str(artifact),
                "--scope", M.AUTHORITY_ALLOW_SECRETS,
                "--label", "drew ok",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() in out
    assert M.AUTHORITY_LIMITATION in out
    assert "self-asserted" in out
    assert _stronger_word_in(out) == []


def test_a_missing_or_empty_artifact_is_refused(repo: Path):
    s = _ready(repo)
    with pytest.raises(M.ManifestError) as exc:
        M.declare_authority(
            s, repo / "nope.md", scope=M.AUTHORITY_ALLOW_SECRETS, label="drew ok"
        )
    assert "no such file" in str(exc.value)

    empty = repo / "EMPTY.md"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(M.ManifestError) as exc:
        M.declare_authority(s, empty, scope=M.AUTHORITY_ALLOW_SECRETS, label="drew ok")
    assert "empty" in str(exc.value)
    assert _authority_lines(repo) == []


@pytest.mark.parametrize("ttl", [0, -1, True, "2", 1.5])
def test_a_ttl_that_authorises_nothing_or_everything_is_refused(repo, ttl):
    """No value means "never", and zero seals authorises nothing.

    `True` is in the list because `bool` is an `int` subclass: without the
    `_is_index` reading it would be accepted as a TTL of 1, which is a real
    number arriving from a place that never meant one.
    """
    s = _ready(repo)
    with pytest.raises(M.ManifestError) as exc:
        M.declare_authority(
            s,
            _artifact(repo),
            scope=M.AUTHORITY_ALLOW_SECRETS,
            label="drew ok",
            expires_after_seals=ttl,
        )
    assert "expires-after-seals" in str(exc.value)


def test_an_unlabelled_authority_is_refused(repo: Path):
    s = _ready(repo)
    with pytest.raises(M.ManifestError) as exc:
        M.declare_authority(
            s, _artifact(repo), scope=M.AUTHORITY_ALLOW_SECRETS, label="   "
        )
    assert "--label" in str(exc.value)


# --- test 7: what the feature actually buys ----------------------------------

def test_retroactive_fabrication_is_detectable_and_only_that(repo: Path):
    """Editing the cited artifact after the seal is detectable. That is ALL.

    This is the ONE property operator authority buys. It does NOT establish that
    a human wrote the artifact, that anyone read it, or that anyone approved
    anything: an agent can author its own authorization artifact in one line,
    cite it, and seal. It is also NOT tamper-proofing — whoever can rewrite the
    note can rewrite the digest inside it just as easily as they can rewrite a
    grade. What is detectable is exactly this: a digest recorded in an EARLIER
    sealed note no longer matches the file the note names.

    Do not read this test as evidence of anything beyond that sentence.
    """
    s = _ready(repo)
    artifact = _artifact(repo)
    M.declare_authority(
        s, artifact, scope=M.AUTHORITY_ALLOW_SECRETS, label="drew ok"
    )
    sealed = M.seal(s, repo, allow_secrets=True)
    sealed_digest = sealed.authority[0]["artifact_sha256"]
    assert sealed_digest == hashlib.sha256(artifact.read_bytes()).hexdigest()

    artifact.write_text(_ARTIFACT_BODY + "and one more line\n", encoding="utf-8")
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() != sealed_digest

    # The earlier note is unchanged and still names the pre-edit digest, which is
    # what makes the mismatch visible at all.
    published = json.loads(_note_body(repo))
    assert published["authority"][0]["artifact_sha256"] == sealed_digest

    # And the mismatch is not a verdict: the claims still grade exactly as they
    # did. An authority is record, never verdict.
    report = M.verify(s, repo)
    assert report.all_verified is True


# --- test 8: compat ----------------------------------------------------------

def test_a_note_without_an_authority_key_reads_back_additively():
    """Every note published before P5.1 lacks the key. [] is what that means."""
    for version in (1, 2, 3):
        body = json.dumps(
            {
                "version": version,
                "commit": "a" * 40,
                "tree": "b" * 40,
                "claims": [],
                "coverage": {"total_events": 0, "by_coverage": {}},
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        m = M.Manifest.from_json(body)
        assert m.authority == []
        assert json.loads(m.to_json())["authority"] == []


def test_a_malformed_authority_block_in_a_note_is_read_as_no_authority():
    """A block that is not a list, or holds things that are not records.

    Read down to nothing rather than raised on: an authority block is record and
    never verdict, so it cannot be the reason a readable note stops verifying.
    """
    base = {
        "version": M.MANIFEST_VERSION,
        "commit": "a" * 40,
        "tree": "b" * 40,
        "claims": [],
        "coverage": {"total_events": 0, "by_coverage": {}},
    }
    for bad in ("standing grant", 7, {"scope": "allow-secrets"}):
        body = json.dumps(
            dict(base, authority=bad), sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        assert M.Manifest.from_json(body).authority == []


def test_the_authority_version_contract_did_not_bump(repo: Path):
    """Additive field, so no MANIFEST_VERSION bump (Locked Decision 9)."""
    assert M.MANIFEST_VERSION == 3
    s = _ready(repo)
    M.declare_authority(
        s, _artifact(repo), scope=M.AUTHORITY_ALLOW_SECRETS, label="drew ok"
    )
    m = M.seal(s, repo, allow_secrets=True)
    assert m.version == 3


def test_an_unreadable_authority_record_is_dropped_not_trusted(repo: Path, capsys):
    """A torn or hand-edited record costs a citation; it never grants one.

    Dropping is the refusing direction, which is why a scope that needed the
    record is refused rather than quietly granted.
    """
    s = _ready(repo)
    M.declare_authority(
        s, _artifact(repo), scope=M.AUTHORITY_ALLOW_SECRETS, label="drew ok"
    )
    path = repo / ".didrun" / "authority.jsonl"
    good = path.read_text(encoding="ascii")
    record = json.loads(good.strip())
    record["expires_after_seals"] = "forever"
    path.write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n{tor\n",
        encoding="ascii",
    )
    with pytest.raises(M.ManifestError):
        M.seal(s, repo, allow_secrets=True, require_authority=True)
    assert "dropped 2 unreadable authority record(s)" in capsys.readouterr().err


def test_an_authority_from_the_future_binds_to_nothing(repo: Path):
    """A record may not name a seal generation that has not happened.

    `authority.jsonl` is a local unhashed file, so this is validate-rather-than-
    trust, not a forgery barrier: whoever can write the file can write a record
    that passes. It closes the accident and the crude backdate, which is the same
    bound every other uncomputed field in this package carries.
    """
    s = _ready(repo)
    M.declare_authority(
        s, _artifact(repo), scope=M.AUTHORITY_ALLOW_SECRETS, label="drew ok"
    )
    path = repo / ".didrun" / "authority.jsonl"
    record = json.loads(path.read_text(encoding="ascii").strip())
    record["declared_at_index"] = 9
    path.write_text(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    assert M.seal(s, repo, allow_secrets=True).authority == []


# --- the published bytes are the scanned bytes -------------------------------

def test_a_secret_in_an_authority_label_blocks_and_is_never_published(repo: Path):
    """The authority block is published, so it is scanned AND redacted.

    Adding a published field that the export gate blocks on but the redactor
    never touches would re-create the defect P3.2 closed: a token in a claim
    label refused the seal and was then published verbatim on the override,
    under a refusal message that had already promised a redacted artifact.

    The scope here is `reseal` rather than `allow-secrets`, and that is not
    incidental: a bound authority is only published when the seal exercises its
    scope, so `allow-secrets` is the one scope whose citation can never be
    blocked — the flag that binds it is the same flag that overrides the block.
    `reseal` is the case where the gate has something to say.
    """
    s = _ready(repo)
    M.declare_authority(
        s,
        _artifact(repo),
        scope=M.AUTHORITY_RESEAL,
        label=f"replace it {_LABEL_TOKEN}",
    )
    with pytest.raises(redact.SecretsBlocked) as exc:
        M.seal(s, repo, reseal=True)
    assert "github-token" in str(exc.value)
    assert _note_body(repo) is None  # the blocked seal published nothing

    m = M.seal(s, repo, reseal=True, allow_secrets=True)
    note = m.to_json().decode("ascii")
    assert _LABEL_TOKEN not in note
    assert "redacted" in m.authority[0]["label"]
    applied = m.authority[0]["redaction"]["fields"]
    assert [f["field"] for f in applied] == ["authority[0].label"]


def _note_body(repo: Path):
    proc = subprocess.run(
        ["git", "notes", f"--ref={M.NOTES_REF}", "show", "HEAD"],
        cwd=str(repo),
        capture_output=True,
    )
    return proc.stdout if proc.returncode == 0 else None


# --- the principal is outside text too ---------------------------------------

# A high-entropy value that trips the notice tier rather than a named detector.
# Notice tier is the dangerous one here: it does not block, so a seal carrying it
# succeeds with `secrets_override` false and nothing asking the operator to look.
_NOTICE_TOKEN = "XMP7t2n3AGm5EhSc-sTMAMpLouiqyBfxD-__oQkcEbg"


def test_a_secret_in_the_principal_blocks_and_is_never_published(repo: Path):
    """`principal` is `--principal` or `$USER` — outside text, and published.

    This is the same defect as the label case above, one field over: the export
    gate scanned `principal` through the whole-manifest backstop and blocked on
    it, the refusal said "re-run with --allow-secrets to export a REDACTED
    artifact anyway", and the override then published the token verbatim into
    the git note with `redaction.fields` empty. A refusal that promises
    redaction has to deliver it for the field it refused over.
    """
    s = _ready(repo)
    M.declare_authority(
        s,
        _artifact(repo),
        scope=M.AUTHORITY_RESEAL,
        label="replace it",
        principal=_LABEL_TOKEN,
    )
    with pytest.raises(redact.SecretsBlocked) as exc:
        M.seal(s, repo, reseal=True)
    assert "github-token" in str(exc.value)
    assert _note_body(repo) is None

    m = M.seal(s, repo, reseal=True, allow_secrets=True)
    note = m.to_json().decode("ascii")
    assert _LABEL_TOKEN not in note
    assert "redacted" in m.authority[0]["principal"]
    applied = m.authority[0]["redaction"]["fields"]
    assert [f["field"] for f in applied] == ["authority[0].principal"]


def test_the_same_secret_is_scrubbed_in_the_label_and_the_principal(repo: Path):
    """One string in two adjacent fields must not come out two different ways.

    The notice tier made this the quiet case: the seal is not refused, nothing
    is overridden, `secrets_override` stays false — and the value was scrubbed
    in `label` and published raw in `principal`, in the same JSON object, in the
    one artifact designed to leave the machine.
    """
    s = _ready(repo)
    M.declare_authority(
        s,
        _artifact(repo),
        scope=M.AUTHORITY_RESEAL,
        label=f"svc {_NOTICE_TOKEN}",
        principal=_NOTICE_TOKEN,
    )
    m = M.seal(s, repo, reseal=True)

    assert m.secrets_override is False  # nothing was overridden
    note = m.to_json().decode("ascii")
    assert _NOTICE_TOKEN not in note
    entry = m.authority[0]
    assert "redacted" in entry["label"] and "redacted" in entry["principal"]
    assert sorted(f["field"] for f in entry["redaction"]["fields"]) == [
        "authority[0].label",
        "authority[0].principal",
    ]


def test_every_authority_field_is_classified(repo: Path):
    """The enumeration is not allowed to be silently incomplete.

    `_redact_authorities` names the fields it redacts by hand. Hand-written
    enumerations go stale — `principal` was published verbatim for exactly that
    reason — so this test fails the moment `declare_authority` or
    `_bind_authorities` grows a field that neither table classifies, instead of
    waiting for a reviewer to notice a new key in a note.
    """
    s = _ready(repo)
    record = M.declare_authority(
        s, _artifact(repo), scope=M.AUTHORITY_RESEAL, label="replace it"
    )
    produced = set(record) | {"grade", "limitation"}
    classified = {name for name, _kind in M._AUTHORITY_TEXT_FIELDS} | set(
        M._AUTHORITY_PASSTHROUGH_FIELDS
    )
    assert produced <= classified, f"unclassified authority field(s): {produced - classified}"

    # And the published entry carries exactly what was classified, plus the
    # redaction declaration — no key reaches a note unaccounted for.
    m = M.seal(s, repo, reseal=True)
    assert set(m.authority[0]) - {"redaction"} <= classified


def test_a_published_authority_field_the_redactor_forgot_still_blocks(
    repo: Path, monkeypatch
):
    """The whole-manifest backstop, exercised rather than asserted.

    `_scan_for_secrets` documents `export_bytes` as the backstop: "a field a
    later version adds and forgets to redact is still in these bytes, so it
    still blocks". Nothing tested that — removing the authority block from
    `export_bytes` broke no test — so the sentence was a comment, not a
    property. Here a field is added, vouched for as safe, and NOT redacted; the
    seal must still refuse.
    """
    s = _ready(repo)
    M.declare_authority(
        s, _artifact(repo), scope=M.AUTHORITY_RESEAL, label="replace it"
    )
    real_bind = M._bind_authorities

    def bind_with_a_new_field(session, scopes, seal_index):
        bound = real_bind(session, scopes, seal_index)
        for entry in bound:
            entry["future_field"] = _LABEL_TOKEN
        return bound

    monkeypatch.setattr(M, "_bind_authorities", bind_with_a_new_field)
    monkeypatch.setattr(
        M,
        "_AUTHORITY_PASSTHROUGH_FIELDS",
        M._AUTHORITY_PASSTHROUGH_FIELDS | {"future_field"},
    )
    with pytest.raises(redact.SecretsBlocked) as exc:
        M.seal(s, repo, reseal=True)
    assert "github-token" in str(exc.value)


def test_an_unclassified_authority_field_is_dropped_not_published(
    repo: Path, monkeypatch
):
    """For a field nobody classified, the failing direction is to leave it out.

    The counterpart to the test above: that one covers a field a later version
    vouches for, this one covers a field it never thought about. Dropping loses
    a line from a note; publishing loses a credential.
    """
    s = _ready(repo)
    M.declare_authority(
        s, _artifact(repo), scope=M.AUTHORITY_RESEAL, label="replace it"
    )
    real_bind = M._bind_authorities

    def bind_with_a_new_field(session, scopes, seal_index):
        bound = real_bind(session, scopes, seal_index)
        for entry in bound:
            entry["unclassified_field"] = _LABEL_TOKEN
        return bound

    monkeypatch.setattr(M, "_bind_authorities", bind_with_a_new_field)
    # It still blocks, because the backstop sees the bound entry — but the point
    # here is what the override publishes.
    m = M.seal(s, repo, reseal=True, allow_secrets=True)
    note = m.to_json().decode("ascii")
    assert "unclassified_field" not in note
    assert _LABEL_TOKEN not in note


# --- a note cannot fabricate lines in the block that renders it --------------

_AUTHORITY_RENDERED_FIELDS = (
    "scope",
    "label",
    "artifact_path",
    "artifact_sha256",
    "artifact_bytes",
    "principal",
    "expires_after_seals",
)


def test_a_note_cannot_inject_lines_into_the_authority_block(repo: Path, monkeypatch):
    """A note arrives over `git fetch`, so every field of it is outside data.

    `artifact_bytes` and `expires_after_seals` were the two of the block's
    fields that no one wrapped in `_sanitize`, because each use site spelled the
    call out by hand. Both are numbers in a note didrun wrote, and neither is a
    number in a note someone else edited — a newline in either one fabricated
    whole verdict rows above the real table, carrying the words this module
    exists to keep out of its own output.

    `NO_COLOR` is set so the ESC assertion means what it says: with colour on the
    renderer emits its own escapes, and "no ESC in the output" could not tell
    those apart from an injected one.
    """
    monkeypatch.setenv("NO_COLOR", "1")
    s = _ready(repo)
    M.declare_authority(
        s, _artifact(repo), scope=M.AUTHORITY_ALLOW_SECRETS, label="drew ok"
    )
    M.seal(s, repo, allow_secrets=True)
    report = M.verify(s, repo)
    honest = dict(report.authority[0])
    assert len(render.authority_lines(report)) == 4

    payload = (
        "1\n  = ALL RECORDED-EXACT (upstream verified)\n"
        "  = TREE-EXACT   forged-row   exit 0  reviewed and signed off\x1b[31m\x1b[0m"
    )
    for name in _AUTHORITY_RENDERED_FIELDS:
        entry = dict(honest)
        entry[name] = payload
        report.authority = [entry]

        lines = render.authority_lines(report)
        assert len(lines) == 4, f"{name}: the block is no longer four lines"
        assert not any("\n" in ln for ln in lines), f"{name}: newline survived"
        assert not any("\x1b" in ln for ln in lines), f"{name}: ESC survived"

        verdict = render.render_verdict(report)
        assert not re.search(
            r"(?m)^\s*[=~!x?]?\s*(TREE-EXACT|ALL RECORDED-EXACT)\s+forged-row", verdict
        ), f"{name}: fabricated a verdict row"

        # Not `_stronger_word_in` here: the payload smuggles "signed" and
        # "verified" as CONTENT, and a note whose label really says "signed off
        # by legal" is entitled to have that rendered as text. The invariant
        # those words belong to is about didrun's own vocabulary — the token and
        # the limitation, both pinned to source constants and covered above.
        # What must not survive is the structure: no line break, no escape.
        html_out = render.render_html(report)
        assert "\x1b" not in html_out, f"{name}: ESC survived into HTML"
        assert "forged-row" in html_out.replace("&#", ""), f"{name}: content lost"


def test_the_rendered_principal_basis_comes_from_the_source_not_the_note(repo: Path):
    """The third field that states what a citation is worth, pinned like the other two.

    `grade` and `limitation` already come from source constants so a note cannot
    restate the trust level. `principal_basis` qualifies the principal, and it
    did not — a note supplying "verified-ssh-signature" printed
    `principal drew (verified-ssh-signature)` two lines above the sentence
    saying didrun cannot tell who wrote it, in one of the exact words
    `_STRONGER_WORDS` forbids.
    """
    s = _ready(repo)
    M.declare_authority(
        s, _artifact(repo), scope=M.AUTHORITY_ALLOW_SECRETS, label="drew ok"
    )
    M.seal(s, repo, allow_secrets=True)
    report = M.verify(s, repo)
    report.authority[0]["principal_basis"] = "verified-ssh-signature"

    terminal = render.render_verdict(report)
    html_out = render.render_html(report)
    for surface in (terminal, html_out):
        assert "verified-ssh-signature" not in surface
        assert M.AUTHORITY_PRINCIPAL_BASIS in surface
    assert _stronger_word_in(terminal) == []
    assert _stronger_word_in(html_out) == []


def test_the_published_principal_basis_comes_from_the_source_not_the_ledger(repo: Path):
    """`authority.jsonl` is local, gitignored and unhashed, so it is outside data too.

    Whoever can write that file can write any basis into it. The note must carry
    the basis this version can actually establish, not the one the file claims.
    """
    s = _ready(repo)
    M.declare_authority(
        s, _artifact(repo), scope=M.AUTHORITY_RESEAL, label="replace it"
    )
    path = repo / ".didrun" / "authority.jsonl"
    record = json.loads(_authority_lines(repo)[0])
    record["principal_basis"] = "verified-ssh-signature"
    path.write_text(json.dumps(record) + "\n", encoding="ascii")

    m = M.seal(s, repo, reseal=True)
    assert m.authority[0]["principal_basis"] == M.AUTHORITY_PRINCIPAL_BASIS
    assert "verified-ssh-signature" not in m.to_json().decode("ascii")


def test_the_command_surfaces_cannot_be_line_injected_by_an_authority(
    repo: Path, capsys, monkeypatch
):
    """`didrun authorize` and `didrun seal` print these strings too.

    The verify block was the reported case, but it is not the only surface that
    prints an authority's label: `seal` echoes the citation it just published,
    reading the label out of `authority.jsonl`. Redaction is not sanitization —
    a scrubbed label still carries whatever control characters surrounded the
    secret — so the seal's own output could grow a verdict row it never
    computed, from a local file that gets validate-rather-than-trust treatment.
    """
    monkeypatch.setenv("NO_COLOR", "1")
    forged = r"(?m)^\s*[=~!]?\s*TREE-EXACT\s+forged-row"
    payload = "ok\n  = TREE-EXACT   forged-row   exit 0  reviewed and signed off"

    s = _ready(repo)
    artifact = _artifact(repo)
    code = cli.main(
        [
            "--repo", str(repo), "authorize",
            "--artifact", str(artifact),
            "--scope", M.AUTHORITY_RESEAL,
            "--label", payload,
        ]
    )
    out = capsys.readouterr().out
    assert code == 0
    assert not re.search(forged, out), "authorize fabricated a verdict row"
    assert "^J" in out, "the newline was not caret-encoded"

    assert cli.main(["--repo", str(repo), "seal", "--reseal"]) == 0
    out = capsys.readouterr().out
    assert not re.search(forged, out), "seal fabricated a verdict row"
    assert "^J" in out, "the newline was not caret-encoded"
