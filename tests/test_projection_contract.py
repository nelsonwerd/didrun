"""P3.1 — the exported redaction projection is a reconstructible span partition.

The criterion here is EXACT RECONSTRUCTION, not "the output's non-marker
characters are a subsequence of the input". The subsequence version was proposed
first and it does not detect the bug it targets: deletion always preserves the
subsequence property, so a redactor that deletes arbitrary text satisfies it.
`test_subsequence_criterion_is_insufficient` pins that, so the weaker check
cannot be reintroduced as an improvement.

Every credential-shaped string below is synthetic and structural — a shape the
detectors match, never a real token.
"""

from __future__ import annotations

import random
import subprocess
import sys
from pathlib import Path

from didrun import manifest as M
from didrun import redact
from didrun.capture import run_wrapped
from didrun.claims import Claim
from didrun.ledger import Session


# The marker format is written out here rather than imported: `_REDACTION_MARKER`
# is a frozen part of the exported format, so the test should fail if it moves.
def _marker(kind: str) -> str:
    return "«redacted:" + kind + "»"


def _reconstruct(source: str, result) -> str:
    """Independent reimplementation of the reconstruction contract.

    Deliberately NOT `redact.reconstruct`: a test that calls the same helper the
    source uses can only check that the helper agrees with itself. Kept slices
    come from the OUTPUT, replaced slices from the source, and markers are
    located by arithmetic — never searched for, because an argv is allowed to
    contain the literal marker text.
    """
    rebuilt = []
    out_i = 0
    src_i = 0
    for span in result.applied:
        keep = span.start - src_i
        assert keep >= 0, f"applied spans overlap or go backwards: {result.applied}"
        rebuilt.append(result.text[out_i:out_i + keep])
        out_i += keep
        marker = _marker(span.kind)
        assert result.text[out_i:out_i + len(marker)] == marker, (
            f"no marker at offset {out_i} for span {span}"
        )
        out_i += len(marker)
        rebuilt.append(source[span.start:span.end])
        src_i = span.end
    rebuilt.append(result.text[out_i:])
    return "".join(rebuilt)


# Both red-team repros verbatim, plus the nested case from the overlap finding.
# Synthetic token bodies; nothing here is a credential.
_GHP = "ghp_" + "A" * 36
_SK = "sk-AbCdEf0123456789XyZwVuTsQq"

CASES = [
    "run --key MY_TOKEN=" + _GHP + " && echo done",
    'sh -c "OPENAI_API_KEY=' + _SK + ' pytest -q" && rm -rf /tmp/x',
    "MY_SECRET=sk-AAAAAAAAAAAAAAAAAAAA tail words here",
    "plain text with nothing to hide",
    "AKIAIOSFODNN7EXAMPLE at the start",
    "trailing secret AKIAIOSFODNN7EXAMPLE",
    "two MY_TOKEN=" + _GHP + " secrets API_SECRET=" + _SK + " in one string",
    # A hostile argv containing the literal marker text. Reconstruction must
    # still be exact: markers are located by offset, not by search.
    "echo " + _marker("openai-key") + " MY_TOKEN=" + _GHP + " done",
]


def test_exact_reconstruction():
    """The criterion (red-team HIGH-7): substituting each marker back with the
    source span the projection records reproduces the input byte for byte."""
    for source in CASES:
        result = redact.redact(source)
        assert _reconstruct(source, result) == source, f"lost content in: {source!r}"


def test_applied_spans_are_disjoint_and_ascending():
    for source in CASES:
        spans = redact.redact(source).applied
        for prev, nxt in zip(spans, spans[1:]):
            assert prev.end <= nxt.start, f"overlapping partition in {source!r}: {spans}"
        for span in spans:
            assert 0 <= span.start < span.end <= len(source)


def test_length_identity():
    for source in CASES:
        result = redact.redact(source)
        widths = sum(s.end - s.start for s in result.applied)
        markers = sum(len(_marker(s.kind)) for s in result.applied)
        assert len(result.text) == len(source) - widths + markers, source


_BENIGN_WORDS = [
    "run", "make", "test", "--verbose", "-q", "build", "src/app.py",
    "&&", "echo", "done", "pytest", "lint", "config.toml", "the", "unit",
]
_SECRET_SHAPES = [
    "AKIAIOSFODNN7EXAMPLE",
    _GHP,
    _SK,
    "MY_TOKEN=" + _GHP,
    "API_SECRET=hunter2taffylongvalue",
    "xoxb-1234567890-abcdefghijkl",
    "sk-proj-AbCdEf0123456789XyZwVuTsQq",
]


def test_property_reconstruction_and_length_over_seeds():
    """Random benign text with k injected secrets, over 200 FIXED seeds.

    Seeded per case and never from the global `random` state: determinism is a
    hard invariant, and a property test that cannot be replayed is not evidence.
    """
    for seed in range(200):
        rng = random.Random(seed)
        words = [rng.choice(_BENIGN_WORDS) for _ in range(rng.randint(4, 20))]
        for _ in range(rng.randint(1, 4)):
            words.insert(rng.randint(0, len(words)), rng.choice(_SECRET_SHAPES))
        source = " ".join(words)
        result = redact.redact(source)
        assert _reconstruct(source, result) == source, f"seed {seed}: {source!r}"
        widths = sum(s.end - s.start for s in result.applied)
        markers = sum(len(_marker(s.kind)) for s in result.applied)
        assert len(result.text) == len(source) - widths + markers, f"seed {seed}"


def _is_subsequence(needle: str, haystack: str) -> bool:
    it = iter(haystack)
    return all(ch in it for ch in needle)


def test_subsequence_criterion_is_insufficient():
    """Why the criterion is exact reconstruction and not a subsequence check.

    v0.1 replaced overlapping spans end-first, so the outer span's stale end
    offset ran past the shortened string and ate whatever followed. Below is
    that measured output. The proposed subsequence assertion PASSES on it,
    because deletion always preserves the subsequence property — which is why
    it was replaced. Do not reintroduce it as a simplification.
    """
    source = CASES[0]
    v01_buggy_output = "run --key " + _marker("env-secret-assignment")
    non_marker = v01_buggy_output.replace(_marker("env-secret-assignment"), "")

    assert _is_subsequence(non_marker, source)  # the weaker criterion passes
    assert "&& echo done" not in v01_buggy_output  # on output missing 12 bytes

    # The criterion that actually catches it.
    fake = redact.RedactionResult(
        text=v01_buggy_output,
        findings=[],
        applied=[redact.AppliedSpan(10, 59, "env-secret-assignment",
                                    "env-secret-assignment")],
    )
    assert _reconstruct(source, fake) != source

    # And the current redactor does not produce it.
    assert redact.redact(source).text != v01_buggy_output


def test_merge_labels_the_widest_finding_not_the_first():
    """Merge policy over a chain that no single finding covers.

    A(0,10) then B(5,30) then C(6,15): the merged extent is (0,30), which
    belongs to no finding, and the label must track the widest contributor
    (B) rather than whichever one opened the run. Hand-built findings, because
    a three-way straddle like this is not reachable from the current detector
    set — the policy still has to be right when it becomes reachable.
    """
    findings = [
        redact.Finding("high-entropy", (0, 10), ""),
        redact.Finding("high-entropy", (5, 30), ""),
        redact.Finding("openai-key", (6, 15), ""),
    ]
    (span,) = redact.merge_findings(findings)
    assert (span.start, span.end) == (0, 30)
    assert span.kind == "high-entropy"

    # Same extents, but now the widest is the structured one.
    findings[1] = redact.Finding("github-token", (5, 30), "")
    (span,) = redact.merge_findings(findings)
    assert span.kind == "github-token"

    # Exact-width tie: the structured detector wins over the entropy sweep.
    (span,) = redact.merge_findings([
        redact.Finding("high-entropy", (0, 20), ""),
        redact.Finding("aws-access-key", (0, 20), ""),
    ])
    assert span.kind == "aws-access-key"


def test_nested_spans_merge_to_one_outermost():
    source = "MY_SECRET=sk-AAAAAAAAAAAAAAAAAAAA tail words here"
    result = redact.redact(source)
    assert len(result.applied) == 1, result.applied
    span = result.applied[0]
    assert (span.start, span.end) == (0, 33)
    # The wider structured detector labels the merged span, not the inner one.
    assert span.kind == "env-secret-assignment"
    assert span.detector_id == "env-secret-assignment"
    assert not span.withheld
    assert result.text == _marker("env-secret-assignment") + " tail words here"


def test_sk_proj_keys_are_recalled():
    """Finding 18: `\\bsk-[A-Za-z0-9]{20,}\\b` missed every `sk-proj-` key."""
    kinds = {f.kind for f in redact.scan("sk-proj-AbCdEf0123456789XyZwVuTsQq")}
    assert "openai-key" in kinds

    # The leading \b still holds: an `sk-` inside a word is not a key.
    benign = "risk-assessment-framework-rollout-plan"
    assert not any(f.kind == "openai-key" for f in redact.scan(benign))


def test_projection_is_stable_for_the_same_input():
    """No wall clock, no randomness: the same argv projects identically."""
    argv = ["run", "--key", "MY_TOKEN=" + _GHP, "&&", "echo", "done"]
    assert redact.redact_argv(argv) == redact.redact_argv(argv)


def test_withheld_element_is_never_an_empty_string(monkeypatch):
    """Redact-or-withhold, never mangle — and never silently.

    The post-condition cannot fail once findings are merged, so this forces it.
    The honesty risk is a withheld element exported as an empty preview, which
    reads as "nothing ran here" instead of "this was suppressed".
    """
    def broken(source, result):
        raise ValueError("forced post-condition failure")

    monkeypatch.setattr(redact, "reconstruct", broken)
    out = redact.redact_argv(["safe", "MY_TOKEN=" + _GHP])
    assert out.argv[0] == "«withheld:unknown»"  # no findings -> unknown
    assert out.argv[1] == "«withheld:env-secret-assignment»"
    assert "" not in out.argv
    assert all(e["withheld"] is True for e in out.applied)
    assert [e["argv_index"] for e in out.applied] == [0, 1]


# --- the README guarantee ----------------------------------------------------

_README = Path(__file__).resolve().parents[1] / "README.md"

# Locked Decision 10: every guarantee in README.md / TRUST_MODEL.md must have a
# test that fails when it stops being true. The removed sentence claimed the
# HTML report was safe to attach to a PR because "secrets are redacted from
# every export" — the HTML path applies no redaction at all. Two assertions,
# not one: a bare negative is satisfied by replacing one false sentence with a
# different false sentence.
#
# The sentence widened once the claim FIELDS started being redacted too, and
# the narrowing that replaced it has to stay narrow: the HTML report's file
# list for a stale claim is recomputed against the working tree at verify time,
# so it is NOT the note's redacted copy. Both halves are asserted, so a future
# edit cannot quietly drop the caveat while keeping the reassuring half.
#
# The enumeration widened again at v3: a conjunction's conjunct names and every
# claim's `reason` joined the redacted set, because a conjunction's reason NAMES a
# conjunct and a conjunct name is operator-authored. The sentence has to keep
# enumerating what is actually covered — a list that goes stale in the
# understating direction is the same defect in a quieter key, and the assertion
# below is what forces the edit.
_REMOVED_CLAIM = "secrets are redacted from every export"
_REPLACEMENT = (
    "Redaction covers the sealed note: every exported claim string — the "
    "`argv_preview`, the label, the pathspecs, the changed paths, the conjuncts "
    "and the reason — is redacted, and the projection is declared in the manifest."
)
_CAVEAT = (
    "a stale claim's file list is recomputed against your working tree at "
    "verify time and is shown as it is on disk"
)


def test_readme_does_not_claim_every_export_is_redacted():
    text = " ".join(_README.read_text(encoding="utf-8").split())
    assert _REMOVED_CLAIM not in text


def test_readme_states_what_is_actually_redacted():
    text = " ".join(_README.read_text(encoding="utf-8").split())
    assert _REPLACEMENT in text


def test_readme_keeps_the_caveat_the_widened_claim_needs():
    """The widened sentence is only true because of what follows it."""
    text = " ".join(_README.read_text(encoding="utf-8").split())
    assert _CAVEAT in text


# --- the projection reaches the note ----------------------------------------

def _git(repo: Path, *a: str) -> None:
    subprocess.run(["git", *a], cwd=str(repo), capture_output=True, text=True, check=True)


def test_sealed_note_declares_the_projection(repo: Path):
    """Test 8: after a seal, `redaction.applied` names exactly the spans that
    were replaced, and a consumer can tell which argv elements were touched."""
    session = Session(repo / ".didrun")
    secret_arg = "MY_TOKEN=" + _GHP
    run_wrapped([sys.executable, "-c", "print(1)", secret_arg], session, repo)
    M.declare_claim(
        session,
        Claim(ctype="tests-pass", label="t", event_indices=(0,), declared_at_index=0),
    )
    m = M.seal(session, repo, allow_secrets=True)

    entry = m.claims[0]
    block = entry["redaction"]
    assert block["projection_version"] == redact.PROJECTION_VERSION
    assert block["detector_set_version"] == redact.DETECTOR_SET_VERSION

    recorded = list(session.events()[0].argv)
    preview = entry["claim"]["argv_preview"]
    assert len(preview) == len(recorded)

    touched = {e["argv_index"] for e in block["applied"]}
    assert touched == {3}
    for i, element in enumerate(recorded):
        if i not in touched:
            assert preview[i] == element  # untouched elements travel verbatim

    (applied,) = block["applied"]
    assert applied["detector_id"] == "env-secret-assignment"
    assert applied["withheld"] is False
    assert (applied["start"], applied["end"]) == (0, len(secret_arg))

    # A consumer reconstructs the redacted element from the declared span.
    rebuilt = (
        recorded[3][:applied["start"]]
        + _marker(applied["detector_id"])
        + recorded[3][applied["end"]:]
    )
    assert preview[3] == rebuilt
    assert _GHP not in " ".join(preview)
