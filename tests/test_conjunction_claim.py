"""P4.2 — a conjunction claim, graded as the worst of its conjuncts.

The property an 80-command proof ledger was hand-enforcing — "all N of these
gates passed against this tree" — had no representation in the tool. This gives
it one, and the whole design rests on a single negative: a conjunction must
never produce a grade its members do not already back.

Test 1 is that negative, over every combination, and it is the gate. If any
combination comes out better than the worst of its pair, the design is weakening
a claim and the design review's refusal to substitute a marker for a witnessed
execution still stands.

Test 2 is the one that fails if the verify-side resolution pass is missing: a
sealed conjunction regraded with no siblings resolves every conjunct to "no
match" and verifies `unknown`, so a note that sealed green fails --strict. It
proves the resolution reads the NOTE's own results by deleting claims.jsonl and
verifying again.
"""

from __future__ import annotations

import itertools
import json
import subprocess
import sys
from pathlib import Path

import pytest

from didrun import cli
from didrun import manifest as M
from didrun import render
from didrun.capture import run_wrapped
from didrun.claims import (
    CONJUNCTION,
    GRADE_ORDER_WORST_FIRST,
    Claim,
    ClaimError,
    GradeResult,
    grade,
)
from didrun.ledger import Session
from didrun import gitplumbing as gp

# tests/compat's leg 2 owns the note round-trip criterion. Test 6 imports it
# rather than restating it: a second copy of a three-part criterion is a second
# chance to write a weaker version of it, and the pack names that leg as the
# compat gate for exactly this reason.
from compat.test_corpus_replay import note_violations

# The six grades a conjunct can carry, written out rather than imported, so the
# matrix below is a statement about the vocabulary and not a restatement of
# whatever the vocabulary happens to be. The equality against the severity order
# is what turns a new grade into a deliberate edit here.
GRADES = (
    "tree-exact",
    "scope-exact",
    "stale",
    "unknown",
    "failed",
    "witness-unavailable",
)


def test_the_matrix_covers_every_grade_the_order_knows():
    """A grade added to the ladder must be added to test 1's matrix."""
    assert set(GRADES) == set(GRADE_ORDER_WORST_FIRST)


# --- helpers -----------------------------------------------------------------


def _session(repo: Path) -> Session:
    return Session(repo / ".didrun")


def _run(session: Session, repo: Path, code: str):
    return run_wrapped([sys.executable, "-c", code], session, repo)


def _claim(session: Session, ctype: str, label: str, event_index: int) -> Claim:
    """Declare an ordinary claim exactly as the CLI would."""
    claim = Claim(
        ctype=ctype,
        label=label,
        event_indices=(event_index,),
        declared_at_index=len(session.events()) - 1,
    )
    M.declare_claim(session, claim)
    return claim


def _conjunction(session: Session, label: str, *conjuncts: str) -> Claim:
    claim = Claim(
        ctype=CONJUNCTION,
        label=label,
        event_indices=(),
        declared_at_index=len(session.events()) - 1,
        conjuncts=tuple(conjuncts),
    )
    M.declare_claim(session, claim)
    return claim


def _result(label: str, grade_value: str) -> GradeResult:
    """One graded sibling, at an arbitrary grade. Not produced by the ladder —
    the point is to reach grade combinations no single fixture repo could."""
    return GradeResult(
        claim=Claim(
            ctype="tests-pass",
            label=label,
            event_indices=(0,),
            declared_at_index=0,
        ),
        grade=grade_value,
        reason="fixture sibling",
    )


def _report(*results: GradeResult) -> M.VerifyReport:
    """A report over ``results`` alone, so `worst_status` is the only authority
    this file consults for which of two grades is worse."""
    return M.VerifyReport(
        commit="0" * 40, tree="1" * 40, resolved_by="commit",
        results=list(results), coverage={},
    )


def _graded_conjunction(*siblings: GradeResult, names=None) -> GradeResult:
    conjuncts = names if names is not None else tuple(s.claim.label for s in siblings)
    claim = Claim(
        ctype=CONJUNCTION,
        label="REL",
        event_indices=(),
        declared_at_index=9,
        conjuncts=tuple(conjuncts),
    )
    return grade(claim, "1" * 40, [], Path("."), None, siblings=list(siblings))


def _note_body(repo: Path, commit: str = "HEAD") -> bytes:
    proc = subprocess.run(
        ["git", "notes", f"--ref={M.NOTES_REF}", "show", commit],
        cwd=str(repo),
        capture_output=True,
    )
    assert proc.returncode == 0, "the commit carries no note"
    return proc.stdout


def _note_json(repo: Path, commit: str = "HEAD") -> dict:
    body = _note_body(repo, commit)
    assert body.endswith(b"\n")
    return json.loads(body[:-1])


def _entry(body: dict, label: str) -> dict:
    (entry,) = [c for c in body["claims"] if c["claim"]["label"] == label]
    return entry


# --- test 1: never better than the worst (THE criterion) ---------------------


@pytest.mark.parametrize("left,right", list(itertools.product(GRADES, GRADES)))
def test_a_conjunction_is_never_better_than_its_worst_conjunct(left: str, right: str):
    """The gate: over EVERY pair of grades, in both orders.

    Three assertions, because "equals the worst" alone is satisfiable by an
    implementation that invents a grade nobody claimed:

      1. it equals what `worst_status` says about the two conjuncts together —
         the same order the verdict line above it is computed with;
      2. it is one of the two grades its conjuncts actually carry, never a
         third one;
      3. adding either conjunct back alongside the conjunction does not make the
         verdict worse, which is "the conjunction is already at least as bad as
         each of them" stated without reusing the implementation's own helper.
    """
    a, b = _result("a", left), _result("b", right)
    result = _graded_conjunction(a, b)

    expected = _report(a, b).worst_status
    assert result.grade == expected, (
        f"conjunction over ({left}, {right}) graded {result.grade}, "
        f"but the worst of them is {expected}"
    )
    assert result.grade in (left, right), "a conjunction invented a grade"
    conj_only = _report(result).worst_status
    assert _report(result, a).worst_status == conj_only
    assert _report(result, b).worst_status == conj_only
    # The reason names the conjunct the grade came from, and its grade.
    named = "a" if expected == left else "b"
    assert repr(named) in result.reason
    assert expected in result.reason
    # The per-conjunct pairs travel with the result, in declaration order.
    assert result.conjunct_grades == (("a", left), ("b", right))


def test_a_tie_names_the_first_declared_conjunct():
    """Determinism: which of two equally-bad members is named is the operator's
    order, never an iteration artefact."""
    first = _graded_conjunction(_result("a", "stale"), _result("b", "stale"))
    reversed_ = _graded_conjunction(_result("b", "stale"), _result("a", "stale"))
    assert "'a'" in first.reason
    assert "'b'" in reversed_.reason


def test_a_conjunction_over_one_conjunct_is_that_conjunct_s_grade():
    for g in GRADES:
        result = _graded_conjunction(_result("only", g))
        assert result.grade == g
        assert result.conjunct_grades == (("only", g),)


# --- test 2: an all-green conjunction verifies, from the note alone ----------


def _three_green_gates(s: Session, repo: Path) -> None:
    """Three self-stable commands, one claim each, plus a conjunction of them."""
    for i, label in enumerate(("unit", "lint", "integration")):
        _run(s, repo, "pass")
        _claim(s, "tests-pass", label, i)
    _conjunction(s, "REL", "unit", "lint", "integration")


def test_an_all_green_conjunction_seals_and_verifies_tree_exact(repo: Path):
    s = _session(repo)
    _three_green_gates(s, repo)

    m = M.seal(s, repo)
    body = _note_json(repo)
    assert _entry(body, "REL")["grade"] == "tree-exact"
    assert [c["grade"] for c in m.claims] == ["tree-exact"] * 4

    report = M.verify(s, repo)
    by_label = {r.claim.label: r for r in report.results}
    assert by_label["REL"].grade == "tree-exact"
    assert by_label["REL"].conjunct_grades == (
        ("unit", "tree-exact"),
        ("lint", "tree-exact"),
        ("integration", "tree-exact"),
    )
    assert report.all_verified is True
    assert report.worst_status == "tree-exact"
    # A conjunction binds no event, so it is not evidence-bound and must not be
    # counted as though it were.
    assert report.evidence_bound_count == 3
    assert report.total == 4
    assert cli.main(["--repo", str(repo), "verify", "--strict"]) == 0


def test_the_conjunction_resolves_against_the_note_not_the_live_claims_file(repo: Path):
    """Delete claims.jsonl; the grade must not move.

    This is the test that fails when verify grades conjunctions in one pass with
    no siblings — and the one that fails again if a later change reaches for the
    live claims file to get them. `verify` reads the manifest and the repo, never
    the session's declared claims: a conjunction resolved against claims.jsonl
    would let a claim declared after the seal change an old commit's verdict.
    """
    s = _session(repo)
    _three_green_gates(s, repo)
    M.seal(s, repo)

    before = {r.claim.label: r.grade for r in M.verify(s, repo).results}
    claims_file = repo / ".didrun" / "claims.jsonl"
    assert claims_file.exists()
    claims_file.unlink()

    after_report = M.verify(s, repo)
    after = {r.claim.label: r.grade for r in after_report.results}
    assert after == before
    assert after["REL"] == "tree-exact"
    assert after_report.all_verified is True
    assert cli.main(["--repo", str(repo), "verify", "--strict"]) == 0


def test_a_conjunction_graded_with_no_siblings_is_unknown_never_green(repo: Path):
    """What the second pass buys, stated as an assertion.

    Grading a conjunction without its siblings — one pass over the note, which
    is what verify did before this unit — resolves every conjunct to no match.
    The result is `unknown`, so the failure mode of forgetting the pass is a
    refusal, never a green verdict over members nobody looked at.
    """
    s = _session(repo)
    _three_green_gates(s, repo)
    tree = gp.commit_tree(repo, "HEAD")
    conjunction = M._load_claims(s)[-1]
    assert conjunction.ctype == CONJUNCTION

    unbound = grade(conjunction, tree, s.events(), repo, s.blobs.root)
    assert unbound.grade == "unknown"
    assert "unit" in unbound.reason


# --- test 3: an unresolvable conjunct is unknown, never tree-exact ----------


def test_a_missing_conjunct_grades_unknown_and_names_it(repo: Path):
    s = _session(repo)
    _run(s, repo, "pass")
    _claim(s, "tests-pass", "unit", 0)
    _conjunction(s, "REL", "unit", "nosuch")

    m = M.seal(s, repo)
    entry = _entry(json.loads(m.to_json()), "REL")
    assert entry["grade"] == "unknown"
    assert "'nosuch'" in entry["reason"]
    assert "names no claim" in entry["reason"]
    assert entry["conjunct_grades"] == [
        {"label": "unit", "grade": "tree-exact"},
        {"label": "nosuch", "grade": None},
    ]

    report = M.verify(s, repo)
    rel = next(r for r in report.results if r.claim.label == "REL")
    assert rel.grade == "unknown"
    assert "'nosuch'" in rel.reason
    assert report.all_verified is False
    assert report.worst_status == "unknown"
    assert cli.main(["--repo", str(repo), "verify", "--strict"]) == 1


def test_an_ambiguous_conjunct_grades_unknown_and_says_how_many(repo: Path):
    """One label, two live claims: a member it cannot identify is a member it
    cannot vouch for. Two different ctypes carrying one label are both live —
    supersession is keyed on the (ctype, label) pair, so neither retires the
    other."""
    s = _session(repo)
    _run(s, repo, "pass")
    _claim(s, "tests-pass", "gate", 0)
    _claim(s, "lint-clean", "gate", 0)
    _conjunction(s, "REL", "gate")

    m = M.seal(s, repo)
    entry = _entry(json.loads(m.to_json()), "REL")
    assert entry["grade"] == "unknown"
    assert "'gate' names 2 claims" in entry["reason"]
    assert M.verify(s, repo).all_verified is False


def test_a_conjunction_naming_a_conjunction_is_unknown(repo: Path):
    """Resolution is one level deep: no recursion to bound, no cycle to detect,
    and no grade asserted for a name this code will not follow."""
    s = _session(repo)
    _run(s, repo, "pass")
    _claim(s, "tests-pass", "unit", 0)
    _conjunction(s, "INNER", "unit")
    _conjunction(s, "OUTER", "INNER")

    m = M.seal(s, repo)
    body = json.loads(m.to_json())
    assert _entry(body, "INNER")["grade"] == "tree-exact"
    outer = _entry(body, "OUTER")
    assert outer["grade"] == "unknown"
    assert "'INNER' names no claim" in outer["reason"]


# --- test 4: superseded conjuncts are skipped -------------------------------


def test_a_conjunction_resolves_to_the_surviving_claim(repo: Path, tmp_path: Path):
    """P4.1's retired attempt shares its label with the claim that replaced it.

    The fix lives OUTSIDE the repo so the tree does not move: the only variable
    is the two attempts at one gate.
    """
    s = _session(repo)
    flag = tmp_path / "gate-fixed"
    code = f"import os, sys; sys.exit(0 if os.path.exists({str(flag)!r}) else 1)"
    _run(s, repo, code)                       # event 0 — the gate fails
    _claim(s, "tests-pass", "gate", 0)
    flag.write_text("fixed\n", encoding="ascii")
    _run(s, repo, code)                       # event 1 — the same gate passes
    _claim(s, "tests-pass", "gate", 1)
    _conjunction(s, "REL", "gate")
    head = gp.head_commit(repo)

    m = M.seal(s, repo)
    body = json.loads(m.to_json())
    assert m.claims[0]["grade"] == "failed"
    assert m.claims[0]["superseded_by"] == 1, "P4.1's mark must be on the note"
    assert m.claims[1]["grade"] == "tree-exact"
    rel = _entry(body, "REL")
    assert rel["grade"] == "tree-exact", "the retired FAILED must not be resolved to"
    assert rel["conjunct_grades"] == [{"label": "gate", "grade": "tree-exact"}]

    report = M.verify(s, repo)
    live = {r.claim.label: r.grade for r in report.live_results}
    assert live == {"gate": "tree-exact", "REL": "tree-exact"}
    assert report.superseded_count == 1
    assert report.all_verified is True
    assert gp.head_commit(repo) == head, "no commit may be needed to converge"
    assert cli.main(["--repo", str(repo), "verify", "--strict"]) == 0

    # The record keeps the failed attempt, verbatim, and the row says why the
    # green headline stands over it.
    text = render.render_verdict(report)
    assert "FAILED" in text
    assert "superseded by claim #1" in text


def test_a_superseded_conjunction_does_not_vote(repo: Path):
    """A conjunction is retired by the same (ctype, label) rule as any claim."""
    s = _session(repo)
    _run(s, repo, "pass")
    _claim(s, "tests-pass", "unit", 0)
    _conjunction(s, "REL", "nosuch")   # attempt 1: unresolvable
    _conjunction(s, "REL", "unit")     # attempt 2: the corrected declaration

    m = M.seal(s, repo)
    assert m.claims[1]["grade"] == "unknown"
    assert m.claims[1]["superseded_by"] == 2
    assert m.claims[2]["grade"] == "tree-exact"
    report = M.verify(s, repo)
    assert report.all_verified is True
    assert report.superseded_count == 1


# --- test 5: vocabulary invariants ------------------------------------------


def test_a_conjunction_with_no_conjuncts_is_refused():
    with pytest.raises(ClaimError) as exc:
        Claim(ctype=CONJUNCTION, label="REL", event_indices=())
    assert "conjunction" in str(exc.value)


def test_a_non_conjunction_carrying_conjuncts_is_refused():
    with pytest.raises(ClaimError):
        Claim(
            ctype="tests-pass",
            label="t",
            event_indices=(0,),
            conjuncts=("unit",),
        )


def test_a_conjunction_binding_an_event_is_refused():
    """The illegitimate composite: a claim spanning several bound events grades
    on the first success it finds and hides a witnessed failure. A conjunction
    must not be built out of that shape, so its bound-event set is required to
    be empty."""
    with pytest.raises(ClaimError) as exc:
        Claim(
            ctype=CONJUNCTION,
            label="REL",
            event_indices=(0,),
            conjuncts=("unit",),
        )
    assert "binds no event" in str(exc.value)


def test_the_cli_refuses_the_flags_a_conjunction_has_no_use_for(repo: Path, capsys):
    """Refused, not silently ignored: an operator who passed --event meant it."""
    s = _session(repo)
    _run(s, repo, "pass")

    assert cli.main(["--repo", str(repo), "claim", "conjunction", "--of", "unit", "--event", "0"]) == 2
    assert cli.main(["--repo", str(repo), "claim", "conjunction", "--of", "unit", "--path", "src/"]) == 2
    assert cli.main(["--repo", str(repo), "claim", "conjunction"]) == 2
    assert cli.main(["--repo", str(repo), "claim", "tests-pass", "--of", "unit"]) == 2
    assert M._load_claims(s) == [], "no refusal may have declared a claim"

    assert cli.main(
        ["--repo", str(repo), "claim", "conjunction", "--label", "REL", "--of", " unit , lint "]
    ) == 0
    (declared,) = M._load_claims(s)
    assert declared.conjuncts == ("unit", "lint"), "--of is order-preserving and trimmed"
    assert declared.event_indices == ()


def test_the_cli_choices_are_the_vocabulary():
    """The parser's choices used to duplicate CLAIM_TYPES, which is how a CLI
    keeps refusing a type the library has accepted for a release."""
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["claim", "no-such-type"])
    assert parser.parse_args(["claim", "conjunction"]).type == CONJUNCTION


# --- test 6: serialization --------------------------------------------------


def test_the_note_carries_the_conjuncts_and_round_trips(repo: Path):
    """The published note says what each member earned, and the body satisfies
    the pack's three-part round-trip criterion — newline discipline, key-superset
    semantic equality, serialization idempotence — not byte equality."""
    s = _session(repo)
    _run(s, repo, "pass")
    _run(s, repo, "pass")
    _claim(s, "tests-pass", "unit", 0)
    _claim(s, "lint-clean", "lint", 1)
    _conjunction(s, "REL", "unit", "lint")
    M.seal(s, repo)

    raw = _note_body(repo)
    assert note_violations(raw, 0) == []

    body = json.loads(raw[:-1])
    rel = _entry(body, "REL")
    assert rel["claim"]["ctype"] == CONJUNCTION
    assert rel["claim"]["conjuncts"] == ["unit", "lint"]
    assert rel["claim"]["event_indices"] == []
    assert rel["conjunct_grades"] == [
        {"label": "unit", "grade": "tree-exact"},
        {"label": "lint", "grade": "tree-exact"},
    ]
    # A conjunction binds no event, so the seal writes it no evidence block:
    # "nothing to bind" and "bound to nothing" are different facts.
    assert "evidence" not in rel
    # Every OTHER claim keeps the keys it always had, and none of them gains a
    # conjunct list it did not declare.
    for entry in body["claims"]:
        if entry["claim"]["label"] != "REL":
            assert entry["claim"]["conjuncts"] == []
            assert "conjunct_grades" not in entry

    # The Claim survives the round trip through its own serialization.
    reparsed = Claim.from_dict(rel["claim"])
    assert reparsed.ctype == CONJUNCTION
    assert reparsed.conjuncts == ("unit", "lint")


def test_a_claim_dict_without_conjuncts_reads_as_carrying_none():
    """A v1/v2 claim entry lacks the key entirely; it reads with a default."""
    claim = Claim.from_dict(
        {"ctype": "tests-pass", "label": "t", "event_indices": [0], "pathspecs": []}
    )
    assert claim.conjuncts == ()
    assert claim.to_dict()["conjuncts"] == []


def test_a_conjunct_label_carrying_a_secret_is_redacted_everywhere_it_is_published(
    repo: Path,
):
    """The conjunct list and the reason are exported operator-authored text.

    A token in a claim label blocked the seal and was then published verbatim on
    the override — the defect the claim-field redaction pass closed. A
    conjunction reintroduces the same shape twice: the conjunct NAME, and the
    reason that names it.
    """
    token = "ghp_" + "b3TA" * 9
    s = _session(repo)
    _run(s, repo, "pass")
    _claim(s, "tests-pass", f"unit {token}", 0)
    _conjunction(s, "REL", f"unit {token}")

    with pytest.raises(M.redact.SecretsBlocked):
        M.seal(s, repo)
    m = M.seal(s, repo, allow_secrets=True)

    published = _note_body(repo).decode("ascii")
    assert token not in published, "a conjunct name was published verbatim"
    rel = _entry(json.loads(m.to_json()), "REL")
    mask = M.redact._mask("github-token")
    assert rel["claim"]["conjuncts"] == [f"unit {mask}"]
    assert rel["conjunct_grades"] == [{"label": f"unit {mask}", "grade": "tree-exact"}]
    assert mask in rel["reason"]
    fields = {f["field"] for f in rel["redaction"]["fields"]}
    assert {"claim.conjuncts[0]", "reason"} <= fields
    # The redaction is the same projection on both sides of the match, so the
    # conjunction still resolves when verify regrades it from the note.
    report = M.verify(s, repo)
    assert next(r for r in report.results if r.claim.label == "REL").grade == "tree-exact"


# --- test 7: the version bump ----------------------------------------------


def test_a_note_carrying_a_conjunction_is_version_3(repo: Path):
    assert M.MANIFEST_VERSION == 3
    s = _session(repo)
    _run(s, repo, "pass")
    _claim(s, "tests-pass", "unit", 0)
    _conjunction(s, "REL", "unit")
    m = M.seal(s, repo)

    body = _note_body(repo)
    assert json.loads(body[:-1])["version"] == 3
    assert m.version == 3
    # A v0.2 binary whose MANIFEST_VERSION is 3 accepts it.
    assert M.Manifest.from_json(body[:-1]).version == 3


def test_the_refuse_unknown_version_gate_rejects_version_4(repo: Path):
    """P0.3's refuse-never-coerce rule, one version above this one."""
    s = _session(repo)
    _run(s, repo, "pass")
    _claim(s, "tests-pass", "unit", 0)
    _conjunction(s, "REL", "unit")
    M.seal(s, repo)

    body = json.loads(_note_body(repo)[:-1])
    body["version"] = 4
    too_new = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")
    with pytest.raises(M.ManifestError) as exc:
        M.Manifest.from_json(too_new)
    assert "version 4" in str(exc.value)
    assert "max 3" in str(exc.value)


# --- rendering --------------------------------------------------------------


def test_the_surfaces_show_the_conjuncts_and_never_grade_an_unresolved_one(
    repo: Path, monkeypatch
):
    monkeypatch.setenv("NO_COLOR", "1")
    s = _session(repo)
    _run(s, repo, "pass")
    _claim(s, "tests-pass", "unit", 0)
    _conjunction(s, "REL", "unit", "nosuch")
    M.seal(s, repo)
    report = M.verify(s, repo)

    text = render.render_verdict(report)
    assert "of unit: TREE-EXACT" in text
    assert "of nosuch: UNRESOLVED" in text

    html = render.render_html(report)
    assert "UNRESOLVED" in html
    assert "nosuch" in html
    # No new grade token, and an unresolved conjunct is not dressed as a grade.
    assert "conjuncts" in html
