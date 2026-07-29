"""Structured, declared claims and the deterministic grading engine.

A claim is a typed assertion a session *declares* — never inferred from prose.
The grading engine assigns one of four grades against a target tree, first match
wins:

  tree-exact   a self-stable event ran against exactly the sealed tree
  scope-exact  the change is confined to claimant-DECLARED pathspecs (set
               arithmetic only; relevance is never auto-inferred)
  stale        evidence exists but the tree moved — MUST carry the exact delta
  unknown      no honest binding (degraded capture, retroactive binding, gc'd
               object, missing digest)

``diff-exercised`` is deliberately NOT a claim type. It is coverage
instrumentation in disguise with no deterministic v1 implementation; it is
killed by design (coverage belongs in an adapter, not the core). Registering it
raises with the flip condition.

``conjunction`` is the one claim type that grades no evidence of its own. It
names other claims in the same seal window by label and is graded as the WORST
of them, so it can never be better than any one of its members. The property it
represents — "all N of these gates passed against this tree" — had no
representation in the tool and was being enforced by hand.

**The distinction this type is on the right side of, stated because the next
reader will conflate the two.** A design review of an 80-command proof ledger
declined a proposal to replace some of those recorded executions with a
transition marker, and the reason is quoted here rather than softened: a marker
witnesses *that a transition occurred*, not *that the command ran and exited
0*, so substituting one for the other genuinely weakens the claim. That refusal
stands, permanently, and nothing here attempts it — a conjunction substitutes
for nothing. Every conjunct keeps its own witnessed exit code and its own tree
comparison, graded by the same ladder as any other claim, and the conjunction
asserts nothing its members do not already back. It conjoins execution witnesses
that exist; it never reconstitutes one that does not.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .ledger import Event, Session
from . import gitplumbing

# The claim vocabulary. `tests-pass` and `lint-clean` are labels over one
# generic engine: "a declared command exited 0". No claim type infers meaning.
#
# `conjunction` is the one entry that binds no event of its own: it names other
# claims in the same seal window and is graded as the worst of them. Extending
# this tuple is a MANIFEST_VERSION bump (docs/COMPAT.md) — an older reader hits
# `unknown claim type` on a note that carries a type it has never seen.
CONJUNCTION = "conjunction"

CLAIM_TYPES = ("command-succeeded", "tests-pass", "lint-clean", CONJUNCTION)

KILLED_CLAIM_TYPES = {
    "diff-exercised": (
        "diff-exercised is killed: it is coverage instrumentation in disguise "
        "with no deterministic v1 implementation. Flip condition: a "
        "coverage-ingest ADAPTER (adapter-attested, non-core) consuming existing "
        "coverage tooling output — never core, never deterministic-core-clean."
    ),
}

GRADE_TREE_EXACT = "tree-exact"
GRADE_SCOPE_EXACT = "scope-exact"
GRADE_STALE = "stale"
GRADE_UNKNOWN = "unknown"
# The strongest negative signal: didrun WITNESSED the claimed command fail. This
# is distinct from `unknown` (no evidence at all) — it is a claim caught lying.
GRADE_FAILED = "failed"
# The note records a grade for this claim, but the live ledger cannot supply the
# evidence it was sealed against — this is not a verification. It is never
# produced by ``grade()``: the ladder below grades a claim against evidence it
# can see, and this state says the evidence itself is gone, or is not the
# evidence that was sealed. manifest.verify assigns it AROUND the ladder, and it
# is never admitted to the set --strict accepts.
GRADE_WITNESS_UNAVAILABLE = "witness-unavailable"

# The environment comparison verify makes ACROSS TIME — between the fingerprint
# the seal recorded and the one this process computes. These are NOT grades: a
# drifted environment does not make a recorded command un-run, so they never
# enter the grading ladder and never reach `worst_status`.
#
# The two refusals are load-bearing. `incomparable` is what a fingerprint from a
# different FINGERPRINT_VERSION (or a bare v0.1 digest) gets — different key
# sets are not measuring the same thing, and calling that drift would make every
# archived note look like the environment moved. `not-recorded` is a note that
# bound no fingerprint at all, which is a different fact again.
ENV_MATCH = "match"
ENV_DRIFT = "env-drift-since-seal"
ENV_INCOMPARABLE = "incomparable"
ENV_NOT_RECORDED = "not-recorded"

# Worst first. This is the ONE severity order in the package: the whole-report
# verdict (manifest.VerifyReport.worst_status) reads it, and a conjunction reads
# it to grade as the worst of its conjuncts. Two copies could disagree about
# which grade is worse, and a conjunction that disagreed with the verdict line
# above it would be the exact overclaim this type has to be incapable of.
#
# `chain-broken` is deliberately absent: it is a statement about the ledger every
# grade was read out of, not a grade any claim can carry, and it dominates the
# verdict before this order is consulted.
GRADE_ORDER_WORST_FIRST = (
    GRADE_FAILED,
    GRADE_UNKNOWN,
    GRADE_WITNESS_UNAVAILABLE,
    GRADE_STALE,
    GRADE_SCOPE_EXACT,
    GRADE_TREE_EXACT,
)


def worst_grade(grades) -> Optional[str]:
    """The worst grade in ``grades`` under ``GRADE_ORDER_WORST_FIRST``.

    Ties go to the first occurrence, so the caller's order decides which of two
    equally-bad members is named — never the iteration order of a set.

    A grade this version does not know ranks WORSE than every registered one. A
    grade nobody here can interpret is not evidence that anything is fine, and
    ranking it best is how an unregistered token would carry a conjunction to
    green. Returns None for an empty input; callers must not treat that as a
    grade.
    """
    worst: Optional[str] = None
    worst_rank: Optional[int] = None
    for g in grades:
        rank = GRADE_ORDER_WORST_FIRST.index(g) if g in GRADE_ORDER_WORST_FIRST else -1
        if worst_rank is None or rank < worst_rank:
            worst, worst_rank = g, rank
    return worst


class ClaimError(Exception):
    """A claim declaration violated an invariant."""


@dataclass(frozen=True)
class Claim:
    """A declared assertion bound to captured events.

    ``pathspecs`` are supplied by the claimant for a scope-exact grade; they are
    never auto-derived. ``declared_at_index`` is the session index at which the
    claim was declared — used for the retroactive-binding rule.

    ``conjuncts`` are the LABELS of other claims in the same seal window that a
    ``conjunction`` conjoins. They are labels rather than event indices on
    purpose: a conjunction must not be a claim bound to several events. That
    shape already exists, grades on the first bound success it finds, and is the
    illegitimate composite the design review ruled out — so ``event_indices`` is
    required to be EMPTY here and its meaning is untouched.
    """

    ctype: str
    label: str
    event_indices: tuple[int, ...]
    pathspecs: tuple[str, ...] = ()
    declared_at_index: int = -1
    conjuncts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.ctype in KILLED_CLAIM_TYPES:
            raise ClaimError(KILLED_CLAIM_TYPES[self.ctype])
        if self.ctype not in CLAIM_TYPES:
            raise ClaimError(f"unknown claim type: {self.ctype!r}")
        if self.ctype == CONJUNCTION:
            if not self.conjuncts:
                raise ClaimError(
                    "a conjunction claim must name the claims it conjoins "
                    "(at least one conjunct label)"
                )
            if self.event_indices:
                raise ClaimError(
                    "a conjunction claim binds no event: it conjoins claims that "
                    "carry their own witnessed events, and widening its bound "
                    "events would make it a multi-index claim instead"
                )
        elif self.conjuncts:
            raise ClaimError(
                f"claim type {self.ctype!r} names no conjuncts; only a "
                f"conjunction claim conjoins other claims"
            )

    def to_dict(self) -> dict:
        return {
            "ctype": self.ctype,
            "label": self.label,
            "event_indices": list(self.event_indices),
            "pathspecs": list(self.pathspecs),
            "declared_at_index": self.declared_at_index,
            # Emitted always, like `pathspecs`, and read with a default below:
            # an older reader that does not know the key sees the claim it
            # always saw, and every claim this version writes declares the key
            # whether or not it carries one.
            "conjuncts": list(self.conjuncts),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Claim":
        return cls(
            ctype=d["ctype"],
            label=d.get("label", d["ctype"]),
            event_indices=tuple(d.get("event_indices", ())),
            pathspecs=tuple(d.get("pathspecs", ())),
            declared_at_index=d.get("declared_at_index", -1),
            conjuncts=tuple(d.get("conjuncts", ())),
        )


@dataclass
class GradeResult:
    """The outcome of grading one claim against a target tree.

    ``evidence_bound`` and ``sealed_grade`` are verify-side facts, not grading
    facts: they say whether this verdict was checked against the specific
    recorded entry the seal named, and what that seal graded. ``grade()`` never
    sets them, so a sealed note carries them at their defaults.

    ``env_status`` / ``env_reason`` are verify-side in the same way, and they
    are deliberately NOT in ``to_dict``: the seal has nothing to compare against
    itself, so writing them would put a permanently-default key in every
    published note.

    ``superseded_by`` is verify-side for a different reason: supersession is a
    fact about the seal WINDOW, not about this claim's evidence, so the seal
    writes the mark onto the exported entry itself (manifest._redact_result) and
    verify reads it back onto the result. Keeping it out of ``to_dict`` is what
    makes the mark appear only on the entries that carry one, instead of putting
    a permanently-null key on every claim in every note.

    ``conjunct_grades`` holds one ``(label, grade)`` pair per conjunct a
    conjunction declared, in declaration order, so the note carries what each
    member earned instead of only the worst of them. ``grade`` is None for a
    conjunct that resolved to no single live claim: an unresolved name has no
    grade, and giving it one would be the invented fact this whole type exists
    not to produce. Serialized only when non-empty, on ``superseded_by``'s
    precedent — every other claim would otherwise carry an empty list forever.
    """

    claim: Claim
    grade: str
    reason: str
    delta: list = field(default_factory=list)  # PathChange list when stale/scope
    supporting_event_index: Optional[int] = None
    exit_code: Optional[int] = None
    evidence_bound: bool = False
    sealed_grade: Optional[str] = None
    env_status: str = ENV_NOT_RECORDED
    env_reason: str = ""
    superseded_by: Optional[int] = None
    conjunct_grades: tuple = ()

    @property
    def is_superseded(self) -> bool:
        """Whether a later claim in the same seal window retired this one.

        A superseded result is RECORD, not verdict: its grade and reason are
        kept verbatim and stay visible, and it is excluded from the verdict —
        never relabelled, re-graded or dropped.
        """
        return self.superseded_by is not None

    def to_dict(self) -> dict:
        d = {
            "claim": self.claim.to_dict(),
            "grade": self.grade,
            "reason": self.reason,
            "delta": [{"status": c.status, "path": c.path} for c in self.delta],
            "supporting_event_index": self.supporting_event_index,
            "exit_code": self.exit_code,
            "evidence_bound": self.evidence_bound,
            "sealed_grade": self.sealed_grade,
        }
        if self.conjunct_grades:
            d["conjunct_grades"] = [
                {"label": label, "grade": g} for label, g in self.conjunct_grades
            ]
        return d


def _supporting_event(claim: Claim, events: list[Event]) -> Optional[tuple[int, Event]]:
    """The command-exited-0 event that backs this claim, if any.

    For command-success claims we require an actual witnessed exit of 0 from a
    capture tier that can see exit codes. A transcript-only event can never
    support a success claim (it has no exit code).
    """
    for idx in claim.event_indices:
        if 0 <= idx < len(events):
            ev = events[idx]
            if ev.exit_code == 0:
                return idx, ev
    return None


def _witnessed_failure(claim: Claim, events: list[Event]) -> Optional[tuple[int, Event]]:
    """A bound event that didrun witnessed FAIL (non-zero exit), if any.

    This is what distinguishes a *caught lie* (FAILED) from *no evidence*
    (UNKNOWN): a success claim bound to a command didrun recorded exiting
    non-zero is the strongest negative signal the tool can produce.
    """
    for idx in claim.event_indices:
        if 0 <= idx < len(events):
            ev = events[idx]
            if ev.exit_code is not None and ev.exit_code != 0:
                return idx, ev
    return None


def grade_conjunction(claim: Claim, siblings: Optional[list] = None) -> GradeResult:
    """Grade a conjunction as the WORST of the claims it names. Never better.

    ``siblings`` are the other graded results of the same seal window. Two kinds
    are filtered out here rather than at the call site, so both callers (seal and
    verify) get the same resolution from the same rule:

    - **superseded entries.** A repair re-declares the same gate, so the retired
      attempt shares its label with the claim that stands in its place. Skipping
      it is what lets a conjunction name a gate that failed and was fixed inside
      the window; counting it would make every such name ambiguous.
    - **other conjunctions.** A conjunction naming a conjunction resolves to no
      match and grades ``unknown``. That is deliberate: it keeps resolution one
      level deep, so there is no recursion to bound and no cycle to detect, and
      the grade of a name this function will not follow is not asserted.

    Resolution is by EXACT label match — never a prefix, never a fuzzy one. A
    name matching no live claim, or more than one, makes the whole conjunction
    ``unknown`` and the reason names it: a member it cannot identify is a member
    it cannot vouch for, and grading around the gap is how a conjunction would
    come out better than its parts.
    """
    pool = [
        s
        for s in (siblings or ())
        if not s.is_superseded and s.claim.ctype != CONJUNCTION
    ]
    pairs: list = []
    unresolved: list[str] = []
    for name in claim.conjuncts:
        matches = [s for s in pool if s.claim.label == name]
        if len(matches) == 1:
            pairs.append((name, matches[0].grade))
            continue
        pairs.append((name, None))
        unresolved.append(
            f"{name!r} names no claim in this seal window"
            if not matches
            else f"{name!r} names {len(matches)} claims in this seal window"
        )
    if unresolved:
        return GradeResult(
            claim,
            GRADE_UNKNOWN,
            reason="unresolved conjunct: " + "; ".join(unresolved),
            conjunct_grades=tuple(pairs),
        )
    worst = worst_grade(g for _name, g in pairs)
    # Ties go to the first declared conjunct, which is what makes this reason
    # reproducible for the same window rather than a function of dict ordering.
    named = next(name for name, g in pairs if g == worst)
    return GradeResult(
        claim,
        worst,
        reason=f"worst of {len(pairs)} conjunct(s): {named!r} graded {worst}",
        conjunct_grades=tuple(pairs),
    )


def grade(
    claim: Claim,
    sealed_tree: str,
    events: list[Event],
    repo: Path,
    ledger_objects: Optional[Path] = None,
    siblings: Optional[list] = None,
) -> GradeResult:
    """Grade one claim against ``sealed_tree``. First match wins.

    The ordering is the honesty ladder: only concede a weaker grade when the
    stronger one cannot be honestly asserted.

    ``siblings`` is consulted for a ``conjunction`` and for nothing else: it
    grades no evidence of its own, so it is dispatched BEFORE the ladder rather
    than added as a rung. Every rung below is untouched, and a caller that
    forgets ``siblings`` gets a conjunction graded ``unknown`` — the fail-closed
    direction, never a green one.
    """
    if claim.ctype == CONJUNCTION:
        return grade_conjunction(claim, siblings)

    # A witnessed failure among the bound events DOMINATES a witnessed success.
    # Consulting _supporting_event first graded a claim bound to
    # [failed, success] on the success and made the caught lie invisible.
    # Reachable only through the library API today (the CLI's --event is
    # type=int, so every CLI claim binds exactly one event).
    failure = _witnessed_failure(claim, events)
    if failure is not None:
        fidx, fev = failure
        return GradeResult(
            claim,
            GRADE_FAILED,
            reason=f"the recorded command exited {fev.exit_code} — claim is not backed",
            supporting_event_index=fidx,
            exit_code=fev.exit_code,
        )

    found = _supporting_event(claim, events)
    if found is None:
        # No witnessed success and no witnessed failure: no evidence at all.
        return GradeResult(
            claim,
            GRADE_UNKNOWN,
            reason="no witnessed successful command backs this claim",
        )
    idx, ev = found

    # Retroactive-binding rule: a claim declared before its backing event ran,
    # or with no ordering at all under degraded capture, cannot be trusted to
    # bind to that evidence — grade unknown and say why.
    if claim.declared_at_index != -1 and claim.declared_at_index < idx:
        return GradeResult(
            claim,
            GRADE_UNKNOWN,
            reason=(
                f"retroactive binding: claim declared at index "
                f"{claim.declared_at_index} precedes its backing event {idx}"
            ),
            supporting_event_index=idx,
            exit_code=ev.exit_code,
        )

    if ev.tree_after is None:
        return GradeResult(
            claim,
            GRADE_UNKNOWN,
            reason="backing event has no honest tree digest",
            supporting_event_index=idx,
            exit_code=ev.exit_code,
        )

    # tree-exact: the command ran self-stably against exactly the sealed tree.
    if ev.self_stable() and ev.tree_after == sealed_tree:
        # A dirty submodule caps the grade (content not digested) — honest.
        if ev.submodule_dirty:
            return GradeResult(
                claim,
                GRADE_STALE,
                reason="tree matches but a submodule is dirty (content not digested)",
                supporting_event_index=idx,
                exit_code=ev.exit_code,
            )
        return GradeResult(
            claim,
            GRADE_TREE_EXACT,
            reason="self-stable command ran against the sealed tree",
            supporting_event_index=idx,
            exit_code=ev.exit_code,
        )

    # Compute the delta between the evidence tree and the sealed tree.
    delta = gitplumbing.tree_delta(repo, ev.tree_after, sealed_tree, ledger_objects)
    if delta is None:
        # Fail closed. `None` is "git could not compute it" — typically the
        # archived-ledger case where the evidence tree's objects have moved.
        # Every branch below would otherwise render that failure as a fact
        # ("0 path(s) differ", "evidence tree equals sealed tree"), and an
        # empty delta would also violate the stale-carries-the-delta invariant.
        return GradeResult(
            claim,
            GRADE_UNKNOWN,
            reason="delta not computable: evidence tree objects unavailable",
            supporting_event_index=idx,
            exit_code=ev.exit_code,
        )

    # scope-exact: every change is within the claimant-declared pathspecs.
    if claim.pathspecs:
        out_of_scope = [c for c in delta if not _within(c.path, claim.pathspecs)]
        if not out_of_scope and delta:
            return GradeResult(
                claim,
                GRADE_SCOPE_EXACT,
                reason=f"all {len(delta)} change(s) within declared pathspecs",
                delta=delta,
                supporting_event_index=idx,
                exit_code=ev.exit_code,
            )
        if not delta:
            # No delta at all but not self-stable → the evidence tree equals the
            # sealed tree yet the command wasn't self-stable; that's stale-clean.
            return GradeResult(
                claim,
                GRADE_STALE,
                reason="evidence tree equals sealed tree but command was not self-stable",
                supporting_event_index=idx,
                exit_code=ev.exit_code,
            )
        # Out-of-scope changes exist — display them; cannot claim scope-exact.
        return GradeResult(
            claim,
            GRADE_STALE,
            reason=f"{len(out_of_scope)} change(s) outside declared pathspecs",
            delta=delta,
            supporting_event_index=idx,
            exit_code=ev.exit_code,
        )

    # stale: evidence exists, tree moved, delta shown. Never bare.
    return GradeResult(
        claim,
        GRADE_STALE,
        reason=f"tree moved since evidence: {len(delta)} path(s) differ",
        delta=delta,
        supporting_event_index=idx,
        exit_code=ev.exit_code,
    )


def _within(path: str, pathspecs: tuple[str, ...]) -> bool:
    """True if ``path`` is under any declared pathspec (prefix match).

    Deliberately simple set-arithmetic (path prefix), never fuzzy relevance.
    """
    p = path.strip("/")
    for spec in pathspecs:
        s = spec.strip("/")
        if p == s or p.startswith(s + "/"):
            return True
    return False
