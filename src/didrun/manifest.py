"""Seal and verify: the commit-bound evidence manifest.

Seal compiles a session's claims + graded evidence + a coverage statement into
a manifest bound to a commit two ways — by commit id AND by tree id — so it
survives amend/rebase (git notes do not follow rewrites by default; the tree id
is the durable anchor). The manifest attaches via ``refs/notes/didrun`` and an
exportable bundle file (notes do not auto-push; the bundle is the cross-machine
transport). Claim-referenced blobs are copied into the ledger at seal for
gc-durability. Commits are never rewritten.

Verify resolves a manifest by commit id, falls back to tree id, recomputes the
grades, and returns a structured report with CI-friendly exit semantics. It is a
pre-merge / PR-head tool: squash-merged trees grade stale/unknown by design.

The note is the only artifact that leaves the machine, so the redaction it
carries is declared rather than inferred: each claim entry gets a `redaction`
block naming the projection version, the detector-set version, and the exact
source spans that were replaced. A consumer reads that block. The marker string
alone is NOT authenticating — a recorded argv can contain the literal text
`«redacted:openai-key»` and nothing escapes it — so "is this a real redaction or
did the command print that?" is answered by `redaction.applied`, never by
pattern-matching the preview. Keyed markers would close the forgery gap; they
are out of scope (see docs/COMPAT.md).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .ledger import Session, canonical_json, _append_lock, _open_private_append
from .claims import (
    CONJUNCTION,
    ENV_DRIFT,
    ENV_INCOMPARABLE,
    ENV_MATCH,
    ENV_NOT_RECORDED,
    GRADE_FAILED,
    GRADE_ORDER_WORST_FIRST,
    GRADE_WITNESS_UNAVAILABLE,
    Claim,
    ClaimError,
    GradeResult,
    grade,
    pool_as_declared,
)
from . import capture, gitplumbing, redact

# 2: a claim may carry an `evidence` block naming the recorded entry that backed
# it, and verify CHECKS that binding instead of regrading by index alone. The
# bump is for the change of meaning, not for the new key: an older reader parses
# a v2 note fine (every key is additive) and regrades it index-only, exactly as
# it does today. See docs/COMPAT.md.
#
# 3: the claim-type vocabulary gained `conjunction`. This one is NOT additive in
# either direction — `Claim.from_dict` raises `unknown claim type` on a type it
# does not know, and in an older binary it raises from OUTSIDE verify's try, so a
# v0.1/v0.2 reader meeting a v3 note exits with an uncaught traceback rather than
# a graded refusal. There is no way to extend a closed vocabulary without that,
# and silently skipping claim types a reader does not know would be worse: the
# note would under-report and still print a verdict. See docs/COMPAT.md.
MANIFEST_VERSION = 3
NOTES_REF = "refs/notes/didrun"


class ManifestError(Exception):
    pass


class ManifestFormatError(ManifestError):
    """A note body this binary cannot parse at all.

    Split from ``ManifestError`` because the two get different treatment on the
    tree-fallback scan: a body that is not a readable manifest is SKIPPED and
    counted (a foreign note under the same ref must not hide every good one),
    while a version this binary does not understand PROPAGATES. Both are a
    graded refusal on the direct-commit path — it subclasses ``ManifestError``,
    which is what the CLI already catches, so an unreadable note exits 2 rather
    than raising out of the command.

    That distinction used to be made by exception type ACCIDENTALLY: the scan
    caught bare ``Exception``, so a malformed body was skipped because
    ``json`` happened to raise something that was not a ``ManifestError``. On
    the direct-commit path the same shapes had nothing to catch them and left as
    an uncaught ``TypeError``/``KeyError`` traceback, with exit 1 — which is
    ``--strict``'s "this graded badly" code, not "I could not read this".
    """


@dataclass
class Manifest:
    version: int
    commit: str
    tree: str
    claims: list[dict]  # graded results (serialized)
    coverage: dict
    secrets_override: bool = False
    # What the secrets pass actually looked at. `secrets_override: false` used
    # to be unfalsifiable — it is the same word for "nothing was found" and
    # "almost nothing was scanned". This says which. Additive, defaults to {},
    # read with .get(): no MANIFEST_VERSION bump (docs/COMPAT.md).
    secrets: dict = field(default_factory=dict)
    # The half-open claim window this note covers: the seal watermark and the
    # claim count at seal time. Without it the note's SCOPE was invisible from
    # the note — a re-seal narrowed to `all_claims[watermark:]` and force-wrote
    # over the wider record, and nothing in the artifact said so. Additive,
    # read with .get() defaults of 0 / len(claims): no MANIFEST_VERSION bump
    # (docs/COMPAT.md).
    claims_from: int = 0
    claims_to: Optional[int] = None
    # The authorisation artifacts this seal cited for its exceptional
    # transitions, each graded `cited` and each carrying AUTHORITY_LIMITATION.
    # A MANIFEST field and never an Event field: a reference to an external
    # artifact inside the chain preimage would make every future rotation of
    # that artifact a schema break (docs/COMPAT.md). Additive, defaults to [],
    # read with .get(): no MANIFEST_VERSION bump.
    authority: list = field(default_factory=list)

    def __post_init__(self) -> None:
        # The reading default for `claims_to`, applied once so every consumer
        # sees an int. `None` is the "key was absent" marker, and it must NOT
        # survive into `to_json` — a note with a null window would be a third
        # state nobody reads. What "absent" MEANS (the window is unknown, not
        # [0, N)) is answered by `_recorded_window`, which reads key presence
        # off the raw body instead of a parsed default.
        if self.claims_to is None:
            self.claims_to = len(self.claims)

    def to_json(self) -> bytes:
        return canonical_json(
            {
                "version": self.version,
                "commit": self.commit,
                "tree": self.tree,
                "claims": self.claims,
                "coverage": self.coverage,
                "secrets_override": self.secrets_override,
                "secrets": self.secrets,
                "claims_from": self.claims_from,
                "claims_to": self.claims_to,
                "authority": self.authority,
            }
        )

    @classmethod
    def from_json(cls, data: bytes) -> "Manifest":
        """Parse a note body. Refuses a version it does not understand.

        Refuse, never coerce: a newer manifest may have changed what an
        existing field MEANS, and grading it under this version's semantics
        would produce a confident verdict about a format this binary has never
        seen. Older versions are accepted — new fields are additive and are
        read with a v1-reproducing default (see docs/COMPAT.md).

        Every shape that is not a readable manifest raises
        ``ManifestFormatError`` rather than whatever ``json`` and ``dict``
        happened to raise on the way past. The version comparison is the reason
        this matters: ``version`` arrives from a file, so it is not necessarily
        an int, and ``"3" > 3`` raises while ``True > 3`` is quietly False. The
        first left a traceback where a refusal belonged; the second ACCEPTED the
        note and verified it green, because ``bool`` is an ``int`` subclass and
        ``True`` compares as 1. A guard the whole forward-compat story rests on
        (docs/COMPAT.md, "Version 3") cannot be one a malformed field walks past.
        """
        try:
            d = json.loads(data)
        except ValueError as exc:
            raise ManifestFormatError(f"note body is not valid JSON: {exc}") from exc
        if not isinstance(d, dict):
            raise ManifestFormatError(
                f"note body is a JSON {type(d).__name__}, not a manifest object"
            )
        if "version" not in d:
            raise ManifestFormatError("note body declares no manifest version")
        version = d["version"]
        # `_is_index` and not `isinstance(..., int)`: bool is an int subclass, so
        # a `version` of `true` would otherwise compare as 1 and be accepted as a
        # v1 note. Measured before the fix: `didrun verify --strict` exited 0 on
        # it. The same reading rule the supersession mark gets, for the same
        # reason — a field that arrived from a file is not a field this process
        # computed.
        if not _is_index(version) or version < 1:
            raise ManifestFormatError(
                f"manifest version is {version!r}, which is not a version number "
                f"(expected an integer >= 1)"
            )
        if version > MANIFEST_VERSION:
            raise ManifestError(
                f"manifest version {version} is newer than this didrun understands "
                f"(max {MANIFEST_VERSION}); upgrade didrun"
            )
        # The keys with no reading default. A note missing one is not a note an
        # older-or-newer default can stand in for, and indexing straight into
        # `d` turned each one into a `KeyError` traceback out of the command.
        missing = [k for k in ("commit", "tree", "claims", "coverage") if k not in d]
        if missing:
            raise ManifestFormatError(
                f"manifest is missing required field(s): {', '.join(missing)}"
            )
        # `claims` is indexed and iterated by every consumer, and `__post_init__`
        # takes its len. A non-list here surfaced as `TypeError: string indices
        # must be integers` from deep inside verify.
        if not isinstance(d["claims"], list):
            raise ManifestFormatError(
                f"manifest `claims` is a {type(d['claims']).__name__}, not a list"
            )
        # A note published before operator authority existed carries no key, and
        # "no authority was cited" is exactly what [] says. A non-list is read as
        # [] for the same reason: an authority block is record, never verdict, so
        # a malformed one must not raise on a path that reads the rest fine.
        authority = d.get("authority", [])
        if not isinstance(authority, list):
            authority = []
        return cls(
            version=version,
            commit=d["commit"],
            tree=d["tree"],
            claims=d["claims"],
            coverage=d["coverage"],
            secrets_override=d.get("secrets_override", False),
            secrets=d.get("secrets", {}),
            claims_from=d.get("claims_from", 0),
            claims_to=d.get("claims_to"),
            authority=authority,
        )


def _coverage_statement(session: Session) -> dict:
    """Summarize how much of the session was completely observed vs. lower grades."""
    counts: dict[str, int] = {}
    for ev in session.events():
        counts[ev.coverage] = counts.get(ev.coverage, 0) + 1
    total = sum(counts.values())
    return {"total_events": total, "by_coverage": counts}


def _gc_durable_copy(session: Session, results: list[GradeResult]) -> None:
    """Copy claim-referenced evidence blobs into the ledger so a later `git gc`
    cannot orphan them out from under a manifest. Deduplicated and cheap —
    claim-bound events are few.
    """
    # Blobs are already content-addressed in session.blobs; ensure the referenced
    # stdout/stderr blobs exist there (they do, since capture wrote them). This
    # is a hook point: with the object redirect, tree objects live in the ledger
    # already. We assert presence and record which blobs are load-bearing.
    referenced = set()
    events = session.events()
    for r in results:
        idx = r.supporting_event_index
        if idx is not None and 0 <= idx < len(events):
            ev = events[idx]
            for blob in (ev.stdout_blob, ev.stderr_blob):
                if blob:
                    referenced.add(blob)
    for digest in referenced:
        if not session.blobs.has(digest):
            raise ManifestError(f"claim-referenced blob missing at seal: {digest}")


def _supersession(claims: list[Claim]) -> dict:
    """Which claims in this window a later one retired, as {index: live index}.

    A repair re-declares the same gate: same ``ctype``, same ``label``. That
    pair is the identity, so a later claim carrying it supersedes every earlier
    one — which is what lets a fix retire a `failed` or `stale` claim INSIDE the
    window, with no intervening commit. Before this, the only two escapes were
    seal-early (needs a commit) and re-seal (which truncated the record), and
    discarding the ledger was the rational third.

    **Claim-preserving by construction.** Nothing here relabels, deletes or
    re-grades anything: every claim in the window is graded and every graded
    result is published. The earlier grade and reason stay in the note verbatim,
    marked with the index of the entry that retired it. Supersession subtracts
    from the VERDICT, never from the RECORD.

    The value is the index of the LIVE entry for that key — the last one in the
    window — not the immediate successor. A reader asking "which claim stands in
    place of this one" gets that answer directly instead of walking a chain, and
    three attempts at the same gate all point at the one that stands.

    Window-local by construction: the caller passes only this seal's claims, so
    a claim in an earlier window (already sealed into an earlier commit's note)
    can never be retired from here. History is not rewritten.
    """
    live: dict = {}
    for index, claim in enumerate(claims):
        live[(claim.ctype, claim.label)] = index
    return {
        index: live[(claim.ctype, claim.label)]
        for index, claim in enumerate(claims)
        if live[(claim.ctype, claim.label)] != index
    }


def _warn_missing_watermark(session: Session, claim_count: int) -> None:
    """Say, loudly, when the watermark file is absent and claims exist.

    The watermark is a local, gitignored, unhashed file, and its ABSENCE is not
    visible from the note: delete it and every later seal silently re-covers the
    whole claim history. Measured in the archives this matters most for — only
    62 of 167 archived ledgers carried a seals.jsonl at all.

    This does not block. A first seal legitimately has no watermark file, and so
    does a rotated ledger, and nothing available here distinguishes the two —
    saying which is impossible, so the warning says BOTH and leaves the operator
    to know which one they are in. Blocking would break the first seal of every
    session; silence is what produced a note whose scope was a function of a
    deleted file.
    """
    if _seals_path(session).exists() or claim_count == 0:
        return
    print(
        f"didrun seal: WARNING: no seal watermark file, so the watermark is 0 "
        f"and this seal covers the WHOLE claim history "
        f"({claim_count} declared claim(s)). That is correct for a session's "
        f"first seal. If this session has sealed before, the watermark file was "
        f"removed or rotated and this seal re-covers claims an earlier note "
        f"already recorded — nothing in the note or the ledger distinguishes the "
        f"two from here.",
        file=sys.stderr,
    )


def seal(
    session: Session,
    repo: Path,
    commitish: str = "HEAD",
    allow_secrets: bool = False,
    write_notes: bool = True,
    bundle_path: Optional[Path] = None,
    reseal: bool = False,
    require_authority: bool = False,
) -> Manifest:
    """Compile, redact, and attach a manifest for ``commitish``.

    Raises ``redact.SecretsBlocked`` if a BLOCK-tier detector fires on the
    EXPORT domain and ``allow_secrets`` is False. Notice-tier findings, and
    block-tier findings confined to the local output blobs, warn loudly on
    stderr and do not stop the seal — the blobs stay in a gitignored ledger and
    are not published, so refusing over them stopped work without protecting
    anything. On override, the exported artifact is still redacted and the
    override is recorded in the manifest.

    Raises ``ManifestError`` when the commit already carries a note whose claim
    window this seal would NARROW, unless ``reseal`` is True. That overwrite was
    silent and lossy: `git notes add -f` force-replaces, and a seal scoped to
    `all_claims[watermark:]` replaced a wide record with a narrow one.

    ``require_authority`` refuses an exceptional transition — ``allow_secrets``
    or ``reseal`` — that no live `cited` authority covers. Default off: an
    authorisation on the happy path becomes a rubber stamp, so an ordinary seal
    demands nothing and binds nothing.
    """
    repo = Path(repo)
    commit = gitplumbing.head_commit(repo) if commitish == "HEAD" else _rev(repo, commitish)
    if commit is None:
        raise ManifestError("cannot seal: no commit to bind to (unborn HEAD?)")
    tree = gitplumbing.commit_tree(repo, commit)
    if tree is None:
        raise ManifestError(f"cannot resolve tree for commit {commit}")

    # Authorities first, and the refusal with them: it is a statement about the
    # INVOCATION, so it must cost nothing and write nothing when it fires. The
    # scopes are the exceptional transitions this seal actually performs — an
    # ordinary seal performs none, binds none, and gains no line anywhere.
    authority_scopes = tuple(
        scope
        for scope, requested in (
            (AUTHORITY_ALLOW_SECRETS, allow_secrets),
            (AUTHORITY_RESEAL, reseal),
        )
        if requested
    )
    bound_authority = _bind_authorities(session, authority_scopes, _seal_count(session))
    if require_authority:
        _require_authority(authority_scopes, bound_authority)

    # Entries, not just events: the seal records WHICH recorded entry backed
    # each claim, and an entry's chain hash is the only handle on that which
    # survives the ledger being archived, rebuilt, or replaced.
    entries = list(session.entries())
    events = [e.event for e in entries]
    ledger_objects = session.blobs.root

    # Seal scoping: a manifest carries the claims declared SINCE THE LAST SEAL —
    # each commit receipts its own unit of work. Earlier claims stay immutable
    # and permanently visible in their own commit's manifest (history is never
    # rewritten); without this scoping, a failed claim from unit 1 would poison
    # every later seal and a fix-verify-reseal loop could never converge.
    # The claims file itself remains append-only; only the seal's view is scoped.
    all_claims = _load_claims(session)
    watermark = _last_seal_watermark(session)
    _warn_missing_watermark(session, len(all_claims))
    new_claims = all_claims[watermark:]

    # Grade the claims for THIS seal against the sealed tree. EVERY claim in the
    # window is graded, including the ones a later claim supersedes: the mark
    # below excludes a retired claim from the verdict, and grading it anyway is
    # what keeps the record honest about what was declared and what it earned.
    #
    # Two passes, because a conjunction is graded against its SIBLINGS and pass
    # one is what produces them. `verify` is restructured the same way, over the
    # note's own results — the two must agree or a note that sealed green would
    # regrade `unknown`.
    results: list = [None] * len(new_claims)
    conjunctions: list[int] = []
    for i, claim in enumerate(new_claims):
        if claim.ctype == CONJUNCTION:
            conjunctions.append(i)
            continue
        results[i] = grade(claim, tree, events, repo, ledger_objects)
    superseded = _supersession(new_claims)
    # Deferrals the operator recorded for this window (`claim --defer`). A
    # retired claim needs none, and a FAILED one is never set aside: the record
    # could have been written by hand, so the grade is checked here and not only
    # at declaration. Conjunctions are decided after pass two, once graded.
    requested = _window_deferrals(session, all_claims, watermark)
    deferred: dict = {}

    def _honour(i: int) -> None:
        if i not in requested or i in superseded:
            return
        if results[i].grade == GRADE_FAILED:
            print(
                f"didrun seal: WARNING: the deferral of claim #{i} "
                f"({new_claims[i].ctype}) is not honoured: it graded failed, and "
                f"a witnessed failure is never set aside — it counts toward this "
                f"verdict",
                file=sys.stderr,
            )
            return
        deferred[i] = requested[i]

    for i, r in enumerate(results):
        if r is not None:
            _honour(i)
    # The retired attempts are dropped from the pool here rather than marked on
    # the result: `superseded_by` on a GradeResult is verify-side, and the seal
    # holds the authoritative mapping already. Deferred claims likewise: they
    # are not part of this commit, so no live conjunction may resolve to one.
    siblings = [
        r
        for i, r in enumerate(results)
        if r is not None and i not in superseded and i not in deferred
    ]
    for i in conjunctions:
        # A retired conjunction is graded as the record of its own declaration,
        # against the claims standing THEN; the live one against the window as
        # sealed. `verify` makes the same split, so the two agree.
        if i in superseded:
            results[i] = grade(
                new_claims[i], tree, events, repo, ledger_objects,
                siblings=pool_as_declared(results, i), as_of=i,
            )
            continue
        results[i] = grade(
            new_claims[i], tree, events, repo, ledger_objects, siblings=siblings
        )
    for i in conjunctions:
        _honour(i)

    _gc_durable_copy(session, results)

    # Secrets pass. The export domain is compiled FIRST so the scan runs over
    # the bytes that would actually be published — claim labels and delta paths
    # included, which the argv+blobs scan never covered. Nothing is written
    # until this clears: a blocked seal must leave the watermark and the note
    # exactly where they were, which is what makes retrying one free.
    #
    # The two fields absent here are the two this pass GENERATES —
    # `secrets_override` and `secrets` — and they are the scan's own counters,
    # versions and booleans, never operator- or command-authored text. Every
    # field that carries content from outside is in these bytes, and a field
    # added later is in them too, without anyone remembering to add it. That is
    # why the claim window is here even though it is two integers this function
    # computed: the rule is "the published bytes are the scanned bytes", and a
    # field exempted because it looked harmless is how that rule stops holding.
    #
    # Compiling the export domain also REDACTS it, and the findings that come
    # back are what the gate blocks on. A field cannot be blocked-but-published
    # (the label bug) or published-but-unscanned, because one pass does both.
    redacted = [
        _redact_result(
            r,
            session,
            entries,
            claim_index=i,
            superseded_by=superseded.get(i),
            deferred=deferred.get(i),
        )
        for i, r in enumerate(results)
    ]
    claims_payload = [rc.payload for rc in redacted]
    field_findings = [f for rc in redacted for f in rc.findings]
    field_bytes = sum(rc.bytes_scanned for rc in redacted)
    # The authority block is published, so it is scanned and redacted by the same
    # pass, on the same rule as the claim fields above.
    authority_payload, authority_findings, authority_bytes = _redact_authorities(
        bound_authority
    )
    field_findings.extend(authority_findings)
    field_bytes += authority_bytes
    coverage = _coverage_statement(session)
    export_bytes = canonical_json(
        {
            "version": MANIFEST_VERSION,
            "commit": commit,
            "tree": tree,
            "claims": claims_payload,
            "coverage": coverage,
            "claims_from": watermark,
            "claims_to": len(all_claims),
            "authority": authority_payload,
        }
    )
    scan = _scan_for_secrets(
        session, results, export_bytes, field_findings, field_bytes
    )
    if scan.blocking and not allow_secrets:
        raise redact.SecretsBlocked(scan.blocking)
    _warn_unblocked_secrets(scan)

    # `secrets_override` keeps its exact v0.1 meaning: "this seal would have
    # been refused and the operator overrode it". The set that would refuse is
    # the blocking set, which is what `findings` denoted before tiering existed.
    overridden = bool(scan.blocking) and allow_secrets
    manifest = Manifest(
        version=MANIFEST_VERSION,
        commit=commit,
        tree=tree,
        claims=claims_payload,
        coverage=coverage,
        secrets_override=overridden,
        secrets=scan.to_dict(overridden),
        claims_from=watermark,
        claims_to=len(all_claims),
        authority=authority_payload,
    )

    # Publication and the watermark are one atomic pair. A published note with
    # no watermark re-seals every earlier claim forever (the watermark is what
    # scopes a seal); a watermark with no published note reports evidence that
    # was never written. Nothing is recorded until the note is on the commit,
    # and if recording fails the note goes back to what it was.
    prior_note = _read_note(repo, commit) if write_notes else None
    if write_notes:
        _refuse_narrowing_reseal(commit, prior_note, manifest, reseal)
        _attach_note(repo, commit, manifest)

    # Everything after publication runs inside the rollback. A caller-supplied
    # bundle path is the likeliest failure in this function, and an exception
    # escaping here would leave the note published with no watermark -- exactly
    # the state the pair above exists to prevent.
    try:
        if bundle_path is not None:
            Path(bundle_path).write_bytes(manifest.to_json())
        # Advance the seal watermark (append-only, like everything in the ledger).
        _record_seal(session, commit, tree, len(all_claims))
    except Exception as exc:
        raise ManifestError(
            f"seal aborted: no watermark was recorded; "
            f"{_rollback_note(repo, commit, prior_note, write_notes)}; cause: {exc}"
        )

    return manifest


# A chain fault is not a grade any claim can carry; it is a statement about the
# ledger every grade was read out of. It dominates the verdict for that reason.
CHAIN_BROKEN = "chain-broken"

# The two chain states that are faults. `empty` and `absent` are not: a missing
# or empty ledger is a witness-availability fact, already reported per claim as
# `witness-unavailable`, and calling it tamper would make every verify against
# an archived ledger look like an attack.
_CHAIN_FAULTS = ("broken", "unverifiable")


@dataclass
class VerifyReport:
    commit: str
    tree: str
    resolved_by: str  # "commit" | "tree-fallback" | "none"
    results: list[GradeResult]
    coverage: dict
    secrets_override: bool = False
    notes_skipped: int = 0  # notes the tree fallback could not parse at all
    # The live ledger's chain state. Defaults to "absent" rather than "intact":
    # a report built without consulting a ledger has not checked the chain, and
    # saying "intact" there would be the same silent lie an unregistered grade
    # is in render.py.
    chain_status: str = "absent"  # intact | broken | unverifiable | empty | absent
    chain_broken_index: Optional[int] = None  # set only when status is "broken"
    chain_reason: str = ""
    # Whether environment drift REFUSES rather than reports. Off by default:
    # drift is a statement about this machine now, not about whether the
    # recorded command ran, so making it fail --strict silently would flip green
    # units red on routine noise. The flag is recorded on the report so a reader
    # can tell which of the two verdicts they are looking at.
    require_env_match: bool = False
    # The authorities the note says this seal cited, as published. Record, never
    # verdict: an authority does not enter `worst_status` or `all_verified`, and
    # it cannot make a red note green. `cited` attests that a file with that
    # digest was cited — not that anyone approved anything — which is why it
    # grades nothing and only renders.
    authority: list = field(default_factory=list)

    @property
    def chain_faulted(self) -> bool:
        return self.chain_status in _CHAIN_FAULTS

    @property
    def live_results(self) -> list:
        """The results the verdict is computed over: everything not superseded.

        A superseded result is record, not verdict — a claim a later claim in the
        same seal window retired. It stays in ``results``, keeps its grade and
        reason verbatim, and renders; it just does not vote.
        """
        return [r for r in self.results if not (r.is_superseded or r.is_deferred)]

    @property
    def deferred_count(self) -> int:
        """How many results the operator set aside from this commit's verdict.

        Record, not verdict, like a superseded result — and counted on both human
        surfaces for the same reason: a deferral is visible or it is a deletion.
        """
        return sum(1 for r in self.results if r.is_deferred and not r.is_superseded)

    @property
    def superseded_count(self) -> int:
        """How many results are retained as record and excluded from the verdict.

        Printed on both human surfaces. Every retry at the same gate is kept and
        counted, so "claim until it goes green" is VISIBLE rather than prevented
        — which is the honest bound, and strictly better than the invisible
        truncation it replaces.
        """
        return sum(1 for r in self.results if r.is_superseded)

    @property
    def worst_status(self) -> str:
        """Worst grade present — drives the verdict and the CI exit code."""
        # A broken chain dominates every grade, including "empty": the grades
        # below it were read out of a ledger that does not recompute, so none of
        # them is a statement anyone should act on.
        if self.chain_faulted:
            return CHAIN_BROKEN
        # Read from claims.py rather than repeated here: a conjunction grades as
        # the worst of its conjuncts under this same order, and two copies of it
        # could disagree about which grade is worse.
        order = GRADE_ORDER_WORST_FIRST
        present = {r.grade for r in self.live_results}
        if not present:
            # "no results at all" and "results, every one of them superseded"
            # are different facts and must not share a word. The first is an
            # unsealed commit. The second is a window that declared claims and
            # retired all of them, which has nothing left to verify — so it
            # grades `unknown`, never `empty` (which renders as NO CLAIMS) and
            # never anything the strict set accepts.
            return "empty" if not self.results else "unknown"
        for status in order:
            if status in present:
                return status
        return "unknown"

    @property
    def all_verified(self) -> bool:
        # Membership is deliberately NOT widened. `witness-unavailable` reports
        # a grade this run did not check, so admitting it here would make
        # --strict pass on evidence nobody has seen.
        #
        # Environment drift subtracts from this set ONLY under
        # --require-env-match. `incomparable` never does, under either mode: it
        # is the state every archived v1 note lands in, and refusing on it would
        # turn "this note predates the current fingerprint" into a failure.
        #
        # Superseded results are excluded — they are record, not verdict — and
        # the NON-EMPTINESS check is over the surviving set for that reason.
        # `all([])` is True, so filtering without re-checking would make a window
        # whose every claim was retired verify vacuously green: a green verdict
        # over zero live claims, which is the exact shape of overclaiming this
        # tool exists to prevent.
        if self.chain_faulted:
            return False
        live = self.live_results
        if not live:
            return False
        for r in live:
            if r.grade not in ("tree-exact", "scope-exact"):
                return False
            if self.require_env_match and r.env_status == ENV_DRIFT:
                return False
        return True

    @property
    def env_counts(self) -> dict:
        """How the sealed environment fingerprints compared, by state.

        Always all four keys, including zeros: "0 drifted" and "not checked"
        are different facts, and a counter that disappears when it is zero
        cannot say the first one.

        Over the live set, like every other header counter: these gloss the
        verdict, and a denominator that silently included retired claims would
        not add up against the one beside it.
        """
        counts = {
            ENV_MATCH: 0,
            ENV_DRIFT: 0,
            ENV_INCOMPARABLE: 0,
            ENV_NOT_RECORDED: 0,
        }
        for r in self.live_results:
            counts[r.env_status] = counts.get(r.env_status, 0) + 1
        return counts

    @property
    def env_drift_count(self) -> int:
        return self.env_counts[ENV_DRIFT]

    @property
    def evidence_bound_count(self) -> int:
        """Claims whose verdict was checked against the entry the seal named.

        The complement is not a failure: a v1 note carries no binding to check,
        so its claims are regraded by index exactly as they always were. The
        counter exists so a reader can tell the two apart at a glance.

        Over the live set, for the same reason as ``env_counts``.
        """
        return sum(1 for r in self.live_results if r.evidence_bound)

    @property
    def total(self) -> int:
        """Entries in the RECORD, superseded ones included.

        The human surfaces count the live set instead — the verdict's
        denominator has to be the set the verdict was computed over — and print
        ``superseded_count`` beside it. This stays the record's size because
        that is what a caller counting what the note holds is asking for.
        """
        return len(self.results)


def verify(
    session: Session,
    repo: Path,
    commitish: str = "HEAD",
    require_env_match: bool = False,
) -> VerifyReport:
    """Resolve and re-grade a manifest for ``commitish``.

    Resolves by commit id, then by tree id (survives amend/rebase). Degrades a
    claim to unknown ("referenced object gc'd") rather than erroring.

    The sealed environment fingerprint is compared against this process's, once
    per verify. That comparison is ACROSS TIME, which is the only axis on which
    it says anything: comparing the fingerprints within a claim's own events is
    vacuous, because every claim didrun's CLI can declare binds exactly one
    event and one event trivially agrees with itself. Drift is reported and does
    not change the verdict unless ``require_env_match`` is set.

    A claim the note bound to a specific recorded entry is only regraded when
    the live ledger still holds that entry; otherwise the sealed grade is
    reported as ``witness-unavailable`` and --strict refuses it. This detects
    ACCIDENT AND DRIFT on a published note — an archived, rebuilt or replaced
    ledger. It is not a forger barrier: whoever can substitute a ledger can
    regenerate its chain and re-run claim+seal to mint fresh hash-bound claims
    (ledger.py's declared non-guarantee, and docs/TRUST_MODEL.md).

    The chain is checked BEFORE any grading and a fault dominates the verdict:
    a ledger whose links do not recompute cannot support a statement about
    anything it holds. Until now ``verify_chain`` had exactly one caller and it
    was ``show --session``, so a forked or mid-file-rewritten ledger certified
    green under --strict. ``seal`` still does not consult the chain; that is a
    separate policy decision, deliberately out of scope here.
    """
    repo = Path(repo)
    commit = _rev(repo, commitish)
    tree = gitplumbing.commit_tree(repo, commitish) if commit else None
    chain_status, chain_index, chain_reason = _chain_state(session)

    manifest, resolved_by, notes_skipped = _resolve_manifest(repo, commit, tree)
    if manifest is None:
        return VerifyReport(
            commit=commit or "",
            tree=tree or "",
            resolved_by="none",
            results=[],
            coverage={},
            notes_skipped=notes_skipped,
            chain_status=chain_status,
            chain_broken_index=chain_index,
            chain_reason=chain_reason,
            require_env_match=require_env_match,
        )

    # Re-grade the MANIFEST'S OWN claims against its sealed tree (deterministic
    # replay). The manifest is the only thing verify reads besides the repo —
    # the source-of-truth rule. Reading the live session claims file
    # here would let later, unsealed claims leak into an old commit's verdict.
    entries = list(session.entries())
    events = [e.event for e in entries]
    ledger_objects = session.blobs.root
    # Once per verify, not once per claim: it is a property of this process, and
    # reading the umask inside it is a read-modify-write (capture.process_umask).
    current_fingerprint = capture.env_fingerprint()

    def _graded(
        position: int, stored: dict, claim: Claim, siblings=None, as_of=None
    ) -> GradeResult:
        result = _verify_claim(
            stored, claim, manifest, entries, events, repo, ledger_objects,
            siblings, as_of,
        )
        # Assigned around the ladder for the same reason as the two below: which
        # claim retired this one is a fact about the seal window, not something
        # the evidence earns.
        result.superseded_by = _superseded_by(stored, position, manifest.claims)
        # Around the ladder for the same reason, and validated the same way: the
        # mark subtracts from the verdict, so it is dropped (and the claim
        # counts) when malformed, when the claim was retired anyway, and when
        # the claim grades failed — which a deferral never sets aside.
        if not result.is_superseded and result.grade != GRADE_FAILED:
            result.deferred = _deferral_mark(stored)
        # Assigned around the ladder, like witness-unavailable: the environment
        # comparison is a fact about this run, not a grade the evidence earns.
        # It is set on EVERY path, including witness-unavailable — the sealed
        # fingerprint is in the note whether or not the ledger still holds the
        # entry it names.
        result.env_status, result.env_reason = _env_comparison(
            stored.get("evidence"), current_fingerprint
        )
        return result

    # Two passes, the same shape `seal` grades in. A conjunction is graded
    # against its siblings' results FROM THIS NOTE, so pass one grades every
    # ordinary claim and pass two grades the conjunctions over what pass one
    # produced. Regrading a conjunction in one pass with no siblings resolves
    # every conjunct to "no match" and verifies `unknown` — so a note that
    # sealed green would fail --strict, which is this restructure's whole point.
    # Resolving them against the live claims.jsonl instead would be worse still:
    # it breaks the source-of-truth rule above and lets a later, unsealed claim
    # change an old commit's verdict.
    results: list = [None] * len(manifest.claims)
    deferred: list = []
    for position, c in enumerate(manifest.claims):
        claim = _stored_claim(c, position)
        if claim.ctype == CONJUNCTION:
            deferred.append((position, c, claim))
            continue
        results[position] = _graded(position, c, claim)
    # Superseded pass-one results are already marked, and grade_conjunction drops
    # them from the pool: a retired attempt shares its label with the claim that
    # replaced it, so counting it would make that name ambiguous.
    siblings = [r for r in results if r is not None]
    for position, c, claim in deferred:
        # The seal's split, read off the note: a retired conjunction regrades
        # as the record of its own declaration (claims.pool_as_declared).
        if _superseded_by(c, position, manifest.claims) is not None:
            results[position] = _graded(
                position, c, claim, pool_as_declared(results, position), position
            )
            continue
        results[position] = _graded(position, c, claim, siblings)
    return VerifyReport(
        commit=manifest.commit,
        tree=manifest.tree,
        resolved_by=resolved_by,
        results=results,
        coverage=manifest.coverage,
        secrets_override=manifest.secrets_override,
        notes_skipped=notes_skipped,
        chain_status=chain_status,
        chain_broken_index=chain_index,
        chain_reason=chain_reason,
        require_env_match=require_env_match,
        # Entries that are not objects are dropped: the block is rendered, and a
        # renderer walking a string as if it were a record is how a malformed
        # note becomes a traceback out of `verify`.
        authority=[a for a in manifest.authority if isinstance(a, dict)],
    )


def _env_comparison(evidence, current: str) -> tuple[str, str]:
    """Compare the fingerprint the seal recorded against this process's.

    Four outcomes, and three of them are refusals to compare. The refusals are
    the reason this is safe to add to a tool with sealed evidence already in the
    world: a note that bound no fingerprint, a bare v0.1 digest, and a
    fingerprint written under a different FINGERPRINT_VERSION are all cases
    where the two strings are not measurements of the same thing. Reporting any
    of them as drift would make every note published before this unit look like
    the environment moved.

    Only the GATE portion is compared. A `path=` difference is appended as an
    advisory to whatever the gate said — never promoted to drift, and never able
    to turn a match into one.
    """
    if not isinstance(evidence, dict):
        return (
            ENV_NOT_RECORDED,
            "this note bound no environment fingerprint to the claim",
        )
    sealed = evidence.get("env_fingerprint")
    if not isinstance(sealed, str) or not sealed:
        return (
            ENV_NOT_RECORDED,
            "the sealed evidence block carries no environment fingerprint",
        )

    sealed_version = capture.fingerprint_version(sealed)
    current_version = capture.fingerprint_version(current)
    if sealed_version is None:
        return (
            ENV_INCOMPARABLE,
            "the sealed fingerprint is an unversioned v0.1 digest, which is "
            "incomparable with this one — not evidence that anything drifted",
        )
    if current_version is None or sealed_version != current_version:
        return (
            ENV_INCOMPARABLE,
            f"the sealed fingerprint is version {sealed_version} and this didrun "
            f"computes version {current_version}; different key sets are "
            "incomparable, not drifted",
        )

    sealed_gate = capture.fingerprint_gate(sealed)
    current_gate = capture.fingerprint_gate(current)
    if sealed_gate is None or current_gate is None:
        return (
            ENV_INCOMPARABLE,
            "a fingerprint carries no readable gate portion to compare",
        )

    advisory = _path_advisory(sealed, current)
    if sealed_gate == current_gate:
        return ENV_MATCH, advisory
    drifted = (
        f"environment changed since seal (sealed gate {sealed_gate}, "
        f"now {current_gate})"
    )
    return ENV_DRIFT, f"{drifted}; {advisory}" if advisory else drifted


def _path_advisory(sealed: str, current: str) -> str:
    """PATH drift, as text. Never a gate, never drift, never a verdict.

    PATH varies with terminal tab, direnv, `nix develop`, tmux and homebrew
    shellenv ordering, so gating on it produces a refusal that fires in a new
    shell and is ignored within a week. It is recorded as its own digest so the
    variation stays visible to a reader who is looking for it.

    Digests, not values: what changed is not said, because saying it would put a
    developer machine's PATH in a published note.
    """
    sealed_path = capture.fingerprint_path_digest(sealed)
    current_path = capture.fingerprint_path_digest(current)
    if not sealed_path or not current_path or sealed_path == current_path:
        return ""
    return (
        f"PATH differs (sealed path={sealed_path}, now path={current_path}) — "
        "recorded, not gated"
    )


def _chain_state(session: Session) -> tuple[str, Optional[int], str]:
    """The live ledger's chain state, as (status, broken_index, reason).

    ``verify_chain_detail`` reports a log with no records as ``empty`` whether
    the file is missing or present-and-zero-length. Those are different facts
    here: a missing log is an ARCHIVED (or never-created) ledger, which P1.2
    already reports honestly per claim as ``witness-unavailable``, and reporting
    it as a chain state at all would put a ledger-integrity sentence in front of
    a reader whose ledger is simply somewhere else.

    ``broken_index`` is populated only for ``broken``. An unverifiable entry has
    no broken index — nothing was shown not to recompute; this binary could not
    recompute it — so its index travels in the reason instead, which is where
    ``verify_chain_detail`` already put it.

    A log this binary cannot even READ — a torn line, a record whose event body
    carries keys the schema rejects — is ``unverifiable`` rather than a
    traceback. Two reasons: the package's stated posture is that evidence it
    cannot read is a graded refusal, not a crash (``cmd_verify``'s exit 2,
    ``_regrade``'s fallback); and this runs BEFORE the manifest is resolved, so
    without it a torn ledger would start crashing ``verify`` on commits with no
    sealed note at all — a path that never read the ledger before.
    """
    try:
        verdict = session.verify_chain_detail()
    except Exception as exc:
        # The message is structural (a parse position, a rejected key name),
        # never a ledger line: nothing here echoes recorded content.
        return "unverifiable", None, f"the ledger could not be read: {exc}"
    status = verdict.status
    if status == "empty" and not session.log_path.exists():
        status = "absent"
    return (
        status,
        verdict.first_broken_index if status == "broken" else None,
        verdict.reason,
    )


def _verify_claim(
    stored: dict,
    claim: Claim,
    manifest: Manifest,
    entries: list,
    events: list,
    repo: Path,
    ledger_objects: Optional[Path],
    siblings: Optional[list] = None,
    as_of: Optional[int] = None,
) -> GradeResult:
    """Grade one sealed claim, checking the note's binding to its evidence first.

    Two paths, and the split is what protects notes published before v0.2:

    - **No evidence block** — a v1 note. Regrade exactly as v0.1 regraded it,
      unbound. There is nothing to check: the note never recorded which entry
      backed the claim, and inventing a binding for it after the fact would be a
      verdict about evidence this run cannot identify.
    - **An evidence block** — check it before grading anything. If the live
      ledger cannot supply that entry, report the SEALED grade under
      ``witness-unavailable`` rather than recomputing a fresh verdict from
      whatever the ledger holds now. That silent recomputation is the defect
      this whole unit exists to close.

    A conjunction takes the first path: it binds no event, so the seal wrote it
    no evidence block and there is no binding to check. ``siblings`` is what it
    is graded against, and it is forwarded unread on every other path, as is
    ``as_of`` (a retired conjunction's own declaration point).
    """
    evidence = stored.get("evidence")
    if not isinstance(evidence, dict):
        return _regrade(claim, manifest, events, repo, ledger_objects, siblings, as_of)

    sealed_grade = stored.get("grade")
    idx = evidence.get("event_index")
    problem = _witness_problem(entries, idx, evidence.get("entry_hash"))
    if problem is not None:
        return GradeResult(
            claim,
            GRADE_WITNESS_UNAVAILABLE,
            reason=(
                f"sealed as {sealed_grade} at commit {manifest.commit[:12]}; "
                f"witness ledger unavailable ({problem})"
            ),
            supporting_event_index=idx if _is_index(idx) else None,
            sealed_grade=sealed_grade,
        )

    result = _regrade(claim, manifest, events, repo, ledger_objects, siblings, as_of)
    result.evidence_bound = True
    result.sealed_grade = sealed_grade
    return result


def _is_index(value) -> bool:
    """A real integer index. ``bool`` is an ``int`` subclass and is not one."""
    return isinstance(value, int) and not isinstance(value, bool)


def _stored_claim(entry, position: int) -> Claim:
    """Parse one stored claim entry, refusing rather than raising out of verify.

    ``Claim.__post_init__`` is the claim vocabulary's gate, and it raises
    ``ClaimError`` — which is not a ``ManifestError``, so it escaped ``verify``
    and the CLI's handler as an uncaught traceback. docs/COMPAT.md's "Version 3"
    section names this exact shape as the vocabulary break an OLD reader hits on
    a v3 note, and the ``MANIFEST_VERSION`` bump is what steers such a reader
    into a version refusal first. This closes the same hole from the other end:
    THIS reader, meeting a claim type it cannot parse in a note whose version it
    accepts, now also refuses instead of crashing.

    A whole-manifest refusal, not a per-claim ``unknown``: grading around the gap
    would print a verdict over the claims this binary happened to understand,
    which docs/COMPAT.md rejects in as many words as the worse of the two
    options. The position is named because a note has many claims and "one of
    them is unreadable" is not an actionable sentence.
    """
    if not isinstance(entry, dict):
        raise ManifestFormatError(
            f"claim entry {position} is a {type(entry).__name__}, not an object"
        )
    stored = entry.get("claim")
    if not isinstance(stored, dict):
        raise ManifestFormatError(
            f"claim entry {position} carries no claim object"
        )
    try:
        return Claim.from_dict(stored)
    except (ClaimError, TypeError, ValueError) as exc:
        # ClaimError is the vocabulary gate. TypeError/ValueError cover the field
        # shapes it never gets to look at — `tuple(d.get("event_indices"))` on an
        # int raises before __post_init__ runs at all.
        raise ManifestFormatError(f"claim entry {position} is unreadable: {exc}") from exc


def _claim_key(entry) -> Optional[tuple]:
    """The (ctype, label) identity of a stored claim entry, or None."""
    if not isinstance(entry, dict):
        return None
    claim = entry.get("claim")
    if not isinstance(claim, dict):
        return None
    return claim.get("ctype"), claim.get("label")


def live_claims(claims: list) -> list:
    """A manifest's claim entries that no later claim in the window retired and
    that the operator did not defer.

    The one definition of "live", shared by the verdict (``verify``) and by the
    seal's own summary line, so the two cannot report different denominators for
    the same note.
    """
    return [
        c
        for i, c in enumerate(claims)
        if _superseded_by(c, i, claims) is None and _deferral_mark(c) is None
    ]


def deferred_claims(claims: list) -> list:
    """A manifest's claim entries set aside by a valid deferral mark (and not
    retired, which would make the mark moot). Read by the same rule as verify."""
    return [
        c
        for i, c in enumerate(claims)
        if _superseded_by(c, i, claims) is None and _deferral_mark(c) is not None
    ]


def _superseded_by(stored: dict, position: int, claims: list) -> Optional[int]:
    """The entry that retired this one, or None — validated, not trusted.

    A supersession mark SUBTRACTS a claim from the verdict, so it is the one
    published field that can turn a red note green. It is therefore checked
    against the definition that produced it rather than taken at face value: the
    target must be a real forward index into this note's own claim list, and it
    must carry the same ``(ctype, label)`` the seal supersedes by.

    A mark that fails any of those is dropped, which counts the claim toward the
    verdict — the direction that refuses rather than the one that excuses. This
    is not a forgery barrier and does not pretend to be one: whoever can rewrite
    a note can rewrite a grade directly (docs/TRUST_MODEL.md). It is the same
    fail-closed reading didrun applies to every other field it did not compute
    in this process.
    """
    mark = stored.get("superseded_by")
    if not _is_index(mark):
        return None
    if not (position < mark < len(claims)):
        return None
    key = _claim_key(stored)
    if key is None or key != _claim_key(claims[mark]):
        return None
    return mark


def _witness_problem(entries: list, idx, recorded_hash) -> Optional[str]:
    """Why the live ledger cannot supply the sealed evidence, or None.

    Two mechanisms, and they are not the same fact. The ledger may be too SHORT
    to hold that index — the archived-ledger case, which an index-keyed regrade
    already noticed, if only by grading everything unknown. Or it may be long
    enough and hold a DIFFERENT entry there, which an index-keyed regrade
    reports as a confident verdict about evidence it never saw. The second is
    the dangerous one, so the reason names which happened.

    The comparison is against the entry's STORED hash. Whether that hash is the
    one the entry's own body recomputes to is the chain check's question, not
    this one; conflating them would report a ledger this binary merely cannot
    recompute as evidence that went missing.
    """
    if not _is_index(idx):
        return "the sealed evidence block names no usable event index"
    if not (0 <= idx < len(entries)):
        return (
            f"recorded event index {idx} is out of range "
            f"(the live ledger holds {len(entries)} event(s))"
        )
    if not isinstance(recorded_hash, str) or not recorded_hash:
        return f"the sealed evidence block carries no entry hash for index {idx}"
    if entries[idx].entry_hash != recorded_hash:
        return f"entry hash mismatch at index {idx}"
    return None


def _regrade(
    claim: Claim,
    manifest: Manifest,
    events: list,
    repo: Path,
    ledger_objects: Optional[Path],
    siblings: Optional[list] = None,
    as_of: Optional[int] = None,
) -> GradeResult:
    try:
        return grade(
            claim, manifest.tree, events, repo, ledger_objects, siblings, as_of=as_of
        )
    except Exception as exc:  # object gc'd or unreadable → unknown, not crash
        return GradeResult(claim, "unknown", reason=f"regrade failed: {exc}")


# --- claim persistence (declared claims live in the ledger dir) --------------

def _claims_path(session: Session) -> Path:
    return session.root / "claims.jsonl"


def _seals_path(session: Session) -> Path:
    return session.root / "seals.jsonl"


def _last_seal_watermark(session: Session) -> int:
    """Index into the claims list where the previous seal stopped (0 if none)."""
    path = _seals_path(session)
    if not path.exists():
        return 0
    watermark = 0
    for line in path.read_text(encoding="ascii").splitlines():
        line = line.strip()
        if line:
            watermark = json.loads(line).get("claims_watermark", watermark)
    return watermark


def _seal_count(session: Session) -> int:
    """How many seals this ledger has recorded — the authority expiry clock.

    Seals, not wall time. A time-based TTL would put a clock in the trust path,
    which is a hard invariant this package does not break, and it would make an
    authority's liveness depend on how long a build took. A seal is the
    transition an authority is cited for, so counting them is the measure that
    means something.
    """
    path = _seals_path(session)
    if not path.exists():
        return 0
    return sum(
        1 for line in path.read_text(encoding="ascii").splitlines() if line.strip()
    )


def _record_seal(session: Session, commit: str, tree: str, claims_watermark: int) -> None:
    # Private-append: these carry operator-authored labels and commit ids into
    # the secret-bearing ledger directory, and a plain open() would create them
    # 0666 & ~umask. canonical_json is already ascii bytes, so the byte written
    # is unchanged from the text-mode open this replaced.
    #
    # Under the ledger's append lock for the same reason as declare_claim below:
    # a seal line carries a commit id and a watermark other seals read back, so a
    # torn one loses the watermark and re-seals every claim.
    with _append_lock(session.root):
        with _open_private_append(_seals_path(session)) as fh:
            fh.write(
                canonical_json(
                    {"commit": commit, "tree": tree, "claims_watermark": claims_watermark}
                )
                + b"\n"
            )


def declare_claim(session: Session, claim: Claim) -> None:
    # O_APPEND is atomic only below PIPE_BUF, and a claim line is not bounded by
    # that: every declared pathspec lengthens it. Two concurrent `didrun claim`
    # invocations could therefore interleave into one unparseable record, so this
    # takes the same ledger-wide lock the event append takes. Cheap by
    # construction — one short local write, never a child process.
    with _append_lock(session.root):
        with _open_private_append(_claims_path(session)) as fh:
            fh.write(canonical_json(claim.to_dict()) + b"\n")


def _load_claims(session: Session) -> list[Claim]:
    path = _claims_path(session)
    if not path.exists():
        return []
    claims = []
    for line in path.read_text(encoding="ascii").splitlines():
        line = line.strip()
        if line:
            claims.append(Claim.from_dict(json.loads(line)))
    return claims


# --- deferral: setting one unsealed claim aside from the next verdict ---------
#
# A seal window is every claim since the last seal, so a claim declared over
# work that never reached this commit — an interrupted unit's draft — rides into
# an unrelated unit's seal and grades stale there. The grade is right and the
# window is wrong for that one claim. A deferral is the operator saying so, with
# a reason, in an append-only record:
#
# - it subtracts from the VERDICT, never from the RECORD: the claim is graded and
#   published as usual and marked `deferred` with the reason (`_redact_result`);
# - it binds one claim INSTANCE by its index in claims.jsonl, never a label going
#   forward, so re-declaring the gate makes a claim that votes;
# - it is never honoured for a WITNESSED FAILURE. A command that exited nonzero
#   is evidence against the claim, and setting it aside would be the cheapest
#   path to green there is. Refused at declaration, and re-checked at seal and
#   at verify against the grade, because a record file and a note can both be
#   edited by hand.
#
# Kept in its own file rather than in claims.jsonl: an older binary loads every
# line of claims.jsonl as a Claim and would raise on a deferral record, while it
# ignores a file it does not know — and then counts the claim, which is the
# fail-closed direction.

def _deferrals_path(session: Session) -> Path:
    return session.root / "deferrals.jsonl"


def _load_deferrals(session: Session) -> list:
    """The deferral records, as written. A line this binary cannot read is
    skipped: a record nobody can parse defers nothing, so its claim votes."""
    path = _deferrals_path(session)
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="ascii").splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def _valid_reason(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _window_deferrals(session: Session, all_claims: list, watermark: int) -> dict:
    """{window position: reason} for the records that name a claim in this window.

    A record names a claim by absolute index AND by the (ctype, label) it had
    when deferred; a record whose index is outside the window, or whose claim
    no longer carries that identity, defers nothing.
    """
    out: dict = {}
    for record in _load_deferrals(session):
        idx = record.get("claim_index")
        if not _is_index(idx) or not (watermark <= idx < len(all_claims)):
            continue
        claim = all_claims[idx]
        if (record.get("ctype"), record.get("label")) != (claim.ctype, claim.label):
            continue
        if not _valid_reason(record.get("reason")):
            continue
        out.setdefault(idx - watermark, record["reason"])
    return out


def declare_deferral(
    session: Session, label: str, reason: str, ctype: Optional[str] = None
) -> dict:
    """Set the live, unsealed claim labelled ``label`` aside from the next verdict.

    Returns the record written, with ``position`` (the claim's index in the
    next seal's window, which is the `claim #N` every surface prints) added.
    Raises ``ManifestError``, writing nothing, when the deferral cannot be
    honoured — see the section comment above for why each refusal exists.
    """
    if not _valid_reason(reason):
        raise ManifestError("--defer needs --reason: a deferral with no reason is a silent drop")
    all_claims = _load_claims(session)
    watermark = _last_seal_watermark(session)
    window = all_claims[watermark:]
    latest: dict = {}
    for pos, claim in enumerate(window):
        latest[(claim.ctype, claim.label)] = pos
    candidates = sorted(
        pos for (t, lbl), pos in latest.items()
        if lbl == label and (ctype is None or t == ctype)
    )
    named = f"{ctype} {label!r}" if ctype else repr(label)
    if not candidates:
        if any(
            c.label == label and (ctype is None or c.ctype == ctype)
            for c in all_claims[:watermark]
        ):
            raise ManifestError(
                f"claim {named} was already sealed into an earlier note, which is "
                f"published; only an unsealed claim can be deferred"
            )
        raise ManifestError(
            f"no unsealed claim {named} in the current seal window "
            f"(claims [{watermark},{len(all_claims)}))"
        )
    if len(candidates) > 1:
        types = ", ".join(window[pos].ctype for pos in candidates)
        raise ManifestError(
            f"{named} names {len(candidates)} live claims ({types}); pass the "
            f"claim type to choose one"
        )
    pos = candidates[0]
    claim = window[pos]
    absolute = watermark + pos
    if any(r.get("claim_index") == absolute for r in _load_deferrals(session)):
        raise ManifestError(f"claim #{pos} {claim.ctype} {claim.label!r} is already deferred")
    events = session.events()
    for idx in claim.event_indices:
        if 0 <= idx < len(events) and events[idx].exit_code not in (None, 0):
            raise ManifestError(
                f"claim #{pos} {claim.ctype} {claim.label!r} is bound to event "
                f"{idx}, which exited {events[idx].exit_code}: a witnessed failure "
                f"is evidence against the claim, and deferral never takes one out "
                f"of a verdict. Fix it, re-run, and re-claim to supersede it"
            )
    record = {
        "claim_index": absolute,
        "ctype": claim.ctype,
        "label": claim.label,
        "reason": reason,
        "declared_at_event": len(events) - 1,
    }
    with _append_lock(session.root):
        with _open_private_append(_deferrals_path(session)) as fh:
            fh.write(canonical_json(record) + b"\n")
    return dict(record, position=pos)


def _deferral_mark(stored: dict) -> Optional[str]:
    """The reason a note entry's ``deferred`` mark carries, validated, or None.

    Read the way ``superseded_by`` is read: a mark subtracts a claim from the
    verdict, so a malformed one is dropped and the claim counts. A mark on an
    entry whose sealed grade is ``failed`` is dropped for the same reason the
    seal never writes one there.
    """
    mark = stored.get("deferred")
    if not isinstance(mark, dict) or not _valid_reason(mark.get("reason")):
        return None
    if stored.get("grade") == GRADE_FAILED:
        return None
    return mark["reason"]


# --- operator authority ------------------------------------------------------
#
# didrun's thesis is that a claim with no witnessed event grades `unknown`. An
# out-of-band human authorisation is structurally a claim with no witnessed
# event, and `--allow-secrets` is the shipped instance: a bare argv flag stored
# as a bare boolean, with no principal, no basis, and no way for a reader to
# tell an authorised override from an agent that simply passed the flag.
#
# What this converts that into is narrow and is stated on every surface: "someone
# passed a flag citing an artifact with this digest, at this point in an
# append-only record". It is NOT evidence that a human approved anything — an
# agent can author its own authorisation artifact in one line. Signing is
# deferred (docs/TRUST_MODEL.md) and this does not close that gap; the honest
# anchor for a stronger tier is a key the agent cannot read.

# The scopes an authority may be cited for: the exceptional transitions, and only
# those. There is deliberately no scope for an ordinary seal — an authorisation
# required on the happy path becomes a rubber stamp within a week, which is
# exactly how `--allow-secrets`'s information content went to zero.
AUTHORITY_ALLOW_SECRETS = "allow-secrets"
AUTHORITY_RESEAL = "reseal"
AUTHORITY_SCOPES = (AUTHORITY_ALLOW_SECRETS, AUTHORITY_RESEAL)

# The grade a bound authority carries, in the same vocabulary as `tree-exact` and
# under the same rule: reported verbatim, never upgraded. `cited` never renders as
# "signed", "approved", "verified" or "authorized by".
AUTHORITY_GRADE = "cited"

# How the principal was established. One value, because there is exactly one
# mechanism: didrun read $USER, or the operator typed a name. Recorded as a field
# rather than left implicit so a reader cannot mistake it for an authenticated
# identity.
AUTHORITY_PRINCIPAL_BASIS = "self-asserted"

# Default TTL in seals when the operator names none. One, not unbounded: a
# standing grant is the shape `--allow-secrets` already had, and re-earning the
# citation per transition is the only thing that keeps it from routine-ising.
AUTHORITY_DEFAULT_TTL = 1

# The feature's honesty, as a constant that ships in the source and is printed on
# every surface that shows an authority — the terminal verdict, the HTML report,
# `authorize`'s own output, and the note itself. It lives here rather than only in
# the docs because a reader of a note or a verdict is not reading the docs, and
# `"grade": "cited"` with nothing beside it would be read as approval.
AUTHORITY_LIMITATION = (
    "cited authority: recorded that a file with this digest was cited for this "
    "scope. NOT a signature and NOT approval — didrun cannot tell who wrote it."
)

_DIGEST_CHUNK = 1 << 20


def _authority_path(session: Session) -> Path:
    return session.root / "authority.jsonl"


def _artifact_digest(path: Path) -> tuple:
    """(sha256 hex, byte count) for the cited artifact. Never its bytes.

    Chunked because an operator may cite a large file and there is no reason to
    hold it in memory. The digest is the only thing that leaves this function:
    an authorisation artifact is exactly the kind of file that carries a
    credential in passing, and the note it would ride into is the one artifact
    that leaves the machine.
    """
    digest = hashlib.sha256()
    total = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_DIGEST_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), total


def declare_authority(
    session: Session,
    artifact: Path,
    scope: str,
    label: str,
    principal: Optional[str] = None,
    expires_after_seals: Optional[int] = None,
) -> dict:
    """Record that a file with this digest was cited as the authority for a scope.

    Refuses a scope outside ``AUTHORITY_SCOPES``, an empty label, a TTL below
    one, and an artifact that does not exist or is empty. An empty file is
    refused rather than digested because its digest is a constant: every empty
    authorisation in the world shares it, so it distinguishes nothing and would
    be the one shape a fabricated citation could produce without a file.

    The path is recorded as the operator wrote it and is not resolved. A relative
    citation therefore stays relative, which keeps a home directory out of a
    published note when the operator cites one relatively; an absolute path is
    published as typed.
    """
    if scope not in AUTHORITY_SCOPES:
        raise ManifestError(
            f"unknown authority scope {scope!r}: didrun authorises only the "
            f"exceptional transitions ({', '.join(AUTHORITY_SCOPES)}). There is "
            f"no scope for an ordinary seal, and none will be added: an "
            f"authorisation required on the happy path becomes a rubber stamp."
        )
    if not label or not label.strip():
        raise ManifestError(
            "an authority needs a --label saying what is being authorised; "
            "an unlabelled citation records nothing a reader can act on"
        )
    ttl = AUTHORITY_DEFAULT_TTL if expires_after_seals is None else expires_after_seals
    if not _is_index(ttl) or ttl < 1:
        raise ManifestError(
            f"--expires-after-seals must be an integer >= 1 (got {ttl!r}); an "
            f"authority that expires after zero seals authorises nothing, and "
            f"there is no value meaning 'never'"
        )
    artifact = Path(artifact)
    if not artifact.is_file():
        raise ManifestError(
            f"cannot cite {artifact}: no such file (an authority cites an "
            f"artifact that exists, so the digest is of something a reviewer "
            f"can open)"
        )
    sha256, size = _artifact_digest(artifact)
    if size == 0:
        raise ManifestError(
            f"cannot cite {artifact}: the file is empty, and every empty file "
            f"has the same digest — it would distinguish nothing"
        )
    record = {
        "principal": (
            principal if principal is not None else os.environ.get("USER", "")
        ),
        "principal_basis": AUTHORITY_PRINCIPAL_BASIS,
        "artifact_path": str(artifact),
        "artifact_sha256": sha256,
        "artifact_bytes": size,
        "scope": scope,
        "label": label,
        "declared_at_index": _seal_count(session),
        "expires_after_seals": ttl,
    }
    # Same append discipline as claims and seals: 0600 at creation, under the
    # ledger-wide lock. A record line carries an operator-authored label and is
    # not bounded by PIPE_BUF, so two concurrent `didrun authorize` invocations
    # could otherwise interleave into one unparseable record.
    with _append_lock(session.root):
        with _open_private_append(_authority_path(session)) as fh:
            fh.write(canonical_json(record) + b"\n")
    return record


def _valid_authority(record) -> bool:
    """Whether a stored authority record is one this seal may read.

    ``authority.jsonl`` is a local, gitignored, unhashed file, exactly like
    ``claims.jsonl`` — so every field here arrived from a file rather than from
    this process, and gets the same validate-rather-than-trust reading that
    ``_superseded_by`` gets. Not a forgery barrier and not presented as one:
    whoever can write this file can write a well-formed record.
    """
    if not isinstance(record, dict):
        return False
    if record.get("scope") not in AUTHORITY_SCOPES:
        return False
    if not _is_index(record.get("declared_at_index")) or record["declared_at_index"] < 0:
        return False
    if not _is_index(record.get("expires_after_seals")) or record["expires_after_seals"] < 1:
        return False
    digest = record.get("artifact_sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        return False
    if any(c not in "0123456789abcdef" for c in digest):
        return False
    if not _is_index(record.get("artifact_bytes")) or record["artifact_bytes"] < 1:
        return False
    for key in ("principal", "artifact_path", "label"):
        if not isinstance(record.get(key), str):
            return False
    return True


def _load_authorities(session: Session) -> tuple:
    """Every readable authority record, plus how many were dropped.

    A record that does not validate is DROPPED. Dropping is the refusing
    direction: an authority grants permission, so ignoring a malformed one
    produces a refusal the operator can see and fix, while trusting it would
    produce a permission nobody granted. A torn tail therefore costs a
    citation, never a false one.
    """
    path = _authority_path(session)
    if not path.exists():
        return [], 0
    records = []
    dropped = 0
    for line in path.read_text(encoding="ascii", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            dropped += 1
            continue
        if _valid_authority(record):
            records.append(record)
        else:
            dropped += 1
    return records, dropped


def _bind_authorities(session: Session, scopes: tuple, seal_index: int) -> list:
    """The authorities this seal cites, graded ``cited``.

    Three conditions, every one of them fail-closed:

    * **Scope** — the record's scope is one this seal actually exercises. An
      ordinary seal exercises none and therefore binds none, which is what keeps
      an authority attached to exceptional transitions instead of becoming a line
      on every note.
    * **Not expired** — ``seal_index - declared_at_index < expires_after_seals``.
      The clock starts at the seal that follows the authorisation, so
      ``--expires-after-seals 1`` covers the next seal and not the one after.
    * **Not from the future** — a record may not name a seal generation that has
      not happened (``declared_at_index <= seal_index``). That is the guard
      against a record written or backdated by hand to cover seals it never saw.

    ``limitation``, ``grade`` and ``principal_basis`` are written into every
    bound entry from their SOURCE CONSTANTS so the note itself carries them,
    not just the surfaces that render it — and so a hand-edited
    ``authority.jsonl`` cannot dictate the three fields that state how much the
    citation is worth. ``principal_basis`` belongs in that set because it
    qualifies the principal: "self-asserted" is the only basis this version can
    establish, so it is the only basis it will publish.
    """
    records, dropped = _load_authorities(session)
    if dropped:
        print(
            f"didrun seal: WARNING: dropped {dropped} unreadable authority "
            f"record(s) from the ledger; they authorise nothing. A dropped "
            f"record is the refusing direction, so a scope that needed one is "
            f"refused rather than granted.",
            file=sys.stderr,
        )
    bound = []
    for record in records:
        if record["scope"] not in scopes:
            continue
        declared = record["declared_at_index"]
        if declared > seal_index:
            continue
        if seal_index - declared >= record["expires_after_seals"]:
            continue
        entry = dict(record)
        entry["grade"] = AUTHORITY_GRADE
        entry["limitation"] = AUTHORITY_LIMITATION
        entry["principal_basis"] = AUTHORITY_PRINCIPAL_BASIS
        bound.append(entry)
    return bound


def _require_authority(scopes: tuple, bound: list) -> None:
    """Refuse a transition whose scope no live cited authority covers.

    Default off, and it stays that way: making it default-on would put an
    authorisation on the happy path, which is the failure mode this whole design
    is shaped around. It exists for a CI gate that wants "a bare
    `--allow-secrets` is not enough", and it says nothing stronger than that —
    the authority it demands is still only a citation.
    """
    covered = {entry["scope"] for entry in bound}
    missing = [scope for scope in scopes if scope not in covered]
    if not missing:
        return
    raise ManifestError(
        "--require-authority: no live cited authority with scope "
        + ", ".join(repr(s) for s in missing)
        + f". Declare one with `didrun authorize --artifact <path> --scope "
        f"{missing[0]} --label \"<text>\"` and re-run. {AUTHORITY_LIMITATION}"
    )


# How `_redact_authorities` must treat every key a bound authority carries. The
# split is exhaustive BY CONSTRUCTION: the pass publishes a key only if it is
# named here, so a field added later is dropped rather than published unscanned,
# and `test_every_authority_field_is_classified` fails the moment
# `declare_authority` grows a field nobody classified.
#
# Enumerating the text fields by hand, with no check that the enumeration was
# complete, is exactly what published `principal` verbatim into a git note while
# the refusal message promised a redacted export. The enumeration is no longer
# allowed to be silently incomplete.
_AUTHORITY_TEXT_FIELDS = (
    # (field name, the FindingSource kind its content is scanned as)
    ("label", "label"),
    ("artifact_path", "pathspec"),
    # `--principal`, or `$USER` when that is absent. Outside text, exactly as
    # much as the label is, and published in the same JSON object.
    ("principal", "label"),
)

# Computed here, validated by `_valid_authority`, or pinned from a source
# constant by `_bind_authorities`. None of these can carry outside text, which
# is why they are published as-is — the reason is recorded per field because
# "this one is safe" is the claim that has to stay true.
_AUTHORITY_PASSTHROUGH_FIELDS = frozenset(
    {
        "artifact_sha256",      # computed here; validated as 64 lowercase hex
        "artifact_bytes",       # computed here; validated as an int >= 1
        "scope",                # closed vocabulary (AUTHORITY_SCOPES)
        "declared_at_index",    # computed here; validated as an int >= 0
        "expires_after_seals",  # validated as an int >= 1
        "principal_basis",      # source constant, pinned at bind
        "grade",                # source constant, pinned at bind
        "limitation",           # source constant, pinned at bind
    }
)


def _redact_authorities(bound: list) -> tuple:
    """Scrub the operator-authored strings in the bound authorities.

    Returns ``(payload, findings, bytes_scanned)`` — the same three things
    ``_redact_result`` returns for a claim, and for the same reason: the
    findings ARE the export gate's input for these fields, so an authority
    label cannot be blocked-but-published. That pair coming apart is the exact
    defect the claim-field pass exists to have closed, and a field added later
    reintroduces it unless it is redacted by the pass that reports it.

    THREE fields carry outside text: the label, the cited path and the principal.
    They are listed in ``_AUTHORITY_TEXT_FIELDS`` and every one of them goes
    through ``redact_field``. Everything else is published only if
    ``_AUTHORITY_PASSTHROUGH_FIELDS`` vouches for it; an unclassified key is
    dropped, because the failing direction for a field nobody has thought about
    is to leave it out of the artifact that leaves the machine.

    Findings are located by field NAME rather than by an authority index —
    ``FindingSource`` addresses claims and streams, and widening it is a change
    to the projection contract, not to this unit — so the precise address
    travels in ``redaction.fields`` instead.
    """
    payload = []
    findings: list = []
    scanned = 0
    for index, entry in enumerate(bound):
        fields: list = []

        def _field(name: str, kind: str, value) -> str:
            nonlocal scanned
            text = value if isinstance(value, str) else str(value)
            scanned += len(text.encode("utf-8", "replace"))
            redaction = redact.redact_field(name, text, redact.FindingSource(kind))
            fields.extend(redaction.applied)
            findings.extend(redaction.findings)
            return redaction.text

        out = {k: v for k, v in entry.items() if k in _AUTHORITY_PASSTHROUGH_FIELDS}
        for name, kind in _AUTHORITY_TEXT_FIELDS:
            if name in entry:
                out[name] = _field(f"authority[{index}].{name}", kind, entry[name])
        out["redaction"] = {
            "projection_version": redact.PROJECTION_VERSION,
            "detector_set_version": redact.DETECTOR_SET_VERSION,
            "fields": fields,
        }
        payload.append(out)
    return payload, findings, scanned


# --- helpers -----------------------------------------------------------------

def _rev(repo: Path, commitish: str) -> Optional[str]:
    proc = subprocess.run(
        ["git", "rev-parse", commitish], cwd=str(repo), capture_output=True, text=True
    )
    return proc.stdout.strip() if proc.returncode == 0 else None


def _git_stderr(proc) -> str:
    err = proc.stderr or b""
    if isinstance(err, bytes):
        err = err.decode("utf-8", "replace")
    return err.strip()[:500]


def _read_note(repo: Path, commit: str) -> Optional[bytes]:
    """The note body currently attached to ``commit``, or None if there is none.

    Read before publishing so a failed seal can put back what it overwrote.
    """
    proc = subprocess.run(
        ["git", "notes", f"--ref={NOTES_REF}", "show", commit],
        cwd=str(repo),
        capture_output=True,
    )
    return proc.stdout if proc.returncode == 0 else None


def _recorded_window(body: Optional[bytes]) -> Optional[tuple]:
    """The claim window an existing note records, or None when it records none.

    None is NOT ``(0, 0)`` and it is not the reading default either. A note
    published before v0.2 carries no window keys at all, so what it covered is
    genuinely unknown — and ``Manifest.from_json``'s defaults (0 / len(claims))
    would turn that unknown into a confident ``[0, N)`` the note never claimed,
    which is exactly the kind of invented fact that would let the guard below
    wave a lossy overwrite through. So this reads key PRESENCE off the raw body.

    A body this function cannot parse also yields None: a foreign or corrupt
    note under the same ref is the case where an overwrite destroys the most and
    explains the least.
    """
    if not body:
        return None
    try:
        d = json.loads(body)
    except ValueError:
        return None
    if not isinstance(d, dict):
        return None
    lo, hi = d.get("claims_from"), d.get("claims_to")
    if not _is_index(lo) or not _is_index(hi):
        return None
    return lo, hi


def _refuse_narrowing_reseal(
    commit: str, prior_note: Optional[bytes], manifest: Manifest, reseal: bool
) -> None:
    """Refuse to replace a commit's note with a narrower record.

    ``git notes add -f`` force-replaces, and a seal is scoped to
    ``all_claims[watermark:]``. Together those two made the documented repair
    loop lossy: re-sealing the same commit published a note holding only the
    post-watermark claims and silently destroyed the record of everything the
    earlier note held. Nothing in the artifact said so, which is what made it
    dangerous rather than merely surprising.

    Three ways past this, and they are all explicit: the commit carries no note;
    the new window CONTAINS the recorded one (a superset re-seal loses nothing);
    or the operator passed ``reseal``. An unknown recorded window is not treated
    as containable — see ``_recorded_window``.
    """
    if prior_note is None or reseal:
        return
    new_window = (manifest.claims_from, manifest.claims_to)
    old_window = _recorded_window(prior_note)
    if old_window is not None and (
        new_window[0] <= old_window[0] and new_window[1] >= old_window[1]
    ):
        return
    recorded = (
        "the note records no claim window (it was published before v0.2, or it is "
        "not a didrun manifest), so what replacing it would destroy cannot be "
        "determined from here"
        if old_window is None
        else (
            f"the note records claims [{old_window[0]},{old_window[1]}), "
            f"which that does not contain"
        )
    )
    raise ManifestError(
        f"refusing to replace the note on {commit[:12]}: this seal covers claims "
        f"[{new_window[0]},{new_window[1]}) and {recorded} — replacing the note "
        f"would drop the earlier record, which exists nowhere else. Commit first "
        f"so this unit gets its own note, or re-run with --reseal to replace it "
        f"anyway (the narrower window is then visible in claims_from/claims_to)."
    )


def _attach_note(repo: Path, commit: str, manifest: Manifest) -> None:
    """Publish the manifest as ``commit``'s note. Fails closed.

    The body travels on stdin (``-F -``), not as an argv element: notes grow
    with claim count and the command line does not. ``-F -`` and ``-m`` produce
    the identical note object, so this moves no stored byte.
    """
    proc = subprocess.run(
        ["git", "notes", f"--ref={NOTES_REF}", "add", "-f", "-F", "-", commit],
        cwd=str(repo),
        input=manifest.to_json(),
        capture_output=True,
    )
    if proc.returncode != 0:
        raise ManifestError(
            f"could not publish note to {NOTES_REF} for {commit}: "
            f"git exited {proc.returncode}: {_git_stderr(proc)}"
        )


def _restore_note(repo: Path, commit: str, prior: Optional[bytes]) -> bool:
    """Put ``commit``'s note back the way it was. Best-effort; never raises.

    ``_attach_note`` forces (-f), so a seal can overwrite an existing note.
    Rolling back by REMOVING the note would turn "the watermark write failed"
    into "the commit's earlier evidence is gone", so the prior body is
    re-attached; removal happens only when there was nothing there before.
    Returns whether the restore is known to have succeeded.
    """
    try:
        if prior is None:
            proc = subprocess.run(
                ["git", "notes", f"--ref={NOTES_REF}", "remove", "--ignore-missing", commit],
                cwd=str(repo),
                capture_output=True,
            )
        else:
            proc = subprocess.run(
                ["git", "notes", f"--ref={NOTES_REF}", "add", "-f", "-F", "-", commit],
                cwd=str(repo),
                input=prior,
                capture_output=True,
            )
        return proc.returncode == 0
    except Exception:
        return False


def _rollback_note(
    repo: Path, commit: str, prior: Optional[bytes], published: bool
) -> str:
    """Undo this seal's publication and say, exactly, what state the commit is in."""
    if not published:
        return "no note was published, so none was rolled back"
    restored = _restore_note(repo, commit, prior)
    if prior is None:
        return (
            "the note was rolled back and the commit was left noteless (it carried none before)"
            if restored
            else "the note could NOT be rolled back and this seal's note is STILL ATTACHED"
        )
    return (
        "the note was rolled back and the commit's prior note was restored"
        if restored
        else "the note was NOT rolled back and the commit's prior note was NOT restored"
    )


def _resolve_manifest(
    repo: Path, commit: Optional[str], tree: Optional[str]
) -> tuple[Optional[Manifest], str, int]:
    """Find the manifest for a commit. Returns (manifest, resolved_by, skipped).

    ``skipped`` counts notes on the tree-fallback path that could not be
    parsed at all — a foreign note under the same ref, or a corrupt body. Those
    are skipped so one bad note cannot hide every good one, but they are
    counted so the caller can say so rather than reporting a silent "none".
    A *version* refusal is not a skip: it means didrun met evidence it cannot
    read, and it propagates.
    """
    skipped = 0
    # Try the note on the exact commit.
    if commit:
        proc = subprocess.run(
            ["git", "notes", f"--ref={NOTES_REF}", "show", commit],
            cwd=str(repo),
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return Manifest.from_json(proc.stdout.encode("ascii")), "commit", skipped
    # Tree fallback: scan notes for one whose sealed tree matches (survives amend).
    if tree:
        listing = subprocess.run(
            ["git", "notes", f"--ref={NOTES_REF}", "list"],
            cwd=str(repo),
            capture_output=True,
            text=True,
        )
        if listing.returncode == 0:
            for line in listing.stdout.splitlines():
                parts = line.split()
                if len(parts) != 2:
                    continue
                note_obj, annotated = parts
                show = subprocess.run(
                    ["git", "cat-file", "-p", note_obj],
                    cwd=str(repo),
                    capture_output=True,
                    text=True,
                )
                if show.returncode == 0 and show.stdout.strip():
                    try:
                        m = Manifest.from_json(show.stdout.encode("ascii"))
                    except ManifestFormatError:
                        # Not a readable manifest: a foreign note under the same
                        # ref, or a corrupt body. Skipped and counted, so one bad
                        # note cannot hide every good one. Ordered BEFORE the
                        # clause below because it is a subclass of it — and it
                        # states by type what used to happen by accident, when a
                        # bare `except Exception` skipped these only because
                        # `json` raised something that was not a ManifestError.
                        skipped += 1
                        continue
                    except ManifestError:
                        # A version this binary cannot read. Fail closed: the
                        # alternative is scanning past it and reporting the
                        # verdict of some older note as if it were current.
                        raise
                    except Exception:
                        skipped += 1
                        continue
                    # First match wins (unchanged). Ambiguity policy is not
                    # this unit's; see docs/COMPAT.md.
                    if m.tree == tree:
                        return m, "tree-fallback", skipped
    return None, "none", skipped


# What the secrets pass looked at, published so `secrets_override: false` is a
# checkable statement rather than the same word for "nothing found" and
# "almost nothing looked at". `claim-fields` is the label, the pathspecs and
# the changed paths: they used to ride into the scan only inside the
# serialized manifest, where they blocked a seal and were published anyway.
SCAN_DOMAIN = "claim-bound-events+claim-fields+manifest"


@dataclass
class SecretsScan:
    """What the secrets pass looked at, and what it found where.

    Two domains, and the distinction is the whole point. ``export`` is what is
    about to leave the machine: the argv of each claim-bound event and the
    serialized manifest bytes themselves. ``local`` is what stays: the stdout
    and stderr blobs, which live in a gitignored ledger and are never published.
    Blocking a seal over bytes that never leave, while publishing claim labels
    and delta paths entirely unscanned, was the gate pointed at the wrong half.
    """

    export: list  # findings in bytes about to be written
    local: list  # findings in blobs that stay on this machine
    events_scanned: int
    events_total: int
    bytes_scanned: int

    @property
    def blocking(self) -> list:
        """The findings that stop a seal: block-tier, in the export domain."""
        return [f for f in self.export if f.tier == redact.TIER_BLOCK]

    @property
    def non_blocking(self) -> list:
        """Everything found that did not stop the seal — reported, not silent."""
        return [f for f in self.export if f.tier != redact.TIER_BLOCK] + list(self.local)

    @property
    def all_findings(self) -> list:
        return self.export + self.local

    def to_dict(self, overridden: bool) -> dict:
        by_tier = {tier: 0 for tier in redact.TIERS}
        for f in self.all_findings:
            by_tier[f.tier] = by_tier.get(f.tier, 0) + 1
        return {
            "scan_domain": SCAN_DOMAIN,
            "events_scanned": self.events_scanned,
            "events_total": self.events_total,
            "bytes_scanned": self.bytes_scanned,
            "detector_set_version": redact.DETECTOR_SET_VERSION,
            "findings_by_tier": by_tier,
            "blocked": bool(self.blocking),
            "overridden": overridden,
        }


def _scan_for_secrets(
    session: Session,
    results: list[GradeResult],
    export_bytes: bytes,
    field_findings: Optional[list] = None,
    field_bytes: int = 0,
) -> SecretsScan:
    """Scan both domains, tagging every finding with where it is.

    Three contributions make up the export domain, and they are deliberately
    not the same mechanism:

    * the argv of each claim-bound event, scanned RAW here and redacted into
      the published `argv_preview` separately;
    * ``field_findings`` — the claim fields (label, pathspecs, changed paths),
      which arrive already located from the pass that redacted them, so what
      blocks and what is scrubbed cannot drift apart;
    * ``export_bytes``, the serialized manifest as it would be published,
      scanned WHOLE rather than field by field. It is the backstop: a field a
      later version adds and forgets to redact is still in these bytes, so it
      still blocks. The redacted fields are already markers by the time they
      get here, so nothing is counted twice.

    The scan covers each claim's supporting event once, not once per claim, so
    ``events_scanned`` counts events rather than claim-event pairs.
    """
    export: list[redact.Finding] = list(field_findings or ())
    local: list[redact.Finding] = []
    events = session.events()
    seen: set = set()
    # Starts at the claim-field bytes rather than 0: those bytes were scanned,
    # by the redaction pass, and a published counter that omitted them would be
    # the same "checkable statement that is not true" this block exists to fix.
    bytes_scanned = field_bytes

    for r in results:
        idx = r.supporting_event_index
        if idx is None or not (0 <= idx < len(events)) or idx in seen:
            continue
        seen.add(idx)
        ev = events[idx]
        for argv_index, arg in enumerate(ev.argv):
            bytes_scanned += len(arg.encode("utf-8", "replace"))
            export.extend(
                redact.scan(
                    arg,
                    redact.FindingSource(
                        "argv", event_index=idx, argv_index=argv_index
                    ),
                )
            )
        for stream, blob in (("stdout", ev.stdout_blob), ("stderr", ev.stderr_blob)):
            if blob and session.blobs.has(blob):
                data = session.blobs.get(blob)
                bytes_scanned += len(data)
                local.extend(
                    redact.scan(data, redact.FindingSource(stream, event_index=idx))
                )

    bytes_scanned += len(export_bytes)
    export.extend(redact.scan(export_bytes, redact.FindingSource("manifest")))

    return SecretsScan(
        export=export,
        local=local,
        events_scanned=len(seen),
        events_total=len(events),
        bytes_scanned=bytes_scanned,
    )


def _warn_unblocked_secrets(scan: SecretsScan) -> None:
    """Say, loudly, what was found and not blocked on.

    Silence here would make the tiering a suppression list with extra steps.
    Notice-tier findings and block-tier findings confined to local blobs do not
    stop a seal, but the operator is told they exist and where they are.
    """
    findings = scan.non_blocking
    if not findings:
        return
    notice = sum(1 for f in findings if f.tier == redact.TIER_NOTICE)
    local_block = len(findings) - notice
    print(
        f"didrun seal: WARNING: {len(findings)} secret finding(s) did not block "
        f"this seal ({notice} notice-tier, {local_block} block-tier in local "
        f"output blobs that are not exported):",
        file=sys.stderr,
    )
    for line in redact.enumerate_findings(findings):
        print(line, file=sys.stderr)


@dataclass(frozen=True)
class RedactedClaim:
    """One exported claim entry, plus what redacting it found.

    ``findings`` is not diagnostic output: it is the export gate's input for
    every field of this claim that is not argv. Producing the two together is
    the only reason the gate cannot disagree with the publication again.
    ``bytes_scanned`` keeps the manifest's published byte count honest about
    the fields this pass added to the domain.
    """

    payload: dict
    findings: list
    bytes_scanned: int = 0


def _redact_result(
    r: GradeResult,
    session: Session,
    entries: list,
    claim_index: int = 0,
    superseded_by: Optional[int] = None,
    deferred: Optional[str] = None,
) -> RedactedClaim:
    d = r.to_dict()
    # Redact argv in the exported claim view, and DECLARE the projection that
    # produced it. The marker string alone is not authenticating — a recorded
    # argv may contain the literal marker text — so a consumer distinguishes a
    # real redaction from literal text by reading `redaction.applied`, which
    # names the source spans that were replaced. Additive, read with .get():
    # no MANIFEST_VERSION bump (docs/COMPAT.md).
    argv_redaction = redact.redact_argv(
        list(_event_argv(session, r.supporting_event_index))
    )
    d["claim"]["argv_preview"] = argv_redaction.argv

    # The rest of the published claim. argv used to be the only field scrubbed
    # here, which made the seal's own refusal message ("re-run with
    # --allow-secrets to export a redacted artifact anyway") false for every
    # other field: a token in a claim label BLOCKED the seal and was then
    # published verbatim into refs/notes/didrun on the override. These are the
    # exported strings that carry operator- or repository-authored text, and
    # each one is redacted by the same pass that reports it.
    fields: list[dict] = []
    findings: list = []
    scanned = 0

    def _field(name: str, kind: str, value: str) -> str:
        nonlocal scanned
        scanned += len(value.encode("utf-8", "replace"))
        redaction = redact.redact_field(
            name,
            value,
            redact.FindingSource(kind, claim_index=claim_index),
        )
        fields.extend(redaction.applied)
        findings.extend(redaction.findings)
        return redaction.text

    d["claim"]["label"] = _field("claim.label", "label", d["claim"]["label"])
    d["claim"]["pathspecs"] = [
        _field(f"claim.pathspecs[{i}]", "pathspec", spec)
        for i, spec in enumerate(d["claim"]["pathspecs"])
    ]
    # A conjunct name is the LABEL of another claim, so it is scanned as one.
    # Every conjunct is redacted by the same deterministic projection that
    # redacted the label it refers to, which is what keeps a conjunction
    # resolvable at verify time: both sides of the match carry the same text.
    d["claim"]["conjuncts"] = [
        _field(f"claim.conjuncts[{i}]", "label", name)
        for i, name in enumerate(d["claim"]["conjuncts"])
    ]
    # `reason` is generated text for every other claim type, and it was exported
    # unredacted for that reason (docs/COMPAT.md). A conjunction's reason NAMES a
    # conjunct, which is operator-authored, so it stops being generated-only text
    # here — and "blocked by the gate, published verbatim on the override" is the
    # exact defect the claim-field pass exists to have closed. Redacted for every
    # claim, not only for a conjunction: a reason a later version interpolates
    # something into is then covered without anyone remembering to add it.
    d["reason"] = _field("reason", "reason", d["reason"])
    d["delta"] = [
        {
            "status": change["status"],
            "path": _field(f"delta[{i}].path", "delta-path", change["path"]),
        }
        for i, change in enumerate(d["delta"])
    ]
    # The operator's reason for setting this claim aside: their text, published,
    # so redacted and reported by the same pass as every other such field.
    if deferred is not None:
        d["deferred"] = {"reason": _field("deferred.reason", "reason", deferred)}

    d["redaction"] = {
        "projection_version": redact.PROJECTION_VERSION,
        "detector_set_version": redact.DETECTOR_SET_VERSION,
        "applied": argv_redaction.applied,
        # Additive and separate from `applied`, which stays argv-addressed by
        # `argv_index` exactly as v0.2 consumers already read it. Entries here
        # are addressed by field name instead, because a label has no argv
        # index. A reader that does not know this key sees the same argv
        # projection it always did.
        "fields": fields,
    }
    pairs = d.pop("conjunct_grades", None)
    if pairs is not None:
        # The pairs' labels ARE `claim.conjuncts`, one per declared conjunct in
        # declaration order (claims.grade_conjunction builds them that way), so
        # they take the redacted text from above instead of being scanned — and
        # reported to the export gate — a second time. The length check is not
        # decoration: a silent zip would drop a graded conjunct out of the
        # published record, so it fails closed instead.
        names = d["claim"]["conjuncts"]
        if len(pairs) != len(names):
            raise ManifestError(
                f"refusing to publish a conjunction claim carrying "
                f"{len(pairs)} graded conjunct(s) for {len(names)} declared "
                f"conjunct(s): the note would not say what each member earned"
            )
        d["conjunct_grades"] = [
            {"label": name, "grade": pair["grade"]}
            for name, pair in zip(names, pairs)
        ]
    block = _evidence_block(entries, r.supporting_event_index)
    if block is not None:
        d["evidence"] = block
    # Written only on the entries that carry one. A permanently-null key on
    # every claim in every note would say nothing, and the absence of the key is
    # already the complete statement "this claim was not retired".
    if superseded_by is not None:
        d["superseded_by"] = superseded_by
    return RedactedClaim(payload=d, findings=findings, bytes_scanned=scanned)


def _evidence_block(entries: list, idx: Optional[int]) -> Optional[dict]:
    """Which recorded entry backed this claim, named by its chain hash.

    This is the handle the note never had. A sealed grade used to be reachable
    only through an integer index into whatever ledger happens to be on disk at
    verify time, so an archived, rebuilt or substituted ledger changed the
    verdict with no signal. The entry hash makes "index 4 of the ledger you have
    now" checkable against "index 4 of the ledger this was sealed from".

    Recorded in the MANIFEST, never in the ledger: the v1 chain preimage is
    frozen (docs/COMPAT.md), and putting a field into Event would invalidate
    every entry hash ever written. Omitted entirely when no event backs the
    claim — an absent block means "nothing to bind", which is not the same fact
    as "bound to nothing".
    """
    if idx is None or not (0 <= idx < len(entries)):
        return None
    entry = entries[idx]
    return {
        "event_index": idx,
        "entry_hash": entry.entry_hash,
        "env_fingerprint": entry.event.env_fingerprint,
        "tree_after": entry.event.tree_after,
    }


def _event_argv(session: Session, idx: Optional[int]):
    if idx is None:
        return ()
    events = session.events()
    if 0 <= idx < len(events):
        return events[idx].argv
    return ()
