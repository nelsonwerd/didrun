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

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .ledger import Session, canonical_json, _append_lock, _open_private_append
from .claims import (
    ENV_DRIFT,
    ENV_INCOMPARABLE,
    ENV_MATCH,
    ENV_NOT_RECORDED,
    GRADE_WITNESS_UNAVAILABLE,
    Claim,
    GradeResult,
    grade,
)
from . import capture, gitplumbing, redact

# 2: a claim may carry an `evidence` block naming the recorded entry that backed
# it, and verify CHECKS that binding instead of regrading by index alone. The
# bump is for the change of meaning, not for the new key: an older reader parses
# a v2 note fine (every key is additive) and regrades it index-only, exactly as
# it does today. See docs/COMPAT.md.
MANIFEST_VERSION = 2
NOTES_REF = "refs/notes/didrun"


class ManifestError(Exception):
    pass


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
        """
        d = json.loads(data)
        version = d["version"]
        if version > MANIFEST_VERSION:
            raise ManifestError(
                f"manifest version {version} is newer than this didrun understands "
                f"(max {MANIFEST_VERSION}); upgrade didrun"
            )
        return cls(
            version=version,
            commit=d["commit"],
            tree=d["tree"],
            claims=d["claims"],
            coverage=d["coverage"],
            secrets_override=d.get("secrets_override", False),
            secrets=d.get("secrets", {}),
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


def seal(
    session: Session,
    repo: Path,
    commitish: str = "HEAD",
    allow_secrets: bool = False,
    write_notes: bool = True,
    bundle_path: Optional[Path] = None,
) -> Manifest:
    """Compile, redact, and attach a manifest for ``commitish``.

    Raises ``redact.SecretsBlocked`` if a BLOCK-tier detector fires on the
    EXPORT domain and ``allow_secrets`` is False. Notice-tier findings, and
    block-tier findings confined to the local output blobs, warn loudly on
    stderr and do not stop the seal — the blobs stay in a gitignored ledger and
    are not published, so refusing over them stopped work without protecting
    anything. On override, the exported artifact is still redacted and the
    override is recorded in the manifest.
    """
    repo = Path(repo)
    commit = gitplumbing.head_commit(repo) if commitish == "HEAD" else _rev(repo, commitish)
    if commit is None:
        raise ManifestError("cannot seal: no commit to bind to (unborn HEAD?)")
    tree = gitplumbing.commit_tree(repo, commit)
    if tree is None:
        raise ManifestError(f"cannot resolve tree for commit {commit}")

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
    new_claims = all_claims[watermark:]

    # Grade the claims for THIS seal against the sealed tree.
    results: list[GradeResult] = []
    for claim in new_claims:
        results.append(grade(claim, tree, events, repo, ledger_objects))

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
    # added later is in them too, without anyone remembering to add it.
    #
    # Compiling the export domain also REDACTS it, and the findings that come
    # back are what the gate blocks on. A field cannot be blocked-but-published
    # (the label bug) or published-but-unscanned, because one pass does both.
    redacted = [
        _redact_result(r, session, entries, claim_index=i)
        for i, r in enumerate(results)
    ]
    claims_payload = [rc.payload for rc in redacted]
    field_findings = [f for rc in redacted for f in rc.findings]
    field_bytes = sum(rc.bytes_scanned for rc in redacted)
    coverage = _coverage_statement(session)
    export_bytes = canonical_json(
        {
            "version": MANIFEST_VERSION,
            "commit": commit,
            "tree": tree,
            "claims": claims_payload,
            "coverage": coverage,
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
    )

    # Publication and the watermark are one atomic pair. A published note with
    # no watermark re-seals every earlier claim forever (the watermark is what
    # scopes a seal); a watermark with no published note reports evidence that
    # was never written. Nothing is recorded until the note is on the commit,
    # and if recording fails the note goes back to what it was.
    prior_note = _read_note(repo, commit) if write_notes else None
    if write_notes:
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

    @property
    def chain_faulted(self) -> bool:
        return self.chain_status in _CHAIN_FAULTS

    @property
    def worst_status(self) -> str:
        """Worst grade present — drives the verdict and the CI exit code."""
        # A broken chain dominates every grade, including "empty": the grades
        # below it were read out of a ledger that does not recompute, so none of
        # them is a statement anyone should act on.
        if self.chain_faulted:
            return CHAIN_BROKEN
        order = [
            "failed",
            "unknown",
            GRADE_WITNESS_UNAVAILABLE,
            "stale",
            "scope-exact",
            "tree-exact",
        ]
        present = {r.grade for r in self.results}
        if not present:
            return "empty"
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
        if self.chain_faulted:
            return False
        if not self.results:
            return False
        for r in self.results:
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
        """
        counts = {
            ENV_MATCH: 0,
            ENV_DRIFT: 0,
            ENV_INCOMPARABLE: 0,
            ENV_NOT_RECORDED: 0,
        }
        for r in self.results:
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
        """
        return sum(1 for r in self.results if r.evidence_bound)

    @property
    def total(self) -> int:
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
    results: list[GradeResult] = []
    for c in manifest.claims:
        claim = Claim.from_dict(c["claim"])
        result = _verify_claim(
            c, claim, manifest, entries, events, repo, ledger_objects
        )
        # Assigned around the ladder, like witness-unavailable: the environment
        # comparison is a fact about this run, not a grade the evidence earns.
        # It is set on EVERY path, including witness-unavailable — the sealed
        # fingerprint is in the note whether or not the ledger still holds the
        # entry it names.
        result.env_status, result.env_reason = _env_comparison(
            c.get("evidence"), current_fingerprint
        )
        results.append(result)
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
    """
    evidence = stored.get("evidence")
    if not isinstance(evidence, dict):
        return _regrade(claim, manifest, events, repo, ledger_objects)

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

    result = _regrade(claim, manifest, events, repo, ledger_objects)
    result.evidence_bound = True
    result.sealed_grade = sealed_grade
    return result


def _is_index(value) -> bool:
    """A real integer index. ``bool`` is an ``int`` subclass and is not one."""
    return isinstance(value, int) and not isinstance(value, bool)


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
) -> GradeResult:
    try:
        return grade(claim, manifest.tree, events, repo, ledger_objects)
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
    r: GradeResult, session: Session, entries: list, claim_index: int = 0
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
    d["delta"] = [
        {
            "status": change["status"],
            "path": _field(f"delta[{i}].path", "delta-path", change["path"]),
        }
        for i, change in enumerate(d["delta"])
    ]

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
    block = _evidence_block(entries, r.supporting_event_index)
    if block is not None:
        d["evidence"] = block
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
