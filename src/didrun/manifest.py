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
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .ledger import Session, canonical_json, _append_lock, _open_private_append
from .claims import GRADE_WITNESS_UNAVAILABLE, Claim, GradeResult, grade
from . import gitplumbing, redact

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

    def to_json(self) -> bytes:
        return canonical_json(
            {
                "version": self.version,
                "commit": self.commit,
                "tree": self.tree,
                "claims": self.claims,
                "coverage": self.coverage,
                "secrets_override": self.secrets_override,
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

    Raises ``redact.SecretsBlocked`` if secrets are found and ``allow_secrets``
    is False. On override, the exported artifact is still redacted and the
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

    # Secrets pass over argv + backing output blobs before anything is exported.
    findings = _scan_for_secrets(session, results)
    if findings and not allow_secrets:
        raise redact.SecretsBlocked(findings)

    manifest = Manifest(
        version=MANIFEST_VERSION,
        commit=commit,
        tree=tree,
        claims=[_redact_result(r, session, entries) for r in results],
        coverage=_coverage_statement(session),
        secrets_override=bool(findings) and allow_secrets,
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
        if self.chain_faulted:
            return False
        return bool(self.results) and all(
            r.grade in ("tree-exact", "scope-exact") for r in self.results
        )

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


def verify(session: Session, repo: Path, commitish: str = "HEAD") -> VerifyReport:
    """Resolve and re-grade a manifest for ``commitish``.

    Resolves by commit id, then by tree id (survives amend/rebase). Degrades a
    claim to unknown ("referenced object gc'd") rather than erroring.

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
        )

    # Re-grade the MANIFEST'S OWN claims against its sealed tree (deterministic
    # replay). The manifest is the only thing verify reads besides the repo —
    # the source-of-truth rule. Reading the live session claims file
    # here would let later, unsealed claims leak into an old commit's verdict.
    entries = list(session.entries())
    events = [e.event for e in entries]
    ledger_objects = session.blobs.root
    results: list[GradeResult] = []
    for c in manifest.claims:
        claim = Claim.from_dict(c["claim"])
        results.append(
            _verify_claim(c, claim, manifest, entries, events, repo, ledger_objects)
        )
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


def _scan_for_secrets(session: Session, results: list[GradeResult]) -> list[redact.Finding]:
    findings: list[redact.Finding] = []
    events = session.events()
    for r in results:
        idx = r.supporting_event_index
        if idx is None or not (0 <= idx < len(events)):
            continue
        ev = events[idx]
        findings.extend(redact.scan(" ".join(ev.argv)))
        for blob in (ev.stdout_blob, ev.stderr_blob):
            if blob and session.blobs.has(blob):
                findings.extend(redact.scan(session.blobs.get(blob)))
    return findings


def _redact_result(r: GradeResult, session: Session, entries: list) -> dict:
    d = r.to_dict()
    # Redact argv in the exported claim view.
    d["claim"]["argv_preview"] = redact.scrub_argv(
        list(_event_argv(session, r.supporting_event_index))
    )
    block = _evidence_block(entries, r.supporting_event_index)
    if block is not None:
        d["evidence"] = block
    return d


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
