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

from .ledger import Session, canonical_json
from .claims import Claim, GradeResult, grade
from . import gitplumbing, redact

MANIFEST_VERSION = 1
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

    events = session.events()
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
        claims=[_redact_result(r, session) for r in results],
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


@dataclass
class VerifyReport:
    commit: str
    tree: str
    resolved_by: str  # "commit" | "tree-fallback" | "none"
    results: list[GradeResult]
    coverage: dict
    secrets_override: bool = False
    notes_skipped: int = 0  # notes the tree fallback could not parse at all

    @property
    def worst_status(self) -> str:
        """Worst grade present — drives the verdict and the CI exit code."""
        order = ["failed", "unknown", "stale", "scope-exact", "tree-exact"]
        present = {r.grade for r in self.results}
        if not present:
            return "empty"
        for status in order:
            if status in present:
                return status
        return "unknown"

    @property
    def all_verified(self) -> bool:
        return bool(self.results) and all(
            r.grade in ("tree-exact", "scope-exact") for r in self.results
        )


def verify(session: Session, repo: Path, commitish: str = "HEAD") -> VerifyReport:
    """Resolve and re-grade a manifest for ``commitish``.

    Resolves by commit id, then by tree id (survives amend/rebase). Degrades a
    claim to unknown ("referenced object gc'd") rather than erroring.
    """
    repo = Path(repo)
    commit = _rev(repo, commitish)
    tree = gitplumbing.commit_tree(repo, commitish) if commit else None

    manifest, resolved_by, notes_skipped = _resolve_manifest(repo, commit, tree)
    if manifest is None:
        return VerifyReport(
            commit=commit or "",
            tree=tree or "",
            resolved_by="none",
            results=[],
            coverage={},
            notes_skipped=notes_skipped,
        )

    # Re-grade the MANIFEST'S OWN claims against its sealed tree (deterministic
    # replay). The manifest is the only thing verify reads besides the repo —
    # the source-of-truth rule. Reading the live session claims file
    # here would let later, unsealed claims leak into an old commit's verdict.
    events = session.events()
    ledger_objects = session.blobs.root
    results: list[GradeResult] = []
    for c in manifest.claims:
        claim = Claim.from_dict(c["claim"])
        try:
            results.append(grade(claim, manifest.tree, events, repo, ledger_objects))
        except Exception as exc:  # object gc'd or unreadable → unknown, not crash
            results.append(
                GradeResult(claim, "unknown", reason=f"regrade failed: {exc}")
            )
    return VerifyReport(
        commit=manifest.commit,
        tree=manifest.tree,
        resolved_by=resolved_by,
        results=results,
        coverage=manifest.coverage,
        secrets_override=manifest.secrets_override,
        notes_skipped=notes_skipped,
    )


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
    with _seals_path(session).open("a", encoding="ascii") as fh:
        fh.write(
            canonical_json(
                {"commit": commit, "tree": tree, "claims_watermark": claims_watermark}
            ).decode("ascii")
            + "\n"
        )


def declare_claim(session: Session, claim: Claim) -> None:
    with _claims_path(session).open("a", encoding="ascii") as fh:
        fh.write(canonical_json(claim.to_dict()).decode("ascii") + "\n")


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


def _redact_result(r: GradeResult, session: Session) -> dict:
    d = r.to_dict()
    # Redact argv in the exported claim view.
    d["claim"]["argv_preview"] = redact.scrub_argv(
        list(_event_argv(session, r.supporting_event_index))
    )
    return d


def _event_argv(session: Session, idx: Optional[int]):
    if idx is None:
        return ()
    events = session.events()
    if 0 <= idx < len(events):
        return events[idx].argv
    return ()
