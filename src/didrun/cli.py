"""didrun command-line interface.

Six commands: run, claim, authorize, seal, verify, show.
`log` is subsumed by `show`; `report` is a `--html` flag on show/verify.

The CLI is a thin shell over the library; all behavior lives in the modules so
it is unit-testable without spawning a process.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional

from . import __version__
from .ledger import LedgerError, Session
from .capture import (
    CaptureInterrupted,
    DIDRUN_ACTIVE_ENV,
    run_wrapped,
    signal_name,
)
from .claims import CLAIM_TYPES, CONJUNCTION, Claim, pathspec_problem
from . import manifest as _manifest
from . import redact
from . import render
from . import gitplumbing


def _ledger_dir(repo: Path) -> Path:
    return Path(repo) / ".didrun"


def _session(repo: Path, readonly: bool = False) -> Session:
    """Open the repo's ledger.

    ``readonly=True`` is for the commands that only read one: it creates no
    directory, writes no .gitignore, and re-modes nothing. Without it `verify`
    on a fresh clone MANUFACTURED an empty ledger — which then graded every
    claim unknown — and pointing `show` at someone else's archive mutated it.
    """
    return Session(_ledger_dir(repo), readonly=readonly)


def cmd_run(args) -> int:
    repo = Path(args.repo or os.getcwd())
    command = list(args.command)
    # argparse.REMAINDER keeps a leading "--" separator; strip it so we exec the
    # real command, not "--".
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("didrun run: nothing to run (usage: didrun run -- <cmd> [args…])", file=sys.stderr)
        return 2
    args.command = command
    session = _session(repo)
    # Mark the session active so Tier-1/2 hooks (if installed) are live only now.
    os.environ.setdefault(DIDRUN_ACTIVE_ENV, "1")
    event = run_wrapped(
        list(args.command), session, repo, tee=args.tee, heartbeat=args.heartbeat
    )
    coverage = "shim" if args.shim else "wrapper"
    print(
        f"recorded {coverage} event  argv={' '.join(event.argv)!r}  "
        f"exit={event.exit_code}  "
        f"tree {(event.tree_after or '(none)')[:12]}"
    )
    return event.exit_code if event.exit_code is not None else 0


def _conjunct_labels(raw: Optional[str]) -> tuple:
    """Parse ``--of``: the comma-separated labels of the claims to conjoin.

    Order is the operator's, and it is kept: it decides which of two
    equally-bad conjuncts the grade's reason names. Surrounding whitespace is
    stripped and an empty name is dropped rather than matched against a label
    nothing carries; an empty result reaches ``Claim``, which refuses it.
    """
    if not raw:
        return ()
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _cmd_defer(args, session: Session) -> int:
    """`claim --defer LABEL --reason TEXT`: set one unsealed claim aside.

    It declares nothing, so every flag that shapes a declaration is refused
    rather than ignored — an operator who passed one meant something by it.
    """
    shaping = [
        flag
        for flag, value in (
            ("--event", args.event),
            ("--path", args.path),
            ("--of", args.of),
            ("--label", args.label),
        )
        if value is not None
    ]
    if shaping:
        print(
            f"didrun claim: --defer sets an existing claim aside and declares no "
            f"claim, so {', '.join(shaping)} has nothing to apply to",
            file=sys.stderr,
        )
        return 2
    try:
        record = _manifest.declare_deferral(
            session, args.defer, args.reason or "", ctype=args.type
        )
    except _manifest.ManifestError as exc:
        print(f"didrun claim: {exc}", file=sys.stderr)
        return 2
    text = render.sanitize_text
    print(
        f"deferred claim #{record['position']} {record['ctype']} "
        f"({text(record['label'])}) out of the next seal's verdict: "
        f"{text(record['reason'])}"
    )
    print(
        "  it stays in the note as record — graded, published with this reason, "
        "and counted on every verdict surface"
    )
    return 0


def cmd_claim(args) -> int:
    repo = Path(args.repo or os.getcwd())
    session = _session(repo)
    if args.defer is not None:
        return _cmd_defer(args, session)
    if args.reason is not None:
        print("didrun claim: --reason only goes with --defer", file=sys.stderr)
        return 2
    if args.type is None:
        print(
            "didrun claim: a claim type is required (or --defer LABEL to set a "
            "claim aside)",
            file=sys.stderr,
        )
        return 2
    events = session.events()
    if not events:
        print("didrun claim: no recorded events to bind to (run something first)", file=sys.stderr)
        return 2
    conjuncts: tuple = ()
    indices: tuple = ()
    # Before anything is bound: a pathspec `_within` cannot honour would make the
    # claim's scope silently empty, so it is refused here rather than declared.
    for spec in args.path or ():
        problem = pathspec_problem(spec)
        if problem is not None:
            print(f"didrun claim: --path {problem}", file=sys.stderr)
            return 2
    if args.type == CONJUNCTION:
        # A conjunction binds no event — it conjoins claims that carry their own
        # witnessed events — so the "most recent event did not exit 0" refusal
        # below is not its refusal. `--event` and `--path` are refused rather than
        # silently ignored: an operator who passed one meant something by it.
        if args.event is not None:
            print(
                "didrun claim: a conjunction binds no event; name the claims it "
                "conjoins with --of instead of --event",
                file=sys.stderr,
            )
            return 2
        if args.path:
            print(
                "didrun claim: a conjunction declares no pathspec; its conjuncts "
                "carry their own",
                file=sys.stderr,
            )
            return 2
        conjuncts = _conjunct_labels(args.of)
    else:
        if args.of:
            print(
                f"didrun claim: --of names the claims a conjunction conjoins; "
                f"{args.type} conjoins none",
                file=sys.stderr,
            )
            return 2
        # Default: bind to the LAST event, never to the last *successful* one.
        #
        # Searching backwards for a success is the failure this tool exists to
        # prevent, reachable through the documented happy path: run the tests
        # (pass), edit, run them again (fail), `didrun claim tests-pass` — the
        # claim bound the older passing event, `declared_at_index` was still the
        # last index so the retroactive-binding rule did not catch it, and if the
        # tree had not moved it graded tree-exact. The only signal was the index
        # in a success line nobody reads. Refuse instead: an operator who really
        # means an earlier event says so with --event N, which is deliberate and
        # is warned about below.
        if args.event is not None:
            indices = (args.event,)
            gap = len(events) - 1 - args.event
            if gap > 0:
                print(
                    f"didrun claim: binding to event {args.event}, {gap} event(s) "
                    f"before the most recent (index {len(events) - 1})",
                    file=sys.stderr,
                )
        else:
            last = len(events) - 1
            recent = events[last]
            if recent.exit_code != 0:
                witness = (
                    f"exited {recent.exit_code}"
                    if recent.exit_code is not None
                    else "recorded no exit code (interrupted, or capture that "
                    "witnesses no exit)"
                )
                print(
                    f"didrun claim: the most recent event (index {last}) "
                    f"{witness} — refusing to bind this claim to an earlier "
                    f"event that passed. Pass --event N to bind an earlier "
                    f"event deliberately.",
                    file=sys.stderr,
                )
                return 2
            indices = (last,)
    try:
        claim = Claim(
            ctype=args.type,
            label=args.label or args.type,
            event_indices=indices,
            pathspecs=tuple(args.path or ()),
            declared_at_index=len(events) - 1,
            conjuncts=conjuncts,
        )
    except Exception as exc:
        print(f"didrun claim: {exc}", file=sys.stderr)
        return 2
    _manifest.declare_claim(session, claim)
    if claim.conjuncts:
        print(
            f"declared claim {claim.ctype} ({claim.label}) over "
            f"{len(claim.conjuncts)} conjunct(s): {', '.join(claim.conjuncts)} "
            f"— graded as the worst of them"
        )
    else:
        print(f"declared claim {claim.ctype} ({claim.label}) bound to event(s) {list(indices)}")
    return 0


def cmd_authorize(args) -> int:
    """Record that a cited artifact is the authority for one scope.

    Prints the digest and, verbatim, the limitation constant. The limitation is
    printed here and not only in the docs because this command's output is where
    an operator forms their idea of what the record means, and what it means is
    much less than "approved".
    """
    repo = Path(args.repo or os.getcwd())
    session = _session(repo)
    try:
        record = _manifest.declare_authority(
            session,
            Path(args.artifact),
            scope=args.scope,
            label=args.label,
            principal=args.principal,
            expires_after_seals=args.expires_after_seals,
        )
    except _manifest.ManifestError as exc:
        print(f"didrun authorize: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"didrun authorize: cannot read the cited artifact: {exc}", file=sys.stderr)
        return 2
    # Sanitized, like every other terminal surface that prints a string this
    # process did not compute: the label, the principal and the path are argv.
    text = render.sanitize_text
    print(
        f"recorded {_manifest.AUTHORITY_GRADE} authority for scope "
        f"{text(record['scope'])}: {text(record['label'])}"
    )
    print(
        f"  artifact {text(record['artifact_path'])}  "
        f"sha256 {text(record['artifact_sha256'])}  "
        f"{text(record['artifact_bytes'])} bytes"
    )
    print(
        f"  principal {text(record['principal']) or '(unnamed)'} "
        f"({_manifest.AUTHORITY_PRINCIPAL_BASIS})  ·  "
        f"expires after {text(record['expires_after_seals'])} seal(s)"
    )
    print(f"  {_manifest.AUTHORITY_LIMITATION}")
    return 0


def cmd_seal(args) -> int:
    repo = Path(args.repo or os.getcwd())
    session = _session(repo)
    try:
        m = _manifest.seal(
            session,
            repo,
            commitish=args.commit or "HEAD",
            allow_secrets=args.allow_secrets,
            bundle_path=Path(args.bundle) if args.bundle else None,
            reseal=args.reseal,
            require_authority=args.require_authority,
        )
    except _manifest.redact.SecretsBlocked as exc:
        print(f"didrun seal: {exc}", file=sys.stderr)
        return 3
    except _manifest.ManifestError as exc:
        print(f"didrun seal: {exc}", file=sys.stderr)
        return 2
    # Counted over the live entries, like the verdict surface: a window whose
    # earlier attempt was retired would otherwise print "1/2 claims
    # recorded-exact" for a unit `verify` calls ALL RECORDED-EXACT, and the two
    # numbers describing the same note have to describe the same set.
    live = _manifest.live_claims(m.claims)
    # The two kinds of record-not-verdict entry, counted apart: a retired retry
    # and an operator's deferral are different facts about the window.
    deferred = len(_manifest.deferred_claims(m.claims))
    superseded = len(m.claims) - len(live) - deferred
    verified = sum(1 for c in live if c["grade"] in ("tree-exact", "scope-exact"))
    # The tier split is reported even when nothing blocked: "0 findings" and
    # "12 findings, none of them blocking" are different facts about the same
    # green seal, and only one of them is worth a second look.
    by_tier = (m.secrets or {}).get("findings_by_tier", {})
    blocking = by_tier.get("block", 0)
    noticed = by_tier.get("notice", 0)
    print(
        f"sealed manifest for {m.commit[:12]} (tree {m.tree[:12]})  "
        f"{verified}/{len(live)} claims recorded-exact  "
        + (f"{superseded} superseded  " if superseded else "")
        + (f"{deferred} deferred  " if deferred else "")
        + f"{blocking + noticed} findings ({blocking} block / {noticed} notice)"
        + ("  [--allow-secrets]" if m.secrets_override else "")
    )
    # What authorised the exceptional transition, if anything did — printed at the
    # moment the citation is published, with the limitation attached. An ordinary
    # seal cites nothing and prints nothing extra.
    # Sanitized for the same reason the verify block is: these strings came from
    # `authority.jsonl`, and redaction is not sanitization — a scrubbed label
    # still carries whatever control characters were written around the secret.
    for entry in m.authority:
        print(
            f"  {_manifest.AUTHORITY_GRADE} authority for scope "
            f"{render.sanitize_text(entry.get('scope', ''))}: "
            f"{render.sanitize_text(entry.get('label', ''))}  "
            f"sha256 {render.sanitize_text(entry.get('artifact_sha256', ''))}"
        )
    if m.authority:
        print(f"  {_manifest.AUTHORITY_LIMITATION}")
    return 0


def cmd_verify(args) -> int:
    repo = Path(args.repo or os.getcwd())
    session = _session(repo, readonly=True)
    try:
        report = _manifest.verify(
            session,
            repo,
            commitish=args.commit or "HEAD",
            require_env_match=args.require_env_match,
        )
    except _manifest.ManifestError as exc:
        # Evidence this binary cannot read is a graded refusal, not a crash. 2,
        # not --strict's 1: "could not read the manifest" is a different fact
        # from "the manifest graded badly".
        print(f"didrun verify: {exc}", file=sys.stderr)
        return 2
    if args.html:
        Path(args.html).write_text(render.render_html(report), encoding="utf-8")
        print(f"wrote HTML report to {args.html}")
        if not args.quiet:
            print(render.render_verdict(report))
        else:
            # --quiet suppresses the VERDICT, not the ledger's integrity. A
            # broken chain says the file that verdict was computed from does not
            # recompute; a reader who sent the detail to HTML still needs that
            # sentence where they are looking.
            banner = render.render_chain_banner(report)
            if banner:
                print(banner)
    else:
        print(render.render_verdict(report))
    if args.strict:
        return 0 if report.all_verified else 1
    return 0


def _show_output(session: Session, args) -> int:
    """Print one recorded output blob to stdout.

    The only path in the CLI that reads a blob back. Without it, reading the
    output of a recorded failure meant resolving digests by hand under
    `.didrun/objects`. `BlobStore.get` re-hashes on read, so a corrupted or
    edited blob is a refusal here rather than bytes presented as the record.
    """
    if args.event is None:
        print(
            "didrun show: --output needs --event N (which recorded event to read)",
            file=sys.stderr,
        )
        return 2
    events = session.events()
    if not 0 <= args.event < len(events):
        print(
            f"didrun show: no event at index {args.event} "
            f"(the session has {len(events)} events)",
            file=sys.stderr,
        )
        return 2
    ev = events[args.event]
    digest = ev.stdout_blob if args.stream == "stdout" else ev.stderr_blob
    if digest is None:
        print(
            f"didrun show: event {args.event} recorded no {args.stream} blob",
            file=sys.stderr,
        )
        return 2
    try:
        data = session.blobs.get(digest)
    except LedgerError as exc:
        # Missing or corrupt evidence is a graded refusal, never a traceback.
        print(f"didrun show: {exc}", file=sys.stderr)
        return 2
    if args.redacted:
        data = redact.redact(data).text.encode("utf-8", "replace")
    out = getattr(sys.stdout, "buffer", None)
    if out is not None:
        out.write(data)
        out.flush()
    else:
        sys.stdout.write(data.decode("utf-8", "replace"))
    return 0


def cmd_show(args) -> int:
    repo = Path(args.repo or os.getcwd())
    session = _session(repo, readonly=True)
    if args.output:
        return _show_output(session, args)
    if args.session:
        # Session history view (subsumes the old `log` command).
        entries = list(session.entries())
        if not entries:
            print("no recorded events")
            return 0
        ok, broke = session.verify_chain()
        chain = "intact" if ok else f"BROKEN at index {broke}"
        print(f"session: {len(entries)} events  chain {chain}")
        if session.tail_truncated:
            # A lost event is not tamper, and the chain line above is about the
            # surviving prefix only. Saying so is the difference between a
            # reader who knows an event is missing and one who does not.
            print(
                f"  note: the log's final record is torn at byte "
                f"{session.tail_truncated_offset} — one event was lost to an "
                f"interrupted write, and `didrun run` will refuse to append "
                f"until that is resolved"
            )
        for e in entries:
            ev = e.event
            exit_txt = f"exit {ev.exit_code}" if ev.exit_code is not None else "no-exit"
            print(
                f"  [{e.index}] {ev.observed_via:<10} {ev.coverage:<18} "
                f"{exit_txt:<8} {' '.join(ev.argv)[:60]}"
            )
        return 0 if ok else 1
    # Default: the verdict view for a commit.
    try:
        report = _manifest.verify(session, repo, commitish=args.commit or "HEAD")
    except _manifest.ManifestError as exc:
        print(f"didrun show: {exc}", file=sys.stderr)
        return 2
    if args.html:
        Path(args.html).write_text(render.render_html(report), encoding="utf-8")
        print(f"wrote HTML report to {args.html}")
    else:
        print(render.render_verdict(report))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="didrun",
        description="Flight records for agent-written code: record what ran, verify claims deterministically.",
    )
    p.add_argument("--version", action="version", version=f"didrun {__version__}")
    p.add_argument("--repo", help="repository root (default: cwd)")
    sub = p.add_subparsers(dest="command_name", required=True)

    pr = sub.add_parser("run", help="record a wrapped command execution (Tier 0)")
    pr.add_argument("--shim", action="store_true", help=argparse.SUPPRESS)
    pr.add_argument(
        "--tee",
        action="store_true",
        help=(
            "also write the command's raw output to this terminal as it arrives "
            "(local output only: NOT redacted, never an export)"
        ),
    )
    pr.add_argument(
        "--heartbeat",
        type=float,
        metavar="SECONDS",
        help=(
            "print a progress line to stderr at most every SECONDS "
            "(elapsed, command, bytes drained; no output content)"
        ),
    )
    pr.add_argument("command", nargs=argparse.REMAINDER, help="-- <cmd> [args…]")
    pr.set_defaults(func=cmd_run)

    pc = sub.add_parser("claim", help="declare a structured claim over recorded events")
    # Read from the vocabulary rather than repeated here. The two lists were
    # duplicates, and a duplicate of a closed vocabulary drifts silently: the CLI
    # would keep refusing a type the library had accepted for a release.
    pc.add_argument(
        "type",
        nargs="?",
        choices=list(CLAIM_TYPES),
        help=(
            "the claim type to declare. With --defer it is optional and only "
            "chooses between live claims that share a label"
        ),
    )
    pc.add_argument("--label", help="human label (default: the type)")
    pc.add_argument(
        "--event",
        type=int,
        help=(
            "bind to a specific event index, warning when it is not the most "
            "recent. Default: the most recent event, and a claim is refused "
            "rather than bound to an earlier one when that event did not exit 0"
        ),
    )
    pc.add_argument(
        "--path",
        action="append",
        metavar="PREFIX",
        help=(
            "a repository-relative path prefix (a directory such as 'src/', or one "
            "file) inside which the sealed commit may differ from the tree this "
            "claim's evidence was recorded against — including files the claimed "
            "run itself wrote — and still grade scope-exact. Any difference "
            "outside every declared prefix grades stale, and the reason names "
            "the --path that would cover it. Repeat --path to declare several. "
            "Plain prefixes only: git pathspec magic (':(exclude)…', ':!…') and "
            "globs are refused, not interpreted. You choose the scope; didrun "
            "never judges whether it is the right one"
        ),
    )
    pc.add_argument(
        "--of",
        metavar="LABEL[,LABEL…]",
        help=(
            "for a conjunction: the comma-separated labels of the claims in this "
            "seal window it conjoins. The conjunction is graded as the WORST of "
            "them and can never be better than any one of them; a label that "
            "names no single live claim in the window grades it unknown"
        ),
    )
    pc.add_argument(
        "--defer",
        metavar="LABEL",
        help=(
            "set the live, UNSEALED claim with this label aside from the next "
            "seal's verdict, because it belongs to work that is not in this "
            "commit (an interrupted unit's draft, say). It declares no claim. "
            "The claim stays in the note as record — graded, published with "
            "--reason, and counted on every verdict surface — and is bound to "
            "that one claim, not the label: re-declaring the gate makes a "
            "claim that votes. A claim bound to a command that exited nonzero "
            "is refused: deferral never sets a witnessed failure aside"
        ),
    )
    pc.add_argument(
        "--reason",
        metavar="TEXT",
        help="with --defer (required there): why, published in the note",
    )
    pc.set_defaults(func=cmd_claim)

    pa = sub.add_parser(
        "authorize",
        help=(
            "record a cited authorization artifact for one exceptional scope "
            "(stores the digest, never the bytes; NOT a signature)"
        ),
    )
    pa.add_argument(
        "--artifact",
        required=True,
        help="path to the authorization artifact; its sha256 is recorded, its bytes are not",
    )
    pa.add_argument(
        "--scope",
        required=True,
        choices=list(_manifest.AUTHORITY_SCOPES),
        help=(
            "the exceptional transition this authority covers. There is no scope "
            "for an ordinary seal: an authorisation on the happy path becomes a "
            "rubber stamp"
        ),
    )
    pa.add_argument("--label", required=True, help="what is being authorised, in words")
    pa.add_argument(
        "--principal",
        help=(
            "who is citing it (default: $USER). Recorded as SELF-ASSERTED — "
            "didrun authenticates nobody"
        ),
    )
    pa.add_argument(
        "--expires-after-seals",
        type=int,
        metavar="N",
        help=(
            f"how many seals the citation covers, starting with the next one "
            f"(default: {_manifest.AUTHORITY_DEFAULT_TTL}). There is no value "
            f"meaning 'never' — a standing grant is what this replaces"
        ),
    )
    pa.set_defaults(func=cmd_authorize)

    ps = sub.add_parser("seal", help="compile and attach a commit-bound manifest")
    ps.add_argument("--commit", help="commit to bind (default: HEAD)")
    ps.add_argument("--allow-secrets", action="store_true", help="export despite secret findings (redacted; logged)")
    ps.add_argument("--bundle", help="also write an exportable bundle to this path")
    ps.add_argument(
        "--reseal",
        action="store_true",
        help=(
            "permit replacing this commit's note with a NARROWER record: the "
            "claims the replaced note held and this seal does not are then in "
            "no note at all. Without it, a narrowing re-seal is refused"
        ),
    )
    ps.add_argument(
        "--require-authority",
        action="store_true",
        help=(
            "refuse --allow-secrets or --reseal unless a live cited authority "
            "covers that scope (see `didrun authorize`). Default off: an "
            "authorisation required on every seal becomes a rubber stamp. The "
            "authority it demands is a citation, not an approval"
        ),
    )
    ps.set_defaults(func=cmd_seal)

    pv = sub.add_parser("verify", help="verify a commit's claims against recorded evidence")
    pv.add_argument("--commit", help="commit to verify (default: HEAD)")
    pv.add_argument("--strict", action="store_true", help="exit nonzero unless all claims are recorded-exact (CI mode)")
    pv.add_argument(
        "--require-env-match",
        action="store_true",
        help=(
            "treat environment drift since the seal as a refusal, not a note "
            "(with --strict, a drifted claim exits nonzero). Fingerprints from "
            "an older didrun are incomparable and never count as drift"
        ),
    )
    pv.add_argument("--html", help="also write an HTML report to this path")
    pv.add_argument("--quiet", action="store_true", help="with --html, suppress the terminal verdict")
    pv.set_defaults(func=cmd_verify)

    pw = sub.add_parser("show", help="show the verdict, or session history with --session")
    pw.add_argument("--commit", help="commit to show (default: HEAD)")
    pw.add_argument("--session", action="store_true", help="show the recorded session history (subsumes `log`)")
    pw.add_argument("--html", help="write an HTML report to this path")
    pw.add_argument("--event", type=int, metavar="N", help="event index to read with --output")
    pw.add_argument(
        "--output",
        action="store_true",
        help="print the recorded output of event N to stdout",
    )
    pw.add_argument(
        "--stream",
        choices=["stdout", "stderr"],
        default="stdout",
        help="which recorded stream --output reads (default: stdout)",
    )
    pw.add_argument(
        "--redacted",
        action="store_true",
        help="run --output through the redactor before printing",
    )
    pw.set_defaults(func=cmd_show)

    return p


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except CaptureInterrupted as exc:
        # The event IS on the record — that is what the exception means. One
        # machine-greppable line and the conventional exit code (130 for SIGINT,
        # 143 for SIGTERM), so a caller that used to detect interruption by
        # scraping a traceback gets a better signal than the one it lost.
        print(
            f"didrun: interrupted by {signal_name(exc.signum)} — recorded event "
            f"{exc.event_index} as unobserved (no exit code was witnessed)",
            file=sys.stderr,
        )
        return exc.exit_code
    except KeyboardInterrupt:
        # Backstop for an interrupt outside a wrapped child's lifetime — during
        # a seal, say, where there is no in-flight command to record. A
        # traceback is still the wrong way to report Ctrl-C.
        print("didrun: interrupted (SIGINT)", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
