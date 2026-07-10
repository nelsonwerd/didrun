"""didrun command-line interface.

Five commands: run, claim, seal, verify, show.
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
from .ledger import Session
from .capture import run_wrapped, DIDRUN_ACTIVE_ENV
from .claims import Claim
from . import manifest as _manifest
from . import render
from . import gitplumbing


def _ledger_dir(repo: Path) -> Path:
    return Path(repo) / ".didrun"


def _session(repo: Path) -> Session:
    return Session(_ledger_dir(repo))


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
    event = run_wrapped(list(args.command), session, repo)
    coverage = "shim" if args.shim else "wrapper"
    print(
        f"recorded {coverage} event  argv={' '.join(event.argv)!r}  "
        f"exit={event.exit_code}  "
        f"tree {(event.tree_after or '(none)')[:12]}"
    )
    return event.exit_code if event.exit_code is not None else 0


def cmd_claim(args) -> int:
    repo = Path(args.repo or os.getcwd())
    session = _session(repo)
    events = session.events()
    if not events:
        print("didrun claim: no recorded events to bind to (run something first)", file=sys.stderr)
        return 2
    # Default: bind to the most recent successful event.
    if args.event is not None:
        indices = (args.event,)
    else:
        indices = tuple(
            i for i, ev in enumerate(events) if ev.exit_code == 0
        )[-1:]  # last success
    if not indices:
        print("didrun claim: no successful event to bind (last command did not exit 0)", file=sys.stderr)
        return 2
    try:
        claim = Claim(
            ctype=args.type,
            label=args.label or args.type,
            event_indices=indices,
            pathspecs=tuple(args.path or ()),
            declared_at_index=len(events) - 1,
        )
    except Exception as exc:
        print(f"didrun claim: {exc}", file=sys.stderr)
        return 2
    _manifest.declare_claim(session, claim)
    print(f"declared claim {claim.ctype} ({claim.label}) bound to event(s) {list(indices)}")
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
        )
    except _manifest.redact.SecretsBlocked as exc:
        print(f"didrun seal: {exc}", file=sys.stderr)
        return 3
    except _manifest.ManifestError as exc:
        print(f"didrun seal: {exc}", file=sys.stderr)
        return 2
    verified = sum(1 for c in m.claims if c["grade"] in ("tree-exact", "scope-exact"))
    print(
        f"sealed manifest for {m.commit[:12]} (tree {m.tree[:12]})  "
        f"{verified}/{len(m.claims)} claims recorded-exact"
        + ("  [--allow-secrets]" if m.secrets_override else "")
    )
    return 0


def cmd_verify(args) -> int:
    repo = Path(args.repo or os.getcwd())
    session = _session(repo)
    report = _manifest.verify(session, repo, commitish=args.commit or "HEAD")
    if args.html:
        Path(args.html).write_text(render.render_html(report), encoding="utf-8")
        print(f"wrote HTML report to {args.html}")
        if not args.quiet:
            print(render.render_verdict(report))
    else:
        print(render.render_verdict(report))
    if args.strict:
        return 0 if report.all_verified else 1
    return 0


def cmd_show(args) -> int:
    repo = Path(args.repo or os.getcwd())
    session = _session(repo)
    if args.session:
        # Session history view (subsumes the old `log` command).
        entries = list(session.entries())
        if not entries:
            print("no recorded events")
            return 0
        ok, broke = session.verify_chain()
        chain = "intact" if ok else f"BROKEN at index {broke}"
        print(f"session: {len(entries)} events  chain {chain}")
        for e in entries:
            ev = e.event
            exit_txt = f"exit {ev.exit_code}" if ev.exit_code is not None else "no-exit"
            print(
                f"  [{e.index}] {ev.observed_via:<10} {ev.coverage:<18} "
                f"{exit_txt:<8} {' '.join(ev.argv)[:60]}"
            )
        return 0 if ok else 1
    # Default: the verdict view for a commit.
    report = _manifest.verify(session, repo, commitish=args.commit or "HEAD")
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
    pr.add_argument("command", nargs=argparse.REMAINDER, help="-- <cmd> [args…]")
    pr.set_defaults(func=cmd_run)

    pc = sub.add_parser("claim", help="declare a structured claim over recorded events")
    pc.add_argument("type", choices=["command-succeeded", "tests-pass", "lint-clean"])
    pc.add_argument("--label", help="human label (default: the type)")
    pc.add_argument("--event", type=int, help="bind to a specific event index")
    pc.add_argument("--path", action="append", help="declare a pathspec for scope-exact grading")
    pc.set_defaults(func=cmd_claim)

    ps = sub.add_parser("seal", help="compile and attach a commit-bound manifest")
    ps.add_argument("--commit", help="commit to bind (default: HEAD)")
    ps.add_argument("--allow-secrets", action="store_true", help="export despite secret findings (redacted; logged)")
    ps.add_argument("--bundle", help="also write an exportable bundle to this path")
    ps.set_defaults(func=cmd_seal)

    pv = sub.add_parser("verify", help="verify a commit's claims against recorded evidence")
    pv.add_argument("--commit", help="commit to verify (default: HEAD)")
    pv.add_argument("--strict", action="store_true", help="exit nonzero unless all claims are recorded-exact (CI mode)")
    pv.add_argument("--html", help="also write an HTML report to this path")
    pv.add_argument("--quiet", action="store_true", help="with --html, suppress the terminal verdict")
    pv.set_defaults(func=cmd_verify)

    pw = sub.add_parser("show", help="show the verdict, or session history with --session")
    pw.add_argument("--commit", help="commit to show (default: HEAD)")
    pw.add_argument("--session", action="store_true", help="show the recorded session history (subsumes `log`)")
    pw.add_argument("--html", help="write an HTML report to this path")
    pw.set_defaults(func=cmd_show)

    return p


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
