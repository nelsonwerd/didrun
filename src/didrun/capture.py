"""Tiered, vendor-neutral session capture.

Only Tier 0 — ``didrun run -- <cmd>`` — guarantees complete capture, and it is
the trust core. The other tiers are enrichment with honest coverage grades; the
measured reason invisible/universal capture is impossible is in
docs/MEASUREMENTS.md (absolute-path execs escape a
PATH shim 100% of the time; a PTY transcript yields no argv/exit).

  Tier 0  didrun run -- <cmd>   complete argv/exit/output/timing        (this file)
  Tier 1  PATH shim             bare-name execs only (structural misses) (generator here)
  Tier 2  per-shell trap        bash BASH_ENV / zsh ~/.zshenv, env-gated  (installers here)
  Tier 3  native adapter        enrichment only                          (adapters/)

The PTY transcript is a *human-facing* artifact, graded ``display-only``: it can
read "tests: 5 passed" for a command that exited 3, so it must never carry an
exit code. That invariant is enforced in ledger.Event.
"""

from __future__ import annotations

import hashlib
import os
import selectors
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from .ledger import Event, Session
from . import gitplumbing

# Environment variables whose presence/identity is safe to fingerprint. We hash
# a sorted allowlist rather than the raw environment so the fingerprint never
# leaks a secret (redaction of captured *output* is a separate pass; see redact.py).
_ENV_FINGERPRINT_KEYS = ("PATH", "SHELL", "LANG", "PWD", "VIRTUAL_ENV")

# The env var that gates Tier-2 traps. The trap does nothing unless this is set,
# and it is set ONLY by `didrun run`, so an installed trap never records an
# unrelated shell session on the machine (the privacy gate).
DIDRUN_ACTIVE_ENV = "DIDRUN_SESSION"


def env_fingerprint(env: Optional[dict] = None) -> str:
    env = env if env is not None else os.environ
    parts = []
    for key in _ENV_FINGERPRINT_KEYS:
        val = env.get(key, "")
        parts.append(f"{key}={val}")
    return hashlib.sha256("\n".join(parts).encode("utf-8", "replace")).hexdigest()[:16]


def run_wrapped(argv: list[str], session: Session, repo: Optional[Path] = None) -> Event:
    """Tier 0: run a command under direct capture and record a complete Event.

    Captures argv, cwd, an env fingerprint, exit code, stdout/stderr as blobs,
    and git tree digests before and after. This is the only path that witnesses
    a real exit code, so its events are ``coverage="complete"``,
    ``observed_via="wrapper"``.
    """
    repo = Path(repo or os.getcwd())
    ledger_objects = session.blobs.root  # digest objects live beside blobs

    tree_before = gitplumbing.tree_digest(repo, ledger_objects)
    submod = gitplumbing.submodule_dirty(repo)

    started = time.time()
    proc = subprocess.run(argv, cwd=str(repo), capture_output=True)
    ended = time.time()

    tree_after = gitplumbing.tree_digest(repo, ledger_objects)

    stdout_digest = session.blobs.put(proc.stdout)
    stderr_digest = session.blobs.put(proc.stderr)

    event = Event(
        argv=tuple(argv),
        cwd=str(repo),
        env_fingerprint=env_fingerprint(),
        observed_via="wrapper",
        coverage="complete",
        exit_code=proc.returncode,
        started_at=started,
        ended_at=ended,
        stdout_blob=stdout_digest,
        stderr_blob=stderr_digest,
        tree_before=tree_before,
        tree_after=tree_after,
        submodule_dirty=submod,
    )
    session.append(event)
    return event


def pty_transcript(argv: list[str], session: Session, repo: Optional[Path] = None) -> Event:
    """Capture a PTY transcript as a human-facing artifact (display-only).

    The raw terminal byte stream is stored as a blob. Per the measured PTY
    limit, we do NOT recover argv semantics or an exit code from the stream, so
    the event is ``coverage="display-only"``, ``observed_via="transcript"`` and
    carries no exit code — enforced by ledger.Event.
    """
    import pty

    repo = Path(repo or os.getcwd())
    chunks: list[bytes] = []

    def _read(fd: int) -> bytes:
        try:
            data = os.read(fd, 65536)
        except OSError:
            return b""
        chunks.append(data)
        return data

    # pty.spawn echoes to our stdout and pumps the child through a pty; the
    # read callback tees the bytes into `chunks` for the transcript blob.
    pty.spawn(argv, _read)

    transcript = b"".join(chunks)
    digest = session.blobs.put(transcript)

    event = Event(
        argv=tuple(argv),
        cwd=str(repo),
        env_fingerprint=env_fingerprint(),
        observed_via="transcript",
        coverage="display-only",
        exit_code=None,  # invariant: a transcript never claims an exit code
        transcript_blob=digest,
        tree_before=None,
        tree_after=None,
    )
    session.append(event)
    return event


# --- Tier 1: PATH shim generator ---------------------------------------------
#
# Honest scope (measured): a PATH shim observes only bare-name, PATH-resolved
# execs. Absolute-path invocations and shell builtins escape 100% of the time.
# The shim re-dispatches a bare-name command through Tier 0 so it is captured
# completely; anything it cannot see is graded as a structural miss, never
# silently dropped.

_SHIM_TEMPLATE = """#!/bin/sh
# didrun Tier-1 shim for `{name}`. Generated — do not edit.
# Re-dispatches through `didrun run` ONLY when a didrun session is active,
# so an installed shim never records unrelated shell activity (privacy gate).
if [ -n "${active_env}" ] && [ -x "{didrun_bin}" ]; then
  exec "{didrun_bin}" run --shim -- "{real}" "$@"
fi
exec "{real}" "$@"
"""


def generate_shim(name: str, real_path: str, didrun_bin: str, out_dir: Path) -> Path:
    """Write a PATH shim for a bare command name. Returns the shim path.

    The shim is inert unless ``DIDRUN_SESSION`` is set (the privacy gate) and
    the real binary is resolved by absolute path so the shim never recurses.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    shim = out_dir / name
    shim.write_text(
        _SHIM_TEMPLATE.format(
            name=name,
            real=real_path,
            didrun_bin=didrun_bin,
            active_env=DIDRUN_ACTIVE_ENV,
        )
    )
    shim.chmod(0o755)
    return shim


# --- Tier 2: per-shell trap installers ---------------------------------------
#
# Measured (docs/MEASUREMENTS.md): Claude Code spawns the user's $SHELL per
# command. bash honors BASH_ENV non-interactively; zsh sources ~/.zshenv and a
# DEBUG trap there fires (preexec does not, non-interactively). Both are gated
# on DIDRUN_SESSION so they are dead unless `didrun run` set it — otherwise the
# trap would observe every shell session on the machine (a privacy incident for
# a trust tool). fish/dash/`/bin/sh` are unsupported and reported as gaps.

_BASH_TRAP = """# didrun Tier-2 bash trap (generated). Inert unless DIDRUN_SESSION is set.
if [ -n "${DIDRUN_SESSION:-}" ] && [ -n "${DIDRUN_LOG:-}" ]; then
  trap 'printf "%s\\t%s\\n" "$?" "$BASH_COMMAND" >> "$DIDRUN_LOG" 2>/dev/null' DEBUG
fi
"""

_ZSH_TRAP = """# didrun Tier-2 zsh trap (generated). Inert unless DIDRUN_SESSION is set.
if [[ -n "${DIDRUN_SESSION:-}" && -n "${DIDRUN_LOG:-}" ]]; then
  trap 'print -r -- "$ZSH_DEBUG_CMD" >> "$DIDRUN_LOG" 2>/dev/null' DEBUG
fi
"""


def tier2_snippet(shell: str) -> str:
    """Return the gated trap snippet for a shell, or raise for unsupported ones."""
    shell = os.path.basename(shell)
    if shell == "bash":
        return _BASH_TRAP
    if shell == "zsh":
        return _ZSH_TRAP
    raise ValueError(
        f"Tier-2 capture unsupported for shell {shell!r} "
        "(bash and zsh only; fish/dash/sh are honest gaps)"
    )
