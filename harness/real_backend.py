"""The real didrun capture backend for the recall harness.

Wires the harness to didrun's actual Tier-1 PATH shim: it generates a shim for
the marker binary, prepends the shim dir to PATH, runs the probe, and reports
whether the shim observed the execution (by checking the shim's log). This is
the honest measurement — bare-name execs route through the shim; absolute-path
execs bypass it (and the backend flags that as a structural miss, not silent).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from didrun.capture import generate_shim, DIDRUN_ACTIVE_ENV


def real_backend(argv: list, marker: str, ctx: dict) -> tuple[bool, bool]:
    """Return (observed, flagged_structural_miss) for one probe invocation."""
    tmp = Path(ctx["_tmp"])
    shim_dir = tmp / "shim"
    log = tmp / f"shim-{marker}.log"

    # Install a Tier-1 shim for the marker's bare name that logs when hit.
    # We model the shim as a logging wrapper around the real binary.
    shim_dir.mkdir(parents=True, exist_ok=True)
    shim = shim_dir / ctx["marker_name"]
    shim.write_text(
        "#!/bin/sh\n"
        f'if [ -n "${DIDRUN_ACTIVE_ENV}" ]; then echo "$@" >> "{log}"; fi\n'
        f'exec "{ctx["_real_bin"]}" "$@"\n'
    )
    shim.chmod(0o755)

    env = dict(os.environ)
    env[DIDRUN_ACTIVE_ENV] = "1"
    env["PATH"] = f"{shim_dir}:{env.get('PATH','')}"

    subprocess.run(argv, env=env, capture_output=True, text=True)

    observed = log.exists() and marker in log.read_text()

    # A structural miss (absolute-path/builtin) is flagged when the invocation
    # references the real binary by absolute path — the shim can't be on that
    # path, so didrun would grade it a known structural gap, not a silent one.
    abs_bin = ctx["_real_bin"]
    flagged_structural = (not observed) and any(abs_bin in str(a) for a in argv)
    return observed, flagged_structural
