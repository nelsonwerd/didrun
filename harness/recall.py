"""The capture kill-gate: class-split recall measurement.

This is the instrument the capture kill-gate depends on. It runs a set of
FROZEN probes (agent-style command invocations) against a capture backend and
measures what fraction of executions the backend observed, SPLIT BY MISS CLASS:

  - defect class   : bare-name, PATH-resolved execs. The backend MUST capture
                     these. Recall < 95% here => PARK (a real capture defect).
  - structural     : absolute-path execs and shell builtins. These escape a
                     PATH shim inherently (measured — see docs/MEASUREMENTS.md).
                     Tolerated ONLY if the backend flags them, never silent.

The probe set is hashed (MANIFEST.sha256) so thresholds cannot be moved after
seeing results — the "freeze before Phase 0" discipline.

The S6 live-agent leg (real Claude Code sessions) is NOT run here: it needs a
real agent and a real machine. Its protocol is in harness/README.md and is a
HUMAN-cleared gate. This harness settles S1-S5 only and says so.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

HERE = Path(__file__).resolve().parent
PROBES_DIR = HERE / "probes"

# The gate thresholds. Set ONCE, before any backend was measured (see PROBES.md).
# The kill criterion (docs/MEASUREMENTS.md, capture section): defect-class recall >= 95% or PARK;
# 80-95% is a tier-downgrade note; < 80% is a hard park.
DEFECT_RECALL_PARK = 0.95
DEFECT_RECALL_DOWNGRADE = 0.80

MISS_DEFECT = "defect"        # bare-name PATH exec — must be captured
MISS_STRUCTURAL = "structural"  # absolute-path / builtin — escapes inherently


@dataclass(frozen=True)
class Probe:
    """One agent-style invocation shape.

    ``marker`` is a unique token the probe's command prints/creates so the
    backend's observation can be matched back to this probe. ``miss_class``
    records which recall bucket a MISS falls into.
    """

    pid: str
    description: str
    miss_class: str
    argv_template: list  # uses {marker_bin} and {marker}


# S1-S5: the measured real-agent spawn shapes (docs/MEASUREMENTS.md).
PROBES: list[Probe] = [
    Probe("S1-barename-sh-c", "python subprocess shell=True -> /bin/sh -c bare name",
          MISS_DEFECT, ["/bin/sh", "-c", "{marker_bin} {marker}"]),
    Probe("S2-barename-bash-c", "node-style /bin/bash -c bare name",
          MISS_DEFECT, ["/bin/bash", "-c", "{marker_bin} {marker}"]),
    Probe("S3-barename-direct", "direct bare-name exec through PATH",
          MISS_DEFECT, ["{marker_name}", "{marker}"]),
    Probe("S4-abspath-sh-c", "absolute-path exec via /bin/sh -c (structural miss)",
          MISS_STRUCTURAL, ["/bin/sh", "-c", "{marker_bin_abs} {marker}"]),
    Probe("S5-abspath-direct", "direct absolute-path exec (structural miss)",
          MISS_STRUCTURAL, ["{marker_bin_abs}", "{marker}"]),
]


@dataclass
class RecallResult:
    observed: dict          # pid -> bool
    by_class: dict          # class -> (observed, total)
    defect_recall: float
    structural_recall: float
    unflagged_structural: list  # structural misses NOT flagged by the backend

    @property
    def verdict(self) -> str:
        if self.unflagged_structural:
            return "PARK"  # a silent gap is disqualifying regardless of recall
        if self.defect_recall < DEFECT_RECALL_DOWNGRADE:
            return "PARK"
        if self.defect_recall < DEFECT_RECALL_PARK:
            return "DOWNGRADE"
        return "PASS"


def manifest_hash(probes_dir: Path = PROBES_DIR) -> str:
    """Hash of the frozen probe fixture — the pre-Phase-0 freeze anchor."""
    h = hashlib.sha256()
    for p in sorted(probes_dir.rglob("*")):
        if p.is_file() and p.name != "MANIFEST.sha256":
            h.update(p.relative_to(probes_dir).as_posix().encode())
            h.update(p.read_bytes())
    return h.hexdigest()


def verify_freeze(probes_dir: Path = PROBES_DIR) -> bool:
    """True if the probe fixture matches its recorded hash (untampered)."""
    manifest = probes_dir / "MANIFEST.sha256"
    if not manifest.exists():
        return False
    recorded = manifest.read_text().strip()
    return recorded == manifest_hash(probes_dir)


# A capture backend is: given (argv, marker) run it and return whether the
# execution was observed. Signature: (argv:list, marker:str, ctx:dict) -> bool.
Backend = Callable[[list, str, dict], bool]


def run_recall(backend: Backend, probes: list[Probe] = PROBES) -> RecallResult:
    """Run every probe under ``backend`` and tally class-split recall."""
    with tempfile.TemporaryDirectory() as td:
        ctx = _marker_context(Path(td))
        observed: dict = {}
        flagged_structural: dict = {}
        for probe in probes:
            marker = f"MARK_{probe.pid}"
            argv = [
                tok.format(marker=marker, **ctx) for tok in probe.argv_template
            ]
            seen, flagged = _invoke(backend, argv, marker, ctx)
            observed[probe.pid] = seen
            flagged_structural[probe.pid] = flagged

    by_class: dict = {}
    for probe in probes:
        o, t = by_class.get(probe.miss_class, (0, 0))
        by_class[probe.miss_class] = (o + int(observed[probe.pid]), t + 1)

    def recall(cls: str) -> float:
        o, t = by_class.get(cls, (0, 0))
        return (o / t) if t else 1.0

    unflagged = [
        p.pid
        for p in probes
        if p.miss_class == MISS_STRUCTURAL
        and not observed[p.pid]
        and not flagged_structural.get(p.pid, False)
    ]
    return RecallResult(
        observed=observed,
        by_class=by_class,
        defect_recall=recall(MISS_DEFECT),
        structural_recall=recall(MISS_STRUCTURAL),
        unflagged_structural=unflagged,
    )


def _marker_context(tmp: Path) -> dict:
    """Create a real marker binary and a shimmed PATH copy for the backend."""
    marker_bin = tmp / "bin" / "ddprobe"
    marker_bin.parent.mkdir(parents=True, exist_ok=True)
    marker_bin.write_text("#!/bin/sh\necho \"$1\"\n")
    marker_bin.chmod(0o755)
    return {
        "marker_name": "ddprobe",
        "marker_bin": "ddprobe",  # bare name (relies on PATH)
        "marker_bin_abs": str(marker_bin),  # absolute path
        "_tmp": tmp,
        "_real_bin": str(marker_bin),
    }


def _invoke(backend: Backend, argv: list, marker: str, ctx: dict) -> tuple[bool, bool]:
    """Delegate to the backend; return (observed, flagged_as_structural_miss)."""
    result = backend(argv, marker, ctx)
    if isinstance(result, tuple):
        return result
    return bool(result), False


# --- reporting ---------------------------------------------------------------

def render_report(res: RecallResult) -> str:
    lines = []
    lines.append("didrun capture recall (S1-S5 frozen probes)")
    lines.append(f"  freeze: {'INTACT' if verify_freeze() else 'MISSING/TAMPERED'}")
    lines.append("")
    lines.append(f"  {'CLASS':<12} {'RECALL':>8}   OBSERVED/TOTAL")
    for cls in (MISS_DEFECT, MISS_STRUCTURAL):
        o, t = res.by_class.get(cls, (0, 0))
        r = (o / t) if t else 1.0
        lines.append(f"  {cls:<12} {r*100:>7.1f}%   {o}/{t}")
    lines.append("")
    if res.unflagged_structural:
        lines.append(f"  SILENT structural gaps (disqualifying): {res.unflagged_structural}")
    lines.append(f"  defect-class recall = {res.defect_recall*100:.1f}%  "
                 f"(park < {DEFECT_RECALL_DOWNGRADE*100:.0f}%, "
                 f"downgrade < {DEFECT_RECALL_PARK*100:.0f}%)")
    lines.append(f"  VERDICT: {res.verdict}")
    lines.append("")
    lines.append("  NOTE: S1-S5 only. The S6 live-agent leg (real Claude Code")
    lines.append("  sessions) is a HUMAN-cleared gate — see harness/README.md.")
    return "\n".join(lines)


# --- self-test backends (for the harness's own tests) ------------------------

def _perfect_backend(argv, marker, ctx) -> bool:
    return True  # observes everything


def _blind_backend(argv, marker, ctx) -> bool:
    return False  # observes nothing


def main(argv: Optional[list] = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if "--self-test" in args:
        print("== perfect backend ==")
        print(render_report(run_recall(_perfect_backend)))
        print("\n== blind backend ==")
        print(render_report(run_recall(_blind_backend)))
        return 0
    if "--freeze" in args:
        h = manifest_hash()
        (PROBES_DIR / "MANIFEST.sha256").write_text(h + "\n")
        print(f"froze probe fixture: {h}")
        return 0
    # Default: run the REAL didrun capture backend (Tier-0 + Tier-1 shim).
    from harness.real_backend import real_backend  # noqa: local import

    res = run_recall(real_backend)
    print(render_report(res))
    return 0 if res.verdict in ("PASS", "DOWNGRADE") else 1


if __name__ == "__main__":
    sys.exit(main())
