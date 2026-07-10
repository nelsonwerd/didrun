"""P0.1 — the capture kill-gate harness: classification, freeze, real backend."""

from __future__ import annotations

from harness import recall
from harness.recall import run_recall, RecallResult, PROBES, MISS_DEFECT, MISS_STRUCTURAL


def test_perfect_backend_passes():
    res = run_recall(recall._perfect_backend)
    assert res.defect_recall == 1.0
    assert res.verdict == "PASS"


def test_blind_backend_parks():
    res = run_recall(recall._blind_backend)
    assert res.defect_recall == 0.0
    assert res.verdict == "PARK"


def test_structural_miss_flagged_is_not_park():
    """A backend that captures all defect-class probes and FLAGS its structural
    misses passes — structural misses are inherent, silent gaps are not."""

    def backend(argv, marker, ctx):
        # Observe bare-name (defect); miss absolute-path but flag it.
        abs_bin = ctx["_real_bin"]
        is_abs = any(abs_bin in str(a) for a in argv)
        if is_abs:
            return (False, True)  # missed but flagged
        return (True, False)

    res = run_recall(backend)
    assert res.defect_recall == 1.0
    assert not res.unflagged_structural
    assert res.verdict == "PASS"


def test_silent_structural_gap_parks():
    """A structural miss that is NOT flagged is disqualifying regardless of
    defect recall (the unexplained-tree-delta principle)."""

    def backend(argv, marker, ctx):
        abs_bin = ctx["_real_bin"]
        is_abs = any(abs_bin in str(a) for a in argv)
        if is_abs:
            return (False, False)  # missed AND silent
        return (True, False)

    res = run_recall(backend)
    assert res.unflagged_structural
    assert res.verdict == "PARK"


def test_freeze_detects_tamper(tmp_path):
    probes = tmp_path / "probes"
    probes.mkdir()
    (probes / "a.txt").write_text("probe content\n")
    h = recall.manifest_hash(probes)
    (probes / "MANIFEST.sha256").write_text(h + "\n")
    assert recall.verify_freeze(probes)
    # Tamper a probe file.
    (probes / "a.txt").write_text("tampered\n")
    assert not recall.verify_freeze(probes)


def test_real_backend_captures_barename_misses_abspath():
    """The real Tier-1 shim backend: bare-name captured, absolute-path missed
    but flagged — the measured behavior in docs/MEASUREMENTS.md."""
    from harness.real_backend import real_backend

    res = run_recall(real_backend)
    # Defect class (bare-name) should be fully captured by the shim.
    assert res.defect_recall == 1.0, res.observed
    # Structural (absolute-path) missed but flagged → not a park.
    assert not res.unflagged_structural
    assert res.verdict == "PASS"
