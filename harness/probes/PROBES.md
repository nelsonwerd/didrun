# Frozen capture probes (S1-S5)

These probe definitions are the class-split kill-gate fixture. They encode the
real agent-spawn shapes documented in `docs/MEASUREMENTS.md`.
The set is frozen by `MANIFEST.sha256`; `harness/recall.py --freeze` records the
hash, and the gate refuses to move thresholds against an altered fixture.

| Probe | Shape | Miss class | Why |
|-------|-------|-----------|-----|
| S1 | `/bin/sh -c "<bare> …"` | defect | aider-style `subprocess(shell=True)`; MUST be captured |
| S2 | `/bin/bash -c "<bare> …"` | defect | node/Claude-style bash `-c`; MUST be captured |
| S3 | direct bare-name exec via PATH | defect | the simplest capturable case |
| S4 | `/bin/sh -c "<abspath> …"` | structural | absolute-path escapes a PATH shim (measured 100% miss) |
| S5 | direct absolute-path exec | structural | same — inherent to `execve`, not a fixable bug |

**Gate:** defect-class recall ≥ 95% or PARK (80-95% = tier-downgrade note). A
structural miss is tolerated ONLY if the backend flags it; a *silent* structural
gap is disqualifying regardless of recall (the unexplained-tree-delta principle).

The definitions live in code (`harness/recall.py::PROBES`) so they are executable;
this file is the human-readable freeze record and is part of the hashed fixture.
