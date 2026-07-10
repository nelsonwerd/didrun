# didrun capture kill-gate harness

This harness is the instrument didrun's capture **kill-gate** depends on. It is
top of the drop order — gate machinery is never dropped.

## What it measures (S1-S5, machine-cleared)

`recall.py` runs the frozen probe set (`probes/`) against a capture backend and
reports **class-split recall**:

- **defect class** (bare-name PATH execs): must be captured. `< 95%` → PARK.
- **structural** (absolute-path / builtins): escape a PATH shim inherently
  (measured). Tolerated only if the backend *flags* them; a silent gap → PARK.

```bash
python -m harness.recall --self-test   # perfect vs blind backend demo
python -m harness.recall --freeze      # record MANIFEST.sha256 (do once, pre-Phase-0)
python -m harness.recall               # run the REAL didrun backend, exit nonzero on PARK
```

The fixture is hashed so thresholds can't be moved after seeing results.

## S6 — the live-agent leg (HUMAN-cleared gate, NOT run here)

S1-S5 measure invocation *shapes*. They do **not** prove capture works against a
real agent, because that needs a real agent and a real machine. S6 is a human
gate — it is emitted here, never simulated:

> **S6 protocol.** On a real machine with Claude Code (or Codex CLI / aider):
> 1. Start a real agent session under `didrun run` (or with the Tier-2 trap
>    installed and `DIDRUN_SESSION` set).
> 2. Have the agent do real work touching ≥ 2 files and running its test command,
>    including at least one command that FAILS and at least one invoked by
>    absolute path.
> 3. Cross-check: every command in the agent's own tool-call transcript must
>    appear as a captured event with argv + exit for the bare-name class; the
>    failing command must be recorded as failing; the absolute-path command must
>    be graded as a structural miss (flagged, not silent).
> 4. Confirm the shim dir survives the agent's shell-snapshot PATH handling
>    (Claude Code sources a snapshot that may reset PATH — verify the shim still
>    intercepts).
>
> **PARK** if real agents can't run under the wrapper, if the shim dies under the
> shell snapshot, or if defect-class recall on real sessions falls below 95%.

Until S6 is cleared by a human on a real agent, capture feasibility is
**measured for S1-S5 shapes only** — do not read a green S1-S5 run as full
capture validation.

## Also human-gated (emitted, never faked)

- **Linux digest rerun.** All timing/capability numbers are macOS/APFS/arm64.
  Run `python -c "from didrun.gitplumbing import capability_probe; capability_probe()"`
  and `harness`'s digest benchmark on Linux/ext4 before the envelope is normative.
- **First-real-session secrets scan.** Run a real captured session through
  `didrun seal` and confirm the redaction blocker fires (or doesn't) on real
  output — the scanner is a safety net, not a guarantee.
