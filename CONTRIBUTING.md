# Contributing to didrun

Thanks for looking. didrun is early-stage and `v0.x`; issues, reproductions, and
focused PRs are welcome.

## Ground rules that are load-bearing

didrun's whole value is that it does not exaggerate. Two rules protect that, and a
PR that violates either will be asked to change:

1. **The runtime is stdlib-only.** `src/didrun/` must import nothing outside the
   Python standard library. Auditability is the trust wedge — anyone should be able
   to read the whole thing. (`pytest` is the only dev dependency.)
2. **Never overclaim.** No code, help text, or doc may say "proven", "certified", or
   "guaranteed". A grade of `tree-exact` means "recorded against the sealed tree",
   never "verified true". See [docs/TRUST_MODEL.md](docs/TRUST_MODEL.md).

## Developing

```bash
python -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest -q            # the suite must stay green
python -m harness.recall       # the capture kill-gate must PASS
```

- Determinism is a hard invariant: no wall-clock or randomness in the trust path
  (capture → ledger → seal → verify). A test that is not reproducible is a bug.
- New behavior needs a test. New capture mechanisms must be measured, not asserted —
  add them to the harness and cite numbers (see [docs/MEASUREMENTS.md](docs/MEASUREMENTS.md)).
- Match the surrounding style; keep comments minimal and load-bearing.

## Good first areas

- **Linux/Windows capability matrix** — run `python -c "from didrun.gitplumbing import capability_probe; capability_probe()"` and the digest benchmark on your platform and report numbers.
- **Tier-1/2/3 wiring** — the shim and per-shell trap generators exist as library
  functions; a user-facing `install`/`hooks` command is not built yet.
- **Additional secret patterns** for the redaction scanner (with false-positive tests).
