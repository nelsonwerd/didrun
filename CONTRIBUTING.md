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
python -m pytest -q            # the suite must stay green (0.2.0: 496 passed, 4 skipped)
python -m harness.recall       # the capture kill-gate must PASS, freeze INTACT
```

The four skips are the real-corpus compat legs, and they stay skipped unless
`DIDRUN_COMPAT_CORPUS` points at a **copy** of an archive tree — never a live one;
`tests/compat` refuses a live tree by name. A green synthetic run is not corpus
validation, which is why the harness prints `corpus: SKIPPED (unverified)` rather
than let a green line imply it.

CI runs exactly those two commands on ubuntu + macOS × Python 3.11 / 3.12 / 3.13. It
does **not** reproduce anything in [docs/MEASUREMENTS.md](docs/MEASUREMENTS.md): those
numbers are one machine, macOS / CPython 3.14, and a PR that moves them has to say
where it measured.

- Determinism is a hard invariant: no wall-clock or randomness in the trust path
  (capture → ledger → seal → verify). A test that is not reproducible is a bug.
- New behavior needs a test. New capture mechanisms must be measured, not asserted —
  add them to the harness and cite numbers (see [docs/MEASUREMENTS.md](docs/MEASUREMENTS.md)).
- **Anything that changes what is written to disk or published as a note belongs in
  [docs/COMPAT.md](docs/COMPAT.md)**, with the reasoning. A new manifest key is additive
  and read with `.get()`; changing an existing field's type or meaning, or the
  claim-type vocabulary, bumps `MANIFEST_VERSION` — and the consequence gets stated,
  because an older reader then refuses the note by design.
- Match the surrounding style; keep comments minimal and load-bearing.

## Three things are frozen, and a PR that edits them fails CI by design

- **The v1 chain preimage** (`ledger._PREIMAGE_FIELDS`). A golden test recomputes a
  known entry hash from a fixed event, so changing the field set fails that test
  instead of silently invalidating every `entry_hash` ever written. Do not regenerate
  the literal to make it pass — define a *new* preimage version and leave version 1
  alone.
- **The probe fixture** (`harness/probes/`, hashed into `MANIFEST.sha256`). The hash
  covers `PROBES.md` too, so editing that prose breaks the freeze and the kill-gate
  reports `MISSING/TAMPERED`. `--freeze` re-records the hash and exists for adding
  probes, never for making a red gate green.
- **Two sentences of README.md**, pinned as string literals in
  `tests/test_projection_contract.py`: the claim about what redaction covers, and the
  caveat that makes it true. Reword either and the suite fails. Extract the new string
  *from the file* rather than retyping it, and keep both halves — those assertions
  exist because a reassuring sentence once outlived the behaviour it described.

## Good first areas

- **Linux and Windows numbers.** CI now runs the *suite* on ubuntu, but every
  measurement in the docs is macOS/APFS/arm64. Run
  `python -c "from didrun.gitplumbing import capability_probe; capability_probe()"` and
  the digest benchmark on your platform and report numbers. Windows is untested end to
  end: `chmod` is close to a no-op there and `fcntl` is absent, so the ledger-permission
  and append-lock guarantees both degrade — [docs/COMPAT.md](docs/COMPAT.md) says where.
- **Tier-1/2/3 wiring** — the shim and per-shell trap generators exist as library
  functions; a user-facing `install`/`hooks` command is not built yet.
- **Additional secret patterns** for the redaction scanner (with false-positive tests).
- **The known-open defects** are listed with their shapes in
  [docs/V02_STATUS.md](docs/V02_STATUS.md). K1 — two operational errors leave a
  traceback with exit 1 where the same binary gives a graded exit 2 elsewhere — is about
  an hour's work and a good first PR.
