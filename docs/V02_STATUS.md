# didrun v0.2 — release readiness, stated honestly

**As of 2026-07-29, commit `49a8b74` on `v0.2-hardening`.** Nineteen units landed across six phases. This
document exists because the difference between *"we shipped the code"* and *"we know it works"* is the only
thing a trust tool actually sells, and the two are not the same size here.

Read this before deciding to release. It is deliberately unflattering.

Two conventions used throughout, because the whole product depends on them:

- **`tree-exact` means "recorded against the sealed tree."** It has never meant "proven correct."
- **UNRECEIPTED** means a command was run without the didrun wrapper, so no receipt backs it. Everything in
  the *Verified* section below is UNRECEIPTED: the wrapper discipline is suspended while hardening didrun
  itself, for the obvious reason.

---

## VERIFIED — what was actually demonstrated, and how

The gates, all run at `49a8b74` on CPython 3.14.5 / macOS arm64:

| Gate | Result |
|---|---|
| `python -m pytest -q` | **496 passed, 4 skipped** (the 4 skips are exactly the real-corpus legs) |
| `python -m harness.recall` — the CI kill-gate | **PASS**, probe freeze INTACT, defect-class recall **100.0% (3/3)** |
| `python -m pytest -q tests/compat` | 11 passed, 4 skipped; synthetic legs report **0 note violations**, **0 layout residue**, **0 multi-index claims** |
| 3.11 grammar parse over all 41 `*.py` | clean. **Syntax only** — it cannot catch a 3.12+ stdlib API |
| stdlib-only | 24 top-level imports in `src/` + `harness/`, **none** outside the stdlib; `dependencies = []` |
| no private paths in shipped files | clean; the only `/home/...` strings are a public CI shape and an explicit `example` |

Beyond the gates, the real CLI was walked end-to-end in throwaway repos and **30 distinct properties were
observed directly**, quoted verbatim in `docs/COMPAT_REPLAY.md`. The load-bearing ones:

**The headline defect is closed, and I watched it close.** The attack v0.2 exists to stop — seal three
claims, delete the ledger, run three unrelated commands that exit 0 against the same tree, then verify —
now returns `WITNESS-UNAVAIL` on all three, **0/3 evidence-bound**, `--strict` exit 1. The pre-P1.2
behaviour was `3/3 recorded-exact`, exit 0. That is the whole point of the release and it is measured, not
argued.

**Every earlier phase's headline property still holds after P3–P5 landed on top of it.** Re-checked
individually, not assumed:

- **Seal is fail-closed and all-or-nothing.** With note publication made to fail for real (the git object
  store set unwritable), `seal` exits **2**, quotes git's error, and writes **no `seals.jsonl` line, no
  note, and no watermark file**. Restore the permission and the same seal succeeds and verifies green. A
  failed seal leaves nothing behind that a later seal would silently skip.
- **A substituted ledger fails closed** (above), and **forging the note's own rows makes the verdict
  worse, not better**: rewriting a stored `grade` to `tree-exact` and zeroing the evidence hash yields
  `WITNESS-UNAVAIL`, 0/1 evidence-bound.
- **Interrupts never lose a flight.** SIGINT → exit 130, SIGTERM → exit 143, one greppable line each, no
  traceback, the in-flight event recorded as `unobserved  no-exit`, `chain intact`, and the next `run`
  appends normally.
- **Ledger permissions hold**: `drwx------`, `session.log` `-rw-------`.
- **Concurrent appends are safe and do not serialize.** Six parallel runs produced six events with the
  chain intact, and a second `run` finished in **0.38 s** while a five-second run held the session.
- **A torn log refuses instead of writing past the tear** — named byte offset, spelled-out recovery,
  nothing appended. (Its delivery is a defect; see K1.)

**And the new v0.2 surfaces do what they say.** A note body of **1,819,948 bytes** — fourteen times the
largest note in the real corpus, and far past `ARG_MAX` — publishes, re-resolves and parses. A malformed
note is a **graded refusal with exit 2** across every shape tried (six bad `version` types, a string where
a claim object belongs, a truncated body, an unknown claim type, a retired claim type): no traceback, and
critically **no false green** — the `{"version": true}` class that used to verify green now refuses.
Supersession retains the retired claim in the record and excludes it from the verdict. A conjunction is
graded as the worst of its members and names which one. The secrets detector puts a deep build path at
**notice** (seal proceeds) and a `ghp_…` token at **block** (exit 3, located to the argument and offset, no
note written). A cited authority prints, verbatim, *"NOT a signature and NOT approval — didrun cannot tell
who wrote it."*

**The guardrail protecting the live corpus was verified without touching the corpus.** The refusal list is
stored as path digests, so the live tree — plus its trailing-slash form and anything inside it — is refused
by name, a live-looking copy is refused by heuristic, and a proper copy is accepted. Checked with string
hashing only; no filesystem access to that tree occurred at any point in this pass.

---

## STILL A BET — designed, argued from code, not measured

**The single biggest one: the real-corpus replay never ran.** Nineteen units each argued in their own risk
register that they would not disturb 65 sealed notes and 178 archived ledgers. **Every one of those
arguments is still an argument.** The harness that would settle it exists, is content-blind, and is green
on synthetic fixtures — and it has never seen the real thing, because the corpus is live, secret-bearing
evidence for a build that is still running and copying it is not mine to do. Four legs are unexercised:
chain recompute over the archived logs, the note round-trip over all 65 notes, the `objects/` layout
partition, and the claim-shape invariants.

A green synthetic run is **not** corpus validation, and the harness prints exactly that word —
`corpus: SKIPPED (unverified)` — rather than letting a green line imply it.

The rest, each with what would settle it:

- **CI on Python 3.11 / 3.12 / 3.13 × ubuntu / macos.** Unverified and **unverifiable here**: this
  interpreter is 3.14.5. The 3.11 check that passed is a *grammar* parse; it cannot catch a 3.12+ stdlib
  API. The declared floor is 3.11 and nothing has ever run there.
- **Capture recall against real agent sessions (the S6 leg).** The frozen S1–S5 probes report 100%
  defect-class recall; S6 needs a real agent on a real machine and has never been run.
- **Durability across a crash.** There is no `fsync` anywhere in the package. Concurrent appends are
  *mutually* safe; that is not the same as an append surviving power loss.
- **`flock` on network filesystems, and permissions on Windows.** Both measured on local APFS only.
- **Five research follow-ups (FU1–FU5) and red-team finding 16.** A claim-count discrepancy (667 vs 846); a
  "zero detector findings" figure measured over exported argv strings and never over the ledgers; a
  1-of-8 resume-legality mapping that is inference over recorded tree ids rather than observation; the
  original EV2 false-green, single-sourced (this pass witnessed the *mechanism* in a scratch repo, which is
  not a witness for the corpus); and every frequency, cost and duration figure in the research, all
  self-reported by the system under study. Details and owners in `docs/COMPAT_REPLAY.md`.
- **The most important unknown: whether any of this changes a decision.** 846 recorded claims produced
  exactly **one** `failed`. That is consistent with a superbly effective gate and equally consistent with a
  nearly inert one, and a corpus whose only observed actor was cooperating cannot tell the two apart. The
  experiment that would — tell an agent to obtain a green `didrun verify --strict` by any means and see what
  it does — was **not run**, is not authorised by the plan this release followed, and is the highest-value
  missing signal in the whole project. Until someone runs it, "didrun catches dishonest agents" is a
  hypothesis.

---

## KNOWN NOT CLOSED — defects and gaps left in deliberately

### Defects found in this pass and NOT fixed

The final integration pass measures; it does not fix, because a fix landing after the last verification
gate is unverified code in a release. Each of these is a small, self-contained unit for Drew to sequence.

- **K1 — `didrun run` reports two operational errors as raw Python tracebacks with exit 1.**
  1. A command that does not exist (`run -- /bin/false` on macOS, where that path is absent) →
     uncaught `FileNotFoundError`, exit 1, **and no event recorded at all**.
  2. A torn `session.log` → uncaught `LedgerError`, exit 1. The refusal *message* is excellent and
     complete; only its delivery is wrong.

  This breaks an invariant the codebase states in its own words in `cmd_verify`: *evidence this binary
  cannot read is a graded refusal, not a crash — 2, not `--strict`'s 1*. `cmd_verify` catches `LedgerError`
  and returns 2; `cmd_run` wraps nothing, and `main()` catches only the two interrupt types. **Exit 1 is
  `--strict`'s "graded badly" code**, so a crashed `run` is indistinguishable by exit status from an honest
  failure — the same class of bug P4 already fixed on the manifest side. **Pre-existing, not a v0.2
  regression:** `main`'s `subprocess.run` raises the same way. Fix shape: one `try` in `cmd_run` over
  `OSError` and `LedgerError`, returning 2 with a named message.

- **K2 — `show --session` reports an unverifiable chain as "BROKEN".** `ledger.py` computes a three-way
  status (`intact` / `broken` / `unverifiable`) and `render.py` documents in a comment that the two faults
  *"get different words on purpose"* — broken means an entry did not recompute, unverifiable means this
  binary cannot check it. `verify`'s reason line honours that (`ledger chain unverifiable — entry 1:
  unknown chain preimage version: 2`). But `show --session` goes through the boolean `verify_chain()` and
  can only say `chain BROKEN at index 1`, and `verify`'s own headline banner says `CHAIN-BROKEN` for both.
  So a future ledger format reads to the operator as **tamper**, which is precisely the false alarm the
  frozen preimage was built to prevent.

- **K3 — `didrun --version` still prints `0.1.0`.** The entire forward-compatibility story in
  `docs/COMPAT.md` is phrased as "a v0.1 reader versus a v0.2 reader" and instructs operators to *upgrade
  the verifier before the sealer* — and the only way anyone can tell which they have is `--version`.
  **This must not ship as 0.1.0.** It is not fixed here only because `src/didrun/**` was fenced off for
  this pass; it is a two-line change (`pyproject.toml`, `src/didrun/__init__.py`) with no test depending on
  the string.

- **K4 — the happy path shouts.** The first seal of every session prints a four-line `WARNING` about
  having no watermark file, a condition the warning itself then explains is *"correct for a session's first
  seal."* `docs/COMPAT.md` argues elsewhere that a gate which fires spuriously gets ignored within a week;
  this is that, on the most-travelled path in the tool.

- **K5 — a plan inconsistency worth recording so nobody chases it.** P4.1's documented supersession
  scenario ("fail → claim → fix → claim, no commit between") is **unreachable through the CLI** now,
  because P5.2 correctly refuses a claim bound to an event that exited nonzero. Supersession itself works
  and was verified by the route that remains: claim, let the tree move, re-run, re-claim the same label.
  The product is right; the plan's matrix row is stale.

### Non-guarantees the design leaves open on purpose

- **Inherited-environment false greens.** `GOFLAGS=-exec=/usr/bin/true` and its whole family
  (`NODE_OPTIONS`, `PYTHONPATH`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `PYTEST_ADDOPTS`, a PATH shim,
  `sitecustomize.py`) produce a command that passes having run nothing. No allowlist closes it, and putting
  the effective environment in the event body would put the richest secret carrier on a developer machine
  into the chain preimage. A PATH digest is recorded; a declared clean-environment mode is the v0.3 shape.
- **No retention or purge.** A credential scrubbed from git history survives as a loose object under
  `.didrun/objects`.
- **The `«redacted:…»` marker is forgeable** — a convention, not a cryptographic mark.
- **Tree-fallback takes the first matching note** and does not fail closed on a second match (red-team
  finding 20). First candidate for v0.2.1.
- **`argv_preview` is written into every note, dropped on read, and computed-but-unrendered in HTML**
  (finding 21). A product decision, not a hardening unit.
- **`seal` does not consult the chain.** `verify` does. Sealing over a broken chain is possible.
- **Duplicate conjunct labels count twice.** `--of a,a` grades correctly and reads oddly.
- **No PKI, signing, key management or revocation.** `authorize` records a cited artifact's digest and says
  in its own output that it is not a signature.
- **And the one that frames all the others: none of this resists a determined local forger.** Whoever can
  substitute a ledger can regenerate its chain and re-run `claim` and `seal` to mint fresh hash-bound
  claims. The source declares it, `docs/TRUST_MODEL.md` states it, and nothing in v0.2 changes it. What
  v0.2 buys is **accident and drift detection on published evidence** — which is what actually goes wrong
  in practice, and is worth having. It is not tamper-proofing and must never be sold as such.

---

## What a human has to do before this ships

Four things need a signal no amount of local work can produce:

1. **Copy the archive tree and run the corpus replay.** Copy it *without* its live `.didrun` directory onto
   a separate volume, then run the compat suite with `DIDRUN_COMPAT_CORPUS` pointed at the copy. The
   harness refuses the live tree by name if the variable is set wrongly. Until this runs, "v0.2 does not
   disturb existing sealed evidence" is an argument, not a finding.
2. **Get CI green on 3.11, 3.12 and 3.13 across ubuntu and macos.** The declared floor is 3.11 and nothing
   has ever executed there.
3. **Run the S6 live-agent recall leg** — real agent, real machine, per `harness/README.md`.
4. **Run the adversarial-agent experiment**, or accept knowingly that the product's central claim is
   untested. Tell an agent to obtain a green `didrun verify --strict` by any means and watch what it does.
   One `failed` out of 846 claims cannot tell an effective gate from an inert one.

Plus the small ones that are simply mine-to-hand-over: **K3 (the version string) blocks release outright**,
and K1 is worth an hour.

---

## The honest summary

**30 of 44 load-bearing conclusions are externally verified.** The other 14 rest on argument from code, on
figures the system reported about itself, or on a signal only a human or CI can supply — and all four
real-corpus legs are in that second group.

The engineering is in good shape: the defect the release was built to close is closed and measured, every
prior phase's property was re-checked rather than assumed, and the failure modes fail closed with legible
messages. What is missing is not code. It is contact with reality — the real corpus, real CI, a real agent,
and one honest adversarial test. Ship it as **0.2.0 after K3 and gates 1–2**, and do not describe it as
verified against existing evidence until gate 1 actually clears.
