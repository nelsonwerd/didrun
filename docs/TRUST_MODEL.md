# didrun trust model

This document states, precisely, what a didrun record proves and does not prove.
It is the most important document in the project. didrun exists for a skeptical
audience — infrastructure engineers who have been burned by tools that overclaim
— and the fastest way to lose them is to exaggerate. So we don't.

## The doctrine (read this first)

A didrun record is a **faithful recording, not a proof.**

- It is **strong for cooperating actors.** A lazy agent that claims "tests pass"
  without running them produces a claim that grades `unknown` — there is no
  witnessed successful command to back it. That is the core win: didrun makes the
  *absence* of evidence visible.
- The local hash chain can be **regenerated in milliseconds** by anyone with write
  access to the ledger. It is a **self-consistency check, not a forger barrier.**
  It detects accidental mutation, truncation, and reordering — not a determined
  local adversary who rebuilds the whole chain.
- `verify` attests **"this command ran and exited 0 against this tree."** It never
  attests "this command meaningfully tested anything," and it never attests "this
  evidence came from someone you can trust."
- didrun is a **trust accelerant among parties with a baseline of trust — never a
  substitute for trust between strangers.**

If you remember one sentence: **didrun records what ran; it does not vouch for who
ran it or whether it mattered.**

## What each grade does and does not mean

| Grade | Attests | Does NOT attest |
|-------|---------|-----------------|
| `tree-exact` | A self-stable command ran against exactly the sealed tree. | That the command tested anything meaningful, or that the code is correct. |
| `scope-exact` | Every change since the evidence is inside claimant-declared pathspecs. | That the declared pathspecs are the *right* scope — the claimant chose them. |
| `stale` | Evidence exists; here is the exact delta between it and the sealed tree. | Nothing beyond "the tree moved" — the reviewer judges whether the delta matters. |
| `unknown` | We could not honestly bind evidence to this claim. | That the claim is false — only that it is unbacked. |

## What it protects against, by actor

| Actor | didrun detects / prevents | didrun does NOT stop |
|-------|--------------------------|----------------------|
| **Lazy agent** (claims without running) | The claim grades `unknown` — no witnessed success. | — |
| **Agent that runs, then edits** | The claim grades `stale` with the exact delta. | — |
| **Honest mistake** (partial/truncated ledger) | The hash chain breaks; `show --session` reports it. | — |
| **Developer massaging their own receipts** | Accidental edits break the chain. | A deliberate local rebuild of the chain — it is regenerable. |
| **Stranger sending forged evidence** | — | Everything. Unsigned local evidence is self-attested; do not trust a stranger's ledger. Cross-party trust needs signing (deferred). |

## Why signing is deferred (and it is a bet)

Cross-party trust — verifying a stranger's evidence — requires cryptographic
signing from outside the agent's trust boundary. didrun v1 does not sign. This is
a deliberate, honest deferral, not an oversight: signing is additive and can land
later. It is also a genuine adoption bet, because voluntary developer commit
signing is rare in practice. Until it lands, **didrun's guarantees hold only among
parties who already share a baseline of trust.**

## The ledger is secret-bearing

The ledger records everything a session printed — including anything an agent
echoed: tokens, `.env` contents, connection strings. Treat `.didrun/` and any
exported bundle as **secret-bearing**:

- `.didrun/` is self-ignored (a `*` gitignore inside it) so it is never committed.
- At `seal`/export, didrun scans argv and captured output for likely secrets and
  **blocks export by default** if it finds any (override with `--allow-secrets`,
  which is logged into the manifest, and still redacts the exported artifact).
- Redaction applies to what *leaves* the machine (bundles, HTML reports). The raw
  local ledger is left intact and stays local.

The scanner is a safety net tuned to bound false positives, not a guarantee. Do
not rely on it to catch a novel secret format; keep secrets out of command output.

## Honest capture limits

didrun is honest about what it cannot see (measured; see MEASUREMENTS.md):

- **Absolute-path executions and shell builtins** escape a PATH shim 100% of the
  time. Only Tier 0 (`didrun run --`) guarantees complete capture.
- **A PTY transcript** records displayed bytes but no argv or exit code — it can
  read "tests: 5 passed" for a command that exited 3, so a transcript event never
  carries an exit code and can never back a success claim.
- **Ignored files** are invisible to every git-based tree digest — `tree-exact`
  does not certify `.env` or build caches.
- **Dirty submodule content** is flagged but not digested; such a claim is capped
  at `stale`.
- **Ordering authority is the hash chain, never timestamps.** Timestamps are
  recorded as data only.

## The one rule

didrun never says "proven," "certified," or "guaranteed" in its output, its help,
or its docs. If you ever see it overclaim, that is a bug — file it.
