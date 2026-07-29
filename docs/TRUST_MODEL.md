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
- At `seal`/export, didrun scans two domains and **tiers** what it finds. The six
  structured detectors are `block`: they fire on shape and name what they found.
  The entropy sweep is `notice`: it fires on "this looked random", which over a
  24-character run is a statement about length far more than about secrecy.
- **A seal is refused only for a `block`-tier finding in the bytes about to be
  published** — the argv of each claim-bound event and the serialized manifest,
  claim labels and delta paths included. Override with `--allow-secrets`, which
  is logged into the manifest; the exported artifact is redacted either way.
- **What blocks and what is redacted are the same fields.** Every string in a
  published claim entry that carries operator- or repository-authored text (the
  argv preview, the label, the pathspecs, the changed paths) is replaced by a
  marker before the note is written, and the spans are declared in
  `redaction.applied` / `redaction.fields`. This is stated because it was once
  false in the worst direction: a token in a claim label refused the seal and
  was then published verbatim on the override, under a refusal message that had
  already promised a redacted artifact. Blocking is not redacting.
- Everything else is **reported loudly and does not stop the seal**: every
  `notice`-tier finding, and any `block`-tier finding confined to the recorded
  output blobs, which stay in a gitignored local ledger and are never published.
  Refusing over bytes that do not leave stopped work without protecting anything.
- The manifest records **what was scanned** (`secrets`: the domain, the events
  scanned out of the events present, the bytes, the detector-set version, and
  the findings per tier), so `secrets_override: false` is a checkable statement
  instead of the same word for "nothing found" and "almost nothing looked at".
- Every finding carries a location: source kind, event index, argv index or line,
  byte offset, and a **locality** fingerprint. The fingerprint deliberately does
  not digest the matched token — an unkeyed digest of a short high-entropy string
  would be a brute-force oracle for the thing just redacted.
- Redaction applies to what *leaves* the machine (bundles, HTML reports). The raw
  local ledger is left intact and stays local. One documented exception: an HTML
  report's file list for a `stale` claim is **recomputed against your working
  tree** at verify time rather than read from the note, so it is not the note's
  redacted copy — see docs/COMPAT.md.

The scanner is a safety net tuned to bound false positives, not a guarantee. Do
not rely on it to catch a novel secret format; keep secrets out of command output.
How weak the entropy tier is in **both** directions is measured, not asserted —
see the detection tables in MEASUREMENTS.md. Those tables also bound the other
direction: the entropy sweep misses roughly 1–3% of slash-bearing base64
credentials by design, and nothing in it resists an attacker who knows the rule.

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
