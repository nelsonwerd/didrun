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
| `failed` | The command backing this claim was *recorded exiting nonzero* — evidence against the claim, not merely absent evidence. | Anything about intent. A recorded failure is a fact about a process's exit code, never a statement about who ran it or why. |
| `witness-unavailable` | The note bound this claim to a recorded entry the live ledger cannot supply; the sealed grade is shown as history. | That anyone tampered. An archived, rebuilt or replaced ledger produces this too. It is never re-earned, and `--strict` never accepts it. |
| `chain-broken` | Report-level, never a per-claim row: the ledger every grade was read out of does not recompute, or this binary cannot check it. | Which of accident or tampering caused it. The chain is regenerable, so a break is evidence of *mutation*, never of *who* mutated. |

The first five are the ladder, evaluated worst-first — `failed`, `unknown`, `stale`,
`scope-exact`, `tree-exact` — and the first match wins, so a claim never grades better
than the weakest fact about it. The last two are not rungs: one replaces a grade when
the evidence behind it cannot be produced, the other overrides the whole report.

## What it protects against, by actor

| Actor | didrun detects / prevents | didrun does NOT stop |
|-------|--------------------------|----------------------|
| **Lazy agent** (claims without running) | The claim grades `unknown` — no witnessed success. | — |
| **Agent that runs, then edits** | The claim grades `stale` with the exact delta. | — |
| **Honest mistake** (partial/truncated ledger) | The hash chain breaks. From v0.2 `verify` checks it *before* grading anything and the fault dominates the verdict, so `--strict` refuses; `show --session` reports it too. | A fault in a ledger `seal` is writing to — `seal` does not consult the chain, so sealing over a broken one is possible. |
| **Developer massaging their own receipts** | Accidental edits break the chain. From v0.2, a note whose bound entry the live ledger cannot supply grades `witness-unavailable` and `--strict` refuses it, so a substituted or rebuilt ledger no longer regrades green. | A deliberate local rebuild of the chain — it is regenerable, and `claim` + `seal` can then mint fresh hash-bound claims. |
| **Stranger sending forged evidence** | — | Everything. Unsigned local evidence is self-attested; do not trust a stranger's ledger. Cross-party trust needs signing (deferred). |

## Why signing is deferred (and it is a bet)

Cross-party trust — verifying a stranger's evidence — requires cryptographic
signing from outside the agent's trust boundary. didrun v1 does not sign. This is
a deliberate, honest deferral, not an oversight: signing is additive and can land
later. It is also a genuine adoption bet, because voluntary developer commit
signing is rare in practice. Until it lands, **didrun's guarantees hold only among
parties who already share a baseline of trust.**

## Operator authority: what `cited` attests

`didrun authorize --artifact <path> --scope <scope> --label "<text>"` records that a
file with a particular SHA-256 was cited as the authority for one exceptional
transition. `seal` binds the live citations into the manifest, grades each one
`cited`, and every surface that shows one prints this sentence beside it:

> cited authority: recorded that a file with this digest was cited for this scope.
> NOT a signature and NOT approval — didrun cannot tell who wrote it.

**What it attests.** A file with this digest existed at this path and was cited for
this scope, at this point in an append-only record. The digest, the scope, the label
and the self-asserted principal are in the note; the artifact's bytes never are.

**What it does not attest — read this part.** It is not evidence that a human wrote,
read, or approved anything. **An agent can author its own authorization artifact in
one line**, cite it, and seal. There is no identity here: `principal` is whatever
`$USER` said, recorded as `self-asserted`, and didrun authenticates nobody. `cited`
must never be rendered or reported as "signed", "approved", "verified" or
"authorized by" — the same rule that keeps `tree-exact` from rendering as "verified
true".

**The one property it buys.** Retroactive fabrication becomes detectable: because the
digest sits in a note sealed earlier, an artifact edited or written after the fact no
longer matches what that earlier note recorded. That is a real, narrow gain, and it is
the whole gain. It converts an authority from prose into a fixed, diffable,
digest-bound object; it does not make the object trustworthy. It is also not tamper
resistance — whoever can rewrite a note can rewrite the digest in it, exactly as they
can rewrite a grade.

**Why it is shaped this way.** `--allow-secrets` was the shipped instance of the
problem: a bare flag stored as a bare boolean, with no principal, no basis and no
artifact, so a reader could not tell an authorized override from an agent that simply
passed the flag. didrun's own thesis is that a claim with no witnessed event grades
`unknown`; an out-of-band authorization is exactly that shape, and the tool used to
grade it implicitly true. So authorities are:

- **scoped** — only `allow-secrets` and `reseal`, the exceptional transitions. There
  is deliberately no scope for an ordinary seal, and none will be added.
- **expiring** — a TTL counted in seals (default 1, minimum 1, and no value meaning
  "never"). Seals rather than wall time, because a clock in the trust path is not
  allowed here.
- **never required by default** — `seal --require-authority` is opt-in. Any
  authorization demanded on the happy path becomes a rubber stamp within a week,
  which is precisely how the information content of `--allow-secrets` reached zero.

**The honest anchor for a stronger tier is a key the agent cannot read.** A
passphrase-less key in `~/.ssh` that the agent can read is theatre; a hardware-backed
key with touch-to-sign (`ssh-keygen -t ecdsa-sk`, or a Secure Enclave key) is the real
anchor, because the human's finger is the thing an agent cannot fake. Two further
tiers are designed and **not built**:

- **Tier 1 — reuse the key the developer already has.** `git verify-tag` /
  `git verify-commit` under `gpg.format=ssh` and `~/.ssh/allowed_signers`, recording
  the signer identity and the verification output. Zero new key management, no crypto
  inside didrun. **Not built.**
- **Tier 2 — org identity, roles, revocation, trust roots.** **Not built**, and out of
  scope for a local single-user tool.

Both are consequences of the deferral in the section above, and neither is claimed
anywhere in didrun's output.

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
  published entry that carries operator- or repository-authored text is replaced
  by a marker before the note is written, and the spans are declared in
  `redaction.applied` / `redaction.fields`. For a claim that is the argv preview,
  the label, the pathspecs and the changed paths; for a cited authority it is the
  label, the cited path **and the principal**. This is stated because it was once
  false in the worst direction, twice: a token in a claim label refused the seal
  and was then published verbatim on the override, under a refusal message that
  had already promised a redacted artifact — and when authorities were added,
  `principal` reproduced it exactly, having been scanned by the whole-manifest
  backstop but left out of the pass that redacts. Blocking is not redacting. An
  enumeration of "the fields that carry outside text" also goes stale the moment
  a field is added, so the authority enumeration is checked for completeness by a
  test rather than trusted, and a field it does not classify is dropped from the
  note instead of published.
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

- **A `block` finding must name something that could be a secret.** The assignment
  detector reads its value the way the shell will, so a value that is purely a shell
  expansion (`API_KEY="$(grep … .env)"` inside a recorded `bash -c` script) is not a
  finding: the argv holds the recipe for reading the secret, never the secret. A closed,
  exact-match list of vendor-published dummy values (today: Cloudflare Turnstile's three
  test secret keys) is demoted to `notice` — reported, redacted, and not blocking. That
  is a demotion and never a suppression list: nothing found is dropped, and a value that
  authenticates to anything, test account or not, is not eligible. The reason to allow
  it at all is the rubber-stamp argument under operator authority, above: a gate that
  refuses a routine command over a public constant teaches its operator to pass
  `--allow-secrets` on reflex. docs/COMPAT.md states what this costs in recall.

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
