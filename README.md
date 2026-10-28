# didrun

[![ci](https://github.com/nelsonwerd/didrun/actions/workflows/ci.yml/badge.svg)](https://github.com/nelsonwerd/didrun/actions/workflows/ci.yml)
&nbsp;![status: v0 · experimental](https://img.shields.io/badge/status-v0%20%C2%B7%20experimental-orange)
&nbsp;![python: 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
&nbsp;![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green)

**Flight records for agent-written code.**

> **v0.2 · experimental.** The six commands (`run`, `claim`, `authorize`, `seal`,
> `verify`, `show`) work, and the test suite and capture kill-gate are green on the full
> CI matrix — ubuntu + macOS × Python 3.11 / 3.12 / 3.13, which is what the badge above
> tracks. The declared floor of **3.11** is now executed rather than only declared. Read
> that as "the suite runs there", not as a v0.2 measurement: every *number* in these docs
> is still one machine, macOS / CPython 3.14, because CI runs the suite and does not
> reproduce the benchmarks. The API and CLI may still change, and there has been
> no independent security review. **Upgrading from v0.1? Verifiers before sealers** — see
> [What changed in v0.2](#what-changed-in-v02). What didrun does and does not attest is
> [here](docs/TRUST_MODEL.md); the unflattering version of what this release did and did
> not establish is [here](docs/V02_STATUS.md).

When an AI coding agent says *"done — tests pass,"* the proof usually evaporates
the moment the session ends. The transcript is unverifiable prose, CI only re-runs
what CI knows about, and the reviewer is left re-deriving the work or trusting
vibes.

didrun records what an agent **actually executed** — the command, the exit code,
the output, and the exact git tree state it ran against — then binds structured
claims to a commit and lets a reviewer check them in seconds. A verdict carrying one
row of each of the five ladder grades:

```
x FAILED — review needed
  2/5 claims recorded-exact · commit 7eebe0fd0d9f · tree c6876974c0c0 · resolved-by commit
  4/5 claims evidence-bound
  env: 4 match / 0 drifted / 0 incomparable / 1 not-recorded

    STATUS       CLAIM                      DETAIL
  ----------------------------------------------------------------------------
  x FAILED       integration tests pass     exit 1  the recorded command exited 1 — claim is not backed
  ? UNKNOWN      migration applied cleanly  no witnessed successful command backs this claim
  ! STALE        lint clean                 exit 0  tree moved since evidence: 2 path(s) differ
                                              M src/api/handlers.py
                                              A src/api/new_route.py
  ~ SCOPE-EXACT  unit tests pass            exit 0  all 2 change(s) within declared pathspecs
                                              M src/api/handlers.py
                                              A src/api/new_route.py
  = TREE-EXACT   type check passes          exit 0  self-stable command ran against the sealed tree

  didrun records what ran; it does not prove the code is correct. See docs/TRUST_MODEL.md.
```

There is **no LLM in the trust path.** Capture and verification are deterministic.
didrun is a *recording*, not a *proof* — read [what it does and does not attest](docs/TRUST_MODEL.md).

## Why it exists

A reviewer needs to check an agent's claims without re-running the work, and the
usual answer is another model reading the diff — a judgement about whether the code
looks right. didrun answers a different and much narrower question, *what actually
happened?*, and answers it deterministically, so what a reviewer gets is evidence
they can check rather than a second opinion they have to weigh.

## Quickstart (under 5 minutes)

didrun is Python 3.11+, **stdlib-only** (zero runtime dependencies — you can read
the whole thing). Install it into your project's environment:

```bash
git clone https://github.com/nelsonwerd/didrun && pipx install ./didrun   # PyPI release pending
```

Then wrap the commands your agent runs, declare a claim, and seal it to the commit:

```bash
# 1. Record a command exactly as it ran (Tier 0 — complete capture).
didrun run -- pytest -q

# 2. Declare a structured claim over what you just recorded.
didrun claim tests-pass --label "unit tests pass"

# 3. Commit your code, then seal the evidence to that commit.
git commit -am "add feature"
didrun seal

# 4. Verify — in CI or at review time.
didrun verify --strict        # exit 0 only if every claim is recorded-exact
```

The `--strict` exit code is the CI seam: wire `didrun verify --strict` into your
pipeline and a drifted or unbacked claim fails the build.

Every verdict also reports how the environment compared with the one the seal
recorded — `env: N match / M drifted / K incomparable`. Drift is advisory unless
you pass `--require-env-match`, because a changed environment is a fact about the
machine verifying, not about whether the recorded command ran. Evidence sealed by
an older didrun is *incomparable*, never drifted, and never refuses.

`didrun verify --html evidence.html` writes a self-contained report for humans:
one file, zero external assets, opens offline and prints cleanly. Redaction
covers the sealed note — every exported claim string (`argv_preview`, label,
pathspecs, changed paths, conjuncts, reason, deferral reason) is redacted by the same pass that
reports findings to the gate, and the projection is declared in the manifest.
The HTML carries no argv at all and renders the note's redacted label, but a
stale claim's file list is recomputed against your working tree at verify time
and shown as it is on disk — read it before you attach it to a PR.

Detection is pattern- and entropy-based, so it is a filter, not a guarantee: a
base64 credential whose own slashes chop it into short, name-like pieces is scored
as a path and missed ([docs/COMPAT.md](docs/COMPAT.md) quantifies that class). And
redaction covers the *published* artifact only. The local ledger is not redacted
and has no retention or purge — `didrun run` stores each command's raw stdout and
stderr as content-addressed blobs under `.didrun/`, so a credential scrubbed out of
git history survives there until you delete the directory by hand. `.didrun/` is
gitignored and its root is forced to `0700` (files didrun creates are `0600`; ones
an older didrun created keep their modes, and `.didrun/objects/**` is git's at
git's modes). Treat it as secret-bearing: do not commit it, share it, or attach it
to an issue.

## Use it with your coding agent

You don't have to run these commands by hand. Tell your agent to route its own
verification through didrun, and it produces receipts as a side effect of working.
Drop the snippet for your tool into its instructions file — `CLAUDE.md` for Claude
Code, `AGENTS.md` for Codex and anything agent-agnostic, a project rule for Cursor,
a system-prompt block for anything else. Copy-paste snippets for each, plus the
honest bounds, are in [docs/agents.md](docs/agents.md). The short version:

```markdown
For any check you'll cite as evidence, run `didrun run -- <cmd>`. Per finished
unit: `didrun claim <type>`, commit, `didrun seal`. Gate on
`didrun verify --strict` and loop until it exits 0. Never claim un-wrapped work
as verified.
```

This is **cooperative capture** — it works because the agent follows the
instruction, not because anything is enforced. Commands the agent *doesn't* route
through `didrun run` are simply not recorded (a claim with no backing run grades
`unknown`), so didrun never mistakes "didn't capture it" for "verified." Tiers 1–3
narrow how much an agent can forget to route; nothing closes it, and none of them
is wired to a command yet — see the note below.

## The grades

didrun never says "verified — trust me." Each claim gets an honest grade against
the sealed commit's tree:

| Grade | Meaning |
|-------|---------|
| **TREE-EXACT** | A self-stable command ran against *exactly* the sealed tree. |
| **SCOPE-EXACT** | Every change since the evidence is within claimant-declared pathspecs. |
| **STALE** | Evidence exists but the tree moved — the exact path+content delta is shown. |
| **UNKNOWN** | No honest binding (no witnessed success, retroactive binding, gc'd object). |
| **FAILED** | The command backing the claim was *recorded exiting nonzero* — evidence against the claim, not merely absent evidence. Nothing in the grade speaks to intent. |
| **WITNESS-UNAVAIL** | The live ledger cannot supply the evidence this claim was sealed against. The sealed grade is shown as history, never re-earned, and `--strict` never accepts it. |
| **CHAIN-BROKEN** | Report-level, never a per-claim row: the ledger every grade was read out of does not recompute, or this binary cannot check it. It dominates every grade below it. |

The first five are the ladder. It is evaluated worst-first — `failed`, `unknown`,
`stale`, `scope-exact`, `tree-exact` — and the **first match wins**, so a claim never
grades better than the weakest fact about it. (The table above is in the reverse,
best-first order a verdict prints.) The last two are not rungs: one replaces a grade
when the evidence behind it cannot be produced, the other overrides the whole report.

`STALE` always carries the concrete delta; it is never a bare shrug. `tree-exact`
means the evidence tree equals the sealed tree — it does **not** claim the code is
correct or that the command meaningfully tested anything.

A command that writes into the tree while it runs (a lock file, a snapshot, a
formatter) is never `tree-exact`, even when you commit exactly what it wrote: it ran
against the tree it started from. Its row names what the run itself changed —
`the run itself changed 1 path(s): ant.lock … add --path ant.lock to make this
scope-exact` — and declaring those paths with `--path` is how it earns `scope-exact`.
didrun never declares them for you.

## The six commands

- `didrun run [--tee] [--heartbeat SECONDS] -- <cmd>` — record a wrapped execution (complete capture). `--tee` mirrors the child's raw output to your terminal as it arrives (local only, never redacted); `--heartbeat` prints a content-free progress line to stderr. Both default **off**, so anything parsing didrun's stdout sees what it saw before.
- `didrun claim <type> [--label L] [--event N] [--path PREFIX]… [--of a,b,c]` — declare a structured claim. With no `--event` it binds the command that just ran, and **refuses** (exit 2) rather than bind an earlier passing event when the latest one exited nonzero. Each `--path` (repeatable) is a repository-relative path prefix inside which the sealed commit may differ from the tree the evidence was recorded against — files the run itself wrote included — and still grade `scope-exact`; a difference outside every prefix grades `stale`, and the reason names the `--path` that would cover it. Plain prefixes only: git pathspec magic such as `:(exclude)…`, globs, `.` and `./…` are refused with exit 2, because a prefix match would read them as covering nothing. `claim conjunction --label REL --of a,b,c` declares one over other claims in the same seal window, graded as the worst of them. Re-declaring the same type and label supersedes the earlier claim: the retired one keeps its grade in the record, drops out of the verdict, and is counted on both surfaces. A retired conjunction's record is graded against the claims standing when it was declared (`as declared at claim #N: …`), so it never reads green over a gate that was red at the time. `claim --defer LABEL --reason TEXT` sets one live, *unsealed* claim aside from the next seal's verdict when it belongs to work that is not in that commit — an interrupted unit's claim over a draft, say. It declares nothing: the claim is still graded and published with the reason, marked deferred and counted on both surfaces, and a claim bound to a command that exited nonzero is refused, because a witnessed failure is never set aside.
- `didrun authorize --artifact <path> --scope {allow-secrets,reseal} --label "<text>"` — record a cited authorization artifact for one exceptional scope, storing its SHA-256 and never its bytes. What that establishes, narrowly: **a file with this content was cited.** Not a signature, not authentication, not evidence a human approved anything — an agent can write its own artifact in one line, and every surface that prints one says so. A citation covers `--expires-after-seals N` seals starting with the next one (default **1**), and there is no value meaning *never*. `seal --require-authority` demands one for those two scopes; it is opt-in, because an authorization required on the happy path is a rubber stamp within a week.
- `didrun seal [--commit C] [--allow-secrets] [--bundle F] [--reseal] [--require-authority]` — compile and publish a commit-bound evidence manifest. **Fails closed**: exit 2 if the note cannot be published (leaving no note, no watermark, no seal record), exit 3 on a structured secret in the bytes it is about to publish. Replacing a note with a *narrower* record needs `--reseal`.
- `didrun verify [--commit C] [--strict] [--require-env-match] [--html F] [--quiet]` — check claims against the evidence they were sealed against.
- `didrun show [--commit C] [--session] [--event N --output [--stream stdout|stderr] [--redacted]] [--html F]` — the verdict, the recorded session history, or a recorded output blob, re-hashed on read so a corrupted one is a refusal rather than bytes presented as the record.

## What changed in v0.2

**`verify` is now bound to the evidence it sealed.** Before v0.2 it regraded against
whatever ledger happened to be on disk, keyed by integer index, and never checked the
chain. Measured: seal three claims, delete the ledger, run three unrelated commands into
a fresh one on the same tree, then verify. v0.1 reported `3/3 recorded-exact` and exited
0. v0.2:

```
? WITNESS-UNAVAIL — review needed
  0/3 claims recorded-exact · commit 8710d403a1b8 · tree 7c75e84f39ea · resolved-by commit
  0/3 claims evidence-bound
```

`--strict` exits 1, and a chain that does not recompute now dominates the verdict
outright rather than being ignored. The rest:

- **Seal is atomic and fails closed.** Publication and the watermark are one pair: nothing is recorded until the note is on the commit, and a failure after that rolls the note back. A seal that could not publish used to report success.
- **The v1 chain preimage is frozen behind an explicit field list**, so adding an `Event` field cannot silently change hashes already written. An entry whose preimage version this binary does not know is reported unverifiable *with its index*, never graded against a guess.
- **Interrupts no longer lose a flight.** Signals are held across the digest-and-append window (SIGINT → 130, SIGTERM → 143, one line each), and a `run` that dies after the digest records `tree_after=None` with observed-text-only coverage instead of costing the event.
- **The ledger is tighter.** Its root is `0700` and the files didrun creates are `0600`; read-only `verify` and `show` no longer manufacture one as a side effect; concurrent appends take an `fcntl.flock`, so parallel writers cannot fork the chain. Bounds are declared rather than rounded up: inherited files keep their old modes, `.didrun/objects/**` is git's at git's modes, and on a platform with no `fcntl` or no meaningful `chmod` both properties degrade to v0.1 behaviour instead of pretending.
- **Redaction and reporting are one act.** The entropy detector scores runs rather than characters — a path in segments, a base64 blob whole — every detector declares a tier (six structured patterns at `block`, the entropy sweep at `notice`), and the fields that block are the fields that get redacted, so `--allow-secrets` cannot publish raw what the gate blocked. The projection is *declared*, not inferred: `projection_version`, `detector_set_version`, and the exact replaced spans, which substitute back to the input byte for byte.
- **Claims can be superseded**, so a fix-verify loop converges instead of accumulating red rows, and a conjunction grades as the worst of its members. Both are described under `claim` above.

**What v0.2 did not establish.** Compatibility with evidence already sealed is **not** a
finding: the compat harness is content-blind and green on synthetic fixtures only, the
real archive replay has never run, and the harness prints `corpus: SKIPPED (unverified)`
rather than let a green line imply otherwise. And two operational errors still escape as
Python tracebacks with exit **1** instead of the graded refusal with exit 2 that the same
binary gives elsewhere: a command that does not exist, and a `session.log` this binary
cannot parse (which takes `run`, `verify` and `show --session` down alike). Exit 1 is
`--strict`'s "graded badly" code, so a crash is not distinguishable by exit status from
an honest failure. [docs/V02_STATUS.md](docs/V02_STATUS.md) separates verified from bet,
item by item.

> **Upgrading: verifiers before sealers.** `MANIFEST_VERSION` is now **3**, and an older
> reader **refuses** a v0.2 note by design — exit 2, `manifest version N is newer than
> this didrun understands (max M); upgrade didrun` — because regrading a note index-only,
> without checking the binding it was sealed under, is the confidently-wrong verdict this
> tool exists to avoid. Seal on a v0.2 workstation, verify in v0.1 CI, and every commit
> fails. The other direction is fine: a v1 note carries no evidence block and regrades
> exactly as v0.1 regraded it. Two smaller breaks the same way — a tree digest now also
> excludes `.didrun-history/`, so a repository carrying one **un-gitignored** sees claims
> against the older digest grade `stale`; and a narrowing re-seal needs `--reseal`.
> [docs/COMPAT.md](docs/COMPAT.md).

## Capture is tiered and honest about coverage

Universal, invisible capture of everything an agent runs is not possible from
outside the agent (measured — absolute-path executions escape a PATH shim every
time). didrun is honest about this instead of pretending:

- **Tier 0 — `didrun run -- <cmd>`:** the trust core. Complete argv/exit/output/tree state. This is the only tier that *guarantees* a claim's evidence — **and, in v0.2, the only tier wired to a command.** Use it explicitly for anything you'll claim.
- **Tier 1 — PATH shim:** re-dispatches bare-name commands through Tier 0. Absolute-path invocations and shell builtins are honest structural gaps.
- **Tier 2 — per-shell trap:** bash/zsh enrichment. The snippet is gated on `DIDRUN_SESSION`, which only `didrun run` sets, so it is **inert outside a didrun session** rather than observing every shell on the machine.
- **Tier 3 — native adapters:** e.g. Claude Code hooks. Enrichment only; the core works without them.

Every recorded event carries a coverage grade, so the manifest is honest about
what was and wasn't observed.

> **v0.2 status:** Tiers 1–3 exist as measured, tested library functions (see
> `harness/` and `src/didrun/capture.py`) but are **not yet exposed as a
> user-facing `install`/`hooks` command** — wiring them up is on the roadmap.
> Today you get their guarantee by calling `didrun run -- <cmd>` directly.

## What didrun is not

didrun does not prove your code is correct, does not judge quality, and does not
verify a stranger's evidence you have no other reason to trust (that needs
cryptographic signing, which is deferred — see [TRUST_MODEL.md](docs/TRUST_MODEL.md)).
It is a **trust accelerant among people with a baseline of trust**, not a substitute
for it. It records; you review.

**It does not resist a local forger.** Whoever can substitute a ledger can regenerate
its chain and re-run `claim` and `seal` to mint fresh hash-bound claims. What v0.2 buys
is **accident and drift detection on published evidence** — the thing that actually goes
wrong in practice, and worth having. It is not tamper-proofing and must not be sold as
such.

**And the honest limit of the evidence for the whole idea:** in the largest run to date —
846 sealed claims by one count and 667 by another, a discrepancy that is itself an open
research item, and every figure here self-reported by the system under study — exactly
**one** claim graded `failed`. That is equally consistent with a highly effective gate and
with a nearly inert one, and a run whose only actor was cooperating cannot distinguish
them. Until someone tells an agent to obtain a green
`didrun verify --strict` by any means and watches what it does, "didrun catches dishonest
agents" is a hypothesis.

## License

Apache-2.0.
