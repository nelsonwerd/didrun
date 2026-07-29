# didrun

[![ci](https://github.com/nelsonwerd/didrun/actions/workflows/ci.yml/badge.svg)](https://github.com/nelsonwerd/didrun/actions/workflows/ci.yml)
&nbsp;![status: v0 · experimental](https://img.shields.io/badge/status-v0%20%C2%B7%20experimental-orange)
&nbsp;![python: 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
&nbsp;![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green)

**Flight records for agent-written code.**

> **v0 · experimental.** The core (`didrun run/claim/seal/verify/show`) works and is
> covered by CI on Linux + macOS across Python 3.11–3.13, but the API and CLI may
> still change, and there has been no independent security review yet. Treat it
> accordingly. See [what it does and does not attest](docs/TRUST_MODEL.md).

When an AI coding agent says *"done — tests pass,"* the proof usually evaporates
the moment the session ends. The transcript is unverifiable prose, CI only re-runs
what CI knows about, and the reviewer is left re-deriving the work or trusting
vibes. That gap is the 2026 bottleneck: teams merge far more agent-authored PRs
than they can review, and AI PRs wait the longest for a reviewer.

didrun records what an agent **actually executed** — the command, the exit code,
the output, and the exact git tree state it ran against — then binds structured
claims to a commit and lets a reviewer check them in seconds:

```
x FAILED — review needed
  2/5 claims recorded-exact · commit a1b2c3d4e5f6 · tree 0f1e2d3c4b5a · resolved-by commit

    STATUS       CLAIM                      DETAIL
  ----------------------------------------------------------------------------
  x FAILED       integration tests pass     exit 1  the recorded command exited 1 — claim is not backed
  ? UNKNOWN      migration applied cleanly  no witnessed successful command backs this claim
  ! STALE        lint clean                 exit 0  tree moved since evidence: 2 path(s) differ
                                              M src/api/handlers.py
                                              A src/api/new_route.py
  ~ SCOPE-EXACT  unit tests pass            exit 0  all 3 change(s) within declared pathspecs
  = TREE-EXACT   type check passes          exit 0  self-stable command ran against the sealed tree
```

There is **no LLM in the trust path.** Capture and verification are deterministic.
didrun is a *recording*, not a *proof* — read [what it does and does not attest](docs/TRUST_MODEL.md).

## Why it exists

- **Verification is the bottleneck, not generation.** Reviewers need to check an
  agent's claims without re-running the work.
- **Everything else in this space is another LLM judging the code.** didrun answers
  a different question — *what actually happened?* — deterministically.
- **Trust is an artifact problem, not a model problem.** The fix for unverifiable
  work is work that carries its own machine-checkable evidence.

## Quickstart (under 5 minutes)

didrun is Python 3.14+, **stdlib-only** (zero runtime dependencies — you can read
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
recorded — `env: N match / M drifted / K incomparable`. Drift is advisory by
default, because a changed environment is a fact about the machine verifying,
not about whether the recorded command ran; `didrun verify --require-env-match
--strict` makes it a refusal. Evidence sealed by an older didrun is
*incomparable*, never drifted, and never refuses.

For humans, generate a self-contained HTML evidence report:

```bash
didrun verify --html evidence.html
```

The report is a single file with zero external assets — it opens offline and
prints cleanly. Redaction covers the sealed note: every exported claim string —
the `argv_preview`, the label, the pathspecs and the changed paths — is
redacted, and the projection is declared in the manifest. The HTML report
carries no argv at all and renders the note's redacted label, but a stale
claim's file list is recomputed against your working tree at verify time and is
shown as it is on disk — read it before you attach it to a PR.

## Use it with your coding agent

You don't have to run these commands by hand. Tell your agent to route its own
verification through didrun, and it produces receipts as a side effect of working.
Drop the snippet for your tool into its instructions file:

- **Claude Code** → add the block to `CLAUDE.md`
- **Codex / agent-agnostic** → add it to `AGENTS.md`
- **Cursor** → a project rule
- **Any agent** → a system-prompt block

Copy-paste snippets for each — plus the honest bounds — are in
[docs/agents.md](docs/agents.md). The short version:

```markdown
For any check you'll cite as evidence, run `didrun run -- <cmd>`. Per finished
unit: `didrun claim <type>`, commit, `didrun seal`. Gate on
`didrun verify --strict` and loop until it exits 0. Never claim un-wrapped work
as verified.
```

This is **cooperative capture** — it works because the agent follows the
instruction, not because anything is enforced. Commands the agent *doesn't* route
through `didrun run` are simply not recorded (a claim with no backing run grades
`unknown`), so didrun never mistakes "didn't capture it" for "verified." Enforced,
agent-can't-forget capture is what Tiers 1–3 are for — see the note below.

## The grades

didrun never says "verified — trust me." Each claim gets an honest grade against
the sealed commit's tree — **first match wins**:

| Grade | Meaning |
|-------|---------|
| **TREE-EXACT** | A self-stable command ran against *exactly* the sealed tree. |
| **SCOPE-EXACT** | Every change since the evidence is within claimant-declared pathspecs. |
| **STALE** | Evidence exists but the tree moved — the exact path+content delta is shown. |
| **UNKNOWN** | No honest binding (no witnessed success, retroactive binding, gc'd object). |
| **FAILED** | The claimed command was *recorded failing* — a caught lie, not merely missing evidence. |

`STALE` always carries the concrete delta; it is never a bare shrug. `tree-exact`
means the evidence tree equals the sealed tree — it does **not** claim the code is
correct or that the command meaningfully tested anything.

## The five commands

- `didrun run -- <cmd>` — record a wrapped execution (complete capture).
- `didrun claim <type> [--path <spec>]` — declare a structured claim.
- `didrun seal` — compile a commit-bound evidence manifest (redacts secrets; refuses when a structured secret is found in what it is about to publish, warns about the rest).
- `didrun verify [--strict] [--require-env-match] [--html <file>]` — check claims against recorded evidence.
- `didrun show [--session]` — show the verdict, or the recorded session history.

## Capture is tiered and honest about coverage

Universal, invisible capture of everything an agent runs is not possible from
outside the agent (measured — absolute-path executions escape a PATH shim every
time). didrun is honest about this instead of pretending:

- **Tier 0 — `didrun run -- <cmd>`:** the trust core. Complete argv/exit/output/tree state. This is the only tier that *guarantees* a claim's evidence — **and, in v0, the only tier wired to a command.** Use it explicitly for anything you'll claim.
- **Tier 1 — PATH shim:** re-dispatches bare-name commands through Tier 0. Absolute-path invocations and shell builtins are honest structural gaps.
- **Tier 2 — per-shell trap:** bash/zsh enrichment, **inert unless a didrun session is active** (it never records unrelated shell activity on your machine).
- **Tier 3 — native adapters:** e.g. Claude Code hooks. Enrichment only; the core works without them.

Every recorded event carries a coverage grade, so the manifest is honest about
what was and wasn't observed.

> **v0 status:** Tiers 1–3 exist as measured, tested library functions (see
> `harness/` and `src/didrun/capture.py`) but are **not yet exposed as a
> user-facing `install`/`hooks` command** — wiring them up is on the roadmap.
> Today you get their guarantee by calling `didrun run -- <cmd>` directly.

## What didrun is not

didrun does not prove your code is correct, does not judge quality, and does not
verify a stranger's evidence you have no other reason to trust (that needs
cryptographic signing, which is deferred — see [TRUST_MODEL.md](docs/TRUST_MODEL.md)).
It is a **trust accelerant among people with a baseline of trust**, not a substitute
for it. It records; you review.

## License

Apache-2.0.
