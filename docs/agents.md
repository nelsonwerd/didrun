# Using didrun with a coding agent

The fastest way to get receipts is to have your coding agent route its own
verification commands through didrun. This is **cooperative capture**: the agent
reads an instruction and follows it. It is the right fit for the agent use case —
when the agent declares what it's claiming, you *want* it in the loop.

Paste the snippet for your tool below into that tool's durable-instructions file,
then work normally. See the honest bounds at the bottom — cooperative capture is
best-effort, not enforced, and didrun is careful never to pretend otherwise.

Prerequisites: `didrun` on `PATH` (`pipx install didrun` once it's published, or a
`pipx install ./didrun` from a clone today), and the project is a git repo.

---

## Claude Code — `CLAUDE.md`

Add to the project's `CLAUDE.md` (or your global `~/.claude/CLAUDE.md`):

```markdown
## Verification receipts (didrun)

For any build work where you assert something works (tests pass, lint clean,
build green), produce a receipt with `didrun`:

1. Run every load-bearing verification command through the wrapper:
   `didrun run -- <cmd>` (e.g. `didrun run -- pytest -q`). Subagents that run
   gate commands use the same prefix.
2. At each shippable unit: `didrun claim tests-pass --label "..."`, commit, then
   `didrun seal`.
3. Gate on `NO_COLOR=1 didrun verify --strict` — this is a loop, not a
   checkpoint. Nonzero exit means the unit is NOT done: read the grade, fix the
   real problem, re-run verification through `didrun run --`, re-claim, commit,
   re-seal, re-verify until it exits 0.

Honesty rules: report grades verbatim (`tree-exact` means "recorded against the
sealed tree", never "proven correct"); anything not run through `didrun run` is
UNRECEIPTED and must not be claimed as verified; never open the gate by weakening
a test or deleting a claim.
```

## Codex / agent-agnostic — `AGENTS.md`

The same contract, in the file Codex and several other agents read at repo root:

```markdown
# Verification receipts (didrun)

When you claim something works, back it with a receipt:
- Wrap load-bearing checks: `didrun run -- <cmd>` (tests, lint, build).
- Per shippable unit: `didrun claim <type> --label "..."`, commit, `didrun seal`.
- Gate progression on `didrun verify --strict` (nonzero = not done; fix, re-run
  through `didrun run --`, re-seal, re-verify until exit 0).
- Commands not run through `didrun run` are UNRECEIPTED — never claim them as
  verified. Report grades verbatim; never weaken a test to pass the gate.
```

## Cursor — project rule

Add a rule (`.cursor/rules/didrun.md`, or the Rules for AI settings):

```markdown
When running tests/lint/build to verify a change, run the command through
`didrun run -- <cmd>` so it is recorded. Before finishing a unit, `didrun claim`
the assertion, commit, and `didrun seal`. Treat `didrun verify --strict` as the
done-gate. Never claim work as verified if it was not run through `didrun run`.
```

## Any agent — generic system-prompt block

For a tool with no standard instructions file, add to its system prompt:

```
You have `didrun`, a verification recorder. Any command whose result you will
cite as evidence (tests/lint/build), run as `didrun run -- <command>`. At a
finished unit, declare the claim (`didrun claim <type>`), commit, and `didrun
seal`. Use `didrun verify --strict` as the pass/fail gate and loop on it until
it exits 0. Never present un-wrapped commands as verified.
```

---

## Two v0.2 behaviours the loop depends on

Both are what make "fix, re-claim, re-seal, re-verify until it exits 0" actually
converge, and an agent that doesn't know about them will read the first as a bug.

- **`claim` refuses to bind past a failure.** With no `--event`, a claim binds the
  command that just ran, and it **exits 2** rather than reach back for an earlier
  passing event when the latest one exited nonzero. So the loop cannot be closed by
  running the gate again after a failure and claiming the older green — the fix has to
  come first. A refused claim writes nothing.
- **Re-declaring the same type *and* label supersedes the earlier claim.** The retired
  one keeps its grade in the record, drops out of the verdict, and is counted on both
  surfaces. This is why a fix-verify loop converges instead of accumulating red rows —
  but it is keyed on `(type, label)`, so an agent that varies the label each pass gets
  a growing pile of stale claims rather than one that supersedes.

Note the shape of what this buys: repeatedly claiming a gate until one attempt goes
green is not *prevented*. Every attempt stays in the note and the retired count is
printed, so it is visible. Visible, not blocked, is the honest bound.

## The honest bounds (read this — it's the whole point)

Cooperative capture works because the agent *complies with an instruction*, not
because the system intercepts commands no matter what. So:

- **Unwrapped commands are simply not recorded.** If the agent forgets, is
  interrupted, or a subagent doesn't inherit the instruction, those commands leave
  no evidence. didrun does not pretend otherwise: a claim with no backing recorded
  run grades `unknown`, and the convention is to mark un-wrapped work `UNRECEIPTED`.
- **Absence of a receipt is ambiguous** under this model — it can mean "nothing ran"
  or "the agent didn't route it through didrun." Read `didrun show --session` to see
  what was actually captured.
- **`authorize` is not an approval channel.** If a workflow reaches for
  `didrun authorize` to get past `--allow-secrets` or `--reseal`, understand what it
  records: that a file with a given SHA-256 was cited. An agent can write its own
  authorization artifact in one line, and every surface that prints one says so. It is
  not a signature, not authentication, and not evidence a human approved anything —
  see [TRUST_MODEL.md](TRUST_MODEL.md).
- **This is not enforcement.** A tool that *guarantees* capture regardless of agent
  cooperation is what didrun's Tier 1–3 (PATH shim / shell trap / native adapter)
  are for; those are not yet exposed as a turnkey command. Cooperative Tier 0 is the
  recommended interface for the agent use case today; enforced capture is on the
  roadmap for the "don't trust the producer to self-report" case.

In short: this makes your agent produce receipts as a side effect of working, and
it's honest about the seam. It records what ran; you still review.
