# Measurements behind the design

didrun's architecture follows from things that were **measured, not argued**.
This file summarizes the load-bearing experiments so the "why" of each design
decision is auditable. All numbers below were taken on macOS (APFS, arm64,
SIP enabled), git 2.50.1, Python 3.14.5 — **a Linux/ext4 rerun is required
before any number here is treated as normative on Linux** (tracked as an open
gate; `python -c "from didrun.gitplumbing import capability_probe; capability_probe()"`
emits the environment matrix for comparison).

## Capture: why it is tiered

Tested against the spawn shapes real agent CLIs use (`/bin/sh -c` from
`subprocess(shell=True)`, node-style `/bin/bash -c` with absolute paths,
`$SHELL -c`, direct execs):

| Mechanism | What it sees | What it misses |
|---|---|---|
| **Explicit wrapper** (`didrun run --`) | complete argv/exit/output/timing | nothing — +55µs/spawn (~3% on a no-op, ~0 on real work) |
| **PATH shim** | bare-name, PATH-resolved execs at every process level | **absolute-path execs: 100% miss** across all four spawn styles; grandchildren by absolute path escape even under a shimmed parent; shell builtins invisible. Inherent to `execve`, not a fixable bug |
| **PTY transcript** | the full terminal byte stream, losslessly | argv and exit codes are **not recoverable**: a command that exited 3 produced a transcript reading "tests: 5 passed". This is why transcript events can never carry an exit code or back a success claim |
| **`BASH_ENV` DEBUG trap** | bare AND absolute-path commands — but only under `bash` | `/bin/sh` honors neither `BASH_ENV` nor `ENV` non-interactively; zsh `preexec` never fires non-interactively |
| **zsh `~/.zshenv` DEBUG trap** | works non-interactively, including nested `eval` | zsh only; noisy (fires on scaffolding); persistent on-disk footprint — hence the env-var privacy gate |
| **`DYLD_INSERT_LIBRARIES`** | homebrew-installed interpreters | **stripped by SIP** for `/bin/bash`, `/bin/sh`, `/usr/bin/git` — blind at exactly the layer agents dispatch through. Dead end |

Conclusion: invisible universal capture is infeasible from outside the agent;
only the explicit wrapper guarantees completeness. Hence Tier 0 as the trust
core, honest coverage grades on everything else, and the class-split kill gate
in `harness/` (bare-name recall ≥95% required; absolute-path misses tolerated
only when flagged).

Relevant detail for Claude Code specifically: its Bash tool spawns the **user's
`$SHELL`** per command (verified against the binary and live process table) —
`/bin/zsh -c` on a default macOS box — which is why Tier 2 is per-shell dispatch
rather than `BASH_ENV` alone.

## Tree digests: why copied-index write-tree

The digest must reflect staged + unstaged + **untracked** state, deterministically,
fast enough to run per command. Mechanisms tested on synthetic repos (~2,000 and
~10,000 files):

| Mechanism | Verdict | Measured reason |
|---|---|---|
| **Copy real index → temp; `git add -A` (ledger-redirected); `git write-tree`** | **kept** | 46–119 ms per digest at realistic dirt (including cold-clean); correct on untracked files |
| `git stash create` | banned | returns "clean" when only untracked files exist — agents create files constantly |
| hash of `git status --porcelain=v2` | banned | never hashes worktree *content*: different file contents collide |
| `git diff \| sha256` | banned | output changes under user git config (`diff.mnemonicPrefix`, `core.abbrev`) |
| fresh `read-tree HEAD` variant | banned | correct but 3–5× slower (~210–330 ms) |

Two properties of the kept mechanism are load-bearing:

- `GIT_OBJECT_DIRECTORY` redirects digest objects into the ledger — **zero
  pollution** of the repo's object DB, and the content each command ran against
  is physically retained, which is what lets `verify` show an **exact
  path+content delta** for `stale` grades instead of a shrug.
- A failed `git add` yields **no digest** (→ grade `unknown`), never a partial
  tree — a partial tree would silently under-report dirt.

Also measured: git notes do **not** follow `commit --amend`/rebase by default
(`notes.rewriteRef` defaults exclude custom refs) — which is why manifests
dual-bind to commit id **and** tree id, with tree-fallback lookup.

## Known digest blind spots (by design, documented rather than hidden)

Ignored files are invisible to every git-based digest (`tree-exact` does not
certify `.env` or build caches); dirty submodule *content* is flagged via
porcelain-v2 but not digested (grade capped at `stale`); permission bits beyond
the exec bit are not represented. Ordering authority is always the hash chain,
never timestamps.
