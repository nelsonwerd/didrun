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

## Capture: what the streaming pump costs (v0.2)

Tier 0 drained the child through `subprocess.run(capture_output=True)` until
v0.2, which buffers both pipes to completion — so a wrapped command surfaced
nothing at all until it exited (measured on real sessions: single events of
201.95 s, 332.42 s, 447.77 s and 530.21 s with no progress, and a 14.6-hour
chain whose entire operator-visible output was one summary line per command).
v0.2 replaces it with a `selectors` pump that drains both pipes incrementally.

The question that had to be answered with numbers rather than a shrug is what
the pump costs per spawn. Both arms measured **alternately in one process** (so
machine load is shared, not donated to whichever arm ran during a quiet minute),
macOS 26.5 / APFS / arm64, Python 3.14.5:

| Shape | Old — `subprocess.run(capture_output=True)` | New — `selectors` pump | Delta (median) |
|---|---|---|---|
| `/bin/echo hi`, 200 paired runs | 2.340 ms median (mean 2.358, p90 2.601) | 2.364 ms median (mean 2.370, p90 2.628) | **+0.024 ms (+1.0%)** |
| 1 MiB to stdout, 40 paired runs | 24.099 ms median (p90 24.661) | 23.581 ms median (p90 24.309) | **−0.517 ms (−2.1%)** |

So the pump is ~24 µs per short spawn — the same order as the wrapper's own
+55 µs, and invisible next to the two tree digests a `didrun run` already pays
(a full `run_wrapped` over `/bin/echo hi` is ~245 ms median on this machine,
almost all of it digest). On large output it is marginally *faster* than
`communicate()`. Both readings are single-machine and macOS-only; the Linux
rerun this file already gates on covers this table too.

What the pump does **not** change is what is recorded: the drained blobs are
byte-identical to the buffered path's, per stream, over empty, 1 MiB, interleaved,
non-UTF-8 (NUL-bearing) and stderr-only output, and exit codes match including
signal deaths. That equality is the criterion, and it is a test
(`tests/test_streaming_capture.py`), not a claim made here.

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

## Secrets detection: why the detectors are tiered (v0.2)

Measured **2026-07-29** over a real archive of **66** sealed `refs/notes/didrun`
notes (**884** graded claims, **22,062** exported argv elements, **602,975**
characters of exported argv), read through `git notes list` + `git cat-file`
only. Counts, never tokens.

**These counts do not agree with the other corpus figures in this repository, and
nothing here reconciles them.** `docs/V02_STATUS.md` and `docs/COMPAT_REPLAY.md`
cite **65** notes and **846** claims from the research pack; `docs/COMPAT.md` cites
**167** archived ledgers where those two cite **178**; and the 846 figure is itself
already contradicted by a 667 elsewhere in the same research. A live corpus measured
on different days would explain some of the gap and is not established for any of it.
The discrepancy is an open item (FU1 / B5), it is settled only by a recount over a
corpus copy, and until that runs every corpus number in these docs should be read as
*one measurement, on one day, self-reported by the system under study* — not as a
single consistent census. What the table below rests on is the **relative** result
(which detector fired, and how often), which is internally consistent within this one
2026-07-29 read.

**What the detectors actually caught, in production:**

| Detector | Redaction markers in the 66 exported notes |
|---|---|
| `high-entropy` (entropy sweep) | **7,482**, in 60 of 66 notes |
| `aws-access-key` | 0 |
| `github-token` | 0 |
| `slack-token` | 0 |
| `openai-key` | 0 |
| `pem-private-key` | 0 |
| `env-secret-assignment` | 0 |

The six structured detectors fired **zero times**. Every finding the tool has
ever blocked on came from the entropy sweep — and **65 of the 66 notes record
`secrets_override: true`**, i.e. the gate was overridden on 98.5% of real seals.
A blocking gate that fires only false positives is a gate that gets switched
off, which is the failure mode the tiering exists to prevent. This asymmetry is
what the two-tier split rests on, so it is a gate on the change and not a
footnote: had the structured tier fired even once here, the split would have
needed a human decision.

**The root cause was one character.** The entropy sweep's token class included
`/`, so an entire absolute filesystem path was a single token — and a path
accumulates distinct characters much faster than any one of its segments does.
Removing `/` from the class, over real absolute paths on this machine:

| Path population | Paths | Entropy findings before | After |
|---|---|---|---|
| Repository file paths (project A) | 556 | 135 | **0** |
| Repository file paths (project B) | 47 | 9 | **0** |
| Homebrew Cellar directories (depth ≤ 6) | 2,039 | 35 | **0** |
| **Total** | **2,642** | **179** | **0** |

The 24-character floor and the 4.2 bits/char threshold are unchanged, so the
before/after is attributable to the candidate — what gets scored — alone. The
population sits right on the knife edge — median 4.110 and 4.088 bits/char for
the two repository populations, against a 4.2 threshold — which is why the same
tool produced wildly different finding counts on runs that differed only in
where the repository was checked out.

**That table is one-directional, and reading it as two-directional was a
mistake that cost a real credential class.** It measures what stopped firing on
paths. It does not measure what stopped firing on secrets — and `/` is not only
a path separator, it is 1 of the 64 characters of base64. Dropping it from the
token class meant a base64 credential whose slash-free runs are all shorter
than the 24-character floor stopped being a *candidate at all*: not re-scored,
not demoted to `notice`, invisible. Replacement is driven off the findings, so
invisible also meant unredacted — published verbatim into `refs/notes/didrun`
under a seal line reading "0 findings".

So the separator is no longer decided by the character class. A run is taken
over the class **including** `/`, and a per-run test decides whether that `/` is
a separator (score the segments) or an alphabet member (score the run whole).
The test is that a filesystem path is a sequence of **names** and base64 is not:
a segment counts as a name if it is ≥3 characters, ≥60% letters, and ≥80% of
those letters are lower case. That admits `usr`, `site-packages` and CamelCase
like `CoreServices` (10/12) or `Frameworks` (9/10); base64 is ~50% lower case by
construction and clears it only by accident. **One** name is enough to call the
whole run a path — the conservative direction, since it can only return a run to
segment scoring.

Measured over the same population plus a wider one (system framework and
shared-library trees, a virtualenv's site-packages, `/usr/share`), and over
seeded credential populations of 20,000 samples each:

| Path population | Paths | pre-v0.2 | `/` dropped | now |
|---|---|---|---|---|
| The 2,642 above | 2,642 | 179 | **0** | **0** |
| Wide (adds system/library trees) | 46,403 | 9,278 | **248** | **248** |

| Credential population (detected) | pre-v0.2 | `/` dropped | now |
|---|---|---|---|
| AWS secret-access-key shape (40 chars of `[A-Za-z0-9+/]`) | 100.0% | 83.6% | **98.9%** |
| `base64(24 bytes)` = 32 chars | 99.3% | 74.6% | **97.1%** |
| `base64(32 bytes)` = 44 chars | 100.0% | 86.8% | **99.0%** |
| `base64(64 bytes)` = 88 chars | 100.0% | 99.6% | **99.9%** |

The false-positive column is **identical** to the `/`-dropped column on both
populations — the path win is kept in full, at zero measured cost — and the
recall lost by dropping the character is mostly recovered. The 1–3% still
missing is a credential whose own slashes chop it into sub-floor pieces *and*
leave one piece looking like a name; that is the price of biasing the test
toward paths, and it is the honest side to lose on for a detector that is
`notice`-tier precisely because it is a poor discriminator. None of this is
evasion-resistant, and it is not offered as such: an attacker who knows the rule
can satisfy it deliberately.

The entropy sweep was **demoted to `notice`, not deleted**: it is the only
detector that catches an unstructured credential, and length is not secrecy in
either direction. Per-character entropy over an *n*-character token is capped at
log2(*n*), so ~18 distinct characters clears 4.2 — and, measured the other way,
a lowercase-base36 credential sits near 4.05 and does **not** clear it. The
threshold is a poor discriminator in both directions; that is an argument for
not blocking on it, not for trusting it.

**Both directions of the blocking change**, replayed over the same 66 notes:
under the new rule **0** would block (the 65 overridden seals become clean
seals with a warning), and **0** newly block — no claim label and no delta path
in the archive carries a structured-secret shape, even though those fields are
exported and were never scanned before.

## Environment fingerprint: what the v2 gate keys actually do (v0.2)

The v2 gate binds `LANG`, `SHELL`, `TZ`, `VIRTUAL_ENV` and the process umask,
and drops `PATH` and `PWD` (both were in v0.1's key set). The fingerprint is now
compared across time, so every key in it is a potential *false*-drift source and
the drop needs a number rather than a shrug.

Measured on one machine (macOS 26.5, arm64), sampling each key across five shell
contexts and comparing each against the value the current process holds. Counts
only — no value is recorded here or anywhere in the repo:

| Key | Contexts disagreeing with the current process (of 5) |
|---|---|
| `SHELL`, `TZ`, `VIRTUAL_ENV` | 0 |
| `LANG` | 1 (login zsh) |
| `PATH` | 1 (login bash) |

Contexts: `zsh -lc`, `zsh -ic`, `bash -lc`, `bash -c`, `sh -c`.

**Read this honestly: it is a weak result and it does not on its own justify
dropping `PATH`.** On this machine `PATH` was no noisier than `LANG`, which is
kept. The measurement bounds the claim rather than proving it — one machine, one
day, no `direnv`, no `nix develop`, no tmux, no second homebrew prefix, which are
the conditions under which `PATH` reordering is reported to be routine. It also
records a real cost of the keys that were kept: `LANG` differs between login and
non-login zsh here, so a seal from one and a verify from the other reports drift.
That is a true statement about the environment rather than a bug, and it is why
drift is advisory unless `--require-env-match` is passed.

The load-bearing argument for the two drops is structural, not statistical:
`PATH` flips on any venv activation that `VIRTUAL_ENV` already records, and
`PWD` is not the child's cwd at all — a wrapped command always runs with
`cwd=<repo>`, so gating on `PWD` would make two byte-identical executions of the
same command against the same repo disagree because the operator was standing in
a different directory. `PATH` is still recorded, as a truncated digest beside the
gate, so its drift stays visible without being a refusal. See docs/COMPAT.md.

## Known digest blind spots (by design, documented rather than hidden)

Ignored files are invisible to every git-based digest (`tree-exact` does not
certify `.env` or build caches); dirty submodule *content* is flagged via
porcelain-v2 but not digested (grade capped at `stale`); permission bits beyond
the exec bit are not represented. Ordering authority is always the hash chain,
never timestamps.
