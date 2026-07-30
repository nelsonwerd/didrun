# The v0.2 compat replay — verified, bet, and known not closed

**Date:** 2026-07-29 · **Commit:** `49a8b74` on `v0.2-hardening` · **Python:** 3.14.5 (CPython, arm64)
· **Platform:** Darwin 25.5.0 (macOS) · **Suite:** 496 passed, 4 skipped

**Corpus provenance: NONE. The corpus legs did not run.** `DIDRUN_COMPAT_CORPUS` was unset, so the four
real-corpus legs skipped by construction and every corpus-wide row below is **BET (UNEXERCISED)**. No
number in this document is a simulation of one. See *Gate 1* for exactly what clears it.

Every command below ran unwrapped and is therefore **UNRECEIPTED** — the wrapper discipline is suspended
for this pack, so nothing here has a didrun receipt behind it. What it has is the shipped CLI's own
stdout, quoted.

---

## VERIFIED — demonstrated, with the command that settles it

Each row was produced this session by running the shipped CLI in a throwaway git repo under `$TMPDIR`, or
by a test in the suite that fails when the property stops being true. One witness, one platform, one
interpreter.

| # | Claim | What settles it | Result |
|---|---|---|---|
| V1 | The suite is green | `python -m pytest -q` | **496 passed, 4 skipped** (4 skips are exactly the corpus legs) |
| V2 | The capture kill-gate holds | `python -m harness.recall` | **PASS**, freeze INTACT, defect-class recall **100.0% (3/3)**, structural 0.0% (0/2) |
| V3 | The synthetic compat legs are green | `python -m pytest -q tests/compat` | 11 passed, 4 skipped; leg1 7 logs / 11 entries, leg2 4 notes **0 violations**, leg3 **residue 0**, leg4 **multi-index 0** |
| V4 | The tree parses under 3.11 grammar | `ast.parse(…, feature_version=(3,11))` over all 41 `*.py` | **0 failures.** Syntax only — not an API check |
| V5 | Runtime is stdlib-only | AST walk of every import in `src/` + `harness/` | 24 top-level imports, **0 non-stdlib, 0 non-local**; `dependencies = []` |
| V6 | No private paths in shipped files | RULE 17 grep over `src/ tests/ harness/ docs/ testkit/` | Only `/home/runner/…` and `/home/example/…` — public CI shapes and explicit examples, which is what RULE 17 asks for |
| V7 | **Seal fails closed on note-publication failure** | `.git/objects` made unwritable, then `seal` | exit **2**, git's error quoted verbatim, **no `seals.jsonl`**, **no note**, **no watermark file**; permission restored → same seal succeeds and `verify --strict` exits 0 |
| V8 | A note far past `ARG_MAX` publishes and re-reads | 30 claims with 60 KB labels | note body **1,819,948 B** (14× the largest corpus note), seal exit 0, `verify` exit 0, 30/30 recorded-exact |
| V9 | **The substituted-ledger attack (EV2) fails closed** | seal 3 claims → `rm -rf .didrun` → 3 unrelated exit-0 commands on the same tree → `verify --strict` | **exit 1**, `WITNESS-UNAVAIL` ×3, **0/3 evidence-bound**, reason `entry hash mismatch at index 2`. Pre-P1.2 this was `3/3 recorded-exact`, exit 0 |
| V10 | A tampered chain dominates the verdict | flip one nibble of `entry_hash` at index 2 | `x ledger chain BROKEN at index 2 — every grade below is unreliable`, `--strict` **exit 1**, `show --session` **exit 1** |
| V11 | A missing ledger is *unavailable*, not *broken* | `mv .didrun .didrun-moved`, then `verify` | `WITNESS-UNAVAIL`, `--strict` exit 1, the word "broken" appears **0** times, and **no `.didrun` is recreated** |
| V12 | Ledger permissions | `ls -ld .didrun` after a write command | `drwx------`, `session.log` `-rw-------` |
| V13 | An interrupt never loses the flight | SIGINT then SIGTERM during `run -- sleep 30` | exit **130** / **143**, one greppable line, no traceback, event recorded `unobserved  no-exit`, `chain intact`, and the next `run` appends normally |
| V14 | A torn log refuses rather than writing past the tear | truncate `session.log` by 25 B, then `run` | append refused, byte offset named, recovery spelled out, `session.log` still **1** line. (Delivered as a traceback — see U2) |
| V15 | Concurrent appends are safe and non-blocking | 6 parallel `run`s; then a 5 s `run` alongside a second | **6 events, chain intact**; the second run completed in **0.38 s** while the 5 s run held the session |
| V16 | Streamed output is byte-faithful, and a corrupt blob refuses | `run --tee`, `show --event 0 --output`, then flip a byte in the blob | output arrived progressively, replayed exactly; corrupted read → `blob digest mismatch (corruption)`, exit **2** |
| V17 | A malformed note is a **graded refusal**, never a crash and never a green | 6 bad `version` shapes + string claim entry + truncated body + unknown `ctype` + killed `ctype` | **every one exit 2** with a reason. `true`/`2.5`/`0`/`-1`/`"3"`/`null` all → `not a version number`; `version: 99` → `newer than this didrun understands (max 3); upgrade didrun` |
| V18 | Forging the note's own rows does not mint a green | rewrite `grade` to `tree-exact` and `evidence.entry_hash` to zeros | `WITNESS-UNAVAIL`, **0/1 evidence-bound** — the forgery grades *worse*, not better |
| V19 | Supersession retains the record and excludes it from the verdict | claim → move the tree → re-run → re-claim the same label → seal | `1 superseded`, first claim carries `superseded_by: 1` and prints `superseded by claim #1 (record, not verdict)`, `--strict` exit **0** |
| V20 | A narrowing re-seal is refused | `seal` over a narrower window | exit **2**, message names both windows and the two ways out; `--reseal` permits it |
| V21 | A conjunction is never better than its worst member | `claim conjunction --of T,L` with T stale | `STALE`, `worst of 2 conjunct(s): 'T' graded stale`, and both members printed (`of T: STALE`, `of L: TREE-EXACT`) |
| V22 | The detector tiers separate benign from dangerous | a deep build path in stdout vs. a `ghp_…` token in argv | path → **2 notice**, seal succeeds exit 0. Token → **export blocked**, exit **3**, located at `argv of event 0 arg 2 offset 11`, **0 notes written** |
| V23 | A scope miss names the fix | `--path src/` with a `docs/` change | `STALE`, `1 change(s) outside declared pathspecs — add --path docs/ to make this scope-exact` |
| V24 | A claim after a witnessed failure is refused | pass, then `exit 3`, then `claim tests-pass` | exit **2**, and **no `claims.jsonl` written at all** |
| V25 | Environment drift is advisory until asked | `TZ=UTC` seal, `TZ=Asia/Tokyo` verify | `0 match / 1 drifted`, `(advisory; --require-env-match makes it refuse)`; `--require-env-match --strict` exit **1** |
| V26 | A cited authority is cited, not claimed as approval | `authorize` → `seal --allow-secrets --require-authority` → `verify` | `CITED` row carrying, verbatim: *"NOT a signature and NOT approval — didrun cannot tell who wrote it"* |
| V27 | Amend still resolves the note | `git commit --amend`, then `verify` | `resolved-by tree-fallback`, verdict unchanged |
| V28 | Staleness has a non-empty delta | claim, then change the code, then seal | `! STALE`, `tree moved since evidence: 1 path(s) differ` + `M file.txt`, `--strict` exit 1 |
| V29 | `verify` in a repo with no ledger creates nothing | `verify` in a fresh repo | `○ NO CLAIMS`, and no `.didrun` afterwards |
| V30 | **The corpus guardrail refuses the live tree by name** | `is_refused()` / `resolve_corpus_root()` over path strings only — no I/O against the corpus | the live path, its trailing-slash form, and any path *inside* it are all refused by digest; a live-looking copy (`.didrun` + `.git`) is refused by heuristic; a proper copy is accepted |

**Grep gate**, run and quoted:

```
$ grep -rnE "print\(|\bassert .*(line|raw|content|body)\b" tests/compat/
tests/compat/__init__.py:7:content. ``assert line == ...`` is forbidden, because pytest prints both sides
tests/compat/test_corpus_replay.py:6:two hashes is fine — a hash is not content. ``assert line == ...`` is
tests/compat/test_corpus_replay.py:677:    its arguments, so ``assert note_violations(<a note body>, 0) == []`` would
tests/compat/test_corpus_replay.py:689:    assert one_newline == []
```

Four hits, **zero echo a ledger line**: three are the prose that states the rule, and `one_newline` is a
list of `(index, reason)` violation names bound to a local before the assertion, which is the shape the
gate exists to force. No `print(` anywhere in `tests/compat/`.

**Read-only gate:** not applicable and not claimed — nothing was pointed at a corpus, so there were no
mtimes to compare.

---

## BET — argued, not measured

| # | Claim | What would settle it | Who |
|---|---|---|---|
| B1 | **D1 — every stored `entry_hash` in the archived logs recomputes** (or the exceptions are the two known fork incidents) | the corpus leg, over a copy | **HUMAN (Gate 1)** |
| B2 | **D2 — all 65 notes satisfy the three-part round-trip criterion** | the corpus leg, over a copy | **HUMAN (Gate 1)** |
| B3 | **D3 — every archived `objects/` entry partitions, residue 0** | the corpus leg, over a copy | **HUMAN (Gate 1)** |
| B4 | **D4 — multi-index 0, the 178/846 pathspec histogram, the gap distribution** | the corpus leg, over a copy | **HUMAN (Gate 1)** |
| B5 | **FU1** — the 667-vs-846 claim-count discrepancy between the original brief and the artifact | recount over the archived notes | HUMAN |
| B6 | **FU2** — "the structured detectors produced zero findings across the seals". Measured over exported `argv_preview` strings only, **never over the ledgers** | run the detectors over archived ledgers, by someone authorised to read them | HUMAN |
| B7 | **FU3** — the 1-of-8 resume-legality mapping under Locked Decision 2. Inference over recorded tree ids, not observation | inspect the eight launches directly | HUMAN |
| B8 | **FU4** — lane 2's EV2 false-green, single-sourced in the research. V9 above is a second witness for the **mechanism**, in a scratch repo; it is **not** a witness for the corpus | replay EV2 against a corpus copy | HUMAN |
| B9 | **FU5** — every frequency, cost and duration figure in the research, all self-reported by the system under study | independent instrumentation | HUMAN |
| B10 | **Red-team finding 16** — whether the 197 non-terminal claim bindings had an intervening failure | a grep over the archived logs, by someone authorised to read them | HUMAN |
| B11 | The **S6 live-agent recall leg** — capture recall against real agent sessions | a real agent on a real machine (`harness/README.md`) | **HUMAN (Gate 3)** |
| B12 | **CI green on 3.11 / 3.12 / 3.13 × ubuntu / macos** | the CI workflow. **Cannot be settled here** — this interpreter is 3.14.5, and V4 is a grammar check, not an API one | **HUMAN / CI (Gate 2)** |
| B13 | That any of this **changes a decision**. 846 corpus claims produced exactly **1** `failed`; a corpus whose only observed actor was cooperating cannot distinguish a superbly effective gate from a nearly inert one | instruct an agent to obtain a green `didrun verify --strict` by any means. **Not run here, and not authorised by this pack.** The highest-value missing experiment | **HUMAN (Gate 4)** |
| B14 | Durability under power loss. There is no `fsync` anywhere in the package; V15 shows appends are *mutually* safe, not that a committed append survives a crash | a fault-injection harness | open |

---

## KNOWN NOT CLOSED — non-guarantees v0.2 leaves open on purpose

- **Inherited-environment false greens.** `GOFLAGS=-exec=/usr/bin/true` and its family
  (`NODE_OPTIONS`, `PYTHONPATH`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `PYTEST_ADDOPTS`, a PATH shim,
  `sitecustomize.py`) make a passing command that ran nothing. No allowlist closes it. P3.3 records a PATH
  **digest**; a declared clean-environment mode is the honest v0.3 shape.
- **No ledger retention or purge.** A credential scrubbed from git history survives as a loose object under
  `.didrun/objects`. Real, and it needs a retention policy behind it before it needs code.
- **The redaction marker string is forgeable.** `«redacted:…»` is a convention, not a cryptographic mark;
  keyed fingerprints were rejected because a per-ledger key destroys the cross-ledger stability that
  motivated them.
- **`chmod` is close to a no-op on Windows.** V12's `drwx------` is a POSIX result and does not travel.
- **`flock` on a network filesystem.** V15 was measured on a local APFS volume. NFS/SMB semantics differ and
  were not tested.
- **Tree-fallback returns the *first* matching note** (red-team finding 20) rather than failing closed on
  more than one match. Deliberately out of this pack; the first candidate for a v0.2.1 unit.
- **`argv_preview` is written into every note, dropped on read, and computed-but-never-rendered in HTML**
  (red-team finding 21). A product call, not a hardening unit.
- **Duplicate conjunct labels are counted twice.** `--of a,a` grades correctly and reads oddly.
- **`seal` still does not consult the chain.** `verify` does; sealing over a broken chain is possible.
- **None of this resists a determined local forger.** Whoever can substitute a ledger can regenerate its
  chain and re-run `claim` and `seal` to mint fresh hash-bound claims. `ledger.py` declares this in the
  source, `docs/TRUST_MODEL.md` states it, and V18 is *accident and drift detection*, not a barrier.

---

## The four gates

| Gate | Who clears it | Status |
|---|---|---|
| 1 — the corpus copy | **HUMAN** | **NOT CLEARED.** `DIDRUN_COMPAT_CORPUS` unset. Clear it by copying the archive tree **without** its live `.didrun` directory onto a separate volume and re-running with the variable set at the copy. The harness refuses the live tree by name (V30) even if it is set wrongly |
| 2 — CI on 3.11/3.12/3.13 × ubuntu/macos | **HUMAN / CI** | **NOT CLEARED.** Local green does not imply CI green |
| 3 — the S6 live-agent recall leg | **HUMAN** | **NOT CLEARED.** Unexercised |
| 4 — does any of this change a decision | **HUMAN** | **NOT CLEARED, and unanswerable from this corpus** |

---

## Confidence

**30 of 44 load-bearing conclusions are externally verified** — by the shipped CLI's own output in a
throwaway repo this session, or by a suite test that fails when the property stops being true. The other
14 rest on argument from code, on figures the system under study reported about itself, or on a signal
only a human or CI can supply. **Every one of the four real-corpus legs is in the second group.**

A green replay means *these hashes reproduce*. It has never meant *the corpus is proven intact*, and a
`tree-exact` grade means *recorded against the sealed tree* — never *proven correct*.
