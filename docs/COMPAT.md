# Format compatibility

didrun writes evidence that is meant to outlive the version that wrote it: a chain of
recorded events on disk, and a manifest published as a git note on a commit. This
document states what is frozen, what may change additively, and what v0.2 changed in a
way that is visible from outside.

The rule behind all of it: **when didrun meets a format it does not understand, it
refuses and says so.** It never reads unknown evidence under the semantics it happens to
know — a confident verdict about a format the binary has never seen is exactly the
failure mode this tool exists to avoid.

## The chain preimage is versioned by an explicit field list

`ChainEntry.compute_hash` does not hash "the event". It hashes the fields named in
`ledger._PREIMAGE_FIELDS` for the entry's `preimage_version`. Version 1 is **frozen**:
its field list is a literal in the source and a golden test recomputes a known entry
hash from a fixed event, so any change to the field set fails that test rather than
silently invalidating every `entry_hash` ever written.

Adding a field to `Event` therefore does not change existing hashes. Putting a field
into the *preimage* does, which is why a new preimage version is a deliberate, tested
step and not a side effect of adding an attribute.

An entry whose `preimage_version` this binary does not know is not verified against a
guess: the chain check reports it as unverifiable and names the index.

## Manifest versioning

`MANIFEST_VERSION` is the note format's version.

- **Additive fields do not bump it.** A new key that older notes simply lack is
  backward-compatible in both directions.
- **A change to an existing field's type or meaning bumps it**, as does a change to the
  claim-type vocabulary — those are the changes that make an old reader wrong rather
  than merely incomplete.
- **A version newer than the reader is refused, not coerced.** `Manifest.from_json`
  raises on a version above the one it knows and names both numbers. Older versions are
  read.
- **Every new manifest key is read with `.get()` and a default that reproduces v1
  semantics.** A required key would break reading every note already published.

### Version 2 — a claim names the evidence it was sealed against

A v2 note may carry an `evidence` block inside a claim entry, naming the recorded ledger
entry that backed that claim: its index, its chain `entry_hash`, and the environment
fingerprint and tree digest recorded on that event. `verify` checks that binding before
grading anything. When the live ledger cannot supply that entry — the index is out of
range, or a different entry sits there — the claim is reported as `witness-unavailable`
carrying the grade the note sealed, and `--strict` refuses it.

The version bumped for the change of MEANING, not for the new key. Before v2, verify
silently regraded against whatever ledger is present, so archival, rebuild or index drift
changed a sealed verdict with no signal. That is the defect v2 closes.

What this buys is **accident and drift detection on a published note**, not resistance to
a local forger. Whoever can substitute a ledger can regenerate its chain and re-run
`claim` and `seal` to mint fresh hash-bound claims. `ledger.py` states that non-guarantee
in the source and nothing here changes it.

Old notes stay readable. New notes do not travel backwards:

- **v0.2 reading a v1 note.** Every note published before v0.2 is version 1 and carries
  no `evidence` block, so it takes the unbound path and regrades exactly as v0.1 regraded
  it, down to the reason string.
- **v0.1 reading a v2 note — REFUSED, by design.** v0.1's `Manifest.from_json` raises on
  any version above its own, so `didrun verify` exits 2 with
  `manifest version 2 is newer than this didrun understands (max 1); upgrade didrun`.
  This is the refuse-never-coerce rule at the top of this document applied to us: a v0.1
  reader would regrade a v2 note index-only and report a confident verdict without ever
  checking the binding the note was sealed under. Refusing is the correct behaviour, but
  it is a real forward incompatibility and it bites a mixed-version setup — seal on a
  v0.2 workstation, verify in v0.1 CI, and every commit fails. **Upgrade the verifier
  first, then the sealer.**

The evidence block lives in the manifest, never in an `Event`. Putting it into the chain
preimage would invalidate every `entry_hash` ever written — the break the frozen preimage
above exists to prevent.

When didrun falls back to resolving a manifest by tree id it scans the notes ref. A note
it cannot parse at all — a foreign note under the same ref, a corrupt body — is skipped
and counted, and the count is reported, so one bad note cannot hide every good one. A
note it *can* parse but whose version is too new is not skipped: it aborts the
resolution. The fallback returns the first note whose sealed tree matches; it does not
currently detect a second match.

## The exported redaction projection is declared, not inferred

Each claim entry in a v0.2 note carries an additive `redaction` block:

```json
"redaction": {"projection_version": 1, "detector_set_version": 2,
              "applied": [{"argv_index": 2, "start": 10, "end": 59,
                           "detector_id": "env-secret-assignment",
                           "withheld": false}]}
```

`applied` names the exact source spans that were replaced in `argv_preview`, in the
source's own coordinates. It exists because the projection used to be readable only by
inference, and inference was wrong: which tokens the entropy sweep flagged turned on
letter frequency, so the same argv shape exported differently from one seal to the next
and a downstream validator had to keep a matrix of didrun's historical behaviour. A
consumer now reads the contract. `projection_version` bumps when the rule turning
findings into replaced spans changes; `detector_set_version` bumps when the detectors do.

**The marker string alone is not authenticating.** `«redacted:openai-key»` is plain text
that a recorded argv is free to contain, and didrun does not escape a pre-existing
marker. A consumer that wants to know whether a preview was really redacted — and where
— reads `redaction.applied`; it must not pattern-match the preview. Keyed markers would
make the marker itself unforgeable and are deliberately not built: they need a per-ledger
key store, and a per-ledger key destroys the cross-ledger comparability that motivated
them.

`withheld: true` marks the honest-absence path: the element was dropped whole rather than
rewritten, and the preview shows `«withheld:<detector>»` in its place. It is never an
empty string, because an empty preview and a suppressed one are different facts.

This block is additive and read with `.get()`, so it does not bump `MANIFEST_VERSION` and
older notes that lack it are read exactly as before. **v0.2 projections differ from
v0.1's for any input with overlapping findings**: v0.1 replaced overlapping spans
end-first, which deleted the text after the outermost span, so an argv like
`run --key MY_TOKEN=<token> && echo done` exported with `&& echo done` silently gone.
v0.2 merges findings into disjoint maximal spans first, and the result is exactly
reconstructible — substituting each marker back with the source span `applied` names
reproduces the input byte for byte.

**`detector_set_version` is 2 from v0.2's detector work onward.** The entropy sweep no
longer decides in the character class whether `/` is a path separator; it decides per
run, scoring a filesystem path in segments and a base64 blob whole, and every detector
now declares a tier. That is a change to what the detectors match, which is exactly what
the number is for — a consumer comparing a `1` projection with a `2` one is told the
detectors differ instead of having to infer it. `projection_version` stays 1: the
span-partition algorithm did not change.

### The projection covers the claim fields, not only argv

A v0.2 `redaction` block carries a second, additive list beside `applied`:

```json
"redaction": {"projection_version": 1, "detector_set_version": 2,
              "applied": [{"argv_index": 3, "start": 9, "end": 49, ...}],
              "fields":  [{"field": "claim.label", "start": 17, "end": 57,
                           "detector_id": "github-token", "withheld": false}]}
```

`applied` is unchanged and stays argv-addressed by `argv_index`; `fields` is addressed
by field name, because a label has no argv index. Field names in v0.2 are `claim.label`,
`claim.pathspecs[i]` and `delta[i].path`. A reader that does not know the key sees
exactly the argv projection it always did.

This exists because blocking and redacting were not the same set. A structured secret in
a claim label refused the seal — and the refusal says *"re-run with `--allow-secrets` to
export a redacted artifact anyway"* — but on the override the label was serialized into
`refs/notes/didrun` verbatim, a ref that gets pushed. The claim fields are now scrubbed
by the same pass that reports them to the gate, so the two cannot drift apart again.
`scan_domain` says so: it reads `claim-bound-events+claim-fields+manifest` rather than
`claim-bound-events+manifest`. A stored note carrying the older string is still read
normally; the string is a description of that seal, not a compatibility gate.

## The manifest records what the secrets pass scanned

A v0.2 manifest carries an additive top-level `secrets` block beside `secrets_override`:

```json
"secrets": {"scan_domain": "claim-bound-events+claim-fields+manifest", "events_scanned": 1,
            "events_total": 7, "bytes_scanned": 4213, "detector_set_version": 2,
            "findings_by_tier": {"block": 0, "notice": 3},
            "blocked": false, "overridden": false}
```

It is additive, defaults to `{}`, and is read with `.get()`, so it does **not** bump
`MANIFEST_VERSION` and a stored note that lacks it reads exactly as before. The compat
harness's per-version additive-key allowlist carries `secrets` for both v1 and v2 — the
deliberate one-line diff that keeps the note round-trip leg honest instead of red across
every stored note at once.

`secrets_override` is untouched: same name, same type, same meaning — *this seal would
have been refused and the operator overrode it*. It is deliberately not replaced by a
dict, because a v0.1 binary reads it with `.get("secrets_override", False)` and a dict
there is truthy, which would make every clean v0.2 seal print "sealed with
--allow-secrets" on an older reader. What `secrets` adds is the domain behind the
boolean: `false` used to be the same word for "nothing was found" and "almost nothing was
scanned", and `events_scanned` / `events_total` now say which.

**What blocks changed direction in v0.2.** A refusal is scoped to the export domain —
the argv of each claim-bound event plus the serialized manifest, which carries the claim
labels and delta paths that were previously published entirely unscanned. Findings
confined to the local output blobs, and every `notice`-tier finding, warn on stderr and
do not stop the seal. So some previously-refused seals now pass and some previously
passing ones now refuse; both directions are measured in MEASUREMENTS.md.

## The environment fingerprint is versioned in band

`env_fingerprint()` returns `v2:<16 hex gate>:path=<8 hex>`. The prefix exists because the
digest's *shape* does not change when its key set does — two bare digests over different
key sets look comparable and are not.

A value with **no prefix was produced by v0.1** and is **incomparable** with a versioned
one. It is not evidence that the environment drifted, and nothing may report it as such;
`capture.fingerprint_version()` returns `None` for it so a consumer can tell the two
apart. `capture.fingerprint_gate()` returns `None` for the same values, so a consumer
cannot compare one by accident.

### v2: what the gate binds, and what it deliberately does not

The **gate** — the only portion any comparison reads — is a digest of `LANG`, `SHELL`,
`TZ`, `VIRTUAL_ENV` and the **process umask**. Two of v0.1's keys were dropped:

- **`PATH`** varies with terminal tab, `direnv`, `nix develop`, tmux and homebrew
  shellenv ordering, and flips on any venv activation `VIRTUAL_ENV` already records. A
  gate that refuses in a new shell is ignored within a week. PATH is instead recorded as
  its own truncated digest in the `path=` suffix: drift in it is **advisory**, reported
  as a suffix on a verdict line, and can never turn a match into drift.
- **`PWD`** is not the child's cwd. A wrapped command always runs with `cwd=<repo>`, and
  `Event.cwd` records that same resolved path; `PWD` is the caller's shell variable,
  which can be stale and can be absent when didrun is spawned by a launcher. Once the
  fingerprint is compared, gating on it would mean two byte-identical executions of the
  same command against the same repo disagree because the operator was standing
  somewhere else.

`umask` is added because it is the fact whose absence made two green wrapper events under
different umasks indistinguishable in the receipt. It is read **once per process**
(`capture.process_umask`) and reused: reading a umask is a read-modify-write on
process-global state, so a per-event read would open that window on every wrapped command.

**The `path=` digest is a deviation, stated plainly.** The design review asked for `PATH`
to be recorded *unhashed in the event body*. A raw `PATH` there would enter the v1 chain
preimage — which is frozen — and would sit one redaction pass away from a published note,
against the export-scoped secrets rule. A digest in the existing free-form `str` field
gives the same drift visibility at zero schema cost and leaks less. What it costs is
legibility: a reader learns *that* PATH changed, never *how*.

### The comparison verify makes, and what it may not do

`verify` computes this process's fingerprint once and compares the **gate** against the
one each claim's `evidence` block recorded. Four outcomes:

| `env_status` | when |
|---|---|
| `match` | same fingerprint version, equal gates |
| `env-drift-since-seal` | same fingerprint version, different gates |
| `incomparable` | different fingerprint versions, or a bare v0.1 digest |
| `not-recorded` | the note bound no fingerprint for the claim |

**Only `env-drift-since-seal` can ever refuse, and only under `--require-env-match`.**
By default drift is reported in the verdict and does not change `all_verified`, because
a changed environment is a fact about this machine now, not about whether the recorded
command ran. `incomparable` never refuses under either mode — it is the state every note
published before v0.2 lands in, and refusing on it would convert "this note predates the
current key set" into a failure.

**No archived evidence changes.** `Event`'s field set is untouched, so no stored
`entry_hash` moves; archived events keep their v0.1 and v1 fingerprint strings verbatim;
and a note with no `evidence` block is compared not at all. Note also that this makes
green **harder** to reach, not easier: anyone measuring whether v0.2 reduced failed
attempts must be told that `--require-env-match` adds a way to fail. A fingerprint that
can never refuse is not binding anything.

## Tree-digest semantics changed in v0.2 (release-note level)

## Tree-digest semantics changed in v0.2 (release-note level)

v0.1 excluded only `.didrun/` from a tree digest. v0.2 also excludes the archive root
`.didrun-history/`, so rotating a ledger into the archive no longer moves the digest of
the tree that just archived it.

This is a **semantics change, not hygiene**: for a repository that carries a
`.didrun-history/` directory which is **not** gitignored, a tree digest taken by v0.2
differs from one taken by v0.1, and claims recorded against the older digest grade
`stale`. For every other repository the digest is unchanged: with no such directory there
is nothing to exclude, and with a gitignored one `git add -A` already skipped it before
the exclusion pass ever ran.

The one repository where this was measured before release gitignores `.didrun-history/`,
so no archived tree id there is affected. That is a measurement of one repository, not a
proof about all repositories. Both configurations are pinned by tests.

`.didrun/` itself remains excluded unconditionally, regardless of gitignore state.

## Ledger permissions (v0.2) and where the guarantee stops

v0.2 forces the ledger ROOT to `0700` on every writable open — creation and re-open
both, because `mkdir(exist_ok=True)` never re-tightens a directory an older binary
already made at `0755`. Files this version creates (`session.log`, `claims.jsonl`,
`seals.jsonl`, `.gitignore`, blob temp files) are created `0600`.

Three bounds, stated because a rounded-up version of any of them would be an overclaim:

- **Inherited files keep their modes.** The create mode applies at creation only, and
  `.gitignore` is written only when absent. A ledger a v0.1 binary produced keeps `0644`
  on those files. The root's `0700` is what makes that acceptable — another uid cannot
  reach them through the directory — and it is **not** the same statement as "the files
  are 0600".
- **`.didrun/objects/**` is not covered.** git writes into it directly through the
  `GIT_OBJECT_DIRECTORY` redirect, twice per `didrun run`, at its own modes. didrun does
  not chmod what git owns.
- **Windows.** `os.chmod` is close to a no-op on NTFS, so `.didrun/` inherits the parent
  directory's ACLs and this guarantee does not hold there. The ownership check that
  guards the chmod uses `os.geteuid`, which does not exist on Windows; it is skipped.

Read-only commands (`verify`, `show`) no longer open a writable session: they create no
ledger directory, write no `.gitignore`, and re-mode nothing. Before v0.2, `didrun verify`
in a repo with no ledger *manufactured* an empty world-readable one, after which every
claim graded `unknown`; pointing `show` at an archived ledger re-moded it. Nothing on disk
changes shape, and `.didrun/` is excluded from tree digests unconditionally, so no
archived tree id or sealed note is affected.

## Append serialization is POSIX-only (v0.2, behaviour, not format)

From v0.2 the read-tail-and-append pair inside `Session.append` — and the `claims.jsonl` /
`seals.jsonl` appends — run under an `fcntl.flock` on `.didrun/.lock`, so two didrun
processes writing to one ledger cannot both record the same chain index. **On a platform
without `fcntl` the lock is a declared no-op and didrun degrades to the v0.1 behaviour:
concurrent writers can fork the chain, which `verify_chain` then reports as a permanent
break.** No portable fallback is invented, because a fallback that does not actually
exclude would be worse than a stated gap. `flock` is also emulated or ignored on NFS and
some other network filesystems; the exclusion there is as good as the filesystem's and no
better.

Nothing stored changes. The lock file lives inside the ledger directory, which is excluded
from every tree digest unconditionally and ignored by the `*` rule the ledger writes into
its own `.gitignore`, so it moves no tree id, reaches no sealed note, and cannot be
committed. The lock is held for one short local write and is **never** held across a
wrapped child process — a `didrun run` that takes an hour blocks nobody.

Separately, a blob's temp file is now named per writer rather than `<digest>.tmp`. Two
recorders storing the same bytes at the same time — an empty stderr is a digest every
event shares — used to race on that one name, and the loser died with `FileNotFoundError`
instead of recording. Stored blob names, contents and modes are unchanged.

## Tier-0 capture streams from v0.2 (behaviour, not format)

v0.2 drains the wrapped command's pipes incrementally instead of buffering them to
completion. Nothing recorded changes: the stored blobs are byte-identical to what the
buffered path produced, per stream, and the event's field set, `observed_via`, `coverage`
and exit code are untouched. What changes is that `didrun run` can now show the command's
output while it runs (`--tee`) and print a content-free progress line (`--heartbeat N`).
Both default **off**, so a caller parsing didrun's stdout sees exactly what it saw before.

The drain uses `selectors`, which on Windows is a `select()` over sockets and cannot
register an anonymous pipe. Rather than make Tier-0 capture POSIX-only, registration
failure falls back to one blocking reader thread per pipe — same behaviour, no new
dependency. **The fallback is declared, not measured:** CI runs ubuntu and macOS only, so
no Windows leg exercises it.

`didrun show --event N --output` reads a recorded blob back (`--stream stderr`,
`--redacted`). It is a reader over the existing store, adds no format, and re-hashes on
read, so a corrupted blob is a refusal rather than bytes presented as the record.

## Known, not closed: the redaction domain

Found while fixing the two defects above, judged real, and deliberately left open rather
than fixed quietly in the same change. Each is a bounded statement about where redaction
stops, not a plan.

1. **An HTML report's file list is recomputed, not read from the note.** `verify`
   regrades a claim against the working tree, so a `stale` claim's changed paths in
   `didrun verify --html` come from the local repository at verify time — they are not
   the note's redacted copy. The note itself is redacted; the HTML file is an export and
   this path is not. It predates the claim-field work and is unchanged by it. Redacting
   at render time is the obvious fix and is not taken here because it also degrades the
   local terminal's `stale` drill-down, which is the one thing that grade exists to show;
   choosing between them needs its own measurement. README.md carries the caveat in the
   sentence that describes the report.

2. **The entropy sweep misses roughly 1–3% of slash-bearing base64 credentials.** A
   credential whose own slashes chop it into pieces all shorter than the 24-character
   floor, *and* leave one piece looking like a name, is scored as a path and missed. That
   is the measured price of biasing the path test toward paths (MEASUREMENTS.md), and it
   is a `notice`-tier detector either way. Nothing in the rule resists an attacker who
   knows it — the rule is published here, and satisfying it deliberately is trivial.

3. **`reason` and `coverage` are exported unredacted.** Both are didrun's own generated
   text — grade names, counts, path *counts* — and carry no operator or repository
   string today. That is a property of the current generators, not an enforced
   invariant: a future `reason` that interpolates a path or a label would leave the
   redacted set without anything failing. The whole-blob manifest scan still *blocks* on
   such a field, so the failure mode would be a blocked seal, not a silent leak.

## Two things v0.2 does not close

Stated here because a trust tool's silence about its own limits is the same defect as an
overclaim.

1. **A wrapped command inherits the caller's environment.** didrun records *that* the
   command ran and *what* it exited with; it does not control what the environment made
   the command do. `GOFLAGS=-exec=/usr/bin/true` yields an exit-0 event and a
   `tree-exact` `tests-pass` claim for a command that ran no tests. No allowlist closes
   this — `NODE_OPTIONS`, `PYTHONPATH`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`,
   `PYTEST_ADDOPTS`, a user gitconfig, a `sitecustomize.py`, and a `PATH` shim all
   produce it — and putting the effective environment into the event body would put the
   richest secret carrier on a developer machine into the chain preimage. A declared
   clean-environment mode is the honest shape for this, and it is not built.

   **The v2 environment fingerprint does not close this and must not be described as
   closing it.** It binds five facts (`LANG`, `SHELL`, `TZ`, `VIRTUAL_ENV`, umask) and
   records a PATH digest. `GOFLAGS` is in none of them, and adding it would only move the
   line — the list above has no end. What the fingerprint buys is that a *change* in
   those five facts between seal and verify is visible instead of silent.

2. **The ledger has no retention or purge.** Captured stdout and stderr are stored as
   content-addressed blobs under `.didrun/objects`. A credential that was scrubbed out of
   git history survives there as a loose object until the ledger directory is removed by
   hand. Treat the ledger as secret-bearing: it is gitignored by default, and it should
   not be committed, shared, or attached to an issue.
