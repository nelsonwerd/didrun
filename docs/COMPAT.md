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

## The environment fingerprint is versioned in band

`env_fingerprint()` returns `v<N>:<16 hex chars>`. The prefix exists because the digest's
*shape* does not change when its key set does — two bare digests over different key sets
look comparable and are not.

A value with **no prefix was produced by v0.1** and is **incomparable** with a versioned
one. It is not evidence that the environment drifted, and nothing may report it as such;
`capture.fingerprint_version()` returns `None` for it so a consumer can tell the two
apart.

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

2. **The ledger has no retention or purge.** Captured stdout and stderr are stored as
   content-addressed blobs under `.didrun/objects`. A credential that was scrubbed out of
   git history survives there as a loose object until the ledger directory is removed by
   hand. Treat the ledger as secret-bearing: it is gitignored by default, and it should
   not be committed, shared, or attached to an issue.
