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
