# Security policy

didrun is a trust tool, and it deliberately handles adversarial input: it records
untrusted command output, reads repo-local claim files, and renders reports to
terminals and browsers. We take reports about that surface seriously.

## Supported versions

Fixes land on the latest minor only. There is no backport branch and there never
has been.

| Version | Supported |
|---------|-----------|
| **0.2.x** | yes — the current release |
| 0.1.x | no — upgrade; the evidence-integrity defects named below are fixed in 0.2.0 |

If you run didrun in more than one place, note the upgrade order: `MANIFEST_VERSION`
is now 3 and a v0.1 reader **refuses** a v0.2 note by design, so **upgrade verifiers
before sealers** — see [docs/COMPAT.md](docs/COMPAT.md).

## Reporting a vulnerability

Please **do not** open a public issue for a security problem. Instead, use GitHub's
private vulnerability reporting ("Report a vulnerability" under the Security tab),
which opens a private advisory. Include a description, affected version/commit, and
a reproduction if you have one.

We aim to acknowledge within a few days. Because this is an early-stage,
single-maintainer project, please allow reasonable time for a fix before any public
disclosure.

## Scope worth reporting

didrun's own [trust model](docs/TRUST_MODEL.md) states plainly what it does and does
not defend against — read it first, since some "attacks" are documented non-goals
(e.g. a local adversary regenerating the hash chain; verifying a stranger's unsigned
evidence). Genuinely in-scope reports include:

- **Rendering/injection escapes** — ANSI, HTML/XSS, or control sequences from recorded
  output that reach a terminal or the HTML report unescaped.
- **Secret leakage** — captured secrets that survive `seal`/export into a bundle or
  report despite the redaction pass.
- **Evidence-integrity bugs** — a way to make `verify` report `tree-exact` /
  `scope-exact` for a claim that is not actually backed by a recorded run against the
  sealed tree (i.e. the tool *overclaiming*). This is the most important class.

  **Four instances of it were found by dogfooding didrun on a 15-day autonomous
  build, and are addressed in 0.2.0.** The chain check now runs inside `verify`
  before any grading and a fault dominates the verdict — it previously had exactly
  one caller, `show --session`, so a forked or mid-file-rewritten ledger certified
  green under `--strict`. Ledger appends take an `fcntl.flock`, so two writers
  cannot fork the chain. A seal whose note cannot be published fails closed at
  exit 2 leaving no note, no watermark and no seal record, where it used to report
  N/N claims and publish nothing. And manifest resolution now records *how* it
  resolved (`resolved_by`: `commit` | `tree-fallback` | `none`, plus a count of
  notes it could not parse), where a silent tree-fallback could return a different
  same-tree commit's note and exit 0 under `--strict`.

  **The class is not closed, and three known gaps sit inside it.** `seal` still
  does not consult the chain, so sealing over a broken chain is possible.
  Tree-fallback returns the *first* note whose sealed tree matches and does not
  fail closed on a second match. And none of this resists a determined local
  forger: whoever can substitute a ledger can regenerate its chain and re-run
  `claim` and `seal` to mint fresh hash-bound claims. What v0.2 buys is accident
  and drift detection on published evidence, not tamper-proofing. Reports in this
  class are wanted against 0.2.x whether or not they resemble the four above.
- **Determinism breaks** — nondeterministic hashing/grading that undermines the ledger.

## Not yet reviewed

didrun has **not** had an independent security review. It is `v0.x`, experimental,
and should be treated accordingly until that changes.
