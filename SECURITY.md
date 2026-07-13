# Security policy

didrun is a trust tool, and it deliberately handles adversarial input: it records
untrusted command output, reads repo-local claim files, and renders reports to
terminals and browsers. We take reports about that surface seriously.

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
- **Determinism breaks** — nondeterministic hashing/grading that undermines the ledger.

## Not yet reviewed

didrun has **not** had an independent security review. It is `v0.x`, experimental,
and should be treated accordingly until that changes.
