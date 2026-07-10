"""Secrets redaction for exported artifacts (v1 scope, blocking by default).

The ledger records everything a session printed — including tokens and .env
contents. Exporting a bundle or rendering an HTML report without scrubbing would
turn a trust tool into a leak ("didrun leaked our staging token" is
category-killing; see docs/TRUST_MODEL.md).

This pass runs at seal/export: it scans argv and manifest-bound blobs, BLOCKS
export by default when a likely secret is found, and always redacts what reaches
an exported/rendered artifact. The raw *local* ledger is left intact (it is
gitignored and local); only what leaves the machine is scrubbed.

The heuristic is deliberately tuned to bound false positives — a benign 40-char
git hash must NOT trip it, or the tool blocks everything and gets disabled.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    kind: str
    span: tuple[int, int]
    preview: str  # already-masked preview, never the raw secret


# High-confidence structured patterns. These fire on shape, not entropy.
_PATTERNS = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("pem-private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    # KEY=value / TOKEN=value / SECRET=value / PASSWORD=value assignments in argv.
    (
        "env-secret-assignment",
        re.compile(
            r"\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|APIKEY|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)=([^\s]{6,})"
        ),
    ),
]

_REDACTION_MARKER = "«redacted:{kind}»"

# Entropy heuristic bounds. A long, high-entropy, non-hex token that isn't a git
# hash is suspicious. Git SHAs are hex (entropy ~4.0 bits/char over [0-9a-f]),
# so requiring >4.2 bits/char over a larger alphabet excludes them.
_ENTROPY_MIN_LEN = 24
_ENTROPY_MIN_BITS_PER_CHAR = 4.2
_HEXISH = re.compile(r"^[0-9a-fA-F]+$")
_TOKENISH = re.compile(r"[A-Za-z0-9_\-+/=]{%d,}" % _ENTROPY_MIN_LEN)


def _shannon_bits_per_char(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _mask(kind: str) -> str:
    return _REDACTION_MARKER.format(kind=kind)


def scan(data) -> list[Finding]:
    """Return findings for likely secrets in ``data`` (str or bytes).

    Structured patterns first, then a bounded entropy sweep that explicitly
    skips hex-only tokens (git hashes) to keep false positives low.
    """
    if isinstance(data, bytes):
        text = data.decode("utf-8", "replace")
    else:
        text = data
    findings: list[Finding] = []
    matched_spans: list[tuple[int, int]] = []

    for kind, pat in _PATTERNS:
        for m in pat.finditer(text):
            findings.append(Finding(kind=kind, span=m.span(), preview=_mask(kind)))
            matched_spans.append(m.span())

    for m in _TOKENISH.finditer(text):
        tok = m.group(0)
        if _HEXISH.match(tok):
            continue  # git hashes and hex digests are not secrets
        if any(s <= m.start() < e for s, e in matched_spans):
            continue  # already covered by a structured pattern
        if _shannon_bits_per_char(tok) >= _ENTROPY_MIN_BITS_PER_CHAR:
            findings.append(
                Finding(kind="high-entropy", span=m.span(), preview=_mask("high-entropy"))
            )
    return findings


def redact(data) -> tuple[str, list[Finding]]:
    """Return (redacted_text, findings). Matches are replaced by stable markers."""
    if isinstance(data, bytes):
        text = data.decode("utf-8", "replace")
    else:
        text = data
    findings = scan(text)
    # Replace from the end so earlier spans keep their offsets.
    ordered = sorted(findings, key=lambda f: f.span[0], reverse=True)
    out = text
    for f in ordered:
        s, e = f.span
        out = out[:s] + _mask(f.kind) + out[e:]
    return out, findings


def scrub_argv(argv) -> list[str]:
    """Redact secret-shaped tokens inside argv elements (e.g. FOO=secret)."""
    scrubbed = []
    for arg in argv:
        red, _ = redact(arg)
        scrubbed.append(red)
    return scrubbed


class SecretsBlocked(Exception):
    """Raised when export is blocked because secrets were found."""

    def __init__(self, findings: list[Finding]) -> None:
        self.findings = findings
        kinds = ", ".join(sorted({f.kind for f in findings}))
        super().__init__(
            f"export blocked: {len(findings)} likely secret(s) found ({kinds}). "
            "Re-run with --allow-secrets to export a redacted artifact anyway "
            "(the override is logged into the manifest)."
        )
