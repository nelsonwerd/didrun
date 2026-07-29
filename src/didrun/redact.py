"""Secrets redaction for exported artifacts (v1 scope, blocking by default).

The ledger records everything a session printed — including tokens and .env
contents. Exporting a bundle or rendering an HTML report without scrubbing would
turn a trust tool into a leak ("didrun leaked our staging token" is
category-killing; see docs/TRUST_MODEL.md).

This pass runs at seal/export: it scans argv, the bytes about to be published,
and the manifest-bound output blobs. The raw *local* ledger is left intact (it
is gitignored and local); only what leaves the machine is scrubbed. What BLOCKS
is scoped to the export domain for the same reason: stopping a seal over bytes
that never leave the machine, while publishing claim labels unscanned, is the
gate pointed at the wrong half of the tool (see manifest.py's `_scan_for_secrets`).

Blocking and redacting cover the SAME fields, and saying so is not a tautology
— they did not, and the gap was a leak. Every string in the published claim
entry that carries operator- or repository-authored text (the argv preview, the
label, the pathspecs, the changed paths) is replaced by a marker before it is
serialized. A field that only blocked was published raw the moment anyone
passed --allow-secrets, under a refusal message that had already promised
"export a redacted artifact anyway". So ``redact_field`` returns findings along
with text: for those fields, being scrubbed and being reported to the gate are
one act, not two passes that can drift apart.

The heuristic is deliberately tuned to bound false positives — a benign 40-char
git hash must NOT trip it, or the tool blocks everything and gets disabled.

Redaction is a SPAN PARTITION, not a splice. ``scan`` produces overlapping
findings routinely (``OPENAI_API_KEY=sk-…`` matches two patterns at once), and
replacing overlapping spans one at a time silently deletes whatever followed the
outermost one — the exported record then shows a different command than the one
that ran, which is an evidence-integrity bug, not a cosmetic one. ``redact``
therefore merges findings into disjoint maximal spans and rebuilds the string by
walking that partition, so the output is exactly reconstructible: substituting
each marker back with its recorded source span reproduces the input byte for
byte.

The marker string alone is NOT authenticating: a recorded argv can contain the
literal text ``«redacted:openai-key»``, and nothing here escapes it. What a
consumer reads instead is the applied partition, which ``seal`` publishes into
the manifest as ``redaction.applied``. Keyed markers would close the forgery
gap and are deliberately not built (they need a per-ledger key store, and a
per-ledger key destroys the cross-ledger stability that motivated them).

Detectors are TIERED, and the two tiers say different things. The six
structured patterns fire on shape and name what they found: ``block``. The
entropy sweep fires on "this looked random", which over a 24+ character run is
a statement about length far more than about secrecy — per-character entropy is
capped at log2(n), so roughly 18 distinct characters clears the threshold. It
is ``notice``: reported, never blocking, and never deleted, because it is the
only detector that catches an unstructured credential.

Every finding carries its own locality (``source``, ``line``, and the offset
inside that source), because "346 likely secret(s) found" with no address is
not something an operator can act on.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from typing import Optional

# What a finding does to an export. `block` is a structured detector that named
# what it found; `notice` is reported and warned about, never blocking.
TIER_BLOCK = "block"
TIER_NOTICE = "notice"
TIERS = (TIER_BLOCK, TIER_NOTICE)

# Where a finding is. `argv`/`stdout`/`stderr` address a recorded event;
# `label`, `pathspec`, `delta-path` and `reason` address individual exported
# claim fields; `manifest` addresses the serialized bytes about to be published.
SOURCE_KINDS = (
    "argv",
    "stdout",
    "stderr",
    "label",
    "pathspec",
    "delta-path",
    "reason",
    "manifest",
)

# Source kinds that address ONE exported field rather than a stream of bytes.
# A line number inside them would always be 1, which is noise, not locality.
_LINELESS_KINDS = ("argv", "label", "pathspec", "delta-path", "reason")


@dataclass(frozen=True)
class FindingSource:
    """Where a finding is, in the coordinates of the text that was scanned.

    ``event_index`` is the ledger index of the event whose bytes were scanned
    (None when the scanned text is not an event's). ``claim_index`` is the
    seal-relative claim whose field was scanned (None for anything that is not
    a claim field): a label belongs to a claim, not to an event, and without it
    two claims carrying a secret at the same offset are one location.
    ``argv_index`` is the argv element (None for anything that is not argv).
    ``byte_offset`` is the offset of the finding inside that text, so
    ``text[byte_offset:]`` begins at it. The detectors only match ASCII, so
    across a match it is a byte count; in non-ASCII surroundings it counts
    decoded characters.
    """

    kind: str
    event_index: Optional[int] = None
    argv_index: Optional[int] = None
    byte_offset: int = 0
    claim_index: Optional[int] = None

    def __post_init__(self) -> None:
        if self.kind not in SOURCE_KINDS:
            raise ValueError(f"unknown finding source kind: {self.kind!r}")


@dataclass(frozen=True)
class Finding:
    """One detector hit.

    The first three fields are the original positional triple, in their
    original order, so every existing construction still works unchanged.
    Everything tier- and locality-related is additive with a default.
    """

    kind: str
    span: tuple[int, int]
    preview: str  # already-masked preview, never the raw secret
    detector_id: str = ""
    detector_version: int = 1
    tier: str = TIER_NOTICE
    source: Optional[FindingSource] = None
    line: Optional[int] = None  # 1-based within the scanned text; None for argv
    fingerprint: str = ""


@dataclass(frozen=True)
class AppliedSpan:
    """One disjoint span that was actually replaced, in SOURCE coordinates.

    This is the exported projection's unit. ``kind`` is the marker text that
    took its place; ``detector_id`` names the detector whose extent won the
    merge. ``withheld`` marks the honest-absence path: the element was dropped
    whole rather than rewritten, so the span is the element, not a token.
    """

    start: int
    end: int
    kind: str
    detector_id: str
    withheld: bool = False


@dataclass(frozen=True)
class RedactionResult:
    text: str
    findings: list[Finding]
    applied: list[AppliedSpan]


@dataclass(frozen=True)
class ArgvRedaction:
    """Scrubbed argv plus the projection that produced it.

    ``applied`` is the wire shape ``seal`` writes into the manifest, one entry
    per replaced span, addressed by ``argv_index``.
    """

    argv: list[str]
    applied: list[dict]


@dataclass(frozen=True)
class FieldRedaction:
    """One scrubbed exported field, its projection, and what it found.

    ``findings`` is the part that is not a convenience: it is what makes
    "redacted" and "reported to the export gate" the same act for a field,
    rather than two passes that can disagree.
    """

    text: str
    findings: list[Finding]
    applied: list[dict]


# The exported projection's contract version. Bump PROJECTION_VERSION when the
# RULE that turns findings into replaced spans changes (merge policy, marker
# placement, the withheld path). Bump DETECTOR_SET_VERSION when the set of
# detectors or what they match changes. A consumer reads these instead of
# maintaining a matrix of didrun's historical behaviour.
#
# 2: the entropy sweep decides per run whether `/` is a path separator or a
# base64 alphabet member, instead of scoring every run the same way, and every
# detector now declares a tier. That is a change to what the detectors match,
# which is exactly what this number is for — leaving it at 1 would re-create
# the "read the changelog and infer it" problem the version exists to remove.
#
# It stays at 2 rather than going to 3: version 2 has never been released, so
# there is no consumer anywhere that saw the intermediate "tokenizer simply
# dropped `/`" behaviour. Bumping to 3 would publish a version number for a
# detector set that never shipped, which is the opposite of what these numbers
# are for.
#
# The span-partition ALGORITHM did not change, so PROJECTION_VERSION stays 1.
# What the projection COVERS did widen (claim fields, not just argv), and that
# is readable directly off the note: argv spans are in `redaction.applied` and
# field spans are in `redaction.fields`. A consumer checks for the key rather
# than consulting a version matrix.
PROJECTION_VERSION = 1
DETECTOR_SET_VERSION = 2


# High-confidence structured patterns. These fire on shape, not entropy.
_PATTERNS = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    # `[-_]` inside the body, or `sk-proj-…` (and every other prefixed key
    # OpenAI has shipped since) matches nothing: the internal hyphen ends the
    # body under `[A-Za-z0-9]`. Leading \b stays, so a `sk-` inside a word
    # (`risk-...`) is still not a key.
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
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
# Redact-or-withhold, never mangle: when a finding cannot be expressed as a
# whole-span replacement, the element is dropped whole rather than rewritten
# into something that reads authoritative and is wrong.
_WITHHELD_MARKER = "«withheld:{kind}»"

# Detector specificity for merge tie-breaks: a structured pattern names what it
# found, the entropy sweep only names that something looked random.
_ENTROPY_KIND = "high-entropy"

# Entropy heuristic bounds. A long, high-entropy, non-hex token that isn't a git
# hash is suspicious. Git SHAs are hex (entropy ~4.0 bits/char over [0-9a-f]),
# so requiring >4.2 bits/char over a larger alphabet excludes them.
#
# The length floor and the threshold are deliberately UNCHANGED from v0.1: one
# variable at a time, or the measurement stops being interpretable. What moved
# is the CANDIDATE — what gets scored — and it moved twice.
#
# `/` was in the token class in v0.1, and that single character was the
# detector's dominant false-positive source: with `/` included, an entire
# absolute filesystem path is one token, and a path accumulates distinct
# characters faster than any single segment does (179 of 2,642 real paths
# cleared the threshold whole; none clears it per segment).
#
# But `/` is also 1 of the 64 characters of base64, so dropping it outright
# stopped scoring credentials as well as paths: a base64 secret whose
# slash-free runs are all shorter than the floor became invisible — not
# demoted, not re-scored, INVISIBLE, and therefore also unredacted, because
# replacement is driven off the findings. Measured, that cost 15.7% of
# AWS-secret-access-key-shaped strings and 25.3% of base64(24 bytes).
#
# So the separator is not decided by the tokenizer at all. A run is taken over
# the class INCLUDING `/`, and `_looks_like_path` decides whether the `/` in it
# is a separator (score the segments) or an alphabet member (score the run).
# See docs/MEASUREMENTS.md for both directions of that decision.
_ENTROPY_MIN_LEN = 24
_ENTROPY_MIN_BITS_PER_CHAR = 4.2
_HEXISH = re.compile(r"^[0-9a-fA-F]+$")
# One SEGMENT: the credential alphabet with the path separator removed. This is
# the unit a path is scored in.
_TOKENISH = re.compile(r"[A-Za-z0-9_\-+=]{%d,}" % _ENTROPY_MIN_LEN)
# One RUN: the same class plus `/`, which is the unit a base64 credential is
# scored in. A path and a base64 blob are the SAME run shape — they are told
# apart by what the segments look like, below, never by the character class.
_RUNISH = re.compile(r"[A-Za-z0-9_\-+/=]{%d,}" % _ENTROPY_MIN_LEN)

# What tells a filesystem path from a base64 credential, given that both are
# written in [A-Za-z0-9+/]: a path is a sequence of NAMES, and base64 is not.
# A name is mostly letters and those letters are mostly lower case — `usr`,
# `homebrew`, `site-packages`, and CamelCase like `CoreServices` (10/12) or
# `Frameworks` (9/10) all clear 0.8, while base64 is ~50% lower case by
# construction and clears it only by accident.
#
# ONE name is enough to call the whole run a path. That direction is the
# conservative one: it can only move a run from whole-scoring back to the
# segment-scoring that ships today, so it cannot introduce a false positive
# that today's code does not already have — measured at exactly 0 new ones over
# 46,403 real paths. It costs recall instead (~1-3%), and that is the honest
# side to lose on for a notice-tier heuristic.
_NAME_MIN_LEN = 3
_NAME_LETTER_FRACTION = 0.6
_NAME_LOWERCASE_FRACTION = 0.8

# Per-detector revisions. Distinct from DETECTOR_SET_VERSION: this says "this
# detector's own matcher changed", the other says "the set changed".
_DETECTOR_VERSIONS = {_ENTROPY_KIND: 2}


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


def _withheld_mask(kind: str) -> str:
    return _WITHHELD_MARKER.format(kind=kind)


def _tier(kind: str) -> str:
    """Structured patterns block; the entropy sweep only notices."""
    return TIER_NOTICE if kind == _ENTROPY_KIND else TIER_BLOCK


def _is_name(segment: str) -> bool:
    """Is this `/`-delimited segment a NAME (a directory or file name)?

    Mostly letters, and those letters mostly lower case. This is the whole
    path-vs-base64 discriminator; see the constants above for why it is stated
    over case rather than over length or slash density (both of those
    distributions overlap — measured).
    """
    if len(segment) < _NAME_MIN_LEN:
        return False
    letters = [c for c in segment if c.isalpha()]
    if len(letters) < _NAME_LETTER_FRACTION * len(segment):
        return False
    lowercase = sum(1 for c in letters if c.islower())
    return lowercase >= _NAME_LOWERCASE_FRACTION * len(letters)


def _looks_like_path(run: str) -> bool:
    """Is the `/` in this run a separator (True) or an alphabet member (False)?"""
    return any(_is_name(segment) for segment in run.split("/"))


def _entropy_qualifies(token: str) -> bool:
    """The unchanged v0.1 test, applied to whatever candidate is handed to it."""
    if len(token) < _ENTROPY_MIN_LEN:
        return False
    if _HEXISH.match(token):
        return False  # git hashes and hex digests are not secrets
    return _shannon_bits_per_char(token) >= _ENTROPY_MIN_BITS_PER_CHAR


def _entropy_candidates(run: str, base: int):
    """Yield ``(offset, token)`` for every unit of ``run`` that gets scored.

    Three cases, and the third is the one that carries the fix:

    * no `/` at all — the run is the token, exactly as it has always been.
    * `/` as a separator — score the segments, which is what keeps a filesystem
      path from being scored as one 90-character token.
    * `/` as an alphabet member — score the run whole, which is what catches a
      base64 credential that its own slashes chop into sub-floor pieces. If the
      whole run does NOT clear the bar, fall through to the segments anyway, so
      a long low-entropy prefix cannot dilute a high-entropy tail below the
      threshold and hide it.
    """
    if "/" not in run:
        yield base, run
        return
    if not _looks_like_path(run) and _entropy_qualifies(run):
        yield base, run
        return
    for m in _TOKENISH.finditer(run):
        yield base + m.start(), m.group(0)


def locality_fingerprint(detector_id: str, source: FindingSource) -> str:
    """A stable handle on WHERE a finding is. Never on WHAT it matched.

    The token is deliberately not digested: an unkeyed digest of a short
    high-entropy token is a brute-force oracle for the very thing that was just
    redacted, and publishing one in a manifest would undo the redaction for
    anyone willing to spend a GPU-hour. The consequence is that this moves when
    the content around it moves — it identifies a location, not a secret, and
    it is for reporting, never for suppression (there is no suppression).
    """
    material = (
        f"{detector_id}\0{source.kind}\0{source.event_index}\0{source.byte_offset}"
        f"\0{source.claim_index}"
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _locate(kind: str, span: tuple[int, int], text: str, source: Optional[FindingSource]):
    """The (source, line, fingerprint) triple for one hit."""
    if source is None:
        return None, None, ""
    here = FindingSource(
        kind=source.kind,
        event_index=source.event_index,
        argv_index=source.argv_index,
        byte_offset=source.byte_offset + span[0],
        claim_index=source.claim_index,
    )
    # A single exported field (an argv element, a label, a pathspec, a changed
    # path) has no lines; a blob does, and the line is what makes a finding in
    # 4 MB of test output reachable.
    line = (
        None
        if here.kind in _LINELESS_KINDS
        else text.count("\n", 0, span[0]) + 1
    )
    return here, line, locality_fingerprint(kind, here)


def scan(data, source: Optional[FindingSource] = None) -> list[Finding]:
    """Return findings for likely secrets in ``data`` (str or bytes).

    Structured patterns first, then a bounded entropy sweep that explicitly
    skips hex-only tokens (git hashes) to keep false positives low.

    ``source`` is optional and additive: pass one and every finding comes back
    located (source kind, event/argv index, line, offset, fingerprint); omit it
    and the findings are exactly the shape they have always been.
    """
    if isinstance(data, bytes):
        text = data.decode("utf-8", "replace")
    else:
        text = data
    findings: list[Finding] = []
    matched_spans: list[tuple[int, int]] = []

    def _make(kind: str, span: tuple[int, int]) -> Finding:
        here, line, fingerprint = _locate(kind, span, text, source)
        return Finding(
            kind=kind,
            span=span,
            preview=_mask(kind),
            detector_id=kind,
            detector_version=_DETECTOR_VERSIONS.get(kind, 1),
            tier=_tier(kind),
            source=here,
            line=line,
            fingerprint=fingerprint,
        )

    for kind, pat in _PATTERNS:
        for m in pat.finditer(text):
            findings.append(_make(kind, m.span()))
            matched_spans.append(m.span())

    for m in _RUNISH.finditer(text):
        for offset, tok in _entropy_candidates(m.group(0), m.start()):
            if any(s <= offset < e for s, e in matched_spans):
                continue  # already covered by a structured pattern
            if _entropy_qualifies(tok):
                findings.append(_make(_ENTROPY_KIND, (offset, offset + len(tok))))
    return findings


def _specificity(kind: str) -> int:
    """Lower is more specific. A structured detector names what it found."""
    return 1 if kind == _ENTROPY_KIND else 0


def _preferred(a: Finding, b: Finding) -> Finding:
    """Which of two overlapping findings labels the merged span.

    Outermost extent first — the wider finding is the one whose replacement
    covers the other's bytes. On an exact tie, the more specific detector, so a
    structured match is never relabelled as generic entropy. Ties beyond that
    keep the earlier finding, which makes the choice deterministic rather than
    dependent on pattern iteration order.
    """
    a_width = a.span[1] - a.span[0]
    b_width = b.span[1] - b.span[0]
    if b_width > a_width:
        return b
    if b_width == a_width and _specificity(b.kind) < _specificity(a.kind):
        return b
    return a


def merge_findings(findings) -> list[AppliedSpan]:
    """Collapse findings into DISJOINT MAXIMAL spans, left to right.

    ``scan`` emits overlapping findings by construction: the entropy sweep's
    dedup tests start containment only, and the structured patterns are never
    deduped against each other, so `MY_TOKEN=ghp_…` yields both an
    `env-secret-assignment` span and a `github-token` span ending at the same
    offset. Replacing those one at a time deletes the text after the outer span.
    Merging first is what makes replacement a partition.
    """
    ordered = sorted(findings, key=lambda f: (f.span[0], -f.span[1]))
    merged: list[AppliedSpan] = []
    winners: list[Finding] = []  # the finding whose kind currently labels merged[i]
    for f in ordered:
        start, end = f.span
        if merged and start < merged[-1].end:
            prev = merged[-1]
            winner = _preferred(winners[-1], f)
            winners[-1] = winner
            merged[-1] = AppliedSpan(
                start=prev.start,
                end=max(prev.end, end),
                kind=winner.kind,
                detector_id=winner.detector_id or winner.kind,
            )
        else:
            merged.append(
                AppliedSpan(
                    start=start,
                    end=end,
                    kind=f.kind,
                    detector_id=f.detector_id or f.kind,
                )
            )
            winners.append(f)
    return merged


def redact(data, source: Optional[FindingSource] = None) -> RedactionResult:
    """Replace every finding with a marker, as a partition of the input.

    The output is built by walking the merged spans left to right and
    concatenating alternating kept slices and markers — never by index
    arithmetic on a string that is changing length underneath the offsets.

    ``source`` is optional and additive, and it matters for one reason beyond
    reporting: a caller that both redacts a field and needs the findings for
    the export gate gets a LOCATED set here, so the same pass that removes the
    secret is the one that reports it. Redacting and scanning in two places is
    what let a claim label block a seal and be published anyway.
    """
    if isinstance(data, bytes):
        text = data.decode("utf-8", "replace")
    else:
        text = data
    findings = scan(text, source)
    applied = merge_findings(findings)
    parts: list[str] = []
    cursor = 0
    for span in applied:
        parts.append(text[cursor:span.start])
        parts.append(_mask(span.kind))
        cursor = span.end
    parts.append(text[cursor:])
    return RedactionResult(text="".join(parts), findings=findings, applied=applied)


def reconstruct(source: str, result: RedactionResult) -> str:
    """Rebuild ``source`` from the redacted text plus the applied partition.

    Kept slices come from the OUTPUT and replaced slices from the source, so a
    deletion, a stale offset or a misplaced marker all fail to reproduce the
    input. Markers are located arithmetically, never searched for: a recorded
    argv is allowed to contain the literal marker text.
    """
    rebuilt: list[str] = []
    out_cursor = 0
    src_cursor = 0
    for span in result.applied:
        kept = span.start - src_cursor
        if kept < 0:
            raise ValueError("applied spans are not disjoint and ascending")
        rebuilt.append(result.text[out_cursor:out_cursor + kept])
        out_cursor += kept
        marker = _mask(span.kind)
        if result.text[out_cursor:out_cursor + len(marker)] != marker:
            raise ValueError("no marker at the offset the projection names")
        out_cursor += len(marker)
        rebuilt.append(source[span.start:span.end])
        src_cursor = span.end
    rebuilt.append(result.text[out_cursor:])
    return "".join(rebuilt)


def _projection_entry(argv_index: int, span: AppliedSpan) -> dict:
    return {
        "argv_index": argv_index,
        "start": span.start,
        "end": span.end,
        "detector_id": span.detector_id,
        "withheld": span.withheld,
    }


def redact_argv(argv) -> ArgvRedaction:
    """Redact each argv element and report the projection that was applied.

    Post-condition per element: the redaction must reconstruct the element
    exactly. It cannot fail once ``merge_findings`` has run — but if it ever
    does, the element is WITHHELD whole rather than exported in a mangled form.
    An honest absence beats a corrupted string that reads authoritative.
    """
    scrubbed: list[str] = []
    applied: list[dict] = []
    for index, arg in enumerate(argv):
        result = redact(arg)
        source = arg.decode("utf-8", "replace") if isinstance(arg, bytes) else arg
        try:
            faithful = reconstruct(source, result) == source
        except ValueError:
            faithful = False
        if faithful:
            scrubbed.append(result.text)
            applied.extend(_projection_entry(index, s) for s in result.applied)
            continue
        kind = result.applied[0].kind if result.applied else "unknown"
        scrubbed.append(_withheld_mask(kind))
        applied.append(
            _projection_entry(
                index,
                AppliedSpan(
                    start=0,
                    end=len(source),
                    kind=kind,
                    detector_id=kind,
                    withheld=True,
                ),
            )
        )
    return ArgvRedaction(argv=scrubbed, applied=applied)


def scrub_argv(argv) -> list[str]:
    """Redact secret-shaped tokens inside argv elements (e.g. FOO=secret)."""
    return redact_argv(argv).argv


def _field_entry(field: str, span: AppliedSpan) -> dict:
    return {
        "field": field,
        "start": span.start,
        "end": span.end,
        "detector_id": span.detector_id,
        "withheld": span.withheld,
    }


def redact_field(field: str, value: str, source: Optional[FindingSource] = None):
    """Redact ONE named exported field, and return what was found doing it.

    This is ``redact_argv``'s discipline (redact-or-withhold, never mangle;
    declare the projection) for the exported claim fields that are not argv —
    the label, the pathspecs, the changed paths. It returns the findings as
    well as the text on purpose: those findings ARE the export-gate input for
    this field, so the field cannot be blocked-but-published or
    published-but-unscanned. Both of those were real.
    """
    result = redact(value, source)
    try:
        faithful = reconstruct(value, result) == value
    except ValueError:
        faithful = False
    if faithful:
        return FieldRedaction(
            text=result.text,
            findings=result.findings,
            applied=[_field_entry(field, s) for s in result.applied],
        )
    kind = result.applied[0].kind if result.applied else "unknown"
    return FieldRedaction(
        text=_withheld_mask(kind),
        findings=result.findings,
        applied=[
            _field_entry(
                field,
                AppliedSpan(
                    start=0,
                    end=len(value),
                    kind=kind,
                    detector_id=kind,
                    withheld=True,
                ),
            )
        ],
    )


# How many findings a refusal enumerates before it collapses into a count. A
# refusal that prints 19,900 lines is as unusable as one that prints none.
ENUMERATION_CAP = 20


def describe_finding(f: Finding) -> str:
    """One located line for a finding. Carries the masked preview, never the token."""
    src = f.source
    if src is None:
        where = "unlocated"
        offset = "-"
    else:
        where = src.kind
        if src.claim_index is not None:
            where += f" of claim {src.claim_index}"
        if src.event_index is not None:
            where += f" of event {src.event_index}"
        if src.argv_index is not None:
            where += f" arg {src.argv_index}"
        offset = str(src.byte_offset)
    return (
        f"{f.detector_id or f.kind} [{f.tier}] at {where} "
        f"line {'-' if f.line is None else f.line} offset {offset}: "
        f"{f.preview} fingerprint {f.fingerprint or '-'}"
    )


def enumerate_findings(findings, cap: int = ENUMERATION_CAP) -> list[str]:
    """Located lines for ``findings``, capped, with the remainder as a count."""
    lines = [f"  - {describe_finding(f)}" for f in findings[:cap]]
    remainder = len(findings) - cap
    if remainder > 0:
        lines.append(f"  ... and {remainder} more finding(s) not listed")
    return lines


class SecretsBlocked(Exception):
    """Raised when export is blocked because secrets were found.

    The message ENUMERATES: a finding an operator cannot locate is a finding
    they can only respond to with --allow-secrets, which is the failure mode
    that gets a blocking gate switched off.
    """

    def __init__(self, findings: list[Finding], cap: int = ENUMERATION_CAP) -> None:
        self.findings = findings
        kinds = ", ".join(sorted({f.kind for f in findings}))
        lines = [
            f"export blocked: {len(findings)} likely secret(s) found in the "
            f"exported artifact ({kinds}).",
        ]
        lines.extend(enumerate_findings(findings, cap))
        lines.append(
            "Re-run with --allow-secrets to export a redacted artifact anyway "
            "(the override is logged into the manifest)."
        )
        super().__init__("\n".join(lines))
