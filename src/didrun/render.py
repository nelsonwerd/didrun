"""Human surfaces: the CLI verdict/table and the single-file HTML report.

Design direction (load-bearing): a flight recorder, not a
dashboard. Evidence-first hierarchy (verdict -> proof -> detail); monochrome base
with one semantic signal channel; failing/stale states are the MOST designed
states; the tool never exaggerates. "tree-exact" means the evidence tree equals
the sealed tree — never "independently verified true".

Two hard rules encoded here:
  - Color is never the sole channel: every status also carries a text token
    (TREE-EXACT/SCOPE-EXACT/STALE/UNKNOWN/FAILED), so NO_COLOR / dumb terminals
    lose nothing.
  - Failing/stale claims sort to the top, so the thing a reviewer must see is in
    the first screenful.
"""

from __future__ import annotations

import html
import os
from typing import Optional

from .claims import ENV_DRIFT, ENV_INCOMPARABLE, ENV_MATCH, ENV_NOT_RECORDED
from .manifest import (
    AUTHORITY_GRADE,
    AUTHORITY_LIMITATION,
    AUTHORITY_PRINCIPAL_BASIS,
)

# Grade -> (text token, ANSI color, severity marker for NO_COLOR, honest gloss).
# The token NEVER overclaims: the strongest positive says TREE-EXACT ("the
# evidence tree equals the sealed tree"), never "VERIFIED"/"PROVEN" — didrun
# records, it does not prove. The marker carries severity when color is absent.
#
# EVERY grade must be registered in BOTH tables. Both are read through
# `.get(…, UNKNOWN)`, so an unregistered grade does not raise — it renders as
# UNKNOWN, which is a silent lie about what the verdict actually said.
#
# `chain-broken` is the one row here that is not a claim grade: no GradeResult
# ever carries it, so no table row ever displays it. It is a whole-report
# verdict — `VerifyReport.worst_status` returns it when the live ledger's chain
# does not recompute — and `render_verdict` looks the VERDICT up in this same
# table, so without a row the worst thing didrun can say about a ledger would
# print as UNKNOWN.
_GRADE_DISPLAY = {
    "chain-broken": ("CHAIN-BROKEN", "31", "x", "the ledger chain does not recompute"),
    "failed": ("FAILED", "31", "x", "recorded command exited non-zero"),
    "unknown": ("UNKNOWN", "33", "?", "no honest binding"),
    "witness-unavailable": (
        "WITNESS-UNAVAIL",
        "33",
        "?",
        "sealed grade shown; live evidence not found",
    ),
    "stale": ("STALE", "33", "!", "tree moved since evidence"),
    "scope-exact": ("SCOPE-EXACT", "36", "~", "change within declared scope"),
    "tree-exact": ("TREE-EXACT", "32", "=", "recorded against the sealed tree"),
}

# Sort order: worst first. A reviewer sees problems before recorded-exact rows.
# `chain-broken` sorts above `failed` for completeness only — it is a report-level
# verdict, never a per-claim grade, so nothing is ever sorted by this rank. Do not
# go looking for the rows; there are none.
_SORT_RANK = {
    "chain-broken": -1,
    "failed": 0,
    "unknown": 1,
    "witness-unavailable": 2,
    "stale": 3,
    "scope-exact": 4,
    "tree-exact": 5,
}


def _use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    return True


def _c(text: str, code: str) -> str:
    if not _use_color():
        return text
    return f"\033[{code}m{text}\033[0m"


def _sanitize(s: str) -> str:
    """Neutralize control characters so a hostile recorded argv/output cannot
    hijack the terminal (ANSI injection). Caret-encode C0 controls except tab.
    """
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\t":
            out.append("    ")
        elif o < 0x20 or o == 0x7F:
            out.append(f"^{chr((o + 0x40) % 0x80)}")
        else:
            out.append(ch)
    return "".join(out)


def sanitize_text(value) -> str:
    """`_sanitize` for the command surfaces outside this module.

    `didrun seal` and `didrun authorize` print an authority's label and principal
    straight to the terminal, and neither value is computed by this process:
    `authority.jsonl` is a local, unhashed, gitignored file that gets the same
    validate-rather-than-trust reading as `claims.jsonl`, so whoever can write it
    chooses those strings. A newline in a label fabricates a verdict row in the
    seal's own output, the same way it did in the verify block.
    """
    return _sanitize(value if isinstance(value, str) else str(value))


def _skipped_notes(n: int) -> str:
    """Notes under the didrun ref that could not be parsed at all.

    Reported rather than swallowed: "no manifest" and "there were notes here
    and none of them could be read" are different facts.
    """
    return f"{n} note{'' if n == 1 else 's'} skipped (unparseable)"


def env_summary_text(report) -> str:
    """One line for how the sealed environment fingerprints compared.

    The three counters are always printed, zeros included: "0 drifted" is a
    measurement and a missing counter is not. `not-recorded` is appended only
    when it is nonzero — it is the shape of every note published before the
    fingerprint was bound, and printing "0 not-recorded" on every modern verify
    would be noise about a case that no longer occurs.

    Whether drift REFUSES is said here rather than left implied. The same three
    numbers mean different things under --require-env-match, and a reader who
    cannot tell which mode produced them cannot act on either.
    """
    counts = report.env_counts
    line = (
        f"env: {counts[ENV_MATCH]} match / {counts[ENV_DRIFT]} drifted / "
        f"{counts[ENV_INCOMPARABLE]} incomparable"
    )
    if counts[ENV_NOT_RECORDED]:
        line += f" / {counts[ENV_NOT_RECORDED]} not-recorded"
    if report.require_env_match:
        line += "  (drift refuses: --require-env-match)"
    elif counts[ENV_DRIFT]:
        line += "  (advisory; --require-env-match makes it refuse)"
    return line


def chain_banner_text(report) -> str:
    """The chain sentence a reviewer must not miss, or "" when there is none.

    Printed for `broken` and `unverifiable` only. `absent` and `empty` are NOT
    chain faults — a ledger that is elsewhere, or has recorded nothing yet, is a
    witness-availability fact that the per-claim rows already state as
    `witness-unavailable`. Rendering a missing ledger as tamper would make every
    verify against an archived ledger read like an attack.

    `broken` and `unverifiable` get different words on purpose: broken means an
    entry did not recompute to its stored hash, unverifiable means this binary
    could not recompute it at all. Only the first is evidence of mutation.
    """
    status = report.chain_status
    if status == "broken":
        where = "" if report.chain_broken_index is None else f" at index {report.chain_broken_index}"
        return f"ledger chain BROKEN{where} — every grade below is unreliable"
    if status == "unverifiable":
        reason = _sanitize(report.chain_reason) or "this binary cannot recompute it"
        return f"ledger chain unverifiable — {reason}; every grade below is unreliable"
    return ""


def render_chain_banner(report) -> str:
    """The terminal form of the chain sentence: marker, colour, "" when clean."""
    text = chain_banner_text(report)
    return _c(f"x {text}", "31") if text else ""


def superseded_text(report) -> str:
    """One line for the claims a later claim in the same window retired, or "".

    Appended only when it is nonzero, on the `not-recorded` precedent: zero
    superseded claims is the shape of nearly every window, and a counter on
    every verify would be boilerplate about a case that did not occur.

    What it says is the honest bound of the mechanism. Retrying a gate until it
    passes is not prevented — it is RETAINED and counted here, which is strictly
    better than the invisible truncation it replaces.
    """
    count = report.superseded_count
    if not count:
        return ""
    return (
        f"{count} claim{'' if count == 1 else 's'} superseded within this seal "
        f"window (retained in the record, excluded from the verdict)"
    )


# The token for a bound authority. Deliberately NOT a row in `_GRADE_DISPLAY` or
# `_SORT_RANK`: `cited` is an AUTHORITY's grade and never a claim's. No
# GradeResult carries it, `worst_status` never returns it, and a `_SORT_RANK` row
# would imply it sorts among the claim grades, which it never does. It is held to
# the same rule as every token in that table — reported verbatim, never upgraded:
# `CITED` must never be rendered as "signed", "approved" or "authorized by".
_AUTHORITY_TOKEN = AUTHORITY_GRADE.upper()


def authority_lines(report, indent: str = "  ") -> list:
    """The block for each authority this note cited, or [] when it cited none.

    The limitation sentence comes from the SOURCE CONSTANT, never from the note.
    A note is data this process did not compute, so a limitation a note could
    edit would be no limitation at all — and this is the one string standing
    between `CITED` and being read as approval.

    An ordinary seal cites nothing, so this returns [] and the verdict gains no
    line. That is not a rendering choice: an authority attaches only to an
    exceptional transition (docs/TRUST_MODEL.md).
    """
    lines: list = []
    for entry in report.authority:

        def field(name: str, _entry=entry) -> str:
            """Every value this block reads out of the note, sanitized at the
            single point of access.

            Not `_sanitize` spelled out at each use site: that is how `size` and
            `ttl` ended up as the two of six fields nobody wrapped. An
            unsanitized value interpolated into these lines can carry newlines,
            and a newline here fabricates whole verdict rows ABOVE the real
            table — rows the renderer never computed, in the vocabulary this
            module exists to keep honest. A note travels over `git fetch`, so it
            is data from another machine, and `_sanitize` is not optional for
            any of it. The HTML path already funnels every field through one
            `esc`; this is the terminal's equivalent.
            """
            value = _entry.get(name, "")
            return _sanitize(value if isinstance(value, str) else str(value))

        scope = field("scope")
        label = field("label")
        path = field("artifact_path")
        # The full digest, not a 12-character prefix like the commit and tree
        # above it. Comparing this value against a file is the one thing the
        # feature buys, and printing a prefix would invite a reviewer to compare
        # a prefix.
        digest = field("artifact_sha256")
        size = field("artifact_bytes")
        principal = field("principal") or "(unnamed)"
        # From the SOURCE CONSTANT, like the token and the limitation below, and
        # for the same reason: this field says how the principal's name was
        # established, so a note that supplied it could print "principal alice
        # (verified-ssh-signature)" directly above a sentence saying didrun
        # cannot tell who wrote it. "self-asserted" is the only basis this
        # version can establish, so it is the only one it will print.
        basis = _sanitize(AUTHORITY_PRINCIPAL_BASIS)
        ttl = field("expires_after_seals")
        lines.append(
            _c(f"{indent}! {_AUTHORITY_TOKEN} authority for scope {scope}", "33")
            + f": {label}"
        )
        lines.append(f"{indent}    artifact {path}  sha256 {digest}  {size} bytes")
        lines.append(
            f"{indent}    principal {principal} ({basis})  ·  "
            f"expires after {ttl} seal(s)"
        )
        lines.append(f"{indent}    {AUTHORITY_LIMITATION}")
    return lines


def _conjunct_token(grade) -> str:
    """The token for one conjunct of a conjunction — never a grade for a name
    that resolved to nothing.

    ``None`` means the label matched no single live claim in the seal window.
    That is not a grade, and rendering it through ``_GRADE_DISPLAY`` would print
    it as UNKNOWN — a real grade, and a claim the note never made. The
    conjunction itself already grades unknown in that case; this row says which
    member is the reason.
    """
    if grade is None:
        return "UNRESOLVED"
    return _GRADE_DISPLAY.get(grade, ("UNKNOWN", "33", "?", ""))[0]


def _row_detail(r, reason: str) -> str:
    """The detail cell text, prefixed when the row is record rather than verdict.

    Without this a retired FAILED row still reads FAILED under an ALL
    RECORDED-EXACT headline, which looks like the tool contradicting itself. The
    grade and reason are NOT rewritten — that is the whole point of keeping the
    entry — so the marker goes in front of them.
    """
    if not r.is_superseded:
        return reason
    return f"superseded by claim #{r.superseded_by} (record, not verdict) — {reason}"


def render_verdict(report, width: int = 80) -> str:
    """Render a VerifyReport as the CLI instrument panel."""
    lines: list[str] = []
    # Retired rows sort BELOW every live one, whatever they graded: they are the
    # record of how the unit got here, and the live claims are what a reviewer
    # is being asked about.
    results = sorted(
        report.results, key=lambda r: (r.is_superseded, _SORT_RANK.get(r.grade, 9))
    )
    banner = render_chain_banner(report)

    worst = report.worst_status if report.results else "empty"
    if worst == "empty":
        lines.append(_c("○ NO CLAIMS", "33") + "  nothing sealed for this commit")
        # A broken chain is worth saying even with nothing sealed here: the
        # ledger is still the thing every other command reads.
        if banner:
            lines.append(banner)
        lines.append(f"  commit {report.commit[:12] or '(none)'} · resolved-by {report.resolved_by}")
        if report.notes_skipped:
            lines.append(_c(f"  ! {_skipped_notes(report.notes_skipped)}", "33"))
        return "\n".join(lines)

    token, color, marker, _gloss = _GRADE_DISPLAY.get(worst, ("UNKNOWN", "33", "?", ""))
    # Counted over the LIVE set, which is the set the verdict was computed over.
    # Counting retired claims here would print "1/2 recorded-exact" under an ALL
    # RECORDED-EXACT headline; the retained count gets its own line instead.
    live = report.live_results
    verified = sum(1 for r in live if r.grade in ("tree-exact", "scope-exact"))
    total = len(live)

    # Verdict header — the one line a reviewer reads first. The marker prefix
    # carries severity even with color stripped.
    headline = "ALL RECORDED-EXACT" if report.all_verified else f"{token} — review needed"
    lines.append(_c(f"{marker} {headline}", color))
    if banner:
        lines.append(banner)
    lines.append(
        f"  {verified}/{total} claims recorded-exact · "
        f"commit {report.commit[:12]} · tree {report.tree[:12]} · "
        f"resolved-by {report.resolved_by}"
    )
    # How many of those verdicts were checked against the recorded entry the
    # seal named, rather than regraded against whatever ledger is on disk now.
    lines.append(f"  {report.evidence_bound_count}/{total} claims evidence-bound")
    superseded = superseded_text(report)
    if superseded:
        lines.append(f"  {superseded}")
    lines.append(f"  {env_summary_text(report)}")
    if report.secrets_override:
        lines.append(_c("  ! sealed with --allow-secrets (redacted export)", "33"))
    # Directly under the override line, because the override is what an authority
    # is most often cited for and a reader must see the two together.
    lines.extend(authority_lines(report))
    if report.notes_skipped:
        lines.append(_c(f"  ! {_skipped_notes(report.notes_skipped)}", "33"))
    lines.append("")

    # Per-claim table. Failing/stale first (already sorted).
    lines.append(f"    {'STATUS':<12} {'CLAIM':<26} DETAIL")
    lines.append("  " + "-" * (width - 4))
    for r in results:
        token, color, marker, gloss = _GRADE_DISPLAY.get(r.grade, ("UNKNOWN", "33", "?", ""))
        label = _sanitize(r.claim.label)[:26]
        detail = _row_detail(r, _sanitize(r.reason))
        if r.exit_code is not None:
            detail = f"exit {r.exit_code}  {detail}"
        lines.append(f"  {marker} {_c(f'{token:<12}', color)} {label:<26} {detail}")
        # The drifted rows say so individually. `incomparable` does not get a
        # row of its own: it is the state of every note published before the
        # fingerprint was bound, so a per-claim line would be a paragraph of
        # boilerplate under an archive — the header counter already reports it.
        if r.env_status == ENV_DRIFT:
            lines.append(
                f"    {'':<12} {'':<26}   {ENV_DRIFT}: {_sanitize(r.env_reason)}"
            )
        # A conjunction's members, each with what it earned. Uncapped on
        # purpose: the row's grade IS one of these, and hiding the tail would
        # hide the conjunct the verdict came from.
        for label, cgrade in r.conjunct_grades:
            lines.append(
                f"    {'':<12} {'':<26}   of {_sanitize(label)}: "
                f"{_conjunct_token(cgrade)}"
            )
        # Drill-down: show the delta for stale/scope, capped.
        for change in r.delta[:5]:
            lines.append(f"    {'':<12} {'':<26}   {change.status} {_sanitize(change.path)}")
        if len(r.delta) > 5:
            lines.append(f"    {'':<12} {'':<26}   … {len(r.delta) - 5} more")
    lines.append("")
    lines.append(
        "  didrun records what ran; it does not prove the code is correct. "
        "See docs/TRUST_MODEL.md."
    )
    return "\n".join(lines)


def render_html(report, title: str = "didrun evidence report") -> str:
    """Render a VerifyReport as a single self-contained HTML file.

    Zero external assets (loads under file:// with no network); strict no-script
    CSP; 100% of dynamic content HTML-escaped; failing/stale first; responsive;
    print-clean. This is the shareable evidence surface.
    """
    results = sorted(
        report.results, key=lambda r: (r.is_superseded, _SORT_RANK.get(r.grade, 9))
    )
    live = report.live_results
    verified = sum(1 for r in live if r.grade in ("tree-exact", "scope-exact"))
    total = len(live)
    worst = report.worst_status if report.results else "empty"
    all_ok = report.all_verified

    def esc(s: str) -> str:
        return html.escape(_sanitize(str(s)), quote=True)

    rows = []
    for r in results:
        token, _color, _marker, _gloss = _GRADE_DISPLAY.get(r.grade, ("UNKNOWN", "", "?", ""))
        grade_class = r.grade.replace("-", "_")
        if r.is_superseded:
            # A second class, not a replaced one: the row keeps the grade it
            # earned (that is the record) and the tone says it does not vote.
            grade_class += " superseded"
        detail = _row_detail(r, esc(r.reason))
        exit_txt = f"exit {r.exit_code}" if r.exit_code is not None else "—"
        argv = " ".join(r.claim.get("argv_preview", [])) if isinstance(r.claim, dict) else ""
        # The conjunct list rides in the detail column, above the delta: a
        # conjunction's grade is one of these, so it is the first thing a reader
        # of that row needs. Same list markup as the delta — a conjunction
        # carries an existing grade, so no new badge or token is introduced.
        conjunct_html = ""
        if r.conjunct_grades:
            items = "".join(
                f"<li><span class='ch'>{esc(_conjunct_token(g))}</span> {esc(label)}</li>"
                for label, g in r.conjunct_grades
            )
            conjunct_html = f"<ul class='delta conjuncts'>{items}</ul>"
        delta_html = ""
        if r.delta:
            items = "".join(
                f"<li><span class='ch'>{esc(c.status)}</span> {esc(c.path)}</li>"
                for c in r.delta[:20]
            )
            more = f"<li>… {len(r.delta) - 20} more</li>" if len(r.delta) > 20 else ""
            delta_html = f"<ul class='delta'>{items}{more}</ul>"
        claim_label = r.claim.label if not isinstance(r.claim, dict) else r.claim.get("label", "")
        # Same rule as the CLI table: drifted rows say so, incomparable ones are
        # left to the header counter.
        env_html = (
            f"<span class='envdrift'>{esc(ENV_DRIFT)}: {esc(r.env_reason)}</span>"
            if r.env_status == ENV_DRIFT
            else ""
        )
        rows.append(
            f"<tr class='{grade_class}'>"
            f"<td class='status'><span class='badge {grade_class}'>{esc(token)}</span></td>"
            f"<td class='claim'>{esc(claim_label)}</td>"
            f"<td class='detail'><span class='reason'>{detail}</span>"
            f"<span class='exit'>{esc(exit_txt)}</span>{env_html}"
            f"{conjunct_html}{delta_html}</td>"
            f"</tr>"
        )

    # The chain sentence gets its own block above the table, not a table row:
    # it is a statement about the ledger every row was read out of, so a row
    # would file it alongside the very grades it invalidates.
    chain_text = chain_banner_text(report)
    chain_html = (
        f'<div class="chainbanner">{esc(chain_text)}</div>' if chain_text else ""
    )
    superseded = superseded_text(report)
    superseded_html = f"{esc(superseded)} ·" if superseded else ""

    # One block per cited authority, above the table for the same reason as the
    # chain sentence: it is a statement about the seal, not about a claim, so a
    # table row would file it alongside the grades. Every field is escaped, and
    # the limitation, the token and the principal's basis come from source
    # constants, never from the note.
    authority_html = "".join(
        "<div class='authority'>"
        f"<span class='badge cited'>{esc(_AUTHORITY_TOKEN)}</span> "
        f"authority for scope {esc(a.get('scope', ''))}: {esc(a.get('label', ''))}"
        f"<span class='ameta'>artifact {esc(a.get('artifact_path', ''))} · "
        f"sha256 {esc(a.get('artifact_sha256', ''))} · "
        f"{esc(a.get('artifact_bytes', ''))} bytes · "
        f"principal {esc(a.get('principal', '') or '(unnamed)')} "
        f"({esc(AUTHORITY_PRINCIPAL_BASIS)}) · "
        f"expires after {esc(a.get('expires_after_seals', ''))} seal(s)</span>"
        f"<span class='alimit'>{esc(AUTHORITY_LIMITATION)}</span>"
        "</div>"
        for a in report.authority
    )

    if all_ok:
        verdict_class, verdict_text = "ok", "ALL RECORDED-EXACT"
    elif worst == "chain-broken":
        verdict_class = "failed"
        verdict_text = (
            f"{esc(_GRADE_DISPLAY['chain-broken'][0])} — the ledger chain does not recompute"
        )
    elif worst == "failed":
        verdict_class = "failed"
        verdict_text = f"{esc(_GRADE_DISPLAY['failed'][0])} — a claimed command was recorded failing"
    else:
        verdict_class = "attention"
        verdict_text = f"{esc(_GRADE_DISPLAY.get(worst, ('UNKNOWN',))[0])} — review needed"
    # Gloss the coverage counters so they read as evidence, not jargon.
    coverage = report.coverage.get("by_coverage", {}) if report.coverage else {}
    _cov_gloss = {
        "complete": "backed by recorded commands",
        "observed-text-only": "text-only",
        "display-only": "transcript-only (unbacked)",
        "unobserved": "unobserved",
    }
    coverage_html = " · ".join(
        f"{esc(v)} {esc(_cov_gloss.get(k, k))}" for k, v in coverage.items()
    ) or "—"

    # Inline styles only. Semantic hues but each row also carries a text badge,
    # so color is never the sole channel.
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">
<title>{esc(title)}</title>
<style>
  :root {{
    --bg:#0f1113; --panel:#16191d; --ink:#e7ebee; --dim:#9aa4ad; --line:#262b31;
    --ok:#3fb950; --warn:#d29922; --bad:#f85149; --scope:#3fb0c0; --mono:#c9d1d9;
    --bad-fill:#f85149; --warn-fill:#d29922; --on-fill:#0f1113;
  }}
  @media (prefers-color-scheme: light) {{
    :root {{
      --bg:#f6f7f8; --panel:#fff; --ink:#1a1d21; --dim:#5b636b; --line:#e2e5e9; --mono:#24292f;
      /* Semantic hues re-tuned for a light background — the dark ramp fails
         WCAG contrast on white (measured ~1.9:1). These clear 4.5:1. */
      --ok:#1a7f37; --warn:#8a5a00; --bad:#cf222e; --scope:#0b6b7a;
      --bad-fill:#cf222e; --warn-fill:#9a6700; --on-fill:#ffffff;
    }}
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
    font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
  .wrap {{ max-width:900px; margin:0 auto; padding:24px 16px 64px; }}
  header {{ border-bottom:1px solid var(--line); padding-bottom:16px; margin-bottom:16px; }}
  .brand {{ color:var(--dim); letter-spacing:.08em; font-size:11px; text-transform:uppercase; }}
  .verdict {{ font-size:20px; font-weight:600; margin:8px 0 4px; }}
  .verdict.ok {{ color:var(--ok); }}
  .verdict.attention {{ color:var(--warn); }}
  .verdict.failed {{ color:var(--bad); }}
  /* Filled, not tinted: a chain fault invalidates every row under it, so it is
     the one block that must survive a fast scan and a monochrome printout. */
  .chainbanner {{ margin:8px 0; padding:8px 10px; border-radius:3px;
    background:var(--bad-fill); color:var(--on-fill); font-weight:700; }}
  .meta {{ color:var(--dim); font-size:12px; word-break:break-all; }}
  /* An authority is record, not verdict, so it is toned like the advisory
     states — never like a pass. The limitation is not small print: it is the
     same size as the citation it qualifies. */
  .authority {{ margin:8px 0; padding:8px 10px; border-radius:3px;
    border:1px solid var(--warn); color:var(--ink); font-size:12px; }}
  .badge.cited {{ color:var(--warn); }}
  .authority .ameta {{ display:block; margin-top:4px; color:var(--dim);
    word-break:break-all; }}
  .authority .alimit {{ display:block; margin-top:4px; color:var(--warn); }}
  table {{ width:100%; border-collapse:collapse; margin-top:8px; table-layout:fixed; }}
  th {{ text-align:left; color:var(--dim); font-weight:500; font-size:11px;
    text-transform:uppercase; letter-spacing:.05em; padding:8px; border-bottom:1px solid var(--line); }}
  td {{ padding:10px 8px; border-bottom:1px solid var(--line); vertical-align:top;
    overflow-wrap:anywhere; }}
  /* Fixed columns keep badges aligned and stop long paths from clipping. */
  col.c-status {{ width:120px; }}
  col.c-claim {{ width:34%; }}
  td.claim {{ color:var(--mono); }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:3px; font-size:11px;
    font-weight:700; letter-spacing:.03em; border:1px solid currentColor; white-space:nowrap; }}
  .badge.tree_exact {{ color:var(--ok); }}
  .badge.scope_exact {{ color:var(--scope); }}
  .badge.stale, .badge.unknown, .badge.witness_unavailable {{ color:var(--warn); }}
  /* Failure and stale are the MOST-designed states: solid-filled badges + a
     left accent bar so a problem row is unmistakable on a fast scan. */
  .badge.failed {{ color:var(--on-fill); background:var(--bad-fill); border-color:var(--bad-fill); }}
  .badge.stale {{ color:var(--on-fill); background:var(--warn-fill); border-color:var(--warn-fill); }}
  tr.stale td, tr.unknown td, tr.witness_unavailable td {{
    background:color-mix(in srgb, var(--warn) 10%, transparent); }}
  tr.failed td {{ background:color-mix(in srgb, var(--bad) 12%, transparent); }}
  /* A retired row is record, not verdict: toned down and stripped of its accent
     bar so it cannot be read as a live problem. Dimmed, never hidden — the
     whole point of supersession is that the earlier attempt stays visible. */
  tr.superseded td {{ opacity:.62; }}
  tr.superseded td.status {{ box-shadow:none; }}
  tr.failed td.status {{ box-shadow:inset 3px 0 0 var(--bad); }}
  tr.stale td.status {{ box-shadow:inset 3px 0 0 var(--warn); }}
  tr.unknown td.status {{ box-shadow:inset 3px 0 0 var(--warn); }}
  tr.witness_unavailable td.status {{ box-shadow:inset 3px 0 0 var(--warn); }}
  .detail {{ color:var(--dim); }}
  .detail .reason {{ display:block; }}
  .exit {{ display:inline-block; margin-top:2px; color:var(--mono); font-size:12px; }}
  /* Advisory by default, so it is toned like the warn states rather than the
     failure ones — drift does not make a recorded command un-run. */
  .envdrift {{ display:block; margin-top:4px; color:var(--warn); font-size:12px; }}
  .delta {{ margin:6px 0 0; padding-left:16px; color:var(--dim); font-size:12px; }}
  .delta li {{ overflow-wrap:anywhere; }}
  .delta .ch {{ display:inline-block; width:14px; color:var(--mono); font-weight:700; }}
  footer {{ margin-top:24px; color:var(--dim); font-size:12px; border-top:1px solid var(--line); padding-top:12px; }}
  @media (max-width:520px) {{
    col.c-status {{ width:92px; }}
    col.c-claim {{ width:38%; }}
    td {{ padding:8px 6px; }}
    .badge {{ padding:2px 5px; font-size:10px; }}
  }}
  @media print {{ body {{ background:#fff; color:#000; }} .wrap {{ max-width:none; }}
    tr.failed td, tr.stale td, tr.unknown td, tr.witness_unavailable td {{
      background:transparent; }}
    /* Browsers drop backgrounds when printing, which would leave the chain
       sentence white-on-white — the one line that must never disappear. */
    .chainbanner {{ background:transparent; color:#000; border:2px solid #000; }} }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">didrun · flight record</div>
    <div class="verdict {verdict_class}">{verdict_text}</div>
    {chain_html}
    {authority_html}
    <div class="meta">{esc(verified)}/{esc(total)} claims recorded-exact ·
      {esc(report.evidence_bound_count)}/{esc(total)} claims evidence-bound ·
      {superseded_html}
      {esc(env_summary_text(report))} ·
      commit {esc(report.commit[:12])} · tree {esc(report.tree[:12])} ·
      resolved-by {esc(report.resolved_by)} · coverage {coverage_html}</div>
  </header>
  <table>
    <colgroup><col class="c-status"><col class="c-claim"><col class="c-detail"></colgroup>
    <thead><tr><th>Status</th><th>Claim</th><th>Detail</th></tr></thead>
    <tbody>
      {''.join(rows) if rows else '<tr><td colspan=3 class=detail>No claims sealed for this commit.</td></tr>'}
    </tbody>
  </table>
  <footer>
    didrun records what ran against which tree state. It is a faithful recording,
    not a proof: it does not attest that a command meaningfully tested anything,
    nor that this evidence came from someone you can trust. See docs/TRUST_MODEL.md.
  </footer>
</div>
</body>
</html>
"""
