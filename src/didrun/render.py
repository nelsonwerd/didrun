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

# Grade -> (text token, ANSI color, severity marker for NO_COLOR, honest gloss).
# The token NEVER overclaims: the strongest positive says TREE-EXACT ("the
# evidence tree equals the sealed tree"), never "VERIFIED"/"PROVEN" — didrun
# records, it does not prove. The marker carries severity when color is absent.
_GRADE_DISPLAY = {
    "failed": ("FAILED", "31", "x", "recorded command exited non-zero"),
    "unknown": ("UNKNOWN", "33", "?", "no honest binding"),
    "stale": ("STALE", "33", "!", "tree moved since evidence"),
    "scope-exact": ("SCOPE-EXACT", "36", "~", "change within declared scope"),
    "tree-exact": ("TREE-EXACT", "32", "=", "recorded against the sealed tree"),
}

# Sort order: worst first. A reviewer sees problems before recorded-exact rows.
_SORT_RANK = {"failed": 0, "unknown": 1, "stale": 2, "scope-exact": 3, "tree-exact": 4}


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


def _skipped_notes(n: int) -> str:
    """Notes under the didrun ref that could not be parsed at all.

    Reported rather than swallowed: "no manifest" and "there were notes here
    and none of them could be read" are different facts.
    """
    return f"{n} note{'' if n == 1 else 's'} skipped (unparseable)"


def render_verdict(report, width: int = 80) -> str:
    """Render a VerifyReport as the CLI instrument panel."""
    lines: list[str] = []
    results = sorted(report.results, key=lambda r: _SORT_RANK.get(r.grade, 9))

    worst = report.worst_status if report.results else "empty"
    if worst == "empty":
        lines.append(_c("○ NO CLAIMS", "33") + "  nothing sealed for this commit")
        lines.append(f"  commit {report.commit[:12] or '(none)'} · resolved-by {report.resolved_by}")
        if report.notes_skipped:
            lines.append(_c(f"  ! {_skipped_notes(report.notes_skipped)}", "33"))
        return "\n".join(lines)

    token, color, marker, _gloss = _GRADE_DISPLAY.get(worst, ("UNKNOWN", "33", "?", ""))
    verified = sum(1 for r in report.results if r.grade in ("tree-exact", "scope-exact"))
    total = len(report.results)

    # Verdict header — the one line a reviewer reads first. The marker prefix
    # carries severity even with color stripped.
    headline = "ALL RECORDED-EXACT" if report.all_verified else f"{token} — review needed"
    lines.append(_c(f"{marker} {headline}", color))
    lines.append(
        f"  {verified}/{total} claims recorded-exact · "
        f"commit {report.commit[:12]} · tree {report.tree[:12]} · "
        f"resolved-by {report.resolved_by}"
    )
    if report.secrets_override:
        lines.append(_c("  ! sealed with --allow-secrets (redacted export)", "33"))
    if report.notes_skipped:
        lines.append(_c(f"  ! {_skipped_notes(report.notes_skipped)}", "33"))
    lines.append("")

    # Per-claim table. Failing/stale first (already sorted).
    lines.append(f"    {'STATUS':<12} {'CLAIM':<26} DETAIL")
    lines.append("  " + "-" * (width - 4))
    for r in results:
        token, color, marker, gloss = _GRADE_DISPLAY.get(r.grade, ("UNKNOWN", "33", "?", ""))
        label = _sanitize(r.claim.label)[:26]
        detail = _sanitize(r.reason)
        if r.exit_code is not None:
            detail = f"exit {r.exit_code}  {detail}"
        lines.append(f"  {marker} {_c(f'{token:<12}', color)} {label:<26} {detail}")
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
    results = sorted(report.results, key=lambda r: _SORT_RANK.get(r.grade, 9))
    verified = sum(1 for r in report.results if r.grade in ("tree-exact", "scope-exact"))
    total = len(report.results)
    worst = report.worst_status if report.results else "empty"
    all_ok = report.all_verified

    def esc(s: str) -> str:
        return html.escape(_sanitize(str(s)), quote=True)

    rows = []
    for r in results:
        token, _color, _marker, _gloss = _GRADE_DISPLAY.get(r.grade, ("UNKNOWN", "", "?", ""))
        grade_class = r.grade.replace("-", "_")
        detail = esc(r.reason)
        exit_txt = f"exit {r.exit_code}" if r.exit_code is not None else "—"
        argv = " ".join(r.claim.get("argv_preview", [])) if isinstance(r.claim, dict) else ""
        delta_html = ""
        if r.delta:
            items = "".join(
                f"<li><span class='ch'>{esc(c.status)}</span> {esc(c.path)}</li>"
                for c in r.delta[:20]
            )
            more = f"<li>… {len(r.delta) - 20} more</li>" if len(r.delta) > 20 else ""
            delta_html = f"<ul class='delta'>{items}{more}</ul>"
        claim_label = r.claim.label if not isinstance(r.claim, dict) else r.claim.get("label", "")
        rows.append(
            f"<tr class='{grade_class}'>"
            f"<td class='status'><span class='badge {grade_class}'>{esc(token)}</span></td>"
            f"<td class='claim'>{esc(claim_label)}</td>"
            f"<td class='detail'><span class='reason'>{detail}</span>"
            f"<span class='exit'>{esc(exit_txt)}</span>{delta_html}</td>"
            f"</tr>"
        )

    if all_ok:
        verdict_class, verdict_text = "ok", "ALL RECORDED-EXACT"
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
  .meta {{ color:var(--dim); font-size:12px; word-break:break-all; }}
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
  .badge.stale, .badge.unknown {{ color:var(--warn); }}
  /* Failure and stale are the MOST-designed states: solid-filled badges + a
     left accent bar so a problem row is unmistakable on a fast scan. */
  .badge.failed {{ color:var(--on-fill); background:var(--bad-fill); border-color:var(--bad-fill); }}
  .badge.stale {{ color:var(--on-fill); background:var(--warn-fill); border-color:var(--warn-fill); }}
  tr.stale td, tr.unknown td {{ background:color-mix(in srgb, var(--warn) 10%, transparent); }}
  tr.failed td {{ background:color-mix(in srgb, var(--bad) 12%, transparent); }}
  tr.failed td.status {{ box-shadow:inset 3px 0 0 var(--bad); }}
  tr.stale td.status {{ box-shadow:inset 3px 0 0 var(--warn); }}
  tr.unknown td.status {{ box-shadow:inset 3px 0 0 var(--warn); }}
  .detail {{ color:var(--dim); }}
  .detail .reason {{ display:block; }}
  .exit {{ display:inline-block; margin-top:2px; color:var(--mono); font-size:12px; }}
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
    tr.failed td, tr.stale td, tr.unknown td {{ background:transparent; }} }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">didrun · flight record</div>
    <div class="verdict {verdict_class}">{verdict_text}</div>
    <div class="meta">{esc(verified)}/{esc(total)} claims recorded-exact ·
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
