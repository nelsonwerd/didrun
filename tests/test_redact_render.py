"""P2.3/P3.1/P3.2 — redaction, CLI rendering, and the HTML adversarial fixture."""

from __future__ import annotations

from dataclasses import dataclass

from didrun import redact
from didrun import render
from didrun.claims import GradeResult, Claim
from didrun.gitplumbing import PathChange


# --- redaction ---------------------------------------------------------------

def test_fake_aws_key_detected():
    # Synthetic test vector — NOT a real credential.
    text = "export AWS_KEY=AKIAIOSFODNN7EXAMPLE and continue"
    findings = redact.scan(text)
    assert any(f.kind == "aws-access-key" for f in findings)


def test_env_secret_assignment_scrubbed():
    argv = ["deploy", "API_SECRET=hunter2taffylongvalue"]
    scrubbed = redact.scrub_argv(argv)
    assert "hunter2taffylongvalue" not in " ".join(scrubbed)
    assert "redacted" in " ".join(scrubbed)


def test_benign_git_hash_not_flagged():
    """False-positive bound: a 40-char hex git hash must not trip the heuristic."""
    text = "commit 356a192b7913b04c54574d18c28d46e6395428ab passed"
    findings = redact.scan(text)
    assert not findings, f"git hash false-positive: {findings}"


def test_redact_replaces_with_marker():
    text = "token sk-ABCDEFGHIJKLMNOPQRSTUVWX here"
    out, findings = redact.redact(text)
    assert findings
    assert "sk-ABCDEFGHIJKLMNOPQRSTUVWX" not in out
    assert "redacted" in out


# --- render helpers ----------------------------------------------------------

def _report(results, all_verified=False, worst="stale", chain="intact",
            chain_index=None, chain_why=""):
    @dataclass
    class R:
        commit: str = "abcdef123456"
        tree: str = "0f0f0f0f0f0f"
        resolved_by: str = "commit"
        results: list = None
        coverage: dict = None
        secrets_override: bool = False
        notes_skipped: int = 0
        # Mirrors VerifyReport's chain fields. Carried as real attributes rather
        # than left off: render reads them directly, so a surface that starts
        # depending on a chain state this fake cannot express fails here loudly
        # instead of silently rendering the default.
        chain_status: str = chain
        chain_broken_index: object = chain_index
        chain_reason: str = chain_why

        @property
        def worst_status(self):
            return worst

        @property
        def all_verified(self):
            return all_verified

        # Mirrors VerifyReport: both human surfaces report how many verdicts
        # were checked against the recorded entry the seal named.
        @property
        def evidence_bound_count(self):
            return sum(1 for r in self.results if r.evidence_bound)

        @property
        def total(self):
            return len(self.results)

    return R(results=results, coverage={"by_coverage": {"complete": 1}})


def _gr(grade, label, delta=None):
    claim = Claim(ctype="tests-pass", label=label, event_indices=(0,), declared_at_index=0)
    return GradeResult(claim, grade, reason=f"{grade} reason", delta=delta or [],
                       supporting_event_index=0, exit_code=0)


def test_cli_failing_sorts_first():
    results = [_gr("tree-exact", "ok one"), _gr("stale", "bad one",
              delta=[PathChange("M", "calc.py")])]
    out = render.render_verdict(_report(results))
    lines = out.splitlines()
    stale_line = next(i for i, l in enumerate(lines) if "bad one" in l)
    ok_line = next(i for i, l in enumerate(lines) if "ok one" in l)
    assert stale_line < ok_line  # problems first


def test_cli_no_color_has_text_tokens(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    results = [_gr("stale", "s", delta=[PathChange("M", "x.py")]),
               _gr("tree-exact", "t")]
    out = render.render_verdict(_report(results))
    assert "\033[" not in out  # zero ANSI
    # Meaning survives without color; the strongest positive is TREE-EXACT,
    # never "VERIFIED" (which would overclaim — the honesty invariant).
    assert "STALE" in out and "TREE-EXACT" in out
    assert "VERIFIED" not in out


def test_unparseable_notes_are_reported_on_both_verdict_paths(monkeypatch):
    """"No manifest" and "there were notes and none could be read" are
    different facts, and the second must reach the operator on the no-claims
    path too — that is the path a repo with only foreign notes lands on."""
    monkeypatch.setenv("NO_COLOR", "1")
    quiet = render.render_verdict(_report([]))
    assert "skipped" not in quiet  # never invented when the count is zero

    empty = _report([], worst="empty")
    empty.notes_skipped = 2
    assert "2 notes skipped (unparseable)" in render.render_verdict(empty)

    graded = _report([_gr("tree-exact", "t")])
    graded.notes_skipped = 1
    assert "1 note skipped (unparseable)" in render.render_verdict(graded)


def test_no_surface_says_verified():
    """Honesty invariant: no human surface may label a grade 'VERIFIED'/'PROVEN'."""
    results = [_gr("tree-exact", "t"), _gr("failed", "f")]
    cli = render.render_verdict(_report(results))
    html_out = render.render_html(_report(results))
    for surface in (cli, html_out):
        assert "VERIFIED" not in surface
        assert "PROVEN" not in surface.upper()


def test_cli_neutralizes_ansi_injection(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    # A hostile recorded label containing a raw escape sequence.
    results = [_gr("stale", "evil\x1b[31mLABEL", delta=[])]
    out = render.render_verdict(_report(results))
    assert "\x1b[31m" not in out  # the injected escape is caret-encoded


def test_html_adversarial_fixture():
    """The RT-6 adversarial fixture: script + ANSI + fake-PASS + delta all neutral."""
    evil = _gr("stale", "<script>alert(1)</script>",
               delta=[PathChange("M", "<img src=x onerror=alert(2)>")])
    evil = GradeResult(
        Claim(ctype="command-succeeded", label="<script>alert(1)</script>",
              event_indices=(0,), declared_at_index=0),
        "stale", reason="pwn\x1b[31m", delta=[PathChange("M", "<b>x</b>")],
        supporting_event_index=0, exit_code=0,
    )
    html_out = render.render_html(_report([evil]))
    assert "<script>alert(1)</script>" not in html_out  # escaped
    assert "&lt;script&gt;" in html_out
    assert "\x1b[31m" not in html_out  # ANSI caret-encoded before escaping
    assert "<script>" not in html_out.split("<style>")[0]  # no injected script anywhere


def test_html_no_external_assets():
    html_out = render.render_html(_report([_gr("tree-exact", "ok")], all_verified=True,
                                          worst="tree-exact"))
    for needle in ("http://", "https://", "//cdn", "src=\"http"):
        assert needle not in html_out
    assert "<script" not in html_out  # no scripts at all
    assert "Content-Security-Policy" in html_out


def test_html_size_bound():
    results = [_gr("stale", f"claim {i}", delta=[PathChange("M", f"f{i}.py")])
               for i in range(30)]
    html_out = render.render_html(_report(results))
    assert len(html_out.encode("utf-8")) < 512 * 1024


def test_cli_failure_first_screenful():
    """Design acceptance criterion 1: a failure in a 30-claim report appears in
    the first screenful (top 25 lines), because problems sort to the top."""
    results = [_gr("tree-exact", f"ok {i}") for i in range(29)]
    results.append(_gr("failed", "the one failure", delta=[]))
    out = render.render_verdict(_report(results)).splitlines()
    fail_line = next(i for i, l in enumerate(out) if "the one failure" in l)
    assert fail_line < 25, f"failure at line {fail_line}, not in first screenful"


def test_html_failed_verdict_styled():
    """The overall-failed verdict must carry the failed style (not fall back to
    plain ink) — the most important element in the most-designed state."""
    html_out = render.render_html(_report([_gr("failed", "f")], worst="failed"))
    assert "verdict failed" in html_out
    assert "badge failed" in html_out
