"""The assignment detector must read a shell expansion as what it is.

Found dogfooding didrun on a real build: a recorded ``bash -c`` script that
loads a key out of a gitignored env file,

    export ANTHROPIC_API_KEY="$(grep "^ANTHROPIC_API_KEY=" apps/web/.env.local | cut -d= -f2-)"

blocked its seal with ``env-secret-assignment [block] at argv … arg 2``. The
"value" there is a command substitution — text the inner shell will EXPAND —
not a credential. The argv carries the recipe for reading the secret, never the
secret, and refusing the seal over it trained the operator toward
``--allow-secrets``, which is the rubber stamp the trust model warns about.

Two directions are pinned, and the second is the one that matters:

1. a value that is PURELY expansion (``$(…)``, backticks, ``${NAME}``,
   ``$NAME``, alone or concatenated, quoted with ``"`` or bare) no longer fires;
2. anything literal still does — a literal secret beside an expansion, a literal
   tail glued onto one, a single-quoted ``'$(…)'`` (which the shell does NOT
   expand), and an unterminated substitution.

The Turnstile half is a design call and is pinned as one: Cloudflare's three
published dummy SECRET keys are demoted from `block` to `notice`, never
suppressed — still found, still reported, still redacted out of the note.

Every credential-shaped string here is synthetic.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from didrun import manifest as M
from didrun import redact
from didrun.capture import run_wrapped
from didrun.claims import Claim
from didrun.ledger import Session

# The argv element that blocked the real seal, verbatim in shape.
KOHAI_SCRIPT = (
    'export ANTHROPIC_API_KEY="$(grep "^ANTHROPIC_API_KEY=" apps/web/.env.local '
    '| cut -d= -f2-)"; ./scripts/x.sh'
)

# Cloudflare's published Turnstile test secret keys — they authenticate nothing.
# https://developers.cloudflare.com/turnstile/troubleshooting/testing/
TURNSTILE_TEST_SECRETS = (
    "1x0000000000000000000000000000000AA",
    "2x0000000000000000000000000000000AA",
    "3x0000000000000000000000000000000AA",
)


def _assignment_hits(text: str) -> list:
    return [f for f in redact.scan(text) if f.kind == "env-secret-assignment"]


def _blocking(text: str) -> list:
    return [f for f in redact.scan(text) if f.tier == redact.TIER_BLOCK]


# --- 1. pure expansions do not fire ------------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        KOHAI_SCRIPT,
        'API_TOKEN="$(cat ~/.config/token)"',
        "API_TOKEN=$(cat ~/.config/token)",
        "API_TOKEN=$(printf '%s' \"$(cat a)\")",          # nested substitution
        'GH_TOKEN="$(gh auth token)" ./deploy.sh',
        "export SECRET_KEY=`cat key.txt`; make",          # backticks
        'export DB_PASSWORD="${PROD_DB_PASSWORD}"',       # ${NAME}
        "export DB_PASSWORD=${PROD_DB_PASSWORD} && run",
        "export DB_PASSWORD=$PROD_DB_PASSWORD_VALUE",     # $NAME
        'CLIENT_SECRET="${PREFIX}$(cat suffix.txt)"',     # concatenated expansions
        "API_TOKEN=$(cat t);next",
        "API_TOKEN=$(cat t)|tee",
    ],
    ids=[
        "kohai-script",
        "dq-command-substitution",
        "bare-command-substitution",
        "nested-substitution",
        "substitution-then-command",
        "backticks",
        "dq-braced-variable",
        "bare-braced-variable",
        "bare-variable",
        "concatenated-expansions",
        "ended-by-semicolon",
        "ended-by-pipe",
    ],
)
def test_a_value_that_is_purely_a_shell_expansion_is_not_an_assignment_finding(text):
    assert _assignment_hits(text) == []
    assert _blocking(text) == []


# --- 2. anything literal still fires -----------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        # A literal secret NEXT TO an expansion: the expansion is skipped, the
        # literal is not.
        'A_TOKEN="$(cat a)" B_TOKEN=hunter2taffylongvalue ./run',
        # A literal tail glued onto an expansion is still literal text.
        "API_TOKEN=$(cat)hunter2taffylongvalue",
        'API_TOKEN="${PREFIX}hunter2taffy"',
        # Single quotes are literal: the shell does not expand '$(…)'.
        "API_TOKEN='$(not expanded)'",
        # An unterminated substitution is not a recognisable expansion.
        'API_TOKEN="$(cat t',
        # `${NAME:-default}` carries a literal default — not exempted.
        'API_TOKEN="${UNSET:-hunter2taffylongvalue}"',
        # A `$` that does not start an expansion is a literal character.
        "API_TOKEN=$%hunter2taffy",
        # The plain case, unchanged.
        "MY_SECRET=hunter2taffylongvalue",
    ],
    ids=[
        "literal-beside-expansion",
        "literal-tail-on-substitution",
        "literal-tail-on-variable",
        "single-quoted-substitution",
        "unterminated-substitution",
        "default-value-expansion",
        "bare-dollar",
        "plain-literal",
    ],
)
def test_a_literal_value_still_fires_at_block(text):
    hits = _assignment_hits(text)
    assert hits, f"expected an env-secret-assignment finding in {text!r}"
    assert all(f.tier == redact.TIER_BLOCK for f in hits)


def test_the_literal_beside_an_expansion_is_the_one_located():
    """Exactly one hit, and it is the literal assignment, not the expansion."""
    text = 'A_TOKEN="$(cat a)" B_TOKEN=hunter2taffylongvalue ./run'
    hits = _assignment_hits(text)
    assert len(hits) == 1
    start, end = hits[0].span
    assert text[start:end] == "B_TOKEN=hunter2taffylongvalue"


def test_structured_detectors_still_scan_inside_a_substitution():
    """Skipping the ASSIGNMENT does not blind the shape detectors to the
    substitution's body: a token written inside one is still found."""
    token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    text = f'GH_TOKEN="$(echo {token})"'
    kinds = {f.kind for f in _blocking(text)}
    assert "github-token" in kinds
    assert "env-secret-assignment" not in kinds


def test_redaction_of_an_exempted_expansion_is_the_identity():
    """Nothing found means nothing replaced: the published argv preview shows
    the script exactly as it ran."""
    out = redact.redact_argv(["bash", "-c", KOHAI_SCRIPT])
    assert out.argv == ["bash", "-c", KOHAI_SCRIPT]
    assert out.applied == []


def test_the_manifest_backstop_reads_the_json_encoded_script_the_same_way():
    """The serialized note carries the script with its quotes as ``\\"``. The
    backstop scan of those bytes must reach the argv pass's conclusion, or the
    seal is still refused — which it was, the first time this was fixed."""
    from didrun.ledger import canonical_json

    source = redact.FindingSource("manifest")
    exempt = canonical_json({"argv_preview": ["bash", "-c", KOHAI_SCRIPT]})
    assert b'\\"$(grep' in exempt, "the fixture must carry JSON-escaped quotes"
    assert [
        f for f in redact.scan(exempt, source) if f.kind == "env-secret-assignment"
    ] == []

    literal = canonical_json(
        {"argv_preview": ['A_TOKEN="$(cat a)" B_TOKEN="hunter2 taffy long"']}
    )
    hits = [
        f for f in redact.scan(literal, source) if f.kind == "env-secret-assignment"
    ]
    assert len(hits) == 1 and hits[0].tier == redact.TIER_BLOCK


# --- the end-to-end shape the dogfood hit ------------------------------------

def test_sealing_the_kohai_script_is_not_blocked(repo: Path):
    """The seal that exited 3 now publishes, and nothing in the export blocked.

    The script itself is never executed: the event is recorded around a
    harmless python child whose argv carries the script text, which is all the
    argv scan reads.
    """
    s = Session(repo / ".didrun")
    run_wrapped(
        [sys.executable, "-c", "pass", "bash", "-c", KOHAI_SCRIPT], s, repo
    )
    M.declare_claim(
        s,
        Claim(ctype="command-succeeded", label="x", event_indices=(0,),
              declared_at_index=0),
    )
    m = M.seal(s, repo)
    assert m.secrets["blocked"] is False
    assert m.secrets_override is False
    assert m.claims[0]["claim"]["argv_preview"][-1] == KOHAI_SCRIPT


# --- Turnstile: demoted to notice, never suppressed --------------------------

@pytest.mark.parametrize("value", TURNSTILE_TEST_SECRETS)
def test_a_published_turnstile_test_secret_is_notice_not_block(value):
    text = f"TURNSTILE_SECRET_KEY={value} npm test"
    findings = redact.scan(text)
    assert _blocking(text) == []
    published = [f for f in findings if f.kind == "published-test-value"]
    assert len(published) == 1, "demoted, not dropped: it is still a finding"
    assert published[0].tier == redact.TIER_NOTICE
    # Still redacted out of anything exported.
    assert value not in redact.redact(text).text


def test_the_turnstile_demotion_is_exact_match_only():
    """One character off the published value is an ordinary literal and blocks;
    so does the published value with a suffix. The list is a set of exact
    strings, never a pattern an attacker can fit a real secret into."""
    near = "1x0000000000000000000000000000000AB"
    for text in (
        f"TURNSTILE_SECRET_KEY={near}",
        f"TURNSTILE_SECRET_KEY={TURNSTILE_TEST_SECRETS[0]}x",
    ):
        hits = _assignment_hits(text)
        assert hits and hits[0].tier == redact.TIER_BLOCK, text


def test_a_turnstile_value_quoted_is_still_recognised():
    text = f'TURNSTILE_SECRET_KEY="{TURNSTILE_TEST_SECRETS[1]}"'
    assert _blocking(text) == []
    assert [f.kind for f in redact.scan(text)] == ["published-test-value"]


def test_the_detector_set_version_moved_for_this_change():
    """What the detectors match changed, so the declared set version moves:
    a consumer must be able to tell a v0.2.0 note's projection from this one's
    without reading a changelog."""
    assert redact.DETECTOR_SET_VERSION == 3
