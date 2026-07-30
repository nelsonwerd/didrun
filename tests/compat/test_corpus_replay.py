"""The compat corpus replay harness — four legs, run content-blind.

THE CONTENT RULE (non-negotiable): this module may READ ledger bytes; it may
never print, log, echo, or assert on them. Every assertion below compares
digests, booleans, counts, or path shapes. ``assert computed == stored`` over
two hashes is fine — a hash is not content. ``assert line == ...`` is
forbidden, because pytest prints both sides of a failed comparison, and a
ledger line is a verbatim record of everything a session ran and printed:
argv, stdout, stderr, and whatever credential passed through them. The tree
this harness is aimed at is live, secret-bearing evidence for a build that is
still running; a harness that leaks one line of it into a CI log or a chat
transcript has done more damage than any bug it could have found.

``_assert_no_content`` is the net under that rule. It is a bound on the SHAPE
of what can escape into an assertion message, not a proof that nothing does —
the only real guarantee is that no leg ever puts a ledger-derived value into a
payload in the first place.

Why the legs are these four (red-team §3.5): a harness asserting the corpus's
815/30/1 grade histogram would have passed on every defect in the audit. A
histogram is a snapshot, not a regression test. The legs that earn their keep
are the chain recompute — which would have caught a schema break across 5,558
archived events before it shipped — and the claim-SHAPE invariants, which is
where two of the audit's blocker findings actually lived.

The corpus leg is env-gated and OFF by default. A green synthetic run is not
corpus validation, and the run summary says so in those words.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pytest

from didrun.ledger import (
    GENESIS_HASH,
    ChainEntry,
    Event,
    LedgerError,
    sha256_hex,
    unknown_event_keys_of,
)
from didrun.manifest import MANIFEST_VERSION, NOTES_REF, Manifest

from . import synthetic
from .conftest import (
    ENV_VAR,
    SKIP_LIVE,
    SKIP_MISSING,
    SKIP_REFUSED,
    SKIP_UNSET,
    has_git_repo,
    is_refused,
    path_digest,
    record_summary,
    resolve_corpus_root,
)

# --- the content net ---------------------------------------------------------

# Lowercase, no whitespace, bounded length: the shape of a status token, a key
# name, a grade, a digest, or a path-shape descriptor. Nothing a ledger line or
# a secret looks like survives it.
_STRUCTURAL = re.compile(r"\A[a-z0-9][a-z0-9_.:@#-]{0,63}\Z")

_NON_STRUCTURAL = "non-structural-token"


def _safe_token(value) -> str:
    """A source-derived string, reduced to a token or replaced outright.

    Manifest key names and grades come from a note body, which means a foreign
    or corrupt note can put anything here. Anything that is not structural is
    replaced rather than passed through, so the leg still reports the finding
    without carrying the value into the failure message.
    """
    if isinstance(value, str) and _STRUCTURAL.match(value):
        return value
    return _NON_STRUCTURAL


def _assert_no_content(obj) -> None:
    """Fail if anything non-structural reached an assertion payload.

    The failure message deliberately reports only the TYPE and LENGTH of the
    offending value. Echoing it is the exact accident this function exists to
    prevent.
    """
    stack = [obj]
    while stack:
        item = stack.pop()
        if item is None or isinstance(item, (bool, int, float)):
            continue
        if isinstance(item, str):
            if not _STRUCTURAL.match(item):
                raise AssertionError(
                    f"a non-structural str of length {len(item)} reached an "
                    "assertion payload; the harness must never put ledger-derived "
                    "values in an assertion message (its value is withheld here "
                    "on purpose)"
                )
            continue
        if isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
            continue
        if isinstance(item, (list, tuple, set, frozenset)):
            stack.extend(item)
            continue
        raise AssertionError(
            f"a {type(item).__name__} reached an assertion payload; only "
            "counts, booleans, digests and shape tokens may appear there"
        )


def _summarize(leg: str, source: str, payload: dict) -> None:
    _assert_no_content(payload)
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    record_summary(f"{leg} [{source}]: {body}")


# --- discovery ---------------------------------------------------------------


def ledger_dirs(root) -> list:
    """Every directory holding a session.log, in a deterministic order.

    Covers both archive shapes without hardcoding either: nested
    ``<name>/.didrun/`` and flat ``<name>/``.
    """
    return sorted(p.parent for p in Path(root).rglob("session.log") if p.is_file())


# --- leg 1: chain recompute --------------------------------------------------


@dataclass(frozen=True)
class LogReplay:
    """One log's outcome.

    ``label`` is an ordinal, not a path: archive directory names are not
    ledger content, but they are not ours to put in a CI log or a transcript
    either. The mapping stays recoverable locally without leaking anything —
    the ordinal is the position in ``ledger_dirs(root)``.
    """

    label: str
    shape: str  # "nested" | "flat"
    entries: int
    status: str  # empty | intact | torn-tail | malformed@N | broken@N | unverifiable@N


def _read_records(path: Path) -> tuple:
    """Parse a log into records. Returns ``(records, torn_tail, malformed_at)``.

    A partial FINAL line is torn-tail — a process killed mid-append, which is
    the commonest real damage and is never the same fact as tamper. A partial
    line anywhere else is malformed and is reported at its position.
    """
    raw = path.read_bytes()
    if not raw:
        return [], False, None
    lines = raw.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    last = len(lines) - 1
    records: list = []
    torn = False
    malformed_at: Optional[int] = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            records.append(json.loads(stripped))
        except ValueError:
            if i == last:
                torn = True
            elif malformed_at is None:
                malformed_at = i
    return records, torn, malformed_at


def _verify_records(records: list) -> tuple:
    """Recompute the chain over parsed records. Returns ``(status, position)``.

    Mirrors Session.verify_chain_detail, but reads instead of constructing a
    Session: Session.__init__ mkdirs its root and writes a .gitignore, which
    would MODIFY an archive this harness is only ever allowed to read.

    Positions are the harness's own counter, never the stored index, so a
    forged index cannot choose the number that gets reported.
    """
    prev = GENESIS_HASH
    for position, rec in enumerate(records):
        try:
            index = rec["index"]
            prev_hash = rec["prev_hash"]
            stored = rec["entry_hash"]
            body = rec["event"]
        except (KeyError, TypeError):
            return "unverifiable", position
        if not isinstance(body, dict):
            return "unverifiable", position
        if index != position or prev_hash != prev:
            return "broken", position
        if unknown_event_keys_of(body):
            return "unverifiable", position
        try:
            entry = ChainEntry(
                index=index,
                prev_hash=prev_hash,
                event=Event.from_dict(body),
                entry_hash=stored,
                preimage_version=rec.get("preimage_version", 1),
            )
            recomputed = entry.compute_hash()
        except (LedgerError, TypeError, ValueError):
            return "unverifiable", position
        if recomputed != stored:
            return "broken", position
        prev = stored
    return "intact", None


def replay_chain(root) -> list:
    out = []
    for i, d in enumerate(ledger_dirs(root)):
        records, torn, malformed_at = _read_records(d / "session.log")
        status, position = _verify_records(records)
        if status != "intact":
            status = f"{status}@{position}"
        elif malformed_at is not None:
            status = f"malformed@{malformed_at}"
        elif torn:
            status = "torn-tail"
        elif not records:
            status = "empty"
        out.append(
            LogReplay(
                label=f"log#{i}",
                shape="nested" if d.name == ".didrun" else "flat",
                entries=len(records),
                status=status,
            )
        )
    return out


def _status_histogram(replays: list) -> dict:
    hist: dict = {}
    for r in replays:
        key = r.status.split("@")[0]
        hist[key] = hist.get(key, 0) + 1
    return hist


def test_leg1_chain_recompute(replay_source):
    """Every archived entry_hash must still recompute under this binary.

    This is the leg that would have caught a chain-preimage change before it
    shipped, across every archived event, instead of after.
    """
    replays = replay_chain(replay_source.root)
    payload = {
        "logs": len(replays),
        "entries": sum(r.entries for r in replays),
        "nested": sum(1 for r in replays if r.shape == "nested"),
        "flat": sum(1 for r in replays if r.shape == "flat"),
        "status": _status_histogram(replays),
    }
    _summarize("leg1 chain-recompute", replay_source.name, payload)

    statuses = tuple(r.status for r in replays)
    _assert_no_content(statuses)
    if replay_source.expected is not None:
        assert statuses == replay_source.expected.log_statuses
        assert tuple(r.entries for r in replays) == replay_source.expected.log_entries
    else:
        # On a real archive tree the regression is `broken`: a stored hash that
        # no longer recomputes. `unverifiable` is a different fact (written by
        # something this binary does not fully understand) and is reported, not
        # asserted away.
        assert [r.label for r in replays if r.status.startswith("broken")] == []
        assert replays != []


# --- leg 2: note round-trip --------------------------------------------------

# Keys `to_json` emits that a stored note of this version may legitimately
# lack, because `from_json` reads them with a v1-reproducing default. Hard
# coded per manifest version so a new manifest field is a deliberate one-line
# diff here and never a silent pass.
# v2 introduced no top-level manifest key — the evidence binding lives inside
# each claim entry.
# `secrets` is P3.2's: the scan-domain record beside `secrets_override`. It is
# additive with a v1-reproducing default ({}), so a stored note of EITHER
# version legitimately lacks it, and both allowlists carry it. This entry is
# the deliberate one-line diff the criterion exists to force — without it the
# round-trip leg would go red across every stored note at once.
# `claims_from`/`claims_to` are P4.1's: the half-open claim window the seal
# covered, which made a truncating re-seal visible in the artifact. Both are read
# with a default (0 / len(claims)), so a stored note of either version
# legitimately lacks them and both allowlists carry them. Second deliberate
# one-line diff this criterion has forced, and the reason it exists.
# Version 3 is P4.2's: the claim-type vocabulary gained `conjunction`. That bump
# added no TOP-LEVEL manifest key — the conjunct list and the per-conjunct grades
# live inside a claim entry, and a claim entry round-trips verbatim — so v3's
# allowlist is v2's. It is spelled out rather than aliased so that a v3-only
# additive key stays a deliberate one-line diff here, exactly as for v1 and v2.
# `authority` is P5.1's: the authorisation artifacts a seal cited, each carrying
# its digest and the limitation constant. Additive with a v1-reproducing default
# ([]) and NO version bump — an authority is a manifest field, never an Event
# field, precisely so it stays compat-neutral. A stored note of any version may
# legitimately lack it (every note published before P5.1 does), so all three
# allowlists carry it. Third deliberate one-line diff this criterion has forced.
MANIFEST_ADDITIVE_KEYS = {
    1: frozenset({"secrets_override", "secrets", "claims_from", "claims_to", "authority"}),
    2: frozenset({"secrets_override", "secrets", "claims_from", "claims_to", "authority"}),
    3: frozenset({"secrets_override", "secrets", "claims_from", "claims_to", "authority"}),
}


def note_violations(raw: bytes, ordinal: int, additive_keys=None) -> list:
    """Apply the pack's three-part note round-trip criterion to one note body.

    Naive byte equality (`from_json(body).to_json() == body`) is NOT the
    criterion and must not be written: it is false on every real note today
    (git notes appends one trailing newline to every body) and it becomes false
    a second way as Manifest gains additive fields. Instead:

      (a) newline discipline  — strip AT MOST one trailing newline; more than
          one is a malformed note and fails closed rather than being rstrip'd;
      (b) key-superset semantic equality — every key in the source body must
          come back with an equal value, and any extra key must be on this
          version's additive allowlist;
      (c) serialization idempotence — re-serializing is byte-stable. This is
          where canonical_json's stability is actually pinned.

    Returns ``(ordinal, code)`` pairs. Notes are identified by ordinal, and
    every code is a structural token: nothing derived from the body's VALUES
    reaches the caller.
    """
    if additive_keys is None:
        additive_keys = MANIFEST_ADDITIVE_KEYS

    body = raw[:-1] if raw.endswith(b"\n") else raw
    if body.endswith(b"\n"):
        return [(ordinal, "multiple-trailing-newlines")]
    try:
        source = json.loads(body)
    except ValueError:
        return [(ordinal, "parse-error")]
    if not isinstance(source, dict) or "version" not in source:
        return [(ordinal, "not-a-manifest")]
    version = source["version"]
    if not isinstance(version, int) or isinstance(version, bool):
        return [(ordinal, "bad-version-type")]
    if version > MANIFEST_VERSION:
        return [(ordinal, "version-too-new")]

    try:
        first = Manifest.from_json(body).to_json()
    except Exception:
        return [(ordinal, "parse-error")]
    round_tripped = json.loads(first)

    violations = []
    for key in sorted(source):
        token = _safe_token(key)
        if key not in round_tripped:
            violations.append((ordinal, f"missing-key:{token}"))
        elif round_tripped[key] != source[key]:
            violations.append((ordinal, f"value-mismatch:{token}"))
    allowed = additive_keys.get(version, frozenset())
    for key in sorted(set(round_tripped) - set(source)):
        if key not in allowed:
            violations.append((ordinal, f"undeclared-extra-key:{_safe_token(key)}"))

    # Compared by digest, not by bytes: an `assert a == b` over two manifest
    # bodies would print both of them.
    second = Manifest.from_json(first).to_json()
    if sha256_hex(second) != sha256_hex(first):
        violations.append((ordinal, "not-idempotent"))
    return violations


def note_bodies(root) -> list:
    """Note bodies via git metadata commands. No ledger file is opened."""
    listing = subprocess.run(
        ["git", "-C", str(root), "notes", f"--ref={NOTES_REF}", "list"],
        capture_output=True,
    )
    if listing.returncode != 0:
        return []
    blobs = sorted(
        line.split()[0].decode("ascii")
        for line in listing.stdout.splitlines()
        if line.strip()
    )
    bodies = []
    for blob in blobs:
        proc = subprocess.run(
            ["git", "-C", str(root), "cat-file", "-p", blob], capture_output=True
        )
        if proc.returncode == 0:
            bodies.append(proc.stdout)
    return bodies


def replay_notes(root) -> tuple:
    bodies = note_bodies(root)
    violations = []
    for ordinal, raw in enumerate(bodies):
        violations.extend(note_violations(raw, ordinal))
    return len(bodies), violations


def test_leg2_note_round_trip(replay_source):
    """Every published note must still parse, round-trip and re-serialize.

    Six later prompts cite this leg as their compat gate, so its definition is
    load-bearing: it is the criterion above, not byte equality.
    """
    if not has_git_repo(replay_source.root):
        pytest.skip("no git repo at the replay root; the note legs need refs/notes/didrun")
    count, violations = replay_notes(replay_source.root)
    _summarize(
        "leg2 note-round-trip",
        replay_source.name,
        {"notes": count, "violations": len(violations)},
    )
    _assert_no_content(violations)
    assert violations == []
    assert count >= 1
    if replay_source.expected is not None:
        assert count == replay_source.expected.notes


# --- leg 3: layout classifier ------------------------------------------------

_FLAT_BLOB = re.compile(r"\A[0-9a-f]{64}\Z")
_FANOUT_DIR = re.compile(r"\A[0-9a-f]{2}\Z")
_FANOUT_FILE = re.compile(r"\A[0-9a-f]{38}\Z")


def _shape_token(p: Path) -> str:
    kind = "dir" if p.is_dir() else "file"
    cls = "hex" if re.fullmatch(r"[0-9a-f]+", p.name) else "nonhex"
    return f"{kind}:len{len(p.name)}:{cls}"


def classify_objects(root) -> tuple:
    """Partition every objects/ entry into exactly one of two shapes.

    113 of the archived object dirs carry BOTH namespaces — flat SHA-256 blobs
    written by the ledger and git fan-out dirs from the sealed object
    redirect. A third shape is residue and fails closed; it is reported as a
    shape descriptor, never as a name.
    """
    counts = {"dirs": 0, "flat-64hex": 0, "git-fanout": 0}
    residue: dict = {}
    for d in ledger_dirs(root):
        objects = d / "objects"
        if not objects.is_dir():
            continue
        counts["dirs"] += 1
        for entry in sorted(objects.iterdir()):
            if entry.is_file() and _FLAT_BLOB.match(entry.name):
                counts["flat-64hex"] += 1
            elif entry.is_dir() and _FANOUT_DIR.match(entry.name):
                for child in sorted(entry.iterdir()):
                    if child.is_file() and _FANOUT_FILE.match(child.name):
                        counts["git-fanout"] += 1
                    else:
                        token = "fanout-child:" + _shape_token(child)
                        residue[token] = residue.get(token, 0) + 1
            else:
                token = _shape_token(entry)
                residue[token] = residue.get(token, 0) + 1
    return counts, residue


def test_leg3_layout_classifier(replay_source):
    counts, residue = classify_objects(replay_source.root)
    payload = dict(counts)
    payload["residue"] = sum(residue.values())
    _summarize("leg3 layout-classifier", replay_source.name, payload)
    _assert_no_content(residue)
    assert residue == {}
    if replay_source.expected is not None:
        assert counts == replay_source.expected.objects


# --- leg 4: claim-shape invariants -------------------------------------------


def claim_shape_from_bodies(bodies: list) -> dict:
    """The shape facts nobody measured until they broke three conclusions."""
    notes = 0
    claims = 0
    multi_index = 0
    pathspecs: dict = {}
    gap_ge_1 = 0
    gap_ge_5 = 0
    grades: dict = {}
    for raw in bodies:
        body = raw[:-1] if raw.endswith(b"\n") else raw
        try:
            parsed = json.loads(body)
        except ValueError:
            continue
        if not isinstance(parsed, dict):
            continue
        notes += 1
        for entry in parsed.get("claims", []) or []:
            if not isinstance(entry, dict):
                continue
            claims += 1
            claim = entry.get("claim") or {}
            if len(claim.get("event_indices") or []) > 1:
                multi_index += 1
            n_specs = len(claim.get("pathspecs") or [])
            pathspecs[n_specs] = pathspecs.get(n_specs, 0) + 1
            supporting = entry.get("supporting_event_index")
            declared_at = claim.get("declared_at_index", -1)
            if (
                isinstance(supporting, int)
                and isinstance(declared_at, int)
                and declared_at >= 0
            ):
                gap = declared_at - supporting
                if gap >= 1:
                    gap_ge_1 += 1
                if gap >= 5:
                    gap_ge_5 += 1
            grade = _safe_token(entry.get("grade"))
            grades[grade] = grades.get(grade, 0) + 1
    return {
        "notes": notes,
        "claims": claims,
        "multi-index": multi_index,
        "max-pathspecs": max(pathspecs) if pathspecs else 0,
        "pathspecs": pathspecs,
        "gap-ge-1": gap_ge_1,
        "gap-ge-5": gap_ge_5,
        "grades": grades,
    }


def claim_shape_stats(root) -> dict:
    return claim_shape_from_bodies(note_bodies(root))


def test_leg4_claim_shape_invariants(replay_source):
    """The leg the red-team says earns its keep.

    A grade histogram is a snapshot and is REPORTED, not asserted, against a
    real corpus — asserting it would have passed on every defect in the audit.
    The shape invariants are the regression: had they existed, two blocker
    findings would have been caught here instead of by a reviewer. The
    declared-vs-supporting gap is a signal, so it is reported too.
    """
    if not has_git_repo(replay_source.root):
        pytest.skip("no git repo at the replay root; the note legs need refs/notes/didrun")
    stats = claim_shape_stats(replay_source.root)
    _summarize("leg4 claim-shape", replay_source.name, stats)
    _assert_no_content(stats)
    assert stats["multi-index"] == 0
    assert stats["max-pathspecs"] <= 1
    if replay_source.expected is not None:
        # Synthetic only: here the histogram is testing the instrument against
        # a fixture whose every value is declared, which is not the same thing
        # as pinning a corpus snapshot.
        assert stats == replay_source.expected.claim_shape


# --- meta: the harness must skip cleanly, and must be able to fail -----------


def test_corpus_legs_skip_when_env_unset(tmp_path):
    """CI is green by construction: no env var, no corpus leg, no error."""
    root, reason = resolve_corpus_root({})
    assert root is None
    assert reason == SKIP_UNSET
    assert ENV_VAR in reason

    root, reason = resolve_corpus_root({ENV_VAR: str(tmp_path / "nope")})
    assert root is None
    assert reason == SKIP_MISSING

    root, reason = resolve_corpus_root({ENV_VAR: "   "})
    assert root is None
    assert reason == SKIP_UNSET

    live = tmp_path / "live"
    (live / ".didrun").mkdir(parents=True)
    (live / ".git").mkdir()
    root, reason = resolve_corpus_root({ENV_VAR: str(live)})
    assert root is None
    assert reason == SKIP_LIVE

    ok = tmp_path / "copy"
    (ok / ".didrun-history").mkdir(parents=True)
    root, reason = resolve_corpus_root({ENV_VAR: str(ok)})
    assert root == ok
    assert reason is None


def test_refused_trees_are_refused_by_digest_including_subpaths(tmp_path):
    """The named-tree refusal, and the proof it also covers paths inside it.

    The digests themselves are frozen in conftest; this exercises the
    mechanism against a synthetic path so no private path appears here.
    """
    forbidden = tmp_path / "forbidden-tree"
    (forbidden / "sub" / "deeper").mkdir(parents=True)
    digests = frozenset({path_digest(forbidden)})
    assert is_refused(forbidden, digests)
    assert is_refused(forbidden / "sub" / "deeper", digests)
    assert is_refused(str(forbidden) + "/", digests)
    assert not is_refused(tmp_path / "other", digests)

    # The wiring: a path on the frozen list takes the refusal branch, and it is
    # checked BEFORE the directory-exists test, so a refused tree is refused
    # whether or not it is currently mounted.
    root, reason = resolve_corpus_root({ENV_VAR: str(forbidden)}, digests=digests)
    assert root is None
    assert reason == SKIP_REFUSED
    root, reason = resolve_corpus_root(
        {ENV_VAR: str(tmp_path / "absent")}, digests=frozenset({path_digest(tmp_path)})
    )
    assert reason == SKIP_REFUSED

    from .conftest import _REFUSED_PATH_DIGESTS

    assert len(_REFUSED_PATH_DIGESTS) >= 1
    assert all(re.fullmatch(r"[0-9a-f]{64}", d) for d in _REFUSED_PATH_DIGESTS)


def test_synthetic_known_bad_logs_are_detected(synthetic_corpus, tmp_path):
    """The harness can actually fail: torn, unknown, broken are all detected."""
    replays = replay_chain(synthetic_corpus.root)
    by_status = {r.status for r in replays}
    _assert_no_content(by_status)
    assert "torn-tail" in by_status
    assert "unverifiable@0" in by_status
    assert "broken@1" in by_status
    assert "empty" in by_status
    assert sum(1 for r in replays if r.status == "intact") == 2

    # Independent of the generator's declarations: tamper a good chain here and
    # confirm the recompute catches it.
    records = synthetic._chain(3)
    synthetic._write_log(tmp_path / "good" / ".didrun" / "session.log", records)
    before = replay_chain(tmp_path / "good")[0].status
    assert before == "intact"

    stored = records[2]["entry_hash"]
    records[2]["entry_hash"] = ("0" if stored[0] != "0" else "1") + stored[1:]
    synthetic._write_log(tmp_path / "tampered" / ".didrun" / "session.log", records)
    after = replay_chain(tmp_path / "tampered")[0].status
    assert after == "broken@2"


def test_synthetic_known_bad_notes_are_detected(known_bad_corpus):
    """Each part of the round-trip criterion fails on the thing it targets.

    Every result is bound to a local before it is asserted on. pytest's
    assertion rewriting explains a failing comparison by printing the CALL and
    its arguments, so ``assert note_violations(<a note body>, 0) == []`` would
    put a note body in the failure message. Same rule as everywhere else here,
    and the reason the grep gate looks for exactly that shape.
    """
    synthetic_note = synthetic.multi_index_note_body()

    # (a) newline discipline: one trailing newline is git's and is stripped;
    # two is a malformed note and must fail closed rather than be rstrip'd.
    clean = note_violations(synthetic_note, 0)
    one_newline = note_violations(synthetic_note + b"\n", 0)
    two_newlines = note_violations(synthetic_note + b"\n\n", 0)
    assert clean == []
    assert one_newline == []
    assert two_newlines == [(0, "multiple-trailing-newlines")]

    # (b) the additive-key allowlist: with an empty allowlist, the one key a v1
    # note may legitimately lack becomes a reported violation.
    stripped = json.loads(synthetic_note)
    del stripped["secrets_override"]
    trimmed = json.dumps(stripped, sort_keys=True, separators=(",", ":")).encode("ascii")
    allowed = note_violations(trimmed, 3)
    not_allowed = note_violations(trimmed, 3, additive_keys={1: frozenset()})
    assert allowed == []
    assert not_allowed == [(3, "undeclared-extra-key:secrets_override")]

    unparseable = note_violations(b"not json at all", 1)
    not_manifest = note_violations(b'{"nope":1}', 2)
    bad_version = note_violations(b'{"version":"1"}', 2)
    assert unparseable == [(1, "parse-error")]
    assert not_manifest == [(2, "not-a-manifest")]
    assert bad_version == [(2, "bad-version-type")]

    # End to end through git: a note whose manifest version this binary must
    # refuse rather than coerce.
    count, violations = replay_notes(known_bad_corpus)
    assert count == 1
    assert violations == [(0, "version-too-new")]


def test_synthetic_known_bad_objects_residue_is_detected(known_bad_corpus):
    """A third path shape in objects/ fails closed and is named by shape only."""
    counts, residue = classify_objects(known_bad_corpus)
    _assert_no_content(residue)
    assert counts["flat-64hex"] == 1
    assert counts["git-fanout"] == 1
    assert residue == {"dir:len4:nonhex": 1, "file:len9:nonhex": 1}


def test_synthetic_known_bad_claims_are_detected():
    """The invariant leg catches the claim shapes the corpus says do not exist."""
    stats = claim_shape_from_bodies([synthetic.multi_index_note_body()])
    _assert_no_content(stats)
    assert stats["multi-index"] == 1
    assert stats["max-pathspecs"] == 2
    assert stats["grades"] == {"tree-exact": 1, "scope-exact": 1}


def test_assert_no_content_refuses_content_and_never_echoes_it():
    """The net holds, and its own failure message does not leak the value."""
    _assert_no_content(
        {
            "logs": 7,
            "status": {"intact": 2, "broken@1": 1},
            "ok": True,
            "none": None,
            "digest": "a" * 64,
            "shape": "file:len9:nonhex",
        }
    )

    secret = "AKIAIOSFODNN7EXAMPLE-with-a-space and a tail"
    with pytest.raises(AssertionError) as exc:
        _assert_no_content({"argv": [secret]})
    assert secret not in str(exc.value)
    assert "AKIA" not in str(exc.value)
    assert str(len(secret)) in str(exc.value)

    with pytest.raises(AssertionError):
        _assert_no_content([Path("/w/repo")])

    assert _safe_token("tree-exact") == "tree-exact"
    assert _safe_token("Bearer ABC123") == _NON_STRUCTURAL
    assert _safe_token(None) == _NON_STRUCTURAL
