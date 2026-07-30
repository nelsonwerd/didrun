"""P0.2 — the v1 chain preimage is frozen. Three assertions guard it.

Every entry_hash ever written by didrun was computed over the v1 preimage. If
the preimage changes, every archived ledger reports tamper at index 0. The
literals below pin it.

DO NOT REGENERATE THE LITERALS IN THIS FILE. If an assertion here fails, the
v1 chain preimage changed and every previously recorded entry_hash stopped
reproducing. That is the defect this file exists to catch — fix the code, or
define a *new* preimage version and leave version 1 alone. Recomputing a
literal to make the test pass destroys the only evidence that the freeze held.

Three assertions, because one is not enough:

  (i)   the golden entry_hash literal — catches any change to the hashed bytes;
  (ii)  _PREIMAGE_FIELDS[1] equals the frozen name list below — catches a field
        added to the preimage list;
  (iii) the frozen name list equals Event's dataclass fields — catches a field
        added to Event.

(ii) and (iii) together are what close the hole that set-equality alone leaves:
adding a field to *both* Event and _PREIMAGE_FIELDS[1] satisfies a check that
only compares those two to each other, while breaking every archived hash.

Assertion (i) is deliberately written against the pre-P0.2 API surface
(``ChainEntry(index=..., prev_hash=..., event=...)`` and ``compute_hash()``), so
this file runs unchanged on the code as it stood *before* the preimage freeze
landed. That is what makes the golden literal falsifiable: it was generated
from pre-change code and must reproduce on post-change code.
"""

from __future__ import annotations

import dataclasses

import pytest

from didrun import ledger
from didrun.ledger import ChainEntry, Event, Session

# --- the golden preimage -----------------------------------------------------
# Generated from the code as it stood before the P0.2 edit. Synthetic values
# only: no real path, host, or digest appears here.

GOLDEN_EVENT = {
    "argv": ["pytest", "-q", "tests/"],
    "cwd": "/w/repo",
    "env_fingerprint": "0123456789abcdef",
    "observed_via": "wrapper",
    "coverage": "complete",
    "exit_code": 0,
    "started_at": 1000000.5,
    "ended_at": 1000002.25,
    "stdout_blob": "1" * 64,
    "stderr_blob": "2" * 64,
    "transcript_blob": None,
    "tree_before": "3" * 40,
    "tree_after": "3" * 40,
    "submodule_dirty": False,
}
GOLDEN_INDEX = 7
GOLDEN_PREV_HASH = "4" * 64
GOLDEN_ENTRY_HASH = "99715b0cb8a7d3bef413a9d5c3692518b75ec5a5fddcf9bc7a7f6da333ee7d3c"

# The v1 preimage field names, frozen as a literal. Not derived from anything.
V1_PREIMAGE_FIELD_NAMES = [
    "argv",
    "coverage",
    "cwd",
    "ended_at",
    "env_fingerprint",
    "exit_code",
    "observed_via",
    "started_at",
    "stderr_blob",
    "stdout_blob",
    "submodule_dirty",
    "transcript_blob",
    "tree_after",
    "tree_before",
]

# _PREIMAGE_FIELDS does not exist before P0.2. Assertion (i) is the evidence
# that crosses that boundary; (ii) can only run once the constant is there.
_HAS_PREIMAGE_FIELDS = hasattr(ledger, "_PREIMAGE_FIELDS")


def test_v1_chain_preimage_golden_hash():
    """(i) The hashed bytes of a v1 entry have not moved."""
    entry = ChainEntry(
        index=GOLDEN_INDEX,
        prev_hash=GOLDEN_PREV_HASH,
        event=Event.from_dict(dict(GOLDEN_EVENT)),
    )
    assert entry.compute_hash() == GOLDEN_ENTRY_HASH


@pytest.mark.skipif(
    not _HAS_PREIMAGE_FIELDS,
    reason="pre-P0.2 code has no _PREIMAGE_FIELDS; assertion (i) is the cross-boundary evidence",
)
def test_v1_preimage_field_list_matches_frozen_literal():
    """(ii) The declared v1 field list is exactly the frozen 14 names."""
    assert sorted(ledger._PREIMAGE_FIELDS[1]) == V1_PREIMAGE_FIELD_NAMES


def test_event_dataclass_matches_frozen_literal():
    """(iii) Event's field set is exactly the frozen 14 names.

    Runs on pre- and post-P0.2 code alike. Adding a field to Event fails here
    even if the same field is also added to _PREIMAGE_FIELDS[1].
    """
    assert sorted(f.name for f in dataclasses.fields(Event)) == V1_PREIMAGE_FIELD_NAMES


def test_preimage_api_is_all_or_nothing():
    """The skip above must not be re-armable by deleting the constant.

    If this binary carries the P0.2 chain-verdict API, it must also carry both
    preimage constants — so assertion (ii) cannot be silenced by removing
    _PREIMAGE_FIELDS while keeping the rest of the freeze.
    """
    if hasattr(Session, "verify_chain_detail"):
        assert hasattr(ledger, "PREIMAGE_VERSION")
        assert _HAS_PREIMAGE_FIELDS
