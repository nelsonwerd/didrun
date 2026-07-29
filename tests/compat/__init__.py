"""Compat corpus replay harness — CONTENT-BLIND by construction.

THE CONTENT RULE (non-negotiable, and the reason this package exists at all):
this harness may READ ledger bytes; it may never print, log, echo, or assert on
them. Every assertion in here compares digests, booleans, counts, or path
shapes. ``assert computed_hash == stored_hash`` is fine — a hash is not
content. ``assert line == ...`` is forbidden, because pytest prints both sides
of a failed comparison, and a ledger line is a verbatim record of everything a
session ran and printed: argv, stdout, stderr, and any credential that passed
through them.

The tree this harness is aimed at is 174 MB of secret-bearing evidence for a
build that is still running. A harness that echoes one line of it into a CI log
or a chat transcript has done more damage than any bug it could have found.
"""
