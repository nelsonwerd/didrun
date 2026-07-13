"""didrun — flight records for agent-written code.

didrun records what an AI coding agent actually executed during a working
session, binds structured claims to git tree states, seals a commit-bound
evidence manifest, and verifies those claims with honest staleness grades.

There is no LLM in the trust path: capture and verification are deterministic.
A didrun record is a faithful *recording*, not a *proof* — see docs/TRUST_MODEL.md.

The runtime is stdlib-only by design; auditability is the trust wedge.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
