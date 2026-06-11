"""compile-code — a compiler for AI coding tasks.

Pre-resolves repo facts (callers, history, blast radius, config sites)
BEFORE your coding agent's first model token, and verifies the change
after it edits. The kernel is provided by the `roam-code` dependency;
this package is the product CLI: wire it into your agent once, then use
your agent natively.
"""

from __future__ import annotations

__version__ = "0.1.0"
