"""compile-code — a compiler for AI coding tasks.

Pre-resolves repo facts (callers, history, blast radius, config sites)
BEFORE your coding agent's first model token, and verifies the change
after it edits. The kernel is provided by the `roam-code` dependency;
this package is the product CLI: wire it into your agent once, then use
your agent natively.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    # pyproject.toml is the single release source; read it back at import time
    # so this never drifts from the CLI's `--version` (which already reads the
    # installed package metadata) or from the published wheel.
    __version__ = version("compile-code")
except PackageNotFoundError:
    # Running from a source checkout that was never installed (no dist metadata).
    __version__ = "0.0.0+unknown"
