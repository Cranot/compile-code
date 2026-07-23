"""compile-code — a compiler for AI coding tasks.

Pre-resolves repo facts (callers, history, blast radius, config sites)
BEFORE your coding agent's first model token, and verifies the change
after it edits. The kernel is provided by the `roam-code` dependency;
this package is the product CLI: wire it into Claude Code, or feed
headless ``compile run`` envelopes to other agents.
"""

from __future__ import annotations


def __getattr__(name: str) -> str:
    """Resolve ``__version__`` lazily (PEP 562) on first attribute access.

    Reading installed-package metadata drags in ``importlib.metadata`` plus
    its zipfile/email dependency chain — measured at ~70 ms of the CLI's
    ~100 ms import — so it must not run at import time. Only ``--version``
    actually needs it. pyproject.toml stays the single release source: the
    lookup still reads the installed distribution metadata, so this never
    drifts from the published wheel.
    """
    if name != "__version__":
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib.metadata import PackageNotFoundError, version

    try:
        resolved = version("compile-code")
    except PackageNotFoundError:
        # Running from a source checkout that was never installed (no dist metadata).
        resolved = "0.0.0+unknown"
    globals()[name] = resolved  # cache so later accesses skip this hook
    return resolved
