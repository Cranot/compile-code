#!/usr/bin/env python3
"""Computed truth for compile-code's GitHub repository description.

The provider half of the ``repo_description_drift.py`` contract that lives in
the roam-code repository (``dev/repo_description_drift.py``): the checker
extracts ``<number> <unit>`` claims from the live GitHub description and
resolves each unit against the map returned by ``truth()`` here. The checker
knows nothing about this project; this file knows nothing about extraction.
One implementation of the mechanism, one provider per repository.

Why the description needs its own gate at all: ``scripts/check.py`` covers
every count-bearing file in the tree, but the GitHub description is not a
file. It is edited in the About panel, rendered above the file list and in
search results, and scraped by listing sites — and no in-tree gate can see
it. roam-code's description silently went 43 commands stale exactly that way.

Both numbers below are derived from the roam-code build that this project
actually resolves through its own dependency pin, so they describe what a
user who installs compile-code really gets — not what a README once said.

Run it directly to see the map::

    python scripts/description_truth.py
"""

from __future__ import annotations

import json
import sys


def _procedure_counts() -> tuple[int, int]:
    """Return ``(routable, known)`` procedure counts from the resolved roam.

    ``known_procedures()`` is roam's public accessor for the whole procedure
    universe: every key across the routing registries. It intentionally
    retains dead vocabulary — pre-split fallback names the cache layer may
    still reference — so it is a *superset* of the taxonomy a prompt can
    actually be classified into, and is therefore not the number a reader of
    the description cares about.

    The routable set is ``_L1_PROBE_ELIGIBLE``, which roam derives from its
    single per-procedure metadata table. Today that set is exactly the
    canonical taxonomy. The caller guards the relationship rather than
    trusting it, so this cannot silently under-count.
    """
    from roam.plan import compiler

    return len(frozenset(compiler._L1_PROBE_ELIGIBLE)), len(compiler.known_procedures())


def intent_procedure_count() -> int:
    """Canonical intent procedures in the roam-code build we resolve.

    Guarded, not assumed: the routable set must sit inside the known universe
    and may trail it by at most the one retained dead-vocabulary name. If
    roam's registries move further apart than that, this raises instead of
    quietly returning a number that no longer means what the description
    claims — a loud failure is the correct outcome, because a taxonomy change
    of that size almost certainly means the published claim needs rewriting
    too.
    """
    from roam.plan import compiler

    routable = frozenset(compiler._L1_PROBE_ELIGIBLE)
    known = compiler.known_procedures()
    if not routable <= known:
        raise RuntimeError(
            "roam's routable procedure set is no longer inside known_procedures(); "
            "the intent-procedure derivation in scripts/description_truth.py needs review"
        )
    retained_dead_vocabulary = len(known) - len(routable)
    if retained_dead_vocabulary > 1:
        raise RuntimeError(
            f"roam's known-procedure universe now exceeds the routable set by "
            f"{retained_dead_vocabulary} names (expected at most 1 retained legacy "
            f"name); re-derive the intent-procedure count before trusting it"
        )
    return len(routable)


def language_count() -> int:
    """Languages the resolved roam-code build can parse."""
    from roam.languages.registry import _SUPPORTED_LANGUAGES

    return len(_SUPPORTED_LANGUAGES)


def truth() -> dict[str, int]:
    """Unit phrase -> proven count, for the description drift gate.

    Keys are the phrasings a one-line description would plausibly use; the
    checker handles number agreement, so one spelling per unit is enough. A
    unit the description never mentions is simply never consulted.
    """
    procedures = intent_procedure_count()
    return {
        "intent procedures": procedures,
        "canonical intent procedures": procedures,
        "procedures": procedures,
        "languages": language_count(),
    }


if __name__ == "__main__":
    json.dump(truth(), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
