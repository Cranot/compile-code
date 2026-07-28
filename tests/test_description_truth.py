"""The GitHub description is a count surface, and this is its truth provider.

``scripts/check.py`` gates every count-bearing file in the tree. The GitHub
description is not a file -- it is edited in the About panel and rendered
above the file list, in search results and in scraped listings -- so no
in-tree gate can see it. roam-code's description went 43 commands stale in
that blind spot.

The checker itself lives once, in roam-code, and is pinned by
``.github/workflows/repo-description-drift.yml``. What this repository owns is
``scripts/description_truth.py``: the map from a unit phrase to the number
this project can actually prove. These tests pin the properties that make
that map worth trusting -- that it is derived rather than typed, that its
derivation refuses to guess, and that the wiring which runs it still exists.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROVIDER_PATH = ROOT / "scripts" / "description_truth.py"
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "repo-description-drift.yml"


@pytest.fixture(scope="module")
def provider():
    spec = importlib.util.spec_from_file_location("_test_description_truth", PROVIDER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["_test_description_truth"] = module
    spec.loader.exec_module(module)
    return module


def test_truth_map_is_all_positive_integers(provider) -> None:
    truth = provider.truth()
    assert truth, "the provider must expose at least one provable count"
    for unit, value in truth.items():
        assert isinstance(value, int), f"{unit} is not an int"
        assert value > 0, f"{unit} is not a positive count"


def test_counts_come_from_the_resolved_roam_build(provider) -> None:
    """Derived, never typed: both numbers must trace back to roam-code.

    A literal here would reproduce the exact bug this gate exists to catch --
    a number that was true once and is not re-checked.
    """
    from roam.languages.registry import _SUPPORTED_LANGUAGES
    from roam.plan import compiler

    truth = provider.truth()
    assert truth["languages"] == len(_SUPPORTED_LANGUAGES)
    assert truth["intent procedures"] == len(frozenset(compiler._L1_PROBE_ELIGIBLE))


def test_procedure_derivation_refuses_to_guess(provider, monkeypatch) -> None:
    """If roam's procedure registries move apart, fail loudly.

    The routable set is allowed to trail the known universe by the single
    retained dead-vocabulary name and no further. Silently returning a stale
    number would be worse than failing: the published claim would look
    verified while meaning something else.
    """
    from roam.plan import compiler

    routable = frozenset(compiler._L1_PROBE_ELIGIBLE)
    monkeypatch.setattr(
        compiler,
        "known_procedures",
        lambda: routable | {"_extra_one", "_extra_two"},
    )
    with pytest.raises(RuntimeError, match="re-derive the intent-procedure count"):
        provider.intent_procedure_count()


def test_routable_set_must_stay_inside_the_known_universe(provider, monkeypatch) -> None:
    from roam.plan import compiler

    monkeypatch.setattr(compiler, "known_procedures", frozenset)
    with pytest.raises(RuntimeError, match="no longer inside known_procedures"):
        provider.intent_procedure_count()


def test_the_drift_workflow_still_wires_this_provider() -> None:
    """A provider nobody runs proves nothing."""
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "scripts/description_truth.py" in text
    assert "repo_description_drift.py" in text
    assert "schedule:" in text, (
        "the description can be edited on GitHub without any commit, so a "
        "push-only trigger would never notice a drift that starts there"
    )
    assert "ref: " in text, "the borrowed checker must be pinned to a commit, not a branch"
