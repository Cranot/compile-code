"""The staleness notice for the one hand-maintained roam-code number left.

The runtime product-major ceiling was deleted because it detected nothing and
cost a total verify outage on every kernel major bump. What survives is a
packaging pin -- a resolver preference, not a refusal -- and the failure mode of
a hand-maintained number is that nobody is told it went stale. These tests pin
that this notice fires, names the action, and never reports "up to date" from a
question it could not answer.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load():
    path = ROOT / "scripts" / "roam_pin_drift.py"
    spec = importlib.util.spec_from_file_location("compile_code_roam_pin_drift", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mod = _load()


def _releases(**versions: list[dict[str, object]]) -> dict[str, object]:
    return {"releases": dict(versions)}


class TestDeclaredCeiling:
    def test_reads_the_real_pin_this_repository_ships(self):
        assert mod.declared_ceiling((ROOT / "pyproject.toml").read_text(encoding="utf-8")) == 15

    @pytest.mark.parametrize(
        "pin",
        [
            'dependencies = ["click>=8.3.3"]',
            'dependencies = ["roam-code>=13.10.0"]',
            'dependencies = ["roam-code<14,<15,>=13.10.0"]',
            'dependencies = ["roam-code<=14,>=13.10.0"]',
        ],
        ids=["absent", "open-ended", "two-ceilings", "inclusive-ceiling"],
    )
    def test_a_pin_it_cannot_read_is_an_error_not_a_default(self, pin):
        # An unreadable pin must never resolve to a number, because every
        # number this function could invent would silently answer the
        # staleness question wrong in one direction or the other.
        with pytest.raises(ValueError):
            mod.declared_ceiling(pin)


class TestPublishedMajors:
    def test_counts_only_installable_final_releases(self):
        payload = _releases(
            **{
                "13.10.0": [{"yanked": False}],
                "14.0.0": [{"yanked": False}],
                "15.0.0rc1": [{"yanked": False}],  # a prerelease is not a published major
                "16.0.0": [],  # registered with no files: never installable
                "17.0.0": [{"yanked": True}, {"yanked": True}],  # withdrawn
            }
        )
        assert mod.published_majors(payload) == {13, 14}

    def test_a_partially_yanked_release_still_counts(self):
        payload = _releases(**{"14.0.0": [{"yanked": True}, {"yanked": False}]})
        assert mod.published_majors(payload) == {14}

    @pytest.mark.parametrize(
        "payload",
        [None, {}, {"releases": {}}, {"releases": {"not-a-version": [{"yanked": False}]}}],
        ids=["not-a-mapping", "no-releases-key", "empty-releases", "nothing-final"],
    )
    def test_an_unreadable_response_raises_rather_than_reporting_zero_majors(self, payload):
        with pytest.raises(ValueError):
            mod.published_majors(payload)


class TestNotice:
    @pytest.fixture
    def repo(self, tmp_path, monkeypatch):
        (tmp_path / "pyproject.toml").write_text(
            'dependencies = [\n    "roam-code<15,>=13.10.0",\n    "click>=8.3.3",\n]\n', encoding="utf-8"
        )
        monkeypatch.setattr(mod, "ROOT", tmp_path)
        return tmp_path

    @staticmethod
    def _serve(monkeypatch, payload):
        class _Response:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            @staticmethod
            def read():
                return json.dumps(payload).encode("utf-8")

        monkeypatch.setattr(mod.urllib.request, "urlopen", lambda url, timeout=0: _Response())

    def test_a_pin_that_covers_every_published_major_passes(self, repo, monkeypatch, capsys):
        self._serve(monkeypatch, _releases(**{"13.10.0": [{"yanked": False}], "14.0.0": [{"yanked": False}]}))

        assert mod.main() == 0
        assert "PASS" in capsys.readouterr().out

    def test_a_published_major_at_or_above_the_ceiling_names_the_action_and_every_site(self, repo, monkeypatch, capsys):
        self._serve(monkeypatch, _releases(**{"15.0.0": [{"yanked": False}]}))

        assert mod.main() == 1
        out = capsys.readouterr().out
        assert "STALE PIN" in out
        assert "roam-code 15 is published" in out
        assert "<16" in out
        for site in mod.PIN_SITES:
            assert site in out, f"the printed action does not name {site}"
        # It must not read as an outage: nothing refuses at runtime on a
        # product major any more, and saying otherwise would send a reader
        # looking for a break that does not exist.
        assert "notice, not an outage" in out

    def test_a_question_it_could_not_answer_is_never_reported_as_up_to_date(self, repo, monkeypatch, capsys):
        def _boom(url, timeout=0):
            raise OSError("name resolution failed")

        monkeypatch.setattr(mod.urllib.request, "urlopen", _boom)

        assert mod.main() == 2
        out = capsys.readouterr().out
        assert "UNDETERMINED" in out
        assert "PASS" not in out


class TestTheNamedActionIsComplete:
    """The remedy must name every file, derived from the tree, not from memory.

    This notice shipped naming three sites while the ceiling literal lived in
    seven. Detection was correct and the instruction was not, which is the
    quieter half of the same defect: the maintainer follows the list, raises
    three, and the four unnamed ones fail later somewhere else. Enumerating the
    real set here means adding an eighth site cannot leave the printed action
    behind -- it fails HERE, at the list, naming the file it is missing.
    """

    @staticmethod
    def _tracked_text_files() -> list[str]:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files"],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        ).stdout
        return [line for line in out.splitlines() if line.strip()]

    def _sites_carrying_the_ceiling(self) -> set[str]:
        ceiling = mod.declared_ceiling((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        # The three written forms of the interval, all anchored to the pin so an
        # unrelated "<15" elsewhere in the tree is not mistaken for this number.
        pattern = re.compile(
            rf"roam-code[^\n]*<{ceiling}\b" rf"|<{ceiling}\s*,\s*>=" rf"|>=\s*[\d.]+\s*,\s*<{ceiling}\b"
        )
        found = set()
        for rel in self._tracked_text_files():
            try:
                text = (ROOT / rel).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue  # binary or unreadable: cannot carry the literal as text
            if pattern.search(text):
                found.add(rel.replace("\\", "/"))
        return found

    def test_every_file_carrying_the_ceiling_is_named_in_the_printed_action(self):
        carried = self._sites_carrying_the_ceiling()
        assert carried, "found no file carrying the pin interval — the search itself is broken"
        unnamed = sorted(carried - set(mod.PIN_SITES) - set(mod.HISTORICAL_SITES))
        assert not unnamed, (
            "these files carry the roam-code ceiling but the stale-pin notice does not name them, "
            f"so a maintainer following its instructions would leave them behind: {unnamed}"
        )

    def test_every_named_site_exists(self):
        # The opposite rot: a site is renamed or deleted and the notice keeps
        # sending the reader to a path that is not there.
        missing = sorted(site for site in mod.PIN_SITES if not (ROOT / site).exists())
        assert not missing, f"the notice names sites that do not exist: {missing}"
