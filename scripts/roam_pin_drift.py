"""Report when the hand-maintained roam-code packaging ceiling has gone stale.

There used to be a RUNTIME product-major ceiling on roam, and it was deleted:
it detected nothing, it deferred every compatibility question to a human typing
a bigger number, and its measured effect was a total `compile verify` outage on
every kernel major bump. What remains is a packaging pin in ``pyproject.toml``
-- a resolver preference naming the newest major a receipt-v3 transaction has
actually been run against.

That pin is still a hand-maintained number, and the failure mode of a
hand-maintained number is that nobody is told it went stale. This script is the
thing that tells them. It is NOT a gate on users: nothing refuses at runtime
because of it, so failing here is a stale-pin NOTICE with a named action, never
an outage.

Deliberately not part of ``scripts/check.py``: that gate is the blocking one and
has to stay offline, token-free and runnable by hand on a laptop. This needs the
network, and the answer can change with no commit in this repository at all --
which only a scheduled run can see.

Exit codes: 0 the pin covers every published major; 1 the pin is stale (action
named); 2 the question could not be answered (network, parse, or a pin this
script cannot read). An unanswerable question is never reported as "up to date".
"""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "roam-code"
PYPI_JSON_URL = f"https://pypi.org/pypi/{PACKAGE}/json"
TIMEOUT_SECONDS = 30

# Every site that has to move together when the pin is raised. Named in the
# failure text so the action is a list of files, not a search.
#
# This list shipped naming three of seven. A watcher whose whole purpose is to
# name the action instead sent the maintainer to four files it did not mention
# -- the incompleteness was in the remedy, not the detection, which is the
# harder kind to notice because the gate still goes red at the right moment.
# `tests/test_roam_pin_drift.py` now DERIVES the true set from the tree and
# fails if this tuple is missing one, so the instruction cannot silently rot
# again as sites are added.
PIN_SITES = (
    "pyproject.toml",
    "scripts/release_artifacts.py",
    "scripts/check.py",
    "README.md",
    "tests/test_cli.py",
    "tests/test_release.py",
    "tests/test_roam_pin_drift.py",
)

# Files that carry the interval as a RECORD of what it was, not as a value that
# has to move. A changelog entry describing "<15" is true about the release it
# documents and stays true forever; listing it above would instruct a maintainer
# to edit history. Carrying the literal and needing to be raised are different
# properties, so the completeness check knows about both rather than treating
# every occurrence as an obligation.
HISTORICAL_SITES = ("CHANGELOG.md",)

_RELEASE_RE = re.compile(r"\A(\d+)\.(\d+)\.(\d+)\Z")


def declared_ceiling(pyproject: str) -> int:
    """The exclusive major from the packaging pin, or raise ValueError."""
    pin = re.search(rf'"{re.escape(PACKAGE)}([^"\r\n]+)"', pyproject)
    if pin is None:
        raise ValueError(f"no {PACKAGE} pin found in pyproject.toml")
    ceilings = [
        clause.strip().removeprefix("<")
        for clause in pin.group(1).split(",")
        if clause.strip().startswith("<") and not clause.strip().startswith("<=")
    ]
    if len(ceilings) != 1 or not ceilings[0].split(".")[0].isdigit():
        raise ValueError(f"expected exactly one exclusive ceiling in the {PACKAGE} pin, read {pin.group(1)!r}")
    return int(ceilings[0].split(".")[0])


def published_majors(payload: object) -> set[int]:
    """Majors of every published, non-fully-yanked release in a PyPI response.

    A release with no files has never been installable and is not a published
    major; a release whose every file is yanked has been withdrawn. Both are
    excluded, because raising a pin to cover them would be raising it for
    something no resolver can select.
    """
    if not isinstance(payload, dict):
        raise ValueError("PyPI response was not a JSON object")
    releases = payload.get("releases")
    if not isinstance(releases, dict) or not releases:
        raise ValueError("PyPI response carried no releases map")
    majors = set()
    for version, files in releases.items():
        match = _RELEASE_RE.match(str(version))
        if match is None:  # pre-releases and post-releases are not a new major
            continue
        if not isinstance(files, list) or not files:
            continue
        if all(isinstance(entry, dict) and entry.get("yanked") for entry in files):
            continue
        majors.add(int(match.group(1)))
    if not majors:
        raise ValueError("no published final release found on PyPI")
    return majors


def main() -> int:
    try:
        ceiling = declared_ceiling((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"[roam-pin] UNDETERMINED — could not read the declared ceiling: {exc}")
        return 2
    try:
        with urllib.request.urlopen(PYPI_JSON_URL, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310 - fixed https URL
            payload = json.loads(response.read().decode("utf-8"))
        majors = published_majors(payload)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        print(f"[roam-pin] UNDETERMINED — could not read {PYPI_JSON_URL}: {exc}")
        return 2
    newest = max(majors)
    if newest < ceiling:
        print(f"[roam-pin] PASS — newest published {PACKAGE} major is {newest}; the tested ceiling is <{ceiling}.")
        return 0
    sites = ", ".join(PIN_SITES)
    print(
        f"[roam-pin] STALE PIN — {PACKAGE} {newest} is published; the tested ceiling is <{ceiling}.\n"
        f"  This is a notice, not an outage: nothing refuses at runtime on a product major, so a user "
        f"who already has {PACKAGE} {newest} on PATH is verified against the envelope contract as normal.\n"
        f"  Action: run the receipt-v3 transaction against {PACKAGE} {newest}, then raise the ceiling to "
        f"<{newest + 1} in all of: {sites}."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
