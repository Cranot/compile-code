"""A measured live-repo number in a comment must name the commit it holds at.

Every comment in this repository that states a MEASURED quantity is a claim
that was true once. Four of the eight such claims sampled in one audit had
since drifted, and the discriminator was mechanical rather than a matter of
care: every drifted one phrased its number against LIVE repository state --
"the largest blob anywhere in this repository's history", "this repository's
424 commits", "0 of 51 candidates" -- while the ones that held either named
the commit they were measured at or were pinned by a test.

Nothing could see any of them. These numbers live in comments, so no runtime
assertion, no lint rule and no reviewer diff can notice when the repository
grows past them. The repository had already demonstrated it cannot self-correct
here: ``secret_scan.py`` explicitly retracted the "424 commits" figure that
``prepush_leak_scan.py`` states, and left the false number standing at its own
site. Retraction-by-adjacent-file is the shape this gate exists to stop.

So the rule is not "keep the numbers right" -- that is the instruction that
already failed. The rule is that a live-repo quantity must carry the commit it
was measured at, which makes it a dated observation that stays true instead of
a present-tense assertion that silently stops being one.

This refuses more than the tree did before it and relaxes nothing. It does not
verify that any anchored number is CORRECT -- only that it says when it was
taken. Re-deriving each figure would need git plumbing per claim and would make
the gate fail on a shallow clone, so an anchored-but-wrong number is out of
scope and stays a reading problem.
"""

from __future__ import annotations

import io
import re
import subprocess
import tokenize
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# TWO conditions, both required, because either alone is far too broad. A
# quantity alone matches every captured scanner line in every fixture test; a
# referent alone matches ordinary prose about the repository. It is their
# co-occurrence that identifies the shape that drifts: a number stated ABOUT
# LIVE repository state. Every claim found stale in the audit satisfies both;
# every quoted sample of a scanner's output over a synthetic fixture satisfies
# only the first, which is correct -- those numbers describe the fixture, not
# this tree, and do not drift when the repository grows.
_MEASURED_QUANTITY = re.compile(
    r"\b\d[\d,_]*(?:\.\d+)?\s*"
    r"(?:(?:distinct\s+|binary\s+|tracked\s+|reachable\s+)*(?:commits?|blobs?|candidates?|files?)"
    r"|(?:B|KB|KiB|MB|MiB|GB|GiB|bytes))\b",
    re.IGNORECASE,
)
_LIVE_REPO_REFERENT = re.compile(
    r"this repositor(?:y|y's)|this repo\b|reachable from HEAD|from every ref|rev-list --objects --all",
    re.IGNORECASE,
)

# A claim explicitly scoped to a past state is already a dated observation and
# does not drift, even without a hash. "Measured ... before the fix" and "the
# repository had N commits when it was written" stay true forever; it is the
# present-tense assertion about live state that stops being true silently.
_PAST_SCOPE = re.compile(
    r"before (?:the|this) fix|when it was written|used to|at the time|before it (?:landed|shipped)",
    re.IGNORECASE,
)

# A short hex object name. Not verified against the object database: that would
# make the gate fail on a shallow clone or a fresh fork, which is a worse
# failure than accepting a typo'd anchor.
_COMMIT_ANCHOR = re.compile(r"\b(?=[0-9a-f]{7,40}\b)[0-9a-f]*[a-f][0-9a-f]*\b")

# How far from the claim the anchor may sit. A claim and its anchor belong in
# the same paragraph; anything further apart is not an anchor a reader will
# connect to the number.
_ANCHOR_RADIUS_LINES = 6

# The referent window is much tighter than the anchor window on purpose. A
# quantity and the words "this repository" have to be in the same SENTENCE to
# be one claim; a paragraph-wide window borrows a referent from the sentence
# next door and refuses honest numbers -- measured here on the first draft,
# which flagged four throughput figures that sat six lines above an unrelated
# mention of repository history.
_REFERENT_RADIUS_LINES = 1


def _tracked_python_files() -> list[Path]:
    listing = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.py"],
        cwd=ROOT,
        capture_output=True,
        check=True,
        text=True,
    ).stdout
    return [ROOT / name for name in listing.split("\0") if name]


def _prose_lines(path: Path) -> dict[int, str]:
    """Line number -> text, for every comment and string literal in *path*.

    Comments and docstrings both carry these claims, and a number stated in a
    docstring is exactly as invisible to a runtime assertion as one in a ``#``
    comment.
    """
    source = path.read_text(encoding="utf-8")
    found: dict[int, str] = {}
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    for token in tokens:
        if token.type not in (tokenize.COMMENT, tokenize.STRING):
            continue
        start = token.start[0]
        for offset, line in enumerate(token.string.splitlines()):
            found.setdefault(start + offset, "")
            found[start + offset] += line
    return found


@pytest.mark.parametrize("path", _tracked_python_files(), ids=lambda p: p.relative_to(ROOT).as_posix())
def test_a_live_repo_measurement_names_the_commit_it_was_taken_at(path: Path):
    prose = _prose_lines(path)
    unanchored: list[str] = []
    for number, text in sorted(prose.items()):
        if not _MEASURED_QUANTITY.search(text):
            continue
        sentence = "\n".join(
            prose.get(near, "") for near in range(number - _REFERENT_RADIUS_LINES, number + _REFERENT_RADIUS_LINES + 1)
        )
        if not _LIVE_REPO_REFERENT.search(sentence):
            continue
        if _PAST_SCOPE.search(sentence):
            continue
        window = "\n".join(
            prose.get(near, "") for near in range(number - _ANCHOR_RADIUS_LINES, number + _ANCHOR_RADIUS_LINES + 1)
        )
        if _COMMIT_ANCHOR.search(window):
            continue
        unanchored.append(f"{path.relative_to(ROOT).as_posix()}:{number}: {text.strip()}")

    assert not unanchored, (
        "A comment states a quantity measured from this repository without naming the commit it was "
        "measured at, so it will silently stop being true the next time the repository grows. Write it "
        "as a dated observation -- 'measured at <short sha>, ...' -- rather than as a present-tense "
        "claim about live state:\n  " + "\n  ".join(unanchored)
    )


@pytest.mark.parametrize(
    "stale",
    [
        # The two claims that were measurably wrong when this gate was written.
        "# largest blob anywhere in this repository's history is 191 KB.",
        "# Measured: 0 binary blobs across this repository's 424 commits, so the refusal",
        "# 0 of the 480 distinct blobs reachable from every ref are binary",
    ],
)
def test_the_gate_catches_the_claims_that_motivated_it(stale):
    assert _MEASURED_QUANTITY.search(stale) is not None
    assert _LIVE_REPO_REFERENT.search(stale) is not None
    assert _COMMIT_ANCHOR.search(stale) is None


@pytest.mark.parametrize(
    "accepted",
    [
        # A scanner's captured output over a synthetic fixture. The numbers
        # describe the fixture and do not drift when this repository grows.
        'assert "established 2 candidate paths; examined 2 text files" in out',
        "# prepush_leak_scan: clean (1 commit(s) scanned, 0 findings)",
        # An anchored live-repo claim: a dated observation, still true later.
        "# Measured at 209293e: 0 binary blobs across 442 commits reachable from HEAD.",
    ],
)
def test_the_gate_leaves_a_fixture_number_and_an_anchored_claim_alone(accepted):
    assert not (
        _MEASURED_QUANTITY.search(accepted)
        and _LIVE_REPO_REFERENT.search(accepted)
        and not _COMMIT_ANCHOR.search(accepted)
    )


def test_a_decimal_only_token_is_not_mistaken_for_a_commit_anchor():
    # "1234567" is a plausible byte count and must not silence a claim.
    assert _COMMIT_ANCHOR.search("measured over 1234567 commits") is None
    assert _COMMIT_ANCHOR.search("measured at c003a08 over 42 commits") is not None
