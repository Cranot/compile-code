"""Two credential catalogues, one obligation ledger.

THE DEFECT THIS EXISTS FOR: a catalogue can SHRINK in silence. Measured on the
shipped gates before this file, by deleting entries one at a time and re-running
every gate: 37 of the 43 entries across ``secret_scan.SECRET_PATTERN_DEFS`` (34)
and ``check.LEAK_PATTERNS`` (9) could be removed with every gate still printing
PASS. Only 6 deletions were caught, and only because those 6 happen to be named
in a positive control. Nothing mechanical said the two lists still covered what
they covered yesterday.

WHY NOT A UNION. Neither list is a superset of the other and that is deliberate:
``check`` carries three private-infrastructure shapes no vendor catalogue has,
plus SHORTER forms of three credential prefixes that ``secret_scan`` floors
higher; ``secret_scan`` carries 24 vendor and heuristic shapes ``check`` does
not, because ``.githooks/pre-push`` runs ``check`` over the whole tree on every
push and CI runs ``secret_scan`` over the same inventory. Merging them was
measured at ~5.6x on the pre-push arm and would erase the asymmetry rather than
record it.

WHY NOT A FAMILY-NAME TABLE. A name is not detection. A table of names cannot
tell a load-bearing entry from a redundant one, and it fails on a rename that
changed nothing.

WHY NOT "was it caught by ANYBODY". That question passes when a family vanishes
from one catalogue while the other still happens to cover the shape -- which is
the exact drift that has already had to be repaired here by hand once, for
GitHub's fine-grained PAT. The obligation is PER CATALOGUE.

SO: one row per live catalogue entry, carrying a sample that is a real instance
of that entry's own regex, and the disposition of BOTH catalogues over that
sample, pinned as data. Asymmetry is recorded, never absent. The ledger fails on
a CHANGE in disposition, never on a DIFFERENCE between the lists.

Samples are assembled from fragments, never written as one contiguous literal:
this file is a candidate like any other and is read by both catalogues.
"""

from __future__ import annotations

import re
from typing import NamedTuple

import pytest

from scripts import check, secret_scan

# --- why a shape sits in one catalogue and not the other ---------------------
# Every row whose two dispositions differ must name its reason. A future entry
# that lands in one list only cannot be added to this ledger without saying
# why, which is the difference between a recorded decision and drift.
BREADTH = (
    "vendor/heuristic breadth belongs to the CI catalogue: check.LEAK_PATTERNS "
    "runs on every local push over the whole tree, and carrying all 34 shapes "
    "there was measured at ~5.6x on that arm"
)
PRIVATE = "a private-infrastructure shape that exists in no vendor catalogue and never will"
SHORTER = (
    "check accepts a SHORTER form of this prefix than secret_scan does; the two "
    "floors are different opinions about the format, both deliberate"
)
PEM_WIDE = (
    "check's PEM pattern is [A-Z ]* and admits ENCRYPTED/PGP headers; "
    "secret_scan's optional group lists RSA/EC/DSA/OPENSSH only"
)


class Row(NamedTuple):
    """One detection obligation.

    ``origin`` is the catalogue whose entry this row exists for -- ``family``
    must be a live entry there. ``sample`` must match that entry's own regex.
    ``secret_scan`` and ``check`` are the pinned dispositions: whether that
    whole catalogue produces any hit on the sample, by any of its entries.

    DISPOSITION IS PER CATALOGUE, NOT PER ENTRY, and that is the point. It is
    what makes a deletion that loses nothing distinguishable from one that
    loses a family: measured by leave-one-out over all 43 entries, exactly one
    (the classic ``ghp_`` PAT, which is also a ``gh[pousr]_`` token) keeps its
    catalogue's disposition after deletion. That row's removal is reported by
    ``phantom_failures`` as redundant rather than as lost coverage, so the
    maintainer is told which of the two edits they just made.
    """

    origin: str
    family: str
    sample: str
    secret_scan: bool
    check: bool
    why: str = ""


def _assign(name: str, value: str) -> str:
    """``name = "value"`` built at runtime, so this file's source text never
    carries the assignment shape the catalogues look for."""
    return f'{name} = "{value}"'


LEDGER: tuple[Row, ...] = (
    # --- secret_scan.SECRET_PATTERN_DEFS, 34 entries -------------------------
    Row("secret_scan", "Anthropic OAuth Token", "sk-ant-oat01-" + "Aa9_-" * 12, True, True),
    Row("secret_scan", "Anthropic API Key", "sk-ant-api03-" + "Bb8_-" * 12, True, True),
    Row("secret_scan", "OpenAI Project Key", "sk-proj-" + "Cc7" * 12, True, True),
    Row("secret_scan", "OpenAI API Key", "sk-" + "D" * 48, True, True),
    Row("secret_scan", "xAI API Key", "xai-" + "E" * 24, True, False, BREADTH),
    Row("secret_scan", "Groq API Key", "gsk_" + "F" * 24, True, False, BREADTH),
    Row("secret_scan", "HuggingFace Token", "hf_" + "G" * 34, True, False, BREADTH),
    Row("secret_scan", "Replicate API Token", "r8_" + "H" * 37, True, False, BREADTH),
    Row("secret_scan", "AWS Access Key", "AKIA" + "I" * 16, True, True),
    Row("secret_scan", "AWS Secret Key", _assign("aws_secret_access_key", "J" * 40), True, False, BREADTH),
    Row("secret_scan", "GitHub Token", "gho_" + "K" * 36, True, True),
    Row("secret_scan", "GitHub Personal Access Token (classic)", "ghp_" + "L" * 36, True, True),
    Row("secret_scan", "GitHub Fine-Grained PAT", "github_pat_" + "11ABCDEFG0" + "M" * 47, True, True),
    Row("secret_scan", "GitLab Token", "glpat-" + "N" * 20, True, False, BREADTH),
    Row("secret_scan", "Slack Bot Token", "xoxb-" + "1" * 11 + "-" + "2" * 11 + "-" + "a" * 24, True, False, BREADTH),
    Row(
        "secret_scan",
        "Slack Webhook",
        "https://hooks.slack.com/services/T" + "A1" * 4 + "/B" + "B2" * 4 + "/" + "c3" * 8,
        True,
        False,
        BREADTH,
    ),
    Row("secret_scan", "Stripe Secret Key", "sk_live_" + "P" * 24, True, False, BREADTH),
    Row("secret_scan", "Stripe Publishable Key", "pk_live_" + "Q" * 24, True, False, BREADTH),
    Row("secret_scan", "Google API Key", "AIza" + "R" * 35, True, False, BREADTH),
    Row("secret_scan", "Google OAuth Secret", _assign("client_secret", "S" * 24), True, False, BREADTH),
    Row(
        "secret_scan",
        "Heroku API Key",
        _assign("heroku_app", "01234567-89ab-" + "cdef-0123-456789abcdef"),
        True,
        False,
        BREADTH,
    ),
    Row("secret_scan", "NPM Token", "npm_" + "T" * 36, True, False, BREADTH),
    Row("secret_scan", "PyPI Token", "pypi-" + "U" * 100, True, True),
    Row("secret_scan", "SendGrid API Key", "SG." + "V" * 22 + "." + "W" * 43, True, False, BREADTH),
    Row("secret_scan", "Twilio API Key", "SK" + "0123456789abcdef" * 2, True, False, BREADTH),
    Row("secret_scan", "Mailgun API Key", "key-" + "X" * 32, True, False, BREADTH),
    Row("secret_scan", "Private Key", "-----BEGIN " + "RSA PRIVATE KEY-----", True, True),
    Row("secret_scan", "Generic Password Assignment", _assign("password", "hunter2hunter2"), True, False, BREADTH),
    Row("secret_scan", "Generic Secret Assignment", _assign("api_secret", "aB3xQ7zRt9LmZp2w"), True, False, BREADTH),
    Row("secret_scan", "Generic Bearer Token", "Authorization: Bearer " + "Zz9" * 8, True, False, BREADTH),
    Row(
        "secret_scan",
        "JWT Token",
        "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJ" + "zdWIiOiIxMjM0NSJ9" + "." + "Kx7Qw2Lm9Pz4Rt6",
        True,
        False,
        BREADTH,
    ),
    Row("secret_scan", "Base64 Encoded Secret", _assign("secret_base64", "Ab7" * 20), True, False, BREADTH),
    Row(
        "secret_scan",
        "Database Connection String",
        "postgres" + "://user:pw@db.example:5432/app",
        True,
        False,
        BREADTH,
    ),
    # 20 characters is the shortest value this entry can match, and until the
    # entropy floor was capped at log2(n) no value of that length could clear
    # it. This row is the parity ledger's copy of that pin.
    Row("secret_scan", "High Entropy String", _assign("key", "Qw7zX2mNp9Vk4Rt6Ls1B"), True, False, BREADTH),
    # --- check.LEAK_PATTERNS, 9 entries --------------------------------------
    Row("check", "GitHub token", "ghu_" + "C" * 22, False, True, SHORTER),
    Row("check", "API secret key", "sk-" + "D" * 20, False, True, SHORTER),
    Row("check", "AI provider key", "sk-ant-oat01-" + "Ee9_-" * 4, False, True, SHORTER),
    Row("check", "AWS access key", "AKIA" + "Z" * 16, True, True),
    Row("check", "PyPI upload token", "pypi-" + "Y" * 100, True, True),
    Row("check", "PEM private key", "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----", False, True, PEM_WIDE),
    Row("check", "VPS-local path", "/ro" + "ot/services/app.log", False, True, PRIVATE),
    Row("check", "private internal reference", "int" + "ernal/planning/notes.md", False, True, PRIVATE),
    Row("check", "private transcript export reference", "transcr" + "ipts/session.json", False, True, PRIVATE),
)


def _secret_scan_names() -> set[str]:
    return {d["name"] for d in secret_scan.SECRET_PATTERN_DEFS}


def _check_labels() -> set[str]:
    return {label for _, label in check.LEAK_PATTERNS}


def _own_pattern(row: Row) -> str | None:
    if row.origin == "secret_scan":
        for entry in secret_scan.SECRET_PATTERN_DEFS:
            if entry["name"] == row.family:
                return entry["pattern"]
        return None
    for pattern, label in check.LEAK_PATTERNS:
        if label == row.family:
            return pattern
    return None


def _detected_by_secret_scan(sample: str) -> bool:
    return bool(secret_scan.scan_text("<ledger>", sample))


def _detected_by_check(sample: str) -> bool:
    return bool(check._leak_pattern_hits(sample))


# --- A0: a sample must be an instance of the entry it is filed under ---------
def sample_failures() -> list[str]:
    problems: list[str] = []
    for row in LEDGER:
        pattern = _own_pattern(row)
        if pattern is None:
            continue  # A4 reports this; not this assertion's job.
        if re.search(pattern, row.sample) is None:
            problems.append(f"A0 SAMPLE IS NOT AN INSTANCE of {row.origin} {row.family!r}: {row.sample[:24]!r}")
        if row.secret_scan != row.check and not row.why:
            problems.append(f"A0 UNEXPLAINED ASYMMETRY for {row.origin} {row.family!r}: the row states no reason")
    return problems


# --- A1/A2: every pinned disposition must still hold -------------------------
def disposition_failures() -> list[str]:
    problems: list[str] = []
    for row in LEDGER:
        for catalogue, pinned, live in (
            ("secret_scan", row.secret_scan, _detected_by_secret_scan(row.sample)),
            ("check", row.check, _detected_by_check(row.sample)),
        ):
            if pinned and not live:
                problems.append(
                    f"A1 COVERAGE LOST: {catalogue} no longer detects the {row.origin} shape {row.family!r}. "
                    "A family this ledger says is covered is not covered any more."
                )
            elif live and not pinned:
                problems.append(
                    f"A2 LEDGER IS STALE: {catalogue} now detects the {row.origin} shape {row.family!r}, "
                    "which this row pins as uncovered. Update the row and its reason -- do not revert the gain."
                )
    return problems


# --- A3/A4: rows and entries must be in bijection over names -----------------
def orphan_failures() -> list[str]:
    named = {(row.origin, row.family) for row in LEDGER}
    problems = [
        f"A3 ORPHAN secret_scan entry, named by no ledger row: {name!r}"
        for name in sorted(_secret_scan_names())
        if ("secret_scan", name) not in named
    ]
    problems += [
        f"A3 ORPHAN check entry, named by no ledger row: {label!r}"
        for label in sorted(_check_labels())
        if ("check", label) not in named
    ]
    return problems


def phantom_failures() -> list[str]:
    """A row naming an entry that no longer exists.

    Always a failure -- a ledger that keeps rows for deleted entries rots into
    fiction -- but the message says WHICH of two very different edits produced
    it, because the remedies differ. If the origin catalogue still detects the
    sample, the entry was redundant and deleting this row is the correct and
    complete response. If it does not, a family just lost its last detector and
    ``A1`` above is already saying so.
    """
    live = {"secret_scan": _secret_scan_names(), "check": _check_labels()}
    detects = {"secret_scan": _detected_by_secret_scan, "check": _detected_by_check}
    problems: list[str] = []
    for row in LEDGER:
        if row.family in live[row.origin]:
            continue
        if detects[row.origin](row.sample):
            problems.append(
                f"A4 PHANTOM row: {row.origin} has no entry named {row.family!r}, but its sample is still "
                "detected by that catalogue -- the entry was REDUNDANT. Delete this row; no coverage was lost."
            )
        else:
            problems.append(
                f"A4 PHANTOM row: {row.origin} has no entry named {row.family!r} and no longer detects its "
                "sample at all -- this family lost its last detector in that catalogue."
            )
    return problems


def parity_failures() -> list[str]:
    """Every ledger failure, for callers that want one verdict.

    Kept as a plain function reading the LIVE catalogues on every call so a
    mutation harness can delete an entry and ask this the same question the
    test suite asks.
    """
    return sample_failures() + disposition_failures() + orphan_failures() + phantom_failures()


def test_every_sample_is_an_instance_of_the_entry_it_is_filed_under() -> None:
    assert sample_failures() == []


def test_every_pinned_disposition_still_holds() -> None:
    assert disposition_failures() == []


def test_no_catalogue_entry_is_missing_from_the_ledger() -> None:
    assert orphan_failures() == []


def test_no_ledger_row_names_a_dead_entry() -> None:
    assert phantom_failures() == []


def test_the_ledger_is_green_as_the_two_lists_stand_today() -> None:
    """M0. The lists DIFFER -- 24 secret_scan-only shapes and 7 check-only ones
    -- and the ledger passes anyway. It refuses change, not difference."""
    assert parity_failures() == []
    assert sum(1 for row in LEDGER if row.secret_scan and not row.check) == 24
    assert sum(1 for row in LEDGER if row.check and not row.secret_scan) == 7


def test_the_ledger_covers_both_catalogues_exactly() -> None:
    assert len(LEDGER) == len(secret_scan.SECRET_PATTERN_DEFS) + len(check.LEAK_PATTERNS)
    assert len({(row.origin, row.family) for row in LEDGER}) == len(LEDGER)


@pytest.mark.parametrize(
    ("origin", "family"),
    [(row.origin, row.family) for row in LEDGER],
)
def test_each_entrys_own_pattern_fires_on_its_own_sample(origin: str, family: str) -> None:
    """Stronger than A0's regex self-match: the entry must survive the whole
    scanning path -- placeholder rules, the entropy floor, the identifier-value
    rule -- and still be the one that names the finding."""
    row = next(r for r in LEDGER if r.origin == origin and r.family == family)
    if origin == "secret_scan":
        fired = {f["pattern_name"] for f in secret_scan.scan_text("<ledger>", row.sample)}
    else:
        fired = {label for _, label in check._leak_pattern_hits(row.sample)}
    assert family in fired, f"{origin} {family!r} did not fire on its own sample; fired: {sorted(fired)}"
