#!/usr/bin/env python3
"""Standalone secret scan over tracked and new non-ignored repository files.

Ported from roam-code's two-part scanner (D:/Safe/Projects/roam-code,
2026-07-27):

  - the pattern catalogue: ``src/roam/commands/cmd_secrets.py``
    (``_SECRET_PATTERN_DEFS``)
  - the scanning mechanics: ``scripts/secret_scan.py`` (masking, explicit-
    placeholder exemption, ``# secretsallow`` line suppression)

This is a COPY, not a live import: compile-code's ``roam-code`` dependency
is resolved from a released PyPI version, which lags behind roam-code's own
main branch, and a CI secret gate must not depend on release timing to be
correct. The catalogue is data; keeping a local copy means this gate stays
correct even if the upstream package is temporarily behind.

WHY THIS EXISTS
---------------
Until this scan was added, compile-code's only credential-shaped checks were
four narrow ``LEAK_PATTERNS`` entries in ``scripts/check.py`` (AWS, generic
``sk-``, GitHub, PEM). That generic ``sk-`` pattern requires 20+ alphanumeric
characters immediately after the prefix -- so it did not match AI-provider
keys that embed hyphens right after ``sk-`` (Anthropic's ``sk-ant-oat01-...``,
OpenAI's ``sk-proj-...``): the hyphen breaks the character class after 3-4
chars, well short of the 20-char floor. This repo ships an AI dev tool, so
those are exactly the credentials most likely to turn up in a fixture, a
pasted log, or a ``.env``.

THAT COUNT IS HISTORY, NOT THE CURRENT STATE. ``check.LEAK_PATTERNS`` now
holds 9 entries and carries the hyphenated AI-key shape itself, because
``.githooks/pre-push`` runs ``check.py`` as its whole-tree arm and does not
run this script at all -- only CI does. The two catalogues stay separate on
purpose and the difference runs BOTH ways: ``check`` carries three
private-infrastructure shapes that no vendor catalogue has, plus a shorter
``sk-`` form this one does not accept. Neither list is a superset of the
other, so neither can replace the other; see the comment above
``LEAK_PATTERNS`` in ``scripts/check.py`` for which job each does.

METHOD NOTE -- why the self-test (tests/test_secret_scan.py) plants ONE CASE
PER PROVIDER FAMILY:
the first gate built against this defect (roam-code's) self-tested with a
planted GitHub token, passed, and was declared working, while a real
Anthropic OAuth token sailed through untouched. A self-test exercising a
pattern already known to be covered proves nothing about coverage.

NOTE ON TEST FIXTURES: this scanner does not exempt ``tests/`` wholesale
(mirroring roam-code's ``scripts/secret_scan.py``, not its test-suppressing
``cmd_secrets.scan_project``) -- it scans every candidate file's content.
Planted test secrets must therefore be split across string-literal
concatenations so the raw source text never contains a contiguous match
(see tests/test_secret_scan.py); real secrets do not arrive pre-split.

``tests/test_secret_scan.py`` is READ like every other candidate. What it
gets is not an exemption from the scan but a narrower CATALOGUE: the seven
``HEURISTIC_PATTERN_NAMES`` shapes are suppressed there
(``_HEURISTIC_EXEMPT_FILES`` below) and every vendor shape still runs. A
secret scanner cannot be tested without secret-shaped strings, and that fact
justifies suppressing the half of the catalogue whose match means "this looks
like a place credentials live" -- it does not justify suppressing the half
whose match means "this is an Anthropic key". Measured before that
distinction was drawn: the whole-file form covered 538 lines to serve 1, and
a contiguous live-format credential planted at that path passed every gate in
this repository, with 11 of 15 provider families uncovered inside it.

Exit codes: 0 = clean, and the verdict publishes the denominator that
produced it. 1 = finding(s). 3 = candidates were established but none of
their content was read, so "no findings" would be a verdict this scan did not
compute. 4 = the scanner's own positive control failed -- it is broken and its
verdict means nothing. 5 = the denominator did not reconcile: some candidate
path reached no disposition, so this scan cannot say what happened to it.
"""

from __future__ import annotations

import math
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import NamedTuple

try:
    from scripts.inventory import (
        UNTRACKABLE_DIRECTORY_SEGMENTS,
        InventoryError,
        git_candidate_files,
        is_binary_content,
        is_untrackable_directory_segment,
        without_git_controls,
    )
except ModuleNotFoundError:  # Direct ``python scripts/secret_scan.py`` execution.
    from inventory import (
        UNTRACKABLE_DIRECTORY_SEGMENTS,
        InventoryError,
        git_candidate_files,
        is_binary_content,
        is_untrackable_directory_segment,
        without_git_controls,
    )

ROOT = Path(__file__).resolve().parent.parent

_ALLOWLIST_RE = re.compile(r"(?i)(?:#|//|;)\s*secretsallow\s*$")


def decode_text(data: bytes) -> str:
    """Decode text by its UTF-32/UTF-16/UTF-8 byte-order mark, without guessing."""
    if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return data.decode("utf-32", errors="replace")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig", errors="replace")
    return data.decode("utf-8", errors="replace")


def decode_views(data: bytes) -> list[str]:
    """Return the BOM-directed decode plus a NUL-stripped view when needed."""
    primary = decode_text(data)
    if "\x00" not in primary:
        return [primary]
    return [primary, primary.replace("\x00", "")]


# ---------------------------------------------------------------------------
# Pattern catalogue -- ported verbatim from roam-code's
# src/roam/commands/cmd_secrets.py (_SECRET_PATTERN_DEFS), 2026-07-27.
# ---------------------------------------------------------------------------

SECRET_PATTERN_DEFS: list[dict[str, str]] = [
    # --- AI provider keys ---
    {"name": "Anthropic OAuth Token", "pattern": r"sk-ant-oat[0-9]{2}-[A-Za-z0-9_\-]{40,}", "severity": "high"},
    {"name": "Anthropic API Key", "pattern": r"sk-ant-(?:api)?[0-9]{2}-[A-Za-z0-9_\-]{40,}", "severity": "high"},
    {"name": "OpenAI Project Key", "pattern": r"sk-proj-[A-Za-z0-9_\-]{20,}", "severity": "high"},
    {
        "name": "OpenAI API Key",
        # Anchored on the historical 48-char form; the generic `sk-` prefix
        # alone is too weak and would collide with Stripe's sk_live_ and
        # hex DeepSeek keys.
        "pattern": r"sk-[A-Za-z0-9]{48}",
        "severity": "high",
    },
    {"name": "xAI API Key", "pattern": r"xai-[A-Za-z0-9]{20,}", "severity": "high"},
    {"name": "Groq API Key", "pattern": r"gsk_[A-Za-z0-9]{20,}", "severity": "high"},
    {"name": "HuggingFace Token", "pattern": r"hf_[A-Za-z0-9]{34,}", "severity": "high"},
    {"name": "Replicate API Token", "pattern": r"r8_[A-Za-z0-9]{37,}", "severity": "high"},
    # --- API keys ---
    {"name": "AWS Access Key", "pattern": r"AKIA[0-9A-Z]{16}", "severity": "high"},
    {
        "name": "AWS Secret Key",
        "pattern": r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}",
        "severity": "high",
    },
    {"name": "GitHub Token", "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,255}", "severity": "high"},
    {
        "name": "GitHub Personal Access Token (classic)",
        "pattern": r"ghp_[A-Za-z0-9]{36}",
        "severity": "high",
    },
    {
        # LOCAL ADDITION, not present in the ported upstream catalogue.
        # GitHub's fine-grained PATs are prefixed ``github_pat_``, which
        # matches NEITHER entry above: ``gh[pousr]_`` breaks at ``gi``, and
        # ``ghp_`` does not apply at all. Measured on a 67-character sample --
        # ``scripts/check.py`` matched it and this catalogue returned ``[]``,
        # on all 51 candidate files and on every historical blob, since
        # ``prepush_leak_scan`` runs both catalogues but only one of them knew
        # the shape. The bound mirrors check.py's entry rather than inventing
        # a second opinion about the format.
        "name": "GitHub Fine-Grained PAT",
        "pattern": r"github_pat_[A-Za-z0-9_]{36,}",
        "severity": "high",
    },
    {"name": "GitLab Token", "pattern": r"glpat-[A-Za-z0-9\-]{20,}", "severity": "high"},
    {
        "name": "Slack Bot Token",
        "pattern": r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
        "severity": "high",
    },
    {
        "name": "Slack Webhook",
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
        "severity": "medium",
    },
    {"name": "Stripe Secret Key", "pattern": r"sk_live_[0-9a-zA-Z]{24,}", "severity": "high"},
    {"name": "Stripe Publishable Key", "pattern": r"pk_live_[0-9a-zA-Z]{24,}", "severity": "low"},
    {"name": "Google API Key", "pattern": r"AIza[0-9A-Za-z\-_]{35}", "severity": "high"},
    {
        "name": "Google OAuth Secret",
        "pattern": r"(?i)client_secret.*['\"][A-Za-z0-9\-_]{24}['\"]",
        "severity": "high",
    },
    {
        "name": "Heroku API Key",
        "pattern": r"(?i)heroku.*['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]",
        "severity": "high",
    },
    {"name": "NPM Token", "pattern": r"npm_[A-Za-z0-9]{36}", "severity": "high"},
    {"name": "PyPI Token", "pattern": r"pypi-[A-Za-z0-9\-_]{100,}", "severity": "high"},
    {
        "name": "SendGrid API Key",
        "pattern": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
        "severity": "high",
    },
    {"name": "Twilio API Key", "pattern": r"SK[0-9a-fA-F]{32}", "severity": "medium"},
    {"name": "Mailgun API Key", "pattern": r"key-[0-9a-zA-Z]{32}", "severity": "high"},
    # --- Generic secrets ---
    {
        "name": "Private Key",
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": "high",
    },
    {
        "name": "Generic Password Assignment",
        "pattern": r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"][^\s'\"]{8,}['\"]",
        "severity": "medium",
    },
    {
        "name": "Generic Secret Assignment",
        "pattern": r"(?i)(?:secret|token|api_key|apikey|access_key)\s*[=:]\s*['\"][^\s'\"]{8,}['\"]",
        "severity": "medium",
    },
    {
        "name": "Generic Bearer Token",
        "pattern": r"(?i)bearer\s+(?!Token\b|token\b)[a-zA-Z0-9\-_.~+/]{20,}=*",
        "severity": "medium",
    },
    {
        "name": "JWT Token",
        "pattern": r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]+",
        "severity": "medium",
    },
    {
        "name": "Base64 Encoded Secret",
        "pattern": r"(?i)(?:secret|password|token).*base64.*[A-Za-z0-9+/]{40,}={0,2}",
        "severity": "low",
    },
    {
        "name": "Database Connection String",
        "pattern": r"(?i)(?:mysql|postgres|postgresql|mongodb|redis)://[^\s'\"]{10,}",
        "severity": "high",
    },
    # --- High entropy (post-filtered by Shannon entropy, see below) ---
    {
        "name": "High Entropy String",
        "pattern": r"(?i)(?:key|secret|token|password|api_key|apikey|access_key|auth)\s*[=:]\s*['\"]([A-Za-z0-9+/=\-_]{20,})['\"]",
        "severity": "low",
    },
]

_COMPILED_PATTERNS: list[dict] = [
    {"name": d["name"], "regex": re.compile(d["pattern"]), "severity": d["severity"]} for d in SECRET_PATTERN_DEFS
]

# A PER-STRING ENTROPY FLOOR ABOVE log2(n) CANNOT BE CLEARED BY ANY STRING OF
# LENGTH n. Shannon entropy of a length-n string is maximised when every
# character is distinct, and that maximum is exactly log2(n) -- so an absolute
# floor is a claim about a length as much as about randomness, and 4.5 bits is
# a claim that no value shorter than ``ceil(2**4.5) = 23`` characters can ever
# satisfy.
#
# The only pattern this floor gates is "High Entropy String" (see
# ``_high_entropy_passes``), whose capture group is ``{20,}``. Its three
# shortest matchable values -- 20, 21 and 22 characters, ceilings 4.3219,
# 4.3923 and 4.4594 -- were therefore UNSATISFIABLE by construction. Measured
# over 20000 uniformly random base64url values at each of those lengths: 0
# cleared, at all three. That is not a strict filter, it is a detector that
# cannot fire, and it read as protection. 22 characters is the canonical
# on-disk form of a 128-bit symmetric key (unpadded base64url of 16 bytes),
# and ``key = "..."`` / ``auth = "..."`` are shapes NO other entry in this
# catalogue and none of ``check.LEAK_PATTERNS`` covers -- for those two
# identifiers this pattern is the only detector there is, so the dead floor
# was a live false negative, not mere redundancy.
#
# The fix is not "lower the number": an absolute 3.5 admits 445 of the 648
# quoted opaque-charclass runs in this tree (measured), i.e. it would flag
# ordinary identifiers. The floor is instead capped at what the candidate's
# own length can physically produce, so it can never again be set above its
# own ceiling.
_ENTROPY_THRESHOLD = 4.5

# The fraction of the length ceiling log2(n) the floor may claim. 0.90 is
# measured, not chosen by taste, against the two populations that matter:
#
#   TRUE POSITIVES, 20000 uniformly random base64url values per length --
#   detection at n=20/21/22/23/24 goes 0.00%/0.00%/0.00%/1.09%/5.21% (shipped)
#   -> 83.77%/85.80%/80.59%/81.20%/83.94%. At n>=32 the cap reaches 4.5 and
#   the rule is byte-identical to the shipped one, so nothing about long
#   values changes.
#
#   BENIGN, every quoted ``[A-Za-z0-9+/=\-_]{20,}`` run in the tracked tree
#   (648 of them, whatever identifier precedes them) -- 2 clear this floor,
#   the same 2 the shipped floor clears, and both are deliberately random
#   32-character test fixtures. The highest ratio H/log2(n) reached by a
#   genuinely benign value here is 0.8900 (a 20-character HTTP header name),
#   so 0.90 sits above the whole benign population with 0.043 bits of margin
#   at n=20 and admits none of it. 0.85 admits 77 of the 648 and is refused
#   on that measurement.
#
# A BARE ``r * log2(n)`` normalisation without the ``min`` is a different and
# worse rule: past n≈64 the 67-symbol character class, not the length, is the
# binding constraint, so the floor would keep rising past anything a real
# credential produces and detection would COLLAPSE at long lengths. The cap
# only ever loosens; it never raises the floor above 4.5.
_ENTROPY_LENGTH_FRACTION = 0.90


def _entropy_floor(length: int) -> float:
    """The entropy floor applicable to a candidate value of *length* characters.

    Never above ``log2(length)``, which is the most entropy a string of that
    length can carry, so the floor is always satisfiable by some value the
    pattern can actually match.
    """
    if length < 2:
        return 0.0
    return min(_ENTROPY_THRESHOLD, _ENTROPY_LENGTH_FRACTION * math.log2(length))


# The entries whose findings the floor may suppress -- named as data, not
# spelled inline in ``_high_entropy_passes``, so a test can walk this set,
# derive each entry's minimum matchable capture length from its own regex, and
# refuse a floor that no value of that length could reach. Widening this set to
# a pattern with a shorter capture bound is exactly the edit that re-creates
# the dead gate, and it now has to survive that test.
_ENTROPY_GATED_PATTERNS = frozenset({"High Entropy String"})

# The catalogue splits in two, and the halves carry different evidence.
#
# A VENDOR entry matches a shape only one issuer produces: ``sk-ant-oat01-``,
# ``AKIA``, ``ghp_``, a PEM header. A match is a credential or a deliberate
# forgery of one -- there is no third reading.
#
# A HEURISTIC entry matches a CONTEXT that credentials often appear in --
# ``SECRET = "..."``, a bearer token, a base64 run, a high-entropy string. It
# is the half that a scanner's own fixtures trip by construction, and the half
# whose match is evidence of a shape rather than of an issuer.
#
# Named here rather than flagged in ``SECRET_PATTERN_DEFS`` because that list
# is a verbatim port and must stay diffable against its source. A test pins
# every name below to a real catalogue entry, so a rename cannot silently
# empty this set.
HEURISTIC_PATTERN_NAMES = frozenset(
    {
        "Generic Password Assignment",
        "Generic Secret Assignment",
        "Generic Bearer Token",
        "JWT Token",
        "Base64 Encoded Secret",
        "Database Connection String",
        "High Entropy String",
    }
)


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    freq = Counter(value)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _high_entropy_passes(pat: dict, match: "re.Match[str]") -> bool:
    """Whether *match* clears the entropy floor for its own value length.

    THE FLOOR GATES EXACTLY ONE ENTRY, and reading it as a filter over the
    catalogue is the misreading this early return invites: every vendor
    pattern short-circuits to True here, so an ``AKIA`` key -- 20 characters,
    ceiling 4.3219, which no AWS key can ever clear -- is detected 20000/20000
    because this function never looks at it. The comment above
    ``_ENTROPY_THRESHOLD`` is about "High Entropy String" and about nothing
    else.
    """
    if pat["name"] not in _ENTROPY_GATED_PATTERNS:
        return True
    value = match.group(1) if match.lastindex else match.group()
    return _shannon_entropy(value) >= _entropy_floor(len(value))


def mask_secret(matched_text: str) -> str:
    """Mask a matched secret value for safe display. Never shows the full secret."""
    if len(matched_text) <= 8:
        return matched_text[:4] + "..."
    if len(matched_text) >= 12:
        return matched_text[:4] + "..." + matched_text[-4:]
    return matched_text[:4] + "..."


# Exact placeholder values -- kept split so this file's own catalogue does not
# itself look like a credential to a scanner reading it as plain text. Same
# idiom as roam-code's scripts/secret_scan.py.
_EXACT_PLACEHOLDERS = frozenset(
    {
        "AKIA" + "IOSFODNN7EXAMPLE",
        "changeme",
        "dummy",
        "example",
        "fake",
        "fixme",
        "placeholder",
        "replace_me",
        "sample",
        "todo",
    }
)


def _placeholder_candidate(match: "re.Match[str]") -> str:
    if match.lastindex:
        return match.group(match.lastindex)
    matched = match.group()
    quoted = re.search(r"['\"]([^'\"]+)['\"]\s*$", matched)
    return quoted.group(1) if quoted else matched


# An un-interpolated f-string/``str.format``/shell-style placeholder token
# (``{name}``, ``${name}``, ``%(name)s``) is template SYNTAX, not data -- no
# vendor pattern above can ever legitimately match one (every vendor shape
# requires a fixed prefix or character set a bare placeholder can't produce),
# so this is safe to treat as a placeholder for every pattern, not just the
# generic ones. This is what makes ``f"API_KEY = '{secret}'"`` in
# tests/test_secret_scan.py -- and in prose that quotes that exact line, e.g.
# a commit message -- a template, not a literal value.
_TEMPLATE_PLACEHOLDER_RE = re.compile(
    r"\{[A-Za-z_][A-Za-z0-9_]*\}|\$\{[A-Za-z_][A-Za-z0-9_]*\}|%\([A-Za-z_][A-Za-z0-9_]*\)s"
)

# Patterns whose regex is keyed on a variable NAME ("secret", "token",
# "password", ...) followed by "= '<anything 8+ chars>'" -- i.e. patterns that
# say nothing about the VALUE's shape, unlike e.g. "AWS Access Key" where the
# match *is* the credential. Only these get the identifier-vs-value check
# below; vendor patterns must not, since some real credentials (AWS key IDs)
# are themselves canonically all-uppercase-and-digits.
_GENERIC_ASSIGNMENT_PATTERNS = frozenset({"Generic Secret Assignment", "Generic Password Assignment"})

# A bare SCREAMING_SNAKE_CASE token, e.g. RELEASE_GUARD_READ_TOKEN.
_SCREAMING_SNAKE_IDENTIFIER_RE = re.compile(r"[A-Z][A-Z0-9_]*")


def _is_explicit_placeholder(match: "re.Match[str]") -> bool:
    raw = _placeholder_candidate(match).strip()
    if _TEMPLATE_PLACEHOLDER_RE.fullmatch(raw):
        return True
    value = raw.strip("<>{}[]()'\"")
    lower = value.lower()
    if value in _EXACT_PLACEHOLDERS or lower in _EXACT_PLACEHOLDERS:
        return True
    if re.fullmatch(r"[xX]{6,}", value):
        return True
    return re.fullmatch(r"(?:your|insert|replace)[_-][a-z0-9_-]+", lower) is not None


def _assignment_value_is_credential_shaped(pat: dict, match: "re.Match[str]") -> bool:
    """Reject a "Generic *Assignment" hit whose quoted value is itself a bare
    SCREAMING_SNAKE_CASE identifier -- the NAME of an env var, GitHub secret,
    or constant being assigned (e.g. ``RELEASE_GUARD_SECRET = "RELEASE_GUARD_
    READ_TOKEN"``), not an opaque credential value. Real credentials have
    entropy and character-class diversity; an all-caps-underscore token has
    neither. Scoped to the generic assignment patterns only: some vendor
    patterns (AWS Access Key IDs) are themselves canonically all-uppercase
    and must not be exempted by this rule.
    """
    if pat["name"] not in _GENERIC_ASSIGNMENT_PATTERNS:
        return True
    value = _placeholder_candidate(match)
    return _SCREAMING_SNAKE_IDENTIFIER_RE.fullmatch(value) is None


def _line_is_allowlisted(line: str) -> bool:
    return _ALLOWLIST_RE.search(line) is not None


def scan_text(rel_path: str, text: str, *, skip_heuristics: bool = False) -> list[dict]:
    """Scan one file's text content, returning masked findings.

    ``skip_heuristics`` drops the seven ``HEURISTIC_PATTERN_NAMES`` entries and
    NOTHING else. It exists for one named path -- this scanner's own test
    corpus, see ``_HEURISTIC_EXEMPT_FILES`` -- which used to be skipped whole.
    Every vendor shape still runs there.
    """
    findings: list[dict] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if _line_is_allowlisted(line):
            continue
        for pat in _COMPILED_PATTERNS:
            if skip_heuristics and pat["name"] in HEURISTIC_PATTERN_NAMES:
                continue
            for match in pat["regex"].finditer(line):
                if _is_explicit_placeholder(match):
                    continue
                if not _high_entropy_passes(pat, match):
                    continue
                if not _assignment_value_is_credential_shaped(pat, match):
                    continue
                findings.append(
                    {
                        "file": rel_path,
                        "line": line_no,
                        "severity": pat["severity"],
                        "pattern_name": pat["name"],
                        "matched_text": mask_secret(match.group()),
                    }
                )
    return findings


# ---------------------------------------------------------------------------
# Repository scan
# ---------------------------------------------------------------------------

# NOT a list of its own. This is exactly ``check.ARTIFACT_SEGMENTS``, because
# the only defensible reason to leave a candidate path unread is that a gate in
# this repository refuses to track it at all: then "unread" and "cannot exist"
# coincide, and a directory this scanner never opens cannot hold a published
# credential.
#
# When these were two lists they drifted, and the drift was a live false clean:
# eight names were skipped here that ``artifact_scan`` did not refuse, so a
# tracked ``venv/pip.conf`` carrying an ``sk-ant-oat01-`` token passed all four
# gates with exit 0 while sitting in the current tracked tree. Note what does
# NOT fix that: widening the pattern catalogue. A directory that is never
# opened is invisible to every pattern, however good the pattern is.
#
# ``venv`` is no longer skipped at all -- it can be real tracked source
# (CPython's own ``Lib/venv/__init__.py``), so it is read like any other path,
# and ``.gitignore`` keeps a local virtualenv out of the candidate inventory.
_SKIP_DIRS = frozenset(UNTRACKABLE_DIRECTORY_SEGMENTS)

# There is deliberately no suffix list here any more. A file NAME is not a
# measurement of the bytes behind it: the list this replaced skipped a
# plain-text credential file named ``logo.png`` unread, and -- because
# ``.lock`` sat in it beside ``.exe`` and ``.dll`` -- left all four
# ``release/*.lock`` files (plain-text pip requirement files, the natural home
# for an ``--index-url`` credential) examined by no scanner at all. Binary is
# now decided from the content by ``inventory.is_binary_content``.


def _in_skip_dir(rel_path: str) -> bool:
    """Whether a DIRECTORY component of *rel_path* is one the repo refuses.

    ``parts[:-1]``: the final component is a file name, and a tracked file
    merely NAMED ``build`` is ordinary content that must be read.
    """
    return any(is_untrackable_directory_segment(p) for p in rel_path.split("/")[:-1])


# The scanner's OWN test fixture corpus. This file is READ and scanned like
# every other candidate; only the seven ``HEURISTIC_PATTERN_NAMES`` shapes are
# suppressed on it.
#
# It used to be skipped WHOLE, on the argument that a secret scanner cannot be
# tested without secret-shaped strings. That argument is sound and it justifies
# exactly this much. Measured on the shipped scanner, the blanket covered 538
# lines while 1 needed it -- and the cost of the other 537 was total: a
# CONTIGUOUS live-format credential planted at this path passed every gate in
# the repository, and 11 of 15 provider families had zero coverage inside it.
# The 4 that were still caught were caught only by ``check.py``'s narrow
# 8-pattern catalogue, which reads this path -- coincidence of overlap, not
# design.
#
# The remaining suppression is bounded by what a heuristic match MEANS: a
# fixture that trips ``Generic Secret Assignment`` is doing its job, whereas
# nothing legitimate here produces an ``sk-ant-oat01-`` or an ``AKIA``. It is
# also inert today -- the one fixture line that still trips a heuristic carries
# the per-line ``# secretsallow`` marker, pinned by a test, so this set has
# zero residents at the tip. It stays because a per-line marker cannot clean a
# blob already committed WITHOUT it, and the range scanner reads each commit's
# own text: dropping the set outright would refuse three blobs in the currently
# pending push over a test fixture, which is how a gate gets bypassed.
_HEURISTIC_EXEMPT_FILES = frozenset({"tests/test_secret_scan.py"})


def _is_heuristic_exempt(rel_path: str) -> bool:
    """Whether the HEURISTIC half of the catalogue is suppressed for this path.

    A path allowlist, not a directory rule, so it cannot quietly grow into
    "tests/ is exempt" -- and it no longer decides whether the file is read at
    all, only which half of the catalogue runs.
    """
    return rel_path.replace("\\", "/") in _HEURISTIC_EXEMPT_FILES


def _without_git_controls() -> dict[str, str]:
    """Copy the environment without Git's repository-redirection controls.

    Mirrors ``scripts/check.py::_without_git_controls`` deliberately: both
    gates enumerate the current candidate tree, and both must enumerate *this* tree.
    An ambient ``GIT_INDEX_FILE``/``GIT_DIR``/``GIT_WORK_TREE`` makes
    ``git ls-files`` answer about a different index and exit 0.
    """
    return without_git_controls()


def _tracked_files(root: Path) -> list[str]:
    try:
        return git_candidate_files(root, run_command=subprocess.run)
    except InventoryError as exc:
        raise SystemExit(f"could not establish candidate file inventory: {exc}") from exc


def _unscannable_finding(rel_path: str, reason: str) -> dict:
    """A candidate file this scanner could not read is a finding, not a skip.

    ``scripts/check.py::_scan_file_for_leaks`` already reports symlink and
    unreadable candidates instead of passing over them. A scanner that answers
    "clean" for content it never decoded is stating a result it did not
    compute.

    CANDIDATE, NOT "TRACKED". ``_tracked_files`` returns ``git ls-files
    --cached --others --exclude-standard``, so an untracked, non-ignored
    working-tree file is in this population. The name shipped as ``Unscannable
    Tracked File`` and the remedy shipped as ``git rm --cached``, which
    answers ``fatal: pathspec '<path>' did not match any files`` for every
    untracked path it was printed at -- a false statement about the file and
    an inoperable instruction to the operator, in the same line.
    """
    return {
        "file": rel_path,
        "line": 1,
        "severity": "high",
        "pattern_name": "Unscannable Candidate File",
        "matched_text": reason,
    }


def _finding_identity(finding: dict) -> tuple[object, ...]:
    return (
        finding["file"],
        finding["line"],
        finding["severity"],
        finding["pattern_name"],
        finding["matched_text"],
    )


class RepoScan(NamedTuple):
    """The findings AND the denominator that produced them.

    ``files_examined`` is what makes ``0 findings`` falsifiable: it is the
    count of candidates whose bytes were actually decoded and matched, as
    distinct from the count of paths considered.

    Every other disposition is counted too, and the counts must ADD UP to
    ``candidates`` -- see ``unaccounted``. Publishing only ``candidates`` and
    ``files_examined`` left a silent remainder: the shipped verdict read
    ``established 54 candidate paths; examined 51 text files`` over a tree
    holding a tracked credential, and the three missing paths were the whole
    defect, disclosed as nothing but a gap between two numbers. A path can no
    longer leave this scan without saying which bucket it left by.

    ``heuristics_suppressed`` is deliberately NOT one of those buckets and is
    not part of ``accounted``: those files were read and vendor-scanned, so
    they are already inside ``files_examined``. It rides in the verdict purely
    so a reader can see that a narrower catalogue ran on a named path. It used
    to be a ``corpus_exempt`` bucket -- a path removed from the denominator
    entirely -- which is what a whole-file exemption is.
    """

    findings: list[dict]
    candidates: int
    files_examined: int
    binary_skipped: int
    path_skipped: tuple[str, ...] = ()
    heuristics_suppressed: tuple[str, ...] = ()
    absent: int = 0
    unscannable: int = 0

    @property
    def accounted(self) -> int:
        return self.files_examined + self.binary_skipped + len(self.path_skipped) + self.absent + self.unscannable

    @property
    def unaccounted(self) -> int:
        """Candidates that reached no bucket -- always a bug in this loop."""
        return self.candidates - self.accounted


def _scan_repo(root: Path) -> RepoScan:
    findings: list[dict] = []
    candidates = _tracked_files(root)
    files_examined = 0
    binary_skipped = 0
    path_skipped: list[str] = []
    heuristics_suppressed: list[str] = []
    absent = 0
    unscannable = 0
    for rel_path in candidates:
        if _in_skip_dir(rel_path):
            # Counted and named, never merely absent. Safe only because
            # ``check.artifact_scan`` fails the build on exactly these paths
            # (one shared list, ``inventory.UNTRACKABLE_DIRECTORY_SEGMENTS``),
            # so an unread path here is a path that cannot be published.
            path_skipped.append(rel_path)
            continue
        full = root / rel_path
        if full.is_symlink():
            unscannable += 1
            findings.append(_unscannable_finding(rel_path, "symlink candidate"))
            continue
        if not full.exists():
            # Enumerated but absent from the worktree: there is genuinely no
            # content here to scan. That is a true "nothing", not an
            # uncomputed one, so it stays a skip.
            absent += 1
            continue
        if not full.is_file():
            unscannable += 1
            findings.append(_unscannable_finding(rel_path, "candidate path is not a regular file"))
            continue
        try:
            data = full.read_bytes()
        except OSError as exc:
            unscannable += 1
            findings.append(_unscannable_finding(rel_path, f"unreadable candidate file: {exc.strerror or exc}"))
            continue
        if is_binary_content(data):
            # FAIL CLOSED. Classifying bytes is not matching them: no pattern
            # in this catalogue ever ran over this file, so "0 findings" for it
            # is a verdict this scan did not compute. It stayed non-fatal on
            # the argument that the bytes WERE read -- and the only guard was
            # the range-global ``files_examined == 0`` floor below, which a
            # single readable companion file defeats. Measured over the real
            # 51-file tree: a NUL-prefixed blob carrying an ``sk-ant-oat01-``
            # token in an ``--index-url`` line printed PASS with exit 0, its
            # existence disclosed as nothing but ``1 binary-skipped``.
            #
            # Conservation is kept by the FINDING, not by the skip: the bytes
            # are still never pattern-matched, so this is one line naming a
            # path rather than catalogue noise from every committed image.
            #
            # COST, RE-MEASURED, AND IT IS NOT ZERO. The commit that added this
            # refusal recorded "measured cost: zero" over the TRACKED tree and
            # over history, which is the wrong population: this loop runs on
            # ``git ls-files --cached --others --exclude-standard``, so a stray
            # untracked, non-ignored binary anywhere in the worktree -- a build
            # artifact, a downloaded wheel, a scratch .db -- refuses this scan
            # and, through ``check.leak_scan``, every local push, until it is
            # deleted or gitignored. ``.gitignore`` here carries directory
            # names only, no suffix rules, so nothing catches those by default.
            # What IS zero, re-measured at this commit: 0 of 51 candidates are
            # binary, and 0 of the 480 distinct blobs reachable from every ref
            # (``git rev-list --objects --all``) are binary -- so nothing ever
            # committed here refuses, which is a narrower claim than the one
            # that shipped. The "424 commits" in that claim reproduces under no
            # counting rule; the repository had 426 commits reachable from HEAD
            # when it was written.
            binary_skipped += 1
            findings.append(
                _unscannable_finding(
                    rel_path,
                    "binary content: no pattern catalogue can read these bytes -- "
                    "git rm --cached it if it is tracked, delete it or add a .gitignore rule if it is not, "
                    "rather than admitting content no gate can inspect",
                )
            )
            continue
        files_examined += 1
        skip_heuristics = _is_heuristic_exempt(rel_path)
        if skip_heuristics:
            heuristics_suppressed.append(rel_path)
        prior_view_findings: set[tuple[object, ...]] = set()
        for text in decode_views(data):
            view_findings = scan_text(rel_path, text, skip_heuristics=skip_heuristics)
            findings.extend(
                finding for finding in view_findings if _finding_identity(finding) not in prior_view_findings
            )
            # Preserve repeated matches within one view; suppress only a
            # finding already emitted from an earlier reading of these bytes.
            prior_view_findings.update(_finding_identity(finding) for finding in view_findings)
    findings.sort(key=lambda f: (f["file"], f["line"], f["pattern_name"]))
    return RepoScan(
        findings,
        len(candidates),
        files_examined,
        binary_skipped,
        tuple(path_skipped),
        tuple(heuristics_suppressed),
        absent,
        unscannable,
    )


def scan_repo(root: Path) -> list[dict]:
    return _scan_repo(root).findings


def format_findings(findings: list[dict]) -> str:
    lines = [f"BLOCKED: {len(findings)} secret finding(s)"]
    for f in findings:
        lines.append(f"  {f['file']}:{f['line']} [{f['severity']}] {f['pattern_name']} {f['matched_text']}")
    return "\n".join(lines)


# --- positive control -------------------------------------------------------
# Same discipline ``scripts/prepush_leak_scan.py`` already carried, and for the
# same reason it was needed there: with ``_COMPILED_PATTERNS`` emptied, this
# scanner printed ``PASS (established 51 candidate paths; examined 46 text
# files; 0 findings)`` and returned 0 over the real repository. The control
# runs through ``decode_views``/``scan_text`` -- the exact path a candidate
# file's bytes take -- and is UTF-16 encoded so the decode fix is a live
# control, not only a test. Assembled by concatenation so this file's own
# source text carries no contiguous match.
_CONTROL_EXPECTED = ("AWS Access Key", "Anthropic OAuth Token")
_CONTROL_AWS = "AK" + "IA" + "T" * 16
_CONTROL_ANTHROPIC = "sk-" + "ant-" + "oat" + "01-" + "Bb8_-" * 12


def _control_bytes() -> bytes:
    return f'aws = "{_CONTROL_AWS}"\nkey = "{_CONTROL_ANTHROPIC}"\n'.encode("utf-16")


def _self_test_failures() -> list[str]:
    """Empty iff this scanner can still find a secret it planted itself.

    One planted case per provider FAMILY, never one overall: the first gate
    built against this defect self-tested with a GitHub token, passed, and let
    a real Anthropic OAuth token through untouched.
    """
    data = _control_bytes()
    if is_binary_content(data):
        return ["control content was classified binary; the text/binary rule is broken"]
    views = decode_views(data)
    if not views:
        return ["control content decoded to zero text views"]
    names = {finding["pattern_name"] for view in views for finding in scan_text("<control>", view)}
    return [f"planted control secret not detected: {name}" for name in _CONTROL_EXPECTED if name not in names]


def main(argv: list[str] | None = None) -> int:
    broken = _self_test_failures()
    if broken:
        print("BROKEN: secret_scan's own positive control failed:", file=sys.stderr)
        for problem in broken:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nThis scanner cannot find a secret it planted itself, so its\n"
            "'0 findings' would mean nothing. Fix the scanner; do not push.",
            file=sys.stderr,
        )
        return 4
    scan = _scan_repo(ROOT)
    if scan.findings:
        print(format_findings(scan.findings), file=sys.stderr)
        return 1
    if scan.unaccounted:
        print(
            f"REFUSED: {scan.unaccounted} of {scan.candidates} candidate path(s) reached no disposition -- "
            "this scan cannot say what happened to them.\n"
            f"  examined {scan.files_examined}, binary-skipped {scan.binary_skipped}, "
            f"path-skipped {len(scan.path_skipped)}, "
            f"absent {scan.absent}, unscannable {scan.unscannable}\n"
            "A path that leaves this scan silently is a path whose content nothing measured, which is\n"
            "the exact defect this denominator exists to make impossible. Fix _scan_repo; do not push.",
            file=sys.stderr,
        )
        return 5
    if scan.files_examined == 0:
        print(
            f"REFUSED: established {scan.candidates} candidate path(s) and read the content of none of them "
            f"({scan.binary_skipped} classified binary). 'No findings' would be a verdict this scan did not\n"
            "compute -- it is the same output a working scan of a clean tree prints.",
            file=sys.stderr,
        )
        return 3
    # The denominator CLOSES: every candidate is in exactly one bucket, and the
    # buckets are named. The line this replaced printed candidates and examined
    # only, so the paths it had skipped by directory name showed up as an
    # unexplained difference between two numbers -- and that difference was
    # where a tracked credential sat, reported by nobody.
    print(
        f"secret scan: PASS (established {scan.candidates} candidate paths; "
        f"examined {scan.files_examined} text files; {scan.binary_skipped} binary-skipped; "
        f"{len(scan.path_skipped)} path-skipped; "
        f"{scan.absent} absent; {scan.unscannable} unscannable; "
        f"{len(scan.heuristics_suppressed)} heuristics-suppressed; 0 findings)"
    )
    for rel_path in scan.path_skipped[:10]:
        print(f"  not opened (untrackable directory; check.artifact_scan fails the build on it): {rel_path}")
    if len(scan.path_skipped) > 10:
        print(f"  ... and {len(scan.path_skipped) - 10} more")
    for rel_path in scan.heuristics_suppressed:
        print(f"  read and vendor-scanned; heuristic shapes suppressed (this scanner's own test corpus): {rel_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
