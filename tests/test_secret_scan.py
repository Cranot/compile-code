"""The secret scanner must detect the credentials this repo's own users hold.

compile-code ships an AI dev tool, so Anthropic/OpenAI/xAI/Groq/HuggingFace/
Replicate keys are the credentials most likely to sit in a fixture, a pasted
log, or a ``.env`` -- and this repo had zero coverage for them until this
scan was added (only four narrow patterns lived in ``scripts/check.py``, and
its generic ``sk-`` pattern does not match key shapes with a hyphen right
after the prefix, which is exactly how Anthropic's and OpenAI's project keys
are shaped).

METHOD NOTE -- why one case PER PROVIDER FAMILY:
the first gate built against this defect (roam-code's) self-tested with a
planted GitHub token, passed, and was declared working, while a real
Anthropic OAuth token sailed straight through. A self-test that exercises a
pattern already known to be covered proves nothing about coverage. So every
family gets its own planted case, and benign text must stay clean so the
catalogue cannot "pass" by matching everything.

Planted secrets are synthetic and built via string concatenation, never as
one contiguous literal -- this scanner does not exempt ``tests/`` (mirroring
roam-code's own scripts/secret_scan.py, which has no test-path exemption
either), so a contiguous planted secret in this very file would trip the
gate it is testing. Real secrets do not arrive pre-split like this.
"""

from __future__ import annotations

import pytest

from scripts import secret_scan


def _detect(text: str) -> set[str]:
    return {f["pattern_name"] for f in secret_scan.scan_text("planted.txt", text)}


# (planted secret built from fragments, expected pattern name)
PROVIDER_FAMILY_CASES = [
    ("sk-ant-oat01-" + "Aa9_-" * 12, "Anthropic OAuth Token"),
    ("sk-ant-api03-" + "Bb8_-" * 12, "Anthropic API Key"),
    ("sk-proj-" + "Cc7" * 12, "OpenAI Project Key"),
    ("sk-" + "D" * 48, "OpenAI API Key"),
    ("xai-" + "E" * 24, "xAI API Key"),
    ("gsk_" + "F" * 24, "Groq API Key"),
    ("hf_" + "G" * 34, "HuggingFace Token"),
    ("r8_" + "H" * 37, "Replicate API Token"),
    ("AKIA" + "I" * 16, "AWS Access Key"),
    ("ghp_" + "J" * 36, "GitHub Personal Access Token (classic)"),
    ("glpat-" + "K" * 20, "GitLab Token"),
    ("sk_live_" + "L" * 24, "Stripe Secret Key"),
    ("AIza" + "M" * 35, "Google API Key"),
    ("npm_" + "N" * 36, "NPM Token"),
    ("-----BEGIN " + "RSA PRIVATE KEY-----", "Private Key"),
]


@pytest.mark.parametrize(("secret", "expected"), PROVIDER_FAMILY_CASES)
def test_provider_family_is_detected(secret: str, expected: str) -> None:
    """Each credential family is caught by its own named pattern."""
    hits = _detect(f"API_KEY = '{secret}'")  # f-string template, not a literal value  # secretsallow
    assert hits, f"{expected}: no pattern fired -- this credential would leak"
    assert expected in hits, f"{expected}: expected that pattern, got {sorted(hits)}"


BENIGN = [
    "lets refactor the parser and add a test",
    "why cant it just reuse the existing index instead of rebuilding",
    "the sk- prefix is discussed in our docs but this is not a key",
    "def add(a, b):\n    return a + b",
    "https://example.com/some/path?q=search",
    "API_KEY = 'placeholder'",
]


@pytest.mark.parametrize("text", BENIGN)
def test_benign_text_is_not_flagged(text: str) -> None:
    """Ordinary prose and placeholders must not fire -- otherwise the
    catalogue could 'pass' every detection test by matching everything."""
    assert not _detect(text), f"false positive on: {text!r}"


def test_catalogue_covers_the_major_ai_providers() -> None:
    """Guards the gap itself: a future edit that drops the whole AI-provider
    category should fail here even if every individual case above vanished."""
    names = {d["name"] for d in secret_scan.SECRET_PATTERN_DEFS}
    required = {
        "Anthropic OAuth Token",
        "Anthropic API Key",
        "OpenAI Project Key",
        "OpenAI API Key",
        "xAI API Key",
        "Groq API Key",
        "HuggingFace Token",
        "Replicate API Token",
    }
    missing = required - names
    assert not missing, f"AI-provider patterns missing from the catalogue: {sorted(missing)}"


def test_mask_secret_never_returns_the_full_value() -> None:
    secret = "sk-" + "Z" * 48
    masked = secret_scan.mask_secret(secret)
    assert secret not in masked
    assert masked != secret
    assert masked.startswith("sk-Z")


# --- name-vs-value discrimination -------------------------------------------
# These test cases can use plain contiguous literals (not string-concatenation
# tricks) because this file is on the scanner's own OWN_TEST_CORPUS_FILES
# allowlist -- see the module docstring's "NOTE ON TEST FIXTURES".


def test_screaming_snake_identifier_value_is_not_flagged() -> None:
    """A bare SCREAMING_SNAKE_CASE value is the NAME of a secret (an env var
    or GitHub Actions secret to read at runtime), not a credential value --
    real-world case: scripts/release_artifacts.py's RELEASE_GUARD_SECRET."""
    assert not _detect('RELEASE_GUARD_SECRET = "RELEASE_GUARD_READ_TOKEN"')


def test_screaming_snake_rule_does_not_swallow_a_real_looking_secret() -> None:
    """The identifier-value discrimination must be narrow: a value with
    mixed case and digits (i.e. actual entropy, not just an identifier
    shape) still has to fire Generic Secret Assignment."""
    hits = _detect('API_SECRET = "aB3xQ7zRt9LmZp2w"')
    assert "Generic Secret Assignment" in hits


def test_screaming_snake_rule_does_not_weaken_vendor_patterns() -> None:
    """AWS Access Key IDs are themselves canonically all-uppercase-and-
    digits -- the identifier-value discrimination is scoped to the generic
    assignment patterns only and must not exempt a vendor-shaped credential
    just because it happens to look like a constant name."""
    hits = _detect("AWS_KEY = 'AKIA" + "Q" * 16 + "'")
    assert "AWS Access Key" in hits


def test_unresolved_template_placeholder_value_is_not_flagged() -> None:
    """An un-interpolated f-string/format placeholder like '{secret}' is
    template syntax, not a literal value -- real-world case: this file's own
    f"API_KEY = '{secret}'" parametrized-test line, and prose (e.g. a commit
    message) that quotes it verbatim."""
    assert not _detect("API_KEY = '{secret}'")
    assert not _detect("API_KEY = '${secret}'")
    assert not _detect("API_KEY = '%(secret)s'")


# --- scanner-own-test-corpus path exemption ---------------------------------


def test_own_test_corpus_predicate_is_one_file_not_a_directory() -> None:
    """A path allowlist, not a directory rule: only this exact file is
    exempt, so the exemption cannot quietly grow into "tests/ is exempt"
    (which would reopen the coverage gap this scanner exists to close)."""
    assert secret_scan._is_own_test_corpus("tests/test_secret_scan.py")
    assert secret_scan._is_own_test_corpus("tests\\test_secret_scan.py")
    assert not secret_scan._is_own_test_corpus("tests/test_secret_scan_other.py")
    assert not secret_scan._is_own_test_corpus("tests/test_prepush_leak_scan.py")
    assert not secret_scan._is_own_test_corpus("scripts/secret_scan.py")
