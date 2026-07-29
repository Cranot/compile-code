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
the four narrow ``LEAK_PATTERNS`` entries in ``scripts/check.py`` (AWS,
generic ``sk-``, GitHub, PEM). That generic ``sk-`` pattern requires 20+
alphanumeric characters immediately after the prefix -- so it does not match
AI-provider keys that embed hyphens right after ``sk-`` (Anthropic's
``sk-ant-oat01-...``, OpenAI's ``sk-proj-...``): the hyphen breaks the
character class after 3-4 chars, well short of the 20-char floor. This repo
ships an AI dev tool, so those are exactly the credentials most likely to
turn up in a fixture, a pasted log, or a ``.env``.

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

The ONE narrow exception is ``tests/test_secret_scan.py`` itself
(``_OWN_TEST_CORPUS_FILES`` below): a secret scanner cannot be tested
without planting secret-shaped strings, so that file matching its own
patterns is a structural certainty, not a finding -- not a loophole a real
leak could hide behind, since it is one named path, not a directory rule.
Same idiom as roam-code's ``WHITELIST_FILES`` in
``scripts/internal_language_patterns.py``, which exempts that pattern
catalogue's own test file for the identical reason.
"""

from __future__ import annotations

import math
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

try:
    from scripts.inventory import InventoryError, git_candidate_files, without_git_controls
except ModuleNotFoundError:  # Direct ``python scripts/secret_scan.py`` execution.
    from inventory import InventoryError, git_candidate_files, without_git_controls

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

_ENTROPY_THRESHOLD = 4.5


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    freq = Counter(value)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _high_entropy_passes(pat: dict, match: "re.Match[str]") -> bool:
    if pat["name"] != "High Entropy String":
        return True
    value = match.group(1) if match.lastindex else match.group()
    return _shannon_entropy(value) >= _ENTROPY_THRESHOLD


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


def scan_text(rel_path: str, text: str) -> list[dict]:
    """Scan one file's text content, returning masked findings."""
    findings: list[dict] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if _line_is_allowlisted(line):
            continue
        for pat in _COMPILED_PATTERNS:
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

_SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "dist",
        "build",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".tox",
        ".roam",
        ".eggs",
    }
)

_BINARY_EXTENSIONS = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".ico",
        ".bmp",
        ".webp",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".whl",
        ".pyc",
        ".pyo",
        ".so",
        ".dylib",
        ".dll",
        ".exe",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",
        ".lock",
    }
)


def _in_skip_dir(rel_path: str) -> bool:
    parts = rel_path.split("/")
    return any(p in _SKIP_DIRS or p.endswith(".egg-info") for p in parts[:-1])


# The scanner's OWN test fixture corpus: a path allowlist, not a directory
# rule, so it can't quietly grow into "tests/ is exempt" (which would reopen
# the coverage gap this scanner exists to close). Precedent: roam-code's
# ``WHITELIST_FILES`` in scripts/internal_language_patterns.py exempts that
# pattern catalogue's own test file the same way, for the same reason --
# a scanner cannot be tested without secret-shaped strings, so its own test
# file matching its own patterns is a structural certainty, not a finding.
_OWN_TEST_CORPUS_FILES = frozenset({"tests/test_secret_scan.py"})


def _is_own_test_corpus(rel_path: str) -> bool:
    return rel_path.replace("\\", "/") in _OWN_TEST_CORPUS_FILES


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
    """A tracked file this scanner could not read is a finding, not a skip.

    ``scripts/check.py::_scan_file_for_leaks`` already reports tracked
    symlinks and unreadable tracked files instead of passing over them. A
    scanner that answers "clean" for content it never decoded is stating a
    result it did not compute.
    """
    return {
        "file": rel_path,
        "line": 1,
        "severity": "high",
        "pattern_name": "Unscannable Tracked File",
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


def _scan_repo(root: Path) -> tuple[list[dict], int, int]:
    findings: list[dict] = []
    candidates = _tracked_files(root)
    files_examined = 0
    for rel_path in candidates:
        if _in_skip_dir(rel_path) or _is_own_test_corpus(rel_path):
            continue
        suffix = Path(rel_path).suffix.lower()
        if suffix in _BINARY_EXTENSIONS:
            continue
        full = root / rel_path
        if full.is_symlink():
            findings.append(_unscannable_finding(rel_path, "tracked symlink"))
            continue
        if not full.exists():
            # Tracked but deleted from the worktree: there is genuinely no
            # content here to scan. That is a true "nothing", not an
            # uncomputed one, so it stays a skip.
            continue
        if not full.is_file():
            findings.append(_unscannable_finding(rel_path, "tracked path is not a regular file"))
            continue
        try:
            data = full.read_bytes()
        except OSError as exc:
            findings.append(_unscannable_finding(rel_path, f"unreadable tracked file: {exc.strerror or exc}"))
            continue
        files_examined += 1
        prior_view_findings: set[tuple[object, ...]] = set()
        for text in decode_views(data):
            view_findings = scan_text(rel_path, text)
            findings.extend(
                finding for finding in view_findings if _finding_identity(finding) not in prior_view_findings
            )
            # Preserve repeated matches within one view; suppress only a
            # finding already emitted from an earlier reading of these bytes.
            prior_view_findings.update(_finding_identity(finding) for finding in view_findings)
    findings.sort(key=lambda f: (f["file"], f["line"], f["pattern_name"]))
    return findings, len(candidates), files_examined


def scan_repo(root: Path) -> list[dict]:
    return _scan_repo(root)[0]


def format_findings(findings: list[dict]) -> str:
    lines = [f"BLOCKED: {len(findings)} secret finding(s)"]
    for f in findings:
        lines.append(f"  {f['file']}:{f['line']} [{f['severity']}] {f['pattern_name']} {f['matched_text']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    findings, candidate_count, files_examined = _scan_repo(ROOT)
    if findings:
        print(format_findings(findings), file=sys.stderr)
        return 1
    print(
        f"secret scan: PASS (established {candidate_count} candidate paths; "
        f"examined {files_examined} text files; 0 findings)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
