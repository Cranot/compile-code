#!/usr/bin/env python3
"""Standalone secret scan over this repository's tracked files.

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

NOTE ON TEST FIXTURES: this scanner does not exempt ``tests/`` (mirroring
roam-code's ``scripts/secret_scan.py``, not its test-suppressing
``cmd_secrets.scan_project``) -- it scans every tracked file's content.
Planted test secrets must therefore be split across string-literal
concatenations so the raw source text never contains a contiguous match
(see tests/test_secret_scan.py); real secrets do not arrive pre-split.
"""

from __future__ import annotations

import math
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_ALLOWLIST_RE = re.compile(r"(?i)(?:#|//|;)\s*secretsallow\s*$")

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


def _is_explicit_placeholder(match: "re.Match[str]") -> bool:
    value = _placeholder_candidate(match).strip().strip("<>{}[]()'\"")
    lower = value.lower()
    if value in _EXACT_PLACEHOLDERS or lower in _EXACT_PLACEHOLDERS:
        return True
    if re.fullmatch(r"[xX]{6,}", value):
        return True
    return re.fullmatch(r"(?:your|insert|replace)[_-][a-z0-9_-]+", lower) is not None


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
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp",
        ".pdf", ".zip", ".tar", ".gz", ".whl", ".pyc", ".pyo",
        ".so", ".dylib", ".dll", ".exe", ".woff", ".woff2", ".ttf",
        ".eot", ".otf", ".lock",
    }
)


def _in_skip_dir(rel_path: str) -> bool:
    parts = rel_path.split("/")
    return any(p in _SKIP_DIRS or p.endswith(".egg-info") for p in parts[:-1])


def _tracked_files(root: Path) -> list[str]:
    proc = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=root,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip()
        raise SystemExit(f"could not enumerate tracked files (git exit {proc.returncode}): {detail}")
    return [part for part in proc.stdout.decode("utf-8", "replace").split("\0") if part]


def scan_repo(root: Path) -> list[dict]:
    findings: list[dict] = []
    for rel_path in _tracked_files(root):
        if _in_skip_dir(rel_path):
            continue
        suffix = Path(rel_path).suffix.lower()
        if suffix in _BINARY_EXTENSIONS:
            continue
        full = root / rel_path
        if not full.is_file() or full.is_symlink():
            continue
        try:
            text = full.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(scan_text(rel_path, text))
    findings.sort(key=lambda f: (f["file"], f["line"], f["pattern_name"]))
    return findings


def format_findings(findings: list[dict]) -> str:
    lines = [f"BLOCKED: {len(findings)} secret finding(s)"]
    for f in findings:
        lines.append(f"  {f['file']}:{f['line']} [{f['severity']}] {f['pattern_name']} {f['matched_text']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    findings = scan_repo(ROOT)
    if findings:
        print(format_findings(findings), file=sys.stderr)
        return 1
    print("secret scan: no findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
