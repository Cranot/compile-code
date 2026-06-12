#!/usr/bin/env python3
"""Pre-push pipeline — every commit ships polished or not at all.

Mirrors roam-code's prepush_check discipline at this repo's scale:
lint, format, tests, a leak sweep, and README sanity. Wired via
``.githooks/pre-push`` (``git config core.hooksPath .githooks``);
run by hand any time: ``python3 scripts/check.py``.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Credential shapes + private-infrastructure strings that must never ship.
LEAK_PATTERNS = [
    (r"(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})", "GitHub token"),
    (r"sk-[A-Za-z0-9]{20,}", "API secret key"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "PEM private key"),
    (r"/root/(apps|services|repos)/", "VPS-local path"),
    (r"\binternal/planning/[A-Z]", "private memo reference"),
]


def run(title: str, cmd: list[str]) -> bool:
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    ok = proc.returncode == 0
    print(f"[check] {title}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        print((proc.stdout + proc.stderr).strip()[-2000:])
    return ok


def _scan_file_for_leaks(rel: str) -> list[str]:
    """All leak-pattern hits in one tracked file, formatted for display."""
    path = ROOT / rel
    if path.suffix in (".png", ".jpg", ".gif", ".ico"):
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    hits: list[str] = []
    for pattern, label in LEAK_PATTERNS:
        for m in re.finditer(pattern, text):
            line = text.count("\n", 0, m.start()) + 1
            hits.append(f"  {rel}:{line}  [{label}] {m.group(0)[:40]}")
    return hits


def leak_scan() -> bool:
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.splitlines()
    hits = [hit for rel in tracked for hit in _scan_file_for_leaks(rel)]
    print(f"[check] leak scan: {'PASS' if not hits else 'FAIL'}")
    for h in hits[:10]:
        print(h)
    return not hits


def readme_sanity() -> bool:
    """The promises a reader acts on first must stay true."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    problems = []
    if "pip install git+https://github.com/Cranot/compile-code" not in text:
        problems.append("install command missing")
    if text.count("# compile-code") < 1:
        problems.append("title missing")
    print(f"[check] README sanity: {'PASS' if not problems else 'FAIL'}")
    for p in problems:
        print("  -", p)
    return not problems


def main() -> int:
    results = [
        run("ruff check", [sys.executable, "-m", "ruff", "check", "src", "tests", "scripts"]),
        run("ruff format --check", [sys.executable, "-m", "ruff", "format", "--check", "src", "tests", "scripts"]),
        run("pytest", [sys.executable, "-m", "pytest", "tests/", "-q"]),
        leak_scan(),
        readme_sanity(),
    ]
    if all(results):
        print("[check] all gates passed — safe to push.")
        return 0
    print("[check] BLOCKED — fix the failures above before pushing.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
