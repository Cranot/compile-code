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
ARTIFACT_SEGMENTS = (".venv", "node_modules", "dist", "build", "__pycache__")

# Claims retired by the 2026-07-14 public-claims audit. A match fails unless
# an allow-marker shares its line(s) — i.e. the claim is quoted as corrected
# history ("an earlier ... wording", a parity caveat), not asserted as truth.
RETIRED_CLAIMS = [
    (r"91%\s+of\s+envelopes", "retired 91% pre-executed claim (corrected: 57% L1 + ~33% facts)", ()),
    (r"10/10[\s\S]{0,40}?both\s+arms", "10/10 both-arms phrasing without the parity caveat", ("parity", "n=10")),
    (r"[−-]86%\s+turns", "retired -86% Opus turns claim (corrected: -33% overall)", ("corrected",)),
    (r"pip\s+install\s+compile-code(?![\w-])", "bare pip install compile-code (not on PyPI)", ("pypi", "uninstall")),
]


def _path_is_committed_artifact(rel: str) -> bool:
    """Return whether a tracked relative path belongs to a build artifact."""
    return any(segment in ARTIFACT_SEGMENTS or segment.endswith(".egg-info") for segment in rel.split("/"))


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


def artifact_scan() -> bool:
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.splitlines()
    hits = [rel for rel in tracked if _path_is_committed_artifact(rel)]
    print(f"[check] artifact scan: {'PASS' if not hits else 'FAIL'}")
    for rel in hits[:10]:
        print(f"  {rel}  [committed artifact]")
    return not hits


def _floor_drift(pyproject: str, docs: dict[str, str]) -> list[str]:
    """Every roam-code floor quoted in the docs must match the pyproject pin."""
    pin = re.search(r'"roam-code>=([\d.]+)"', pyproject)
    if not pin:
        return ["roam-code pin missing from pyproject.toml"]
    floor = pin.group(1)
    problems = []
    # The comment above the pin quotes the floor too — keep it honest.
    for quoted in re.findall(r"#\s*>=([\d.]+):", pyproject):
        if quoted != floor:
            problems.append(f"pyproject.toml comment says >={quoted} but the pin is >={floor}")
    for name, doc in docs.items():
        quotes = re.findall(r"roam-code[^\n]{0,60}?>=\s*([\d.]+)", doc)
        if not quotes:
            problems.append(f"{name}: no roam-code floor mention found to verify against the pin")
        problems += [f"{name} quotes roam-code >={q} but the pin is >={floor}" for q in quotes if q != floor]
    return problems


def _retired_claim_hits(name: str, doc: str) -> list[str]:
    """Unannotated reappearances of retired public claims in one doc."""
    hits = []
    for pattern, label, allow in RETIRED_CLAIMS:
        for m in re.finditer(pattern, doc, re.IGNORECASE):
            line_start = doc.rfind("\n", 0, m.start()) + 1
            line_end = doc.find("\n", m.end())
            segment = doc[line_start : line_end if line_end != -1 else len(doc)].lower()
            if any(marker in segment for marker in allow):
                continue
            problems_line = doc.count("\n", 0, m.start()) + 1
            hits.append(f"{name}:{problems_line}: {label}")
    return hits


def readme_sanity() -> bool:
    """The promises a reader acts on first must stay true."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    problems = []
    if "pip install git+https://github.com/Cranot/compile-code" not in text:
        problems.append("install command missing")
    if text.count("# compile-code") < 1:
        problems.append("title missing")
    docs = {"README.md": text, "AGENTS.md": agents}
    problems += _floor_drift(pyproject, docs)
    for name, doc in docs.items():
        problems += _retired_claim_hits(name, doc)
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
        artifact_scan(),
        readme_sanity(),
    ]
    if all(results):
        print("[check] all gates passed — safe to push.")
        return 0
    print("[check] BLOCKED — fix the failures above before pushing.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
