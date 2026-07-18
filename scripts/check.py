#!/usr/bin/env python3
"""Pre-push pipeline — every commit ships polished or not at all.

Mirrors roam-code's prepush_check discipline at this repo's scale:
lint, format, workflow security, tests, leak/package sweeps, README truth,
and release-contract sanity. Wired via
``.githooks/pre-push`` (``git config core.hooksPath .githooks``);
run by hand any time: ``python3 scripts/check.py``.
"""

from __future__ import annotations

import importlib.util
import json
import os
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
    (r"\binternal/(planning|dogfood)/", "private internal reference"),
    (r"(?i)\b(transcripts?|session-exports?)/", "private transcript export reference"),
]
ARTIFACT_SEGMENTS = (".venv", "node_modules", "dist", "build", "__pycache__")

# Claims retired by the 2026-07-14 public-claims audit. A match fails unless
# an allow-marker shares its line(s) — i.e. the claim is quoted as corrected
# history ("an earlier ... wording", a parity caveat), not asserted as truth.
RETIRED_CLAIMS = [
    (r"91%\s+of\s+envelopes", "retired 91% pre-executed claim (corrected: 57% L1 + ~33% facts)", ()),
    (r"10/10[\s\S]{0,40}?both\s+arms", "10/10 both-arms phrasing without the parity caveat", ("parity", "n=10")),
    (r"[−-]86%\s+turns", "retired -86% Opus turns claim (corrected: -33% overall)", ("corrected",)),
    (r"pip\s+install\s+compile-code(?![\w-])", "unpinned bare pip install compile-code", ("pypi", "uninstall")),
]
RELEASE_LOCKS = (
    "release/tooling-requirements.lock",
    "release/build-requirements.lock",
    "release/smoke-requirements.lock",
)
RELEASE_REQUIREMENT = re.compile(r"(?m)^([a-z0-9][a-z0-9._-]*)==([^\s;\\]+).*$")
MAX_SCHEMA_BYTES = 1024 * 1024


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _strict_json_document(data: bytes, label: str) -> object:
    if len(data) > MAX_SCHEMA_BYTES:
        raise ValueError(f"{label} exceeds {MAX_SCHEMA_BYTES} bytes")
    return json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)


def _path_is_committed_artifact(rel: str) -> bool:
    """Return whether a tracked relative path belongs to a build artifact."""
    return any(segment in ARTIFACT_SEGMENTS or segment.endswith(".egg-info") for segment in rel.split("/"))


def run(title: str, cmd: list[str], *, env: dict[str, str] | None = None) -> bool:
    try:
        proc = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, timeout=1200)
    except FileNotFoundError:
        print(f"[check] {title}: FAIL")
        print(f"required executable not found: {cmd[0]}")
        return False
    except OSError as exc:
        print(f"[check] {title}: FAIL")
        print(f"could not launch {cmd[0]}: {exc}")
        return False
    except subprocess.TimeoutExpired:
        print(f"[check] {title}: FAIL")
        print(f"command exceeded the 1200s gate timeout: {' '.join(cmd)}")
        return False
    ok = proc.returncode == 0
    print(f"[check] {title}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        print((proc.stdout + proc.stderr).strip()[-2000:])
    return ok


def _source_test_environment() -> dict[str, str]:
    """Bind pytest to this checkout instead of any previously installed wheel."""
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            # Tests import the release helper through the repository's
            # ``scripts`` namespace, while the product package must resolve
            # from ``src`` ahead of any installed wheel.
            "PYTHONPATH": os.pathsep.join((str(ROOT / "src"), str(ROOT))),
            "PYTHONSAFEPATH": "1",
        }
    )
    return environment


def _scan_file_for_leaks(rel: str) -> list[str]:
    """All leak-pattern hits in one tracked file, formatted for display."""
    path = ROOT / rel
    if path.is_symlink():
        return [f"  {rel}  [tracked symlink] release source must be regular"]
    if path.suffix in (".png", ".jpg", ".gif", ".ico"):
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return [f"  {rel}  [unreadable tracked file] {exc}"]
    hits: list[str] = []
    for pattern, label in LEAK_PATTERNS:
        for m in re.finditer(pattern, text):
            line = text.count("\n", 0, m.start()) + 1
            hits.append(f"  {rel}:{line}  [{label}] {m.group(0)[:40]}")
    return hits


def _tracked_files() -> list[str]:
    """Return the exact NUL-delimited Git inventory or fail the gate closed."""
    try:
        proc = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"could not enumerate tracked files: {exc}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip()[-1_000:]
        raise RuntimeError(f"git ls-files failed ({proc.returncode}): {detail}")
    return [os.fsdecode(item) for item in proc.stdout.split(b"\0") if item]


def leak_scan() -> bool:
    try:
        tracked = _tracked_files()
    except RuntimeError as exc:
        print("[check] leak scan: FAIL")
        print(f"  {exc}")
        return False
    hits = [hit for rel in tracked for hit in _scan_file_for_leaks(rel)]
    print(f"[check] leak scan: {'PASS' if not hits else 'FAIL'}")
    for h in hits[:10]:
        print(h)
    return not hits


def artifact_scan() -> bool:
    try:
        tracked = _tracked_files()
    except RuntimeError as exc:
        print("[check] artifact scan: FAIL")
        print(f"  {exc}")
        return False
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
    if 'python -m pip install "compile-code @ git+https://github.com/Cranot/compile-code.git@v0.2.0"' not in text:
        problems.append("install command missing")
    if 'python -m pip install "compile-code==0.2.0"' not in text:
        problems.append("future owner-gated PyPI install command missing")
    if "`roam-code 13.10.0` is available on PyPI" not in text:
        problems.append("dependency publication gate missing")
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


def _load_release_module():
    """Load the release validator without making scripts a runtime package."""
    path = ROOT / "scripts" / "release_artifacts.py"
    spec = importlib.util.spec_from_file_location("compile_code_release_artifacts", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load scripts/release_artifacts.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _lock_problems(relative: str, text: str) -> list[str]:
    """Reject mutable, unhashed, URL-based, or script-capable lock entries."""
    problems = []
    lowered = text.lower()
    for forbidden in (
        "--config-settings",
        "--editable",
        "--extra-index-url",
        "--find-links",
        "--global-option",
        "--index-url",
        "--install-option",
        "--no-binary",
        "--trusted-host",
        " -e ",
        "git+",
    ):
        if forbidden in lowered:
            problems.append(f"{relative}: forbidden lock construct {forbidden.strip()}")
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if RELEASE_REQUIREMENT.match(line):
            continue
        if re.fullmatch(r"--hash=sha256:[0-9a-f]{64}(?:\s+\\)?", stripped):
            continue
        problems.append(f"{relative}:{line_number}: unexpected or unpinned requirement syntax")
    starts = list(RELEASE_REQUIREMENT.finditer(text))
    if not starts:
        problems.append(f"{relative}: no exact requirements found")
        return problems
    for index, match in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        block = text[match.start() : end]
        version = match.group(2)
        if not re.fullmatch(r"(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){1,3}", version):
            problems.append(f"{relative}: non-canonical exact version for {match.group(1)}: {version}")
        if "--hash=sha256:" not in block:
            problems.append(f"{relative}: {match.group(1)} has no SHA-256 hashes")
    return problems


def release_sanity() -> bool:
    """Static release contract: exact backend, closed schema/locks, hardened workflows."""
    problems = []
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    required_metadata = (
        'requires = ["setuptools==83.0.0", "wheel==0.47.0"]',
        'build-backend = "setuptools.build_meta"',
        'license = "Apache-2.0"',
        'license-files = ["LICENSE"]',
    )
    for fragment in required_metadata:
        if fragment not in pyproject:
            problems.append(f"pyproject.toml: missing release metadata {fragment}")
    if "License :: OSI Approved" in pyproject:
        problems.append("pyproject.toml: legacy license classifier conflicts with PEP 639")
    if re.search(r"(?m)^dynamic\s*=", pyproject):
        problems.append("pyproject.toml: dynamic metadata is forbidden at the release boundary")

    for relative in RELEASE_LOCKS:
        path = ROOT / relative
        if not path.is_file():
            problems.append(f"{relative}: lock missing")
            continue
        problems.extend(_lock_problems(relative, path.read_text(encoding="utf-8")))

    tooling_lock = (ROOT / "release" / "tooling-requirements.lock").read_text(encoding="utf-8")
    for exact_tool in (
        "build==1.5.0",
        "pip==26.1.2",
        "pytest==9.1.1",
        "pyyaml==6.0.3",
        "ruff==0.15.22",
        "setuptools==83.0.0",
        "twine==6.2.0",
        "wheel==0.47.0",
        "zizmor==1.27.0",
    ):
        if not re.search(rf"(?m)^{re.escape(exact_tool)}(?:\s|$)", tooling_lock):
            problems.append(f"tooling lock: required exact tool missing: {exact_tool}")

    schema_path = ROOT / "release" / "manifest.schema.json"
    try:
        schema = _strict_json_document(schema_path.read_bytes(), "manifest schema")
        if not isinstance(schema, dict):
            raise ValueError("manifest schema root must be an object")
        if schema.get("additionalProperties") is not False:
            problems.append("manifest schema: root object is not closed")
        item = schema["properties"]["files"]["items"]
        if item.get("additionalProperties") is not False:
            problems.append("manifest schema: file records are not closed")
        role_order = [item["properties"]["role"]["const"] for item in schema["properties"]["files"]["prefixItems"]]
        if role_order != ["wheel", "sdist", "sbom"]:
            problems.append("manifest schema: canonical role order is not encoded")
        sbom_maximum = item["allOf"][0]["then"]["properties"]["size"]["maximum"]
        if sbom_maximum != 8 * 1024 * 1024:
            problems.append("manifest schema: SBOM size limit differs from the validator")
    except (OSError, KeyError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        problems.append(f"manifest schema invalid: {exc}")

    try:
        release_module = _load_release_module()
        problems.extend(release_module.audit_repository(ROOT))
    except (ImportError, OSError, RuntimeError) as exc:
        problems.append(f"release validator failed to load: {exc}")

    release_workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    ci_workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    workflow_assertions = {
        "release.yml": (
            "install-smoke --bundle release-bundle --mode package-only",
            "install-smoke --bundle release-bundle --mode resolve",
            "verify --bundle release-bundle --dist pypi-dist --github-source",
            "pypi-state --bundle release-bundle --dist pypi-dist --github-source --github-output",
            "pypi-state --bundle release-bundle --dist pypi-dist --github-source --require-exact",
            "actions/attest-build-provenance@",
        ),
        "ci.yml": ("--no-compile --no-build-isolation --only-binary=:all: -e .",),
    }
    for workflow_name, fragments in workflow_assertions.items():
        workflow = release_workflow if workflow_name == "release.yml" else ci_workflow
        normalized_workflow = re.sub(r"\s+", " ", workflow)
        for fragment in fragments:
            if re.sub(r"\s+", " ", fragment) not in normalized_workflow:
                problems.append(f"{workflow_name}: missing install/release assertion {fragment}")

    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if "## 0.2.0 - 2026-07-18" not in changelog:
        problems.append("CHANGELOG.md: current release heading missing")
    print(f"[check] release sanity: {'PASS' if not problems else 'FAIL'}")
    for problem in problems:
        print("  -", problem)
    return not problems


def main() -> int:
    zizmor = Path(sys.executable).with_name("zizmor.exe" if sys.platform == "win32" else "zizmor")
    results = [
        run("ruff check", [sys.executable, "-m", "ruff", "check", "src", "tests", "scripts"]),
        run("ruff format --check", [sys.executable, "-m", "ruff", "format", "--check", "src", "tests", "scripts"]),
        run("zizmor --pedantic", [str(zizmor), "--pedantic", ".github/workflows"]),
        run("pytest", [sys.executable, "-m", "pytest", "tests/", "-q"], env=_source_test_environment()),
        leak_scan(),
        artifact_scan(),
        readme_sanity(),
        release_sanity(),
    ]
    if all(results):
        print("[check] all gates passed — safe to push.")
        return 0
    print("[check] BLOCKED — fix the failures above before pushing.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
