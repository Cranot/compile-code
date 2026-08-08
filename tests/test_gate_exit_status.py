"""Mechanical exit-status contracts for repository gate entry points."""

from __future__ import annotations

import ast
import os
import re
import subprocess
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
PYTHON_GATES = (
    "scripts/build_internal_index.py",
    "scripts/check.py",
    "scripts/prepush_leak_scan.py",
    "scripts/release_artifacts.py",
    "scripts/roam_pin_drift.py",
    "scripts/secret_scan.py",
)


def _has_system_exit_call(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
            if isinstance(node.exc.func, ast.Name) and node.exc.func.id == "SystemExit":
                return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "sys" and node.func.attr == "exit":
                return True
    return False


def test_python_gate_entry_points_raise_their_main_status() -> None:
    for relative in PYTHON_GATES:
        path = ROOT / relative
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        assert _has_system_exit_call(tree), f"{relative} has no explicit SystemExit/sys.exit boundary"


def test_shell_gate_pipelines_are_fail_closed() -> None:
    for path in sorted((ROOT / ".githooks").iterdir()):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        assert "set -e" in text, f"{path} does not enable fail-fast shell handling"
        if "|" in text:
            assert "pipefail" in text, f"{path} contains a pipeline without pipefail"
        assert "|| true" not in text, f"{path} explicitly discards a failure"


def test_workflow_shell_blocks_protect_pipelines_and_substitutions() -> None:
    for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in (document.get("jobs") or {}).values():
            for step in job.get("steps", []):
                command = step.get("run")
                if not isinstance(command, str):
                    continue
                has_status_sensitive_shell = any(token in command for token in ("|", "$(", "while ", " for "))
                if has_status_sensitive_shell:
                    assert "set -euo pipefail" in command, (
                        f"{path}: shell gate uses a pipeline, substitution, or loop without set -euo pipefail"
                    )


def test_workflow_python_gates_are_explicitly_inventoried() -> None:
    referenced: set[str] = set()
    for path in (ROOT / ".github" / "workflows").glob("*.yml"):
        text = path.read_text(encoding="utf-8")
        referenced.update(re.findall(r"\bpython\s+(?:\S+/)?scripts/([a-z0-9_]+\.py)\b", text))

    inventoried = {Path(relative).name for relative in PYTHON_GATES}
    assert referenced <= inventoried, (
        f"workflow gate scripts missing exit-status audit: {sorted(referenced - inventoried)}"
    )


def test_commit_msg_clean_matching_and_unreadable_controls(tmp_path: Path) -> None:
    hook = ROOT / ".githooks" / "commit-msg"
    clean = tmp_path / "clean.commit-message"
    clean.write_text("clean message\n", encoding="utf-8")

    clean_result = subprocess.run(["bash", str(hook), str(clean)], capture_output=True, text=True, check=False)
    assert clean_result.returncode == 0, clean_result.stderr

    matching_message = tmp_path / "matching.commit-message"
    matching_message.write_text("Co-Authored-By: planted\n", encoding="utf-8")
    matching = subprocess.run(
        ["bash", str(hook), str(matching_message)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert matching.returncode != 0, matching.stdout + matching.stderr

    missing = subprocess.run(
        ["bash", str(hook), str(ROOT / "tests" / "does-not-exist.commit-message")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert missing.returncode != 0, missing.stdout + missing.stderr


def test_pre_push_forwards_the_final_gate_status(tmp_path: Path) -> None:
    shim_dir = tmp_path / "bin"
    shim_dir.mkdir()
    python_shim = shim_dir / "python3"
    python_shim.write_text(
        '#!/bin/sh\ncase "$1" in\n  */prepush_leak_scan.py) exit 0 ;;\n  */check.py) exit 7 ;;\n  *) exit 8 ;;\nesac\n',
        encoding="utf-8",
    )
    python_shim.chmod(0o755)
    zero = "0" * 40
    updates = f"refs/heads/main {zero} refs/heads/main {zero}\n"
    result = subprocess.run(
        ["bash", str(ROOT / ".githooks" / "pre-push"), "origin", "example.invalid"],
        cwd=ROOT,
        env={"PATH": f"{shim_dir}:{os.environ['PATH']}"},
        input=updates,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 7, result.stdout + result.stderr
