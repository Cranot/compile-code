from __future__ import annotations

import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PIN_SCRIPT = ROOT / "dev" / "pin_github_actions.sh"


def _run_check(root: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PIN_CHECK_ROOT"] = str(root)
    return subprocess.run(
        ["bash", str(PIN_SCRIPT), "--check"],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )


def test_check_reports_unpinned_references_without_editing(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("jobs:\n  check:\n    steps:\n      - uses: actions/checkout@v4\n", encoding="utf-8")

    result = _run_check(tmp_path)

    assert result.returncode != 0
    assert ".github/workflows/ci.yml:4: uses: actions/checkout@v4" in result.stdout
    assert workflow.read_text(encoding="utf-8").endswith("actions/checkout@v4\n")


def test_check_passes_for_full_sha_and_version_comment(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows" / "ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "jobs:\n  check:\n    steps:\n      - uses: actions/checkout@" + "a" * 40 + " # v4.0.0\n",
        encoding="utf-8",
    )

    result = _run_check(tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 uses references; 1 already pinned" in result.stdout


def test_ci_runs_the_blocking_action_pin_check() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "bash dev/pin_github_actions.sh --check" in workflow
