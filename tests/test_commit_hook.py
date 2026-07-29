from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / ".githooks" / "commit-msg"


def _run(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["bash", str(HOOK), str(path)], capture_output=True, text=True, check=False)


def test_missing_message_inventory_fails_closed(tmp_path: Path) -> None:
    result = _run(tmp_path / "missing-message")

    assert result.returncode == 1
    assert "could not establish the message-file inventory" in result.stderr


def test_clean_message_examines_one_file_and_passes(tmp_path: Path) -> None:
    message = tmp_path / "message"
    message.write_text("Explain the inventory invariant\n", encoding="utf-8")

    result = _run(message)

    assert result.returncode == 0
    assert "PASS (examined 1 message file; 0 findings)" in result.stdout


def test_attribution_finding_still_blocks(tmp_path: Path) -> None:
    message = tmp_path / "message"
    message.write_text("Subject\n\nCo-Authored-By: Example <example@example.invalid>\n", encoding="utf-8")

    result = _run(message)

    assert result.returncode == 1
    assert "does NOT accept Co-Authored-By" in result.stderr
