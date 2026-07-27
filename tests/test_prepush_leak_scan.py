"""scripts/prepush_leak_scan.py must actually block a push carrying a leak that
only exists in HISTORY, and must not block a clean one.

BLIND SPOT this closes: scripts/check.py's leak_scan() (and CI's
scripts/secret_scan.py) both scan the current TRACKED TREE. A secret
committed and then "fixed" by a later commit in the same push is invisible
to either -- the final tree is clean -- but the earlier commit's blob still
reaches the remote the moment the push completes, and purging history
afterwards does not un-publish it (it may already be cloned, cached, or
indexed). This is the exact shape that forced a history purge for a
customer-name leak elsewhere in this project's toolchain (roam-code / stoa's
ROADMAP 4.3); scripts/prepush_leak_scan.py closes the same gap here by
scanning the exact pushed commit range instead of the working tree.

Uses an ISOLATED temp git repo (not this repo's own history) so the test has
no dependency on compile-code's actual commits and is safe to run anywhere,
including CI's checkout.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PREPUSH_LEAK_SCAN = ROOT / "scripts" / "prepush_leak_scan.py"


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, f"git {' '.join(args)} failed: {proc.stderr}"
    return proc.stdout.strip()


def _commit(repo: Path, rel_path: str, content: str, message: str) -> str:
    path = repo / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    _git(repo, "add", rel_path)
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    d = tmp_path / "prepush_leak_scan_fixture_repo"
    d.mkdir()
    _git(d, "init", "-q")
    _git(d, "config", "user.email", "test@example.invalid")
    _git(d, "config", "user.name", "prepush-leak-scan-test")
    return d


def _run(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(PREPUSH_LEAK_SCAN), *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )


def test_leak_several_commits_back_is_caught_even_after_a_later_commit_removes_it(repo: Path) -> None:
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    leak_secret = "AKIA" + "Z" * 16  # synthetic, matches check.py's LEAK_PATTERNS AWS shape
    _commit(
        repo,
        "config.py",
        f'AWS_KEY = "{leak_secret}"\n',
        "add config (planted leak)",
    )
    _commit(repo, "config.py", "AWS_KEY = os.environ['AWS_KEY']\n", "rotate/remove the secret from the tree")
    _commit(repo, "notes.txt", "unrelated\n", "unrelated benign change")
    tip = _commit(repo, "notes2.txt", "more unrelated\n", "another unrelated benign change")

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 2, f"expected BLOCKED, got exit {result.returncode}:\n{result.stderr}"
    assert "AWS access key" in result.stderr
    # The leak commit itself is not the pushed tip -- confirm the report still
    # attributes the finding to that specific (non-HEAD) commit's short sha,
    # not just "somewhere in the range".
    assert "config.py" in result.stderr

    # The whole-tree gate this closes the gap for really does miss it: prove
    # the blind spot stays reproducible, not just historically true.
    tree_text = (repo / "config.py").read_text(encoding="utf-8")
    assert leak_secret not in tree_text


def test_clean_range_passes(repo: Path) -> None:
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    tip = _commit(
        repo,
        "notes.txt",
        "still nothing interesting: tokens and keys discussed only in prose\n",
        "clean follow-up commit",
    )

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 0, f"expected clean, got exit {result.returncode}:\n{result.stdout}\n{result.stderr}"
    assert "clean" in result.stdout


def test_new_branch_first_push_is_scanned_not_skipped(repo: Path) -> None:
    """The --pre-push-updates path with an all-zero remote oid (first push of
    a new ref) must still resolve and scan real commits, not treat 'no known
    remote state' as 'nothing to check'."""
    _commit(repo, "readme.txt", "benign\n", "benign base commit")
    leak_secret = "AKIA" + "Y" * 16
    tip = _commit(repo, "config.py", f'AWS_KEY = "{leak_secret}"\n', "add config (planted leak, first push)")

    updates_file = repo / "updates.txt"
    zero = "0" * 40
    updates_file.write_text(f"refs/heads/feature {tip} refs/heads/feature {zero}\n", encoding="utf-8")

    result = _run(repo, "--pre-push-updates", "updates.txt")

    assert result.returncode == 2, f"expected BLOCKED on first push, got exit {result.returncode}:\n{result.stderr}"
    assert "AWS access key" in result.stderr


def test_malformed_updates_file_fails_closed(repo: Path) -> None:
    _commit(repo, "readme.txt", "benign\n", "benign base commit")
    updates_file = repo / "updates.txt"
    updates_file.write_text("not a valid ref update line\n", encoding="utf-8")

    result = _run(repo, "--pre-push-updates", "updates.txt")

    assert result.returncode == 1, "a malformed update stream must block (exit 1), never silently pass"
    assert "malformed" in result.stderr.lower()


def test_deletion_update_scans_nothing_and_passes(repo: Path) -> None:
    """A branch-deletion push (local oid all-zero) publishes no new bytes."""
    tip = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    updates_file = repo / "updates.txt"
    zero = "0" * 40
    updates_file.write_text(f"refs/heads/feature {zero} refs/heads/feature {tip}\n", encoding="utf-8")

    result = _run(repo, "--pre-push-updates", "updates.txt")

    assert result.returncode == 0
    assert "0 commits" in result.stdout


def test_no_mode_and_no_upstream_fails_closed_instead_of_scanning_nothing(repo: Path) -> None:
    """Manual invocation with neither --range nor --pre-push-updates, and no
    configured upstream, must refuse to guess -- never silently pass."""
    _commit(repo, "readme.txt", "benign\n", "benign base commit")

    result = _run(repo)

    assert result.returncode == 1
    assert "no --range or --pre-push-updates" in result.stderr


def test_secret_scan_catalogue_is_also_applied_to_pushed_history(repo: Path) -> None:
    """The broader scripts/secret_scan.py catalogue (not just check.py's four
    LEAK_PATTERNS) must also see historical blob content, e.g. an Anthropic
    key shape that check.py's own AKIA/PEM/sk- patterns would not catch."""
    base = _commit(repo, "readme.txt", "benign\n", "benign base commit")
    anthropic_key = "sk-ant-oat01-" + "Aa9_-" * 12
    _commit(repo, "config.py", f'ANTHROPIC_KEY = "{anthropic_key}"\n', "add config (planted anthropic key)")
    tip = _commit(repo, "config.py", "ANTHROPIC_KEY = os.environ['ANTHROPIC_KEY']\n", "rotate the key out of the tree")

    result = _run(repo, "--range", f"{base}..{tip}")

    assert result.returncode == 2, f"expected BLOCKED, got exit {result.returncode}:\n{result.stderr}"
    assert "Anthropic OAuth Token" in result.stderr
