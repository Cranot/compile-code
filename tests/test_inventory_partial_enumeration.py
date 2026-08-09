"""A directory git could not open must refuse the inventory, not shrink it.

``git_candidate_files`` runs ``git ls-files --cached --others --exclude-standard``.
``--others`` walks the worktree; meeting a directory it cannot open, git prints
a warning, omits that entire subtree, and **exits 0**.  The old code decoded
stderr only inside the ``returncode != 0`` branch, so a pruned inventory was
byte-indistinguishable from a complete one.

Every one of the four checks that followed catches a mangled RESULT -- a
size ceiling, a missing NUL terminator, an empty list, duplicate paths -- and a
pruned subtree produces a perfectly well-formed result.  So the "partially
enumerated" half of this module's own rule was the half nothing enforced on
the git path, while ``filesystem_files`` had always refused on ``OSError``.

Measured on git 2.43.0 with an unreadable directory holding an untracked
AWS-shaped key::

    $ git ls-files --cached --others --exclude-standard
    visible/a.py
    RC=0
    stderr: warning: could not open directory 'hidden/': Permission denied

    # control, the identical repo with that directory readable
    hidden/leak.py
    visible/a.py
    RC=0
    stderr: (empty)

Same exit code, same well-formed output; the credential's presence in the
inventory turned entirely on a stream nobody read.  One helper feeds
``check.leak_scan``, ``check.artifact_scan`` and ``secret_scan``, so all three
reported PASS over a tree none of them had fully enumerated.

TWO ARMS ON PURPOSE
-------------------
The contract tests drive ``run_command`` with a stub, so they pin the rule on
every host including a CI container running as root.  The end-to-end test uses
real git and a real unreadable directory, and SKIPS where that cannot be set up
(root ignores mode 000).  Without the stubbed arm this file would quietly test
nothing in exactly the environment the gate runs in -- which is the same defect
class it exists to close.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from inventory import InventoryError, git_candidate_files  # noqa: E402

#: Vendor-shaped but synthetic: assembled at runtime so this file never ships
#: a literal the repository's own scanners would flag.
AWS_KEY_LINE = 'AWS_KEY = "' + "AK" + "IA" + "3KJ7QWZX" + "CVBNMLKJ" + '"\n'


class _Proc:
    def __init__(self, returncode: int, stdout: bytes, stderr: bytes) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _stub(returncode: int, stdout: bytes, stderr: bytes):
    def run_command(*_args, **_kwargs):
        return _Proc(returncode, stdout, stderr)

    return run_command


# ---------------------------------------------------------------------------
# The contract, pinned without git
# ---------------------------------------------------------------------------


def test_a_warning_on_a_successful_exit_refuses_the_inventory(tmp_path: Path) -> None:
    """The defect itself: rc 0, well-formed output, and a subtree missing."""
    with pytest.raises(InventoryError) as caught:
        git_candidate_files(
            tmp_path,
            run_command=_stub(
                0,
                b"visible/a.py\0",
                b"warning: could not open directory 'hidden/': Permission denied\n",
            ),
        )

    message = str(caught.value)
    assert "could not fully enumerate" in message, message
    assert "hidden/" in message, (
        f"the refusal must name what git could not read, or the operator cannot act on it: {message}"
    )


def test_a_quiet_successful_enumeration_is_accepted(tmp_path: Path) -> None:
    """The must-not-fire control.

    A gate that refused every push would be discovered by being switched off,
    which is worse than the blind spot it replaced.
    """
    assert git_candidate_files(tmp_path, run_command=_stub(0, b"b.py\0a.py\0", b"")) == ["a.py", "b.py"]


def test_the_refusal_does_not_depend_on_gits_language(tmp_path: Path) -> None:
    """Any stderr counts, because the warning text is localized.

    Binding the check to the English string would fail OPEN under LANG -- an
    unreadable message must not become an unread directory.
    """
    with pytest.raises(InventoryError):
        git_candidate_files(
            tmp_path,
            run_command=_stub(0, b"visible/a.py\0", "avertissement : échec\n".encode()),
        )


def test_a_hard_failure_still_reports_its_own_cause(tmp_path: Path) -> None:
    """The pre-existing rc != 0 path must keep its distinct message.

    Both branches now read the same decoded stderr; this pins that the refusal
    a reader sees still says which of the two happened.
    """
    with pytest.raises(InventoryError) as caught:
        git_candidate_files(tmp_path, run_command=_stub(128, b"", b"fatal: not a git repository\n"))

    message = str(caught.value)
    assert "git ls-files failed (128)" in message, message
    assert "could not fully enumerate" not in message, message


# ---------------------------------------------------------------------------
# End to end, against real git
# ---------------------------------------------------------------------------


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )


def test_real_git_over_an_unreadable_directory_refuses(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("POSIX mode bits; the Windows doors are measured in roam-code")
    if os.geteuid() == 0:
        pytest.skip("root ignores mode 000, so the directory would be readable anyway")

    repo = tmp_path / "repo"
    (repo / "visible").mkdir(parents=True)
    _git(repo, "init", "-q", ".")
    _git(repo, "config", "user.email", "fixture@example.invalid")
    _git(repo, "config", "user.name", "fixture")
    (repo / "visible" / "a.py").write_text("x = 1\n", encoding="utf-8")

    hidden = repo / "hidden"
    hidden.mkdir()
    (hidden / "leak.py").write_text(AWS_KEY_LINE, encoding="utf-8")
    hidden.chmod(0o000)
    try:
        # The premise, measured rather than assumed: git must actually warn and
        # actually omit the path.  If it enumerated the directory regardless,
        # every assertion below would hold over a tree git read perfectly well.
        probe = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=repo,
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
        )
        if probe.returncode != 0 or "could not open directory" not in probe.stderr:
            pytest.skip(f"git enumerated it anyway: rc={probe.returncode} {probe.stderr!r}")
        assert "hidden/leak.py" not in probe.stdout

        with pytest.raises(InventoryError, match="could not fully enumerate"):
            git_candidate_files(repo, run_command=subprocess.run)
    finally:
        hidden.chmod(0o700)


def test_real_git_over_an_ordinary_worktree_is_accepted(tmp_path: Path) -> None:
    """The end-to-end must-not-fire control, with nothing stubbed."""
    repo = tmp_path / "repo"
    (repo / "visible").mkdir(parents=True)
    _git(repo, "init", "-q", ".")
    _git(repo, "config", "user.email", "fixture@example.invalid")
    _git(repo, "config", "user.name", "fixture")
    (repo / "visible" / "a.py").write_text("x = 1\n", encoding="utf-8")

    assert git_candidate_files(repo, run_command=subprocess.run) == ["visible/a.py"]
