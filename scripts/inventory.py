"""Shared fail-closed inventory construction for repository gates.

An empty or partially enumerated collection is not evidence that its members
are clean.  The helpers here keep that distinction in one place so scanners
do not each grow a subtly different loop guard.
"""

from __future__ import annotations

import os
import stat
import subprocess
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Callable

MAX_GIT_INVENTORY_BYTES = 16 * 1024 * 1024


class InventoryError(RuntimeError):
    """The complete set to examine could not be established."""


def without_git_controls(environment: dict[str, str] | None = None) -> dict[str, str]:
    """Remove inherited Git repository/index redirection controls."""
    source = os.environ if environment is None else environment
    return {name: value for name, value in source.items() if not name.upper().startswith("GIT_")}


def git_candidate_files(
    root: Path,
    *,
    run_command: Callable[..., Any] = subprocess.run,
) -> list[str]:
    """Return tracked plus new, non-ignored files from this worktree.

    ``--cached`` preserves the committed/indexed tree surface. ``--others
    --exclude-standard`` adds files created after that index inventory, which
    is the stale-list case this helper exists to prevent.
    """
    try:
        proc = run_command(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=root,
            env=without_git_controls(),
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InventoryError(f"could not establish Git candidate inventory: {exc}") from exc
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip()[-1_000:]
        raise InventoryError(f"git ls-files failed ({proc.returncode}): {detail}")
    if len(proc.stdout) > MAX_GIT_INVENTORY_BYTES:
        raise InventoryError(f"Git candidate inventory exceeds {MAX_GIT_INVENTORY_BYTES} bytes")
    if proc.stdout and not proc.stdout.endswith(b"\0"):
        raise InventoryError("Git candidate inventory is truncated (missing NUL terminator)")
    candidates = [os.fsdecode(item) for item in proc.stdout.split(b"\0") if item]
    if not candidates:
        raise InventoryError(
            "git ls-files reported zero tracked files or new nonignored files; "
            "the scan would pass without reading anything"
        )
    if len(candidates) != len(set(candidates)):
        raise InventoryError("Git candidate inventory contains duplicate paths")
    return sorted(candidates)


def _directory_state(path: Path) -> tuple[int, int, int, int]:
    try:
        value = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise InventoryError(f"could not establish filesystem inventory at {path}: {exc}") from exc
    if not stat.S_ISDIR(value.st_mode):
        raise InventoryError(f"could not establish filesystem inventory: not a directory: {path}")
    return value.st_dev, value.st_ino, value.st_mtime_ns, value.st_ctime_ns


def filesystem_files(roots: Iterable[Path], *, suffixes: frozenset[str]) -> list[Path]:
    """Completely walk concrete roots and return matching regular files.

    A directory is staged before any of its entries enter the result. Any
    enumeration error, link-like entry, or directory mutation invalidates the
    whole inventory rather than admitting the prefix seen before the failure.
    """
    files: list[Path] = []
    root_list = list(roots)
    if not root_list:
        raise InventoryError("could not establish filesystem inventory: no roots supplied")
    pending = list(reversed(root_list))
    while pending:
        directory = pending.pop()
        before = _directory_state(directory)
        staged: list[Path] = []
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    staged.append(Path(entry.path))
        except OSError as exc:
            raise InventoryError(f"could not establish filesystem inventory at {directory}: {exc}") from exc
        after = _directory_state(directory)
        if after != before:
            raise InventoryError(f"could not establish filesystem inventory: directory changed: {directory}")
        child_directories: list[Path] = []
        for path in sorted(staged, key=lambda item: (os.path.normcase(os.fspath(item)), os.fspath(item))):
            try:
                value = path.lstat()
            except OSError as exc:
                raise InventoryError(f"could not establish filesystem inventory at {path}: {exc}") from exc
            if stat.S_ISLNK(value.st_mode):
                raise InventoryError(f"could not establish filesystem inventory: link-like path: {path}")
            if stat.S_ISDIR(value.st_mode):
                child_directories.append(path)
            elif stat.S_ISREG(value.st_mode) and path.suffix.lower() in suffixes:
                files.append(path)
        pending.extend(reversed(child_directories))
    return sorted(files, key=lambda item: (os.path.normcase(os.fspath(item)), os.fspath(item)))


def require_complete_inventory(expected: Iterable[str], observed: Iterable[str], *, label: str) -> None:
    """Reject a partial result whose producer omitted requested members."""
    expected_items = list(dict.fromkeys(expected))
    observed_items = set(observed)
    missing = [item for item in expected_items if item not in observed_items]
    if missing:
        raise InventoryError(
            f"{label} is incomplete: missing {len(missing)} of {len(expected_items)} requested commits"
        )
