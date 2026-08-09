"""Shared fail-closed inventory construction for repository gates.

An empty or partially enumerated collection is not evidence that its members
are clean.  The helpers here keep that distinction in one place so scanners
do not each grow a subtly different loop guard.

The same rule governs an individual member: a scanner may only decline to read
content on evidence from the CONTENT.  ``is_binary_content`` is that evidence,
kept here so all three gates share one answer -- see its docstring for the
false clean that name-based skipping produced.
"""

from __future__ import annotations

import os
import stat
import subprocess
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Callable

MAX_GIT_INVENTORY_BYTES = 16 * 1024 * 1024

# Everything a text file may legitimately contain outside the printable set.
_TEXT_CONTROL_CHARS = frozenset("\t\n\r\f\v")

# The directories this repository refuses to track -- and therefore the ONLY
# directories a scanner here may leave unread.
#
# ONE list, in one place, deliberately: ``check.ARTIFACT_SEGMENTS`` refuses
# exactly these and ``secret_scan._SKIP_DIRS`` declines to open exactly these,
# so "this scanner never opened the path" and "this repository cannot track the
# path" are the same statement instead of two lists that drift apart.
#
# They HAD drifted, and the drift was a live false clean. Measured at 4f3e203:
# ``secret_scan._SKIP_DIRS`` held 13 names against ``ARTIFACT_SEGMENTS``'s 5,
# and for 7 of the 8 extras (``.eggs``, ``.mypy_cache``, ``.pytest_cache``,
# ``.roam``, ``.ruff_cache``, ``.tox``, ``venv``) NOTHING read the content and
# NOTHING refused the path. A tracked ``venv/pip.conf`` carrying an
# ``sk-ant-oat01-`` token passed all four gates -- ``secret_scan`` PASS exit 0,
# ``check.leak_scan`` PASS, ``check.artifact_scan`` PASS, ``prepush_leak_scan``
# clean exit 0 -- with the token in the CURRENT TRACKED TREE, not in history.
# Commit 4f3e203 asserted the residual was "already fatal at the tree gate
# (artifact_scan), so the exposure is history-only"; that holds for 5 of the 13
# names and is false for the other 7, which is why this list now exists.
#
# ``venv`` is deliberately NOT here. It is the one skipped name that can
# legitimately BE tracked source -- CPython ships ``Lib/venv/__init__.py`` --
# so it cannot be refused, and under this rule that means it cannot be left
# unread either. It is scanned; ``.gitignore`` keeps a local virtualenv out of
# the candidate inventory instead.
#
# ``.git`` is deliberately NOT here either. Measured: ``git add .git/probe.txt``
# exits 0 and stages nothing, ``git ls-files --error-unmatch`` then fails, and
# ``git ls-files --cached --others`` never emits a path under ``.git`` -- so
# skipping it was dead weight. An exception carved into this list is exactly
# how the drift above began, so there are none.
UNTRACKABLE_DIRECTORY_SEGMENTS = (
    ".eggs",
    ".mypy_cache",
    ".pytest_cache",
    ".roam",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
)


def is_untrackable_directory_segment(segment: str) -> bool:
    """Whether one path component names a directory this repository refuses.

    Callers decide WHICH components to test -- ``check`` tests every one, and
    ``secret_scan`` exempts the final component so a tracked file merely NAMED
    ``build`` is still opened -- but they must not each keep their own name
    list. That is the drift this function exists to make impossible.
    """
    return segment in UNTRACKABLE_DIRECTORY_SEGMENTS or segment.endswith(".egg-info")


class InventoryError(RuntimeError):
    """The complete set to examine could not be established."""


def is_utf16_text(data: bytes) -> bool:
    """True iff NUL-bearing *data* is UTF-16 text rather than binary.

    A byte-order mark settles it. Without one, the bytes are accepted as text
    only when removing the NUL padding leaves strictly-valid UTF-8 carrying no
    control characters a text file would not -- which a PNG, a zip or an object
    file will not satisfy, so the binary skip is preserved.
    """
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return True
    try:
        text = data.replace(b"\x00", b"").decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    return not any(ch < " " and ch not in _TEXT_CONTROL_CHARS for ch in text)


def is_binary_content(data: bytes) -> bool:
    """True iff *data* is binary, i.e. content a pattern catalogue cannot read.

    THE ONLY admissible reason for a scanner to leave content unread. Each of
    this repository's three scanners used to decide that question from the
    PATH instead -- a suffix list (``.png``, ``.lock``, ...) in
    ``secret_scan``/``prepush_leak_scan``, a shorter one in ``check`` -- and a
    file name is not a measurement of the bytes behind it. Measured on the
    shipped scanners before this moved here: a plain-text file named
    ``logo.png`` carrying an AWS access key produced

        prepush_leak_scan: clean (1 commit(s) scanned, 0 findings; blobs: 0
        scanned / 0 bytes, 0 binary-skipped, 1 path-filtered, 0 unanalyzable)

    with exit 0, and ``check.leak_scan`` printed PASS beside it. A PyPI upload
    token in ``release/tooling-requirements.lock`` -- a plain-text pip
    requirements file, and the natural home for an index credential -- passed
    all three gates for the same reason.

    Deciding from the content keeps the conservation rule the UTF-16 fix
    established (a gate buried in noise from every committed object file is a
    gate that gets bypassed) while making the skip an observation about these
    bytes rather than a guess from their name.
    """
    return b"\x00" in data and not is_utf16_text(data)


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
    complaint = proc.stderr.decode("utf-8", "replace").strip()[-1_000:]
    if proc.returncode != 0:
        raise InventoryError(f"git ls-files failed ({proc.returncode}): {complaint}")
    # ``--others`` walks the worktree.  Meeting a directory it cannot open,
    # git prints a warning, omits that entire subtree, and STILL EXITS 0 --
    # so a pruned inventory is byte-indistinguishable from a complete one
    # everywhere except on this stream.  Measured on git 2.43.0 with an
    # unreadable directory holding an untracked credential: rc 0, the file
    # absent from stdout, `warning: could not open directory` the only trace.
    #
    # This is the "partially enumerated" half of the rule in the module
    # docstring, and it was the only half nothing enforced on the git path --
    # the four checks below all catch a mangled RESULT, and a pruned subtree
    # produces a perfectly well-formed one.  ``filesystem_files`` has always
    # refused on OSError; this brings the git path to the same standard.
    #
    # Any stderr counts, deliberately: for a command whose successful output
    # IS the file list, git having something to say is itself the anomaly.
    # Matching the warning text would bind the gate to git's English locale
    # and fail open under LANG -- an unreadable message must not become an
    # unread directory.
    if complaint:
        raise InventoryError(
            "git ls-files could not fully enumerate the worktree, so this "
            "inventory is a lower bound and no scan over it can establish "
            f"a clean result: {complaint}"
        )
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
