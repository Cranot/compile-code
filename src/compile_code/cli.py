"""compile-code CLI — the product surface over the compile kernel.

Design contract (decision memo 2026-06-05): the daily UX is NOT raw
commands. A dev wires their existing agent once (`compile wire claude`)
or just launches it wrapped (`compile claude`); after that they use
their agent natively and the compile/verify loop runs invisibly.
Raw `compile run` stays for scripts, CI, and power users.

The kernel (task classifier, probe execution, envelope emission, scoped
verify) lives in the `roam-code` dependency — same relationship as a
compiler front-end over its toolchain libraries.

Hardening contract: every toolchain failure surfaces as a one-line
``VERDICT:`` with a copy-paste fix, never a Python traceback. Exit codes:
0 ok, 1 user-fixable state, 2 toolchain missing/broken, 124 timeout,
130 interrupted.
"""

from __future__ import annotations

import ast
import errno
import hashlib
import io
import json
import math
import os
import re
import secrets
import shlex
import signal
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from bisect import bisect_left
from collections import Counter, deque
from collections.abc import Callable, Container, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterator

import click

__all__ = ["cli"]

EXIT_TOOLCHAIN = 2
EXIT_TIMEOUT = 124
# roam verify quality-gate failure (see `roam exit-codes`); the one verify exit
# code the product surface acts on — checks ran and the score fell below threshold.
EXIT_VERIFY_GATE = 5
BASELINE_TIMEOUT = 1200
MIN_ROAM_VERSION = "13.10.0"
# There is deliberately NO runtime product-major ceiling on this line. One used
# to live here and it checked the wrong property. Roam's PRODUCT major says
# nothing about the contract this CLI consumes: measured against the real roam
# 14.0.0 binary, the verify envelope declared `schema_version` 1.2.0 — a MINOR
# bump ACROSS a product major bump — and added zero top-level keys. Roam's own
# contract said "compatible" while the ceiling said "refuse".
#
# Removing it is not a relaxation, because the ceiling never detected anything.
# Nine constructed drift mutations were run through the real verify path
# against a shim delegating to the real roam: seven were caught at exit 2 by
# the contract guards below (`failure_contradiction`, `success_contradiction`,
# `completion_binding`, `invalid_json_document`), and the ceiling caught none
# of them, because a version ceiling defers the whole question to a human
# typing a bigger number — and the deferral ends at exactly the moment the risk
# arrives, since the only way forward is to type it. What it did instead was
# cost a total outage: with the ceiling in place a roam one major up turned
# `compile verify` into exit 2 with no verification at all, while `compile
# report` drove that same binary to a PASS in the same tree.
#
# The guards that DO read the contract stay, and they are what carries this:
# `_envelope_schema_compatible` refuses a different ENVELOPE major,
# `_require_known_shape` refuses an unknown incompleteness-vocabulary key, and
# the receipt/scope/verdict cross-derivations re-derive every gate-determining
# value rather than trusting it. The two residual drifts nothing catches
# (`checks_run` re-defined, roam's DEFAULT threshold moving) are disclosure
# -level, not gate-level, and the ceiling would have deferred them exactly once
# before they became uncaught anyway.
#
# The one exclusive ceiling that remains is the PACKAGING pin in
# pyproject.toml. That is a resolver preference, never a runtime refusal;
# `scripts/check.py::_floor_drift` keeps it honest, and going stale there costs
# a dependency resolution, not a user outage.
ROAM_VERSION_REQUIREMENT = f">={MIN_ROAM_VERSION}"
ROAM_PACKAGE_REQUIREMENT = f"roam-code{ROAM_VERSION_REQUIREMENT}"
MAX_VERIFY_JSON_BYTES = 2 * 1024 * 1024
MAX_VERIFY_STDERR_BYTES = 64 * 1024
MAX_ROAM_VERSION_BYTES = 8 * 1024
MAX_ROAM_EXECUTABLE_BYTES = 64 * 1024 * 1024
# `claude` is a bundled single-file runtime (Node/Bun + embedded assets), not a
# small pip console-script stub like roam's -- a real install measured 272 MiB
# (284,981,920 bytes) on 2026-08-07, up from the ~265 MiB an earlier reading of
# this comment recorded. The observation is dated because it tracks someone
# else's release cadence and will keep moving; the ceiling below is sized with
# headroom rather than to the reading, so the drift costs nothing.
# Reusing MAX_ROAM_EXECUTABLE_BYTES here would make _content_digest
# refuse to hash it at all and turn every real launch into a false "content
# could not be verified" refusal. Sized with real headroom above the observed
# binary, not tightly to it.
MAX_CLAUDE_EXECUTABLE_BYTES = 512 * 1024 * 1024
MAX_VERIFY_GIT_STATUS_BYTES = 1024 * 1024
# Directories that carry tool state, dependencies or build output rather than
# source. Changed-file discovery runs `git status --untracked-files=all`, which
# names every FILE inside an untracked directory -- so a project that does not
# gitignore `.roam/` hands roam its own live SQLite index (index.db, -wal, -shm,
# index.lock, index.state) as changed work. That scope can never verify: the WAL
# moves while roam reads it, the run reports itself incomplete, and the refusal
# blames the roam version for a scope defect no upgrade can fix.
#
# The name alone is NOT the discriminator -- see _partition_non_source_scope.
# Discovery narrows only UNTRACKED paths under these names, because the argument
# above is about a live untracked index and reaches no path the project has
# committed. Bounded directory descent (_expand_verify_targets) has no status
# oracle and no budget for another git call, so it still prunes by NAME.
#
# The pruning applies ONLY to directories DISCOVERED during descent, never to
# the directory NAMED on the command line: `pending` is seeded from the named
# directories unfiltered, and the skip test below is reached only for children.
#
# RUN, not reasoned about. A real git repository with a tracked, changed
# src/venv/mod.py and a stub roam that logs the argv it is handed:
#
#   $ compile verify src
#     delegated -> ["--json", "verify", "--auto", "--", "src/app.py", "src/pkg/mod.py"]
#   $ compile verify src/venv
#     delegated -> ["--json", "verify", "--auto", "--", "src/venv/mod.py"]
#   $ compile verify src/venv/mod.py
#     delegated -> ["--json", "verify", "--auto", "--", "src/venv/mod.py"]
#   $ compile verify venv
#     delegated -> ["--json", "verify", "--auto", "--", "venv/__init__.py",
#                   "venv/mypkg/mod.py"]
#   $ compile verify              # discovery, no arguments
#     delegated -> ["--json", "verify", "--auto", "--", "node_modules/pkg/index.js",
#                   "src/app.py", "src/pkg/mod.py", "src/venv/mod.py",
#                   "venv/mypkg/mod.py"]
#
# So `compile verify src` silently omits tracked, changed source under a
# nested directory with one of these names; naming the subtree or the file
# reaches it; and discovery has no such residual at all, because it narrows on
# trackedness. A trailing slash is not a way to name a directory -- it never
# gets as far as descent, because _verification_scope_paths runs on the
# explicit argument FIRST:
#
#   $ compile verify venv/
#     VERDICT: verifier protocol failure: receipt field/reason
#              scope_path_not_canonical; scope target indices 0
#     EXIT=2, and roam is never handed a verify scope. It IS launched once
#     first: _verify calls _inspect_roam() -> `roam --version` before
#     _prepare_verify_request can raise, so a stub roam logging its argv
#     records ['--version'] on this run and nothing else.
#
# An earlier wording of this bound said descent "reaches venv/__init__.py but
# not venv/mypkg/mod.py", and gave `compile verify venv/` as the command that
# shows it. Both halves are wrong: that command cannot execute, and the form
# that does execute covers both files. It was the only claim in its commit
# stated in inline backticks with no transcript under it, which is the tell.
# The bound is pinned by an executable test now, not by prose --
# test_explicit_descent_prunes_nested_tool_state_names_but_never_the_named_one.
NON_SOURCE_SCOPE_DIRECTORIES = frozenset({".git", ".roam", ".venv", "venv", "node_modules", "__pycache__"})
# git porcelain v1 status for a path git has never been told about. It is the
# only trackedness signal `git status` already hands us, so using it costs no
# extra subprocess.
GIT_STATUS_UNTRACKED = "??"
MAX_STRICT_JSON_DEPTH = 128
_VERIFY_CAPTURE_CHUNK_BYTES = 64 * 1024
_VERIFY_TERMINATION_GRACE_SECONDS = 1.0
_WINDOWS_CREATE_SUSPENDED = 0x00000004
MAX_VERIFY_FILE_BYTES = 64 * 1024 * 1024
MAX_VERIFY_TOTAL_BYTES = 256 * 1024 * 1024
MAX_VERIFY_TARGETS = 4096
MAX_VERIFY_ARG_CHARS = 128 * 1024
MAX_VERIFY_DIRECTORIES = 20_000
MAX_VERIFY_DIRECTORY_ENTRIES = 200_000
MAX_VERIFY_TRAVERSAL_SECONDS = 10.0
MAX_CLAUDE_SETTINGS_BYTES = 1024 * 1024
MAX_CLAUDE_HOOK_BYTES = 512 * 1024
MAX_CLAUDE_GUIDANCE_BYTES = 4 * 1024 * 1024
_ATOMIC_WRITE_LOCK_MAGIC = b"compile-code-owner-lock-v1\n"
_ATOMIC_WRITE_LOCK_TIMEOUT_SECONDS = 10.0
MIN_CLAUDE_HOOK_VERSION = 10
VERIFY_ENVELOPE_SCHEMA = "roam-envelope-v1"
# The envelope shape this build was WRITTEN AGAINST -- not a pin. Roam's
# envelope versioning is semantic: a minor bump only adds optional fields, so
# any same-major envelope is interpretable by this build. A different major is
# a breaking redefinition we cannot read, and is refused. See
# `_envelope_schema_compatible`.
VERIFY_ENVELOPE_SCHEMA_VERSION = "1.1.0"
VERIFY_RECEIPT_SCHEMA = "roam.verify.receipt.v3"

_ROAM_VERSION_LINE = re.compile(r"^roam(?:\.exe)?,\s+version\s+(\S+)\s*$", re.IGNORECASE)
_VERSION_VALUE = re.compile(
    r"^(\d+)\.(\d+)\.(\d+)"
    r"(?P<suffix>(?:(?:a|b|rc)\d+|\.?dev\d+|\.post\d+)?(?:\+[A-Za-z0-9.-]+)?)$",
    re.IGNORECASE,
)
_ENVELOPE_SCHEMA_VERSION_VALUE = re.compile(r"^(\d{1,4})\.(\d{1,4})\.(\d{1,4})$")
# Unrecognised field names are producer-supplied text echoed into the verdict
# block, so only plain identifiers print verbatim and the list is capped:
# a disclosure must not be a place to inject lines or flood the block.
_SAFE_FIELD_NAME = re.compile(r"[A-Za-z0-9_]{1,64}")
MAX_DISCLOSED_UNKNOWN_FIELDS = 8
# Ceiling on one producer-supplied disclosure string this build accepts as a
# known field. Matches the finding-message bound already applied above.
MAX_DISCLOSURE_TEXT_CHARS = 4096
_GIT_HEAD_VALUE = re.compile(r"(?:ref: refs/\S+|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")
_SQLITE_HEADER = b"SQLite format 3\x00"
_MAX_GIT_CONTROL_FILE_BYTES = 4096

# The hook script the roam-code dependency installs into a Claude settings
# file; its presence is how we detect that compile is wired in. Kept as a
# named constant so the delegated hook-detection contract is explicit and
# updates in lockstep if roam-code renames the hook.
HOOK_MARKER = "roam-compile-ups.py"
HOOK_FILENAMES = (HOOK_MARKER, "roam-verify-stop.py")
HOOK_EVENTS = {
    "UserPromptSubmit": HOOK_MARKER,
    "Stop": "roam-verify-stop.py",
}
_HOOK_BODY_MARKERS = {
    HOOK_MARKER: (
        "UserPromptSubmit",
        '"roam", "--json", "compile"',
        "_policy_snapshot",
    ),
    "roam-verify-stop.py": (
        VERIFY_RECEIPT_SCHEMA,
        "ROAM_VERIFY_REQUEST_NONCE",
        "ROAM_VERIFY_SCOPE_SHA256",
        "ROAM_VERIFY_CONTENT_SHA256",
        "_verify_protocol_state",
        "_verification_snapshot",
        "scope_stable",
        "content_sha256_before",
        "content_sha256_after",
    ),
}
_PYTHON_INJECTION_ENV = frozenset(
    {
        "PYTHONCASEOK",
        "PYTHONEXECUTABLE",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONPYCACHEPREFIX",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "PYTHONVERBOSE",
        "PYTHONWARNINGS",
    }
)
_GIT_REDIRECTION_ENV = frozenset(
    {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
    }
)
LAUNCH_INDEX_HEAD_FILE = os.path.join(".roam", ".compile-code-launch-head")
VERIFY_REPORT_FILE = os.path.join(".roam", "verify-report.json")
ROAM_MIDTASK_COMMANDS = (
    "impact",
    "critique",
    "uses",
    "context",
    "preflight",
    "understand",
    "at",
    "retrieve",
)
ROAM_MIDTASK_ALLOW = tuple(f"Bash(roam {command}:*)" for command in ROAM_MIDTASK_COMMANDS)
ROAM_GUIDANCE_BEGIN = "<!-- BEGIN compile-code roam graph access -->"
ROAM_GUIDANCE_END = "<!-- END compile-code roam graph access -->"


def _path_is_within(path: Path, root: Path) -> bool:
    """Return whether *path* is *root* or one of its descendants."""
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _read_git_control_file(path: Path) -> str | None:
    """Read one small regular Git control file without trusting its contents."""
    try:
        state = path.stat()
        if not stat.S_ISREG(state.st_mode) or state.st_size > _MAX_GIT_CONTROL_FILE_BYTES:
            return None
        contents = path.read_bytes()
        if len(contents) > _MAX_GIT_CONTROL_FILE_BYTES:
            return None
        return contents.decode("utf-8").strip()
    except (OSError, UnicodeError):
        return None


def _git_directory_has_evidence(git_dir: Path) -> bool:
    """Return whether a Git metadata directory has a credible minimal structure."""
    try:
        if not git_dir.is_dir():
            return False
        head = _read_git_control_file(git_dir / "HEAD")
        if head is None or _GIT_HEAD_VALUE.fullmatch(head) is None:
            return False

        common_dir = git_dir
        common_pointer = git_dir / "commondir"
        if common_pointer.exists():
            common_value = _read_git_control_file(common_pointer)
            if not common_value:
                return False
            common_dir = Path(common_value)
            if not common_dir.is_absolute():
                common_dir = git_dir / common_dir
            common_dir = common_dir.resolve(strict=True)
        return (common_dir / "objects").is_dir() and (common_dir / "refs").is_dir()
    except (OSError, RuntimeError, ValueError):
        return False


def _git_marker_has_evidence(candidate: Path) -> bool:
    """Return whether *candidate/.git* describes a real repository or worktree."""
    marker = candidate / ".git"
    if marker.is_dir():
        return _git_directory_has_evidence(marker)
    pointer = _read_git_control_file(marker)
    if pointer is None or not pointer.startswith("gitdir: "):
        return False
    git_dir_value = pointer.removeprefix("gitdir: ").strip()
    if not git_dir_value:
        return False
    try:
        git_dir = Path(git_dir_value)
        if not git_dir.is_absolute():
            git_dir = candidate / git_dir
        return _git_directory_has_evidence(git_dir.resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        return False


def _roam_index_has_evidence(candidate: Path) -> bool:
    """Return whether *candidate* has a readable SQLite roam index."""
    index = candidate / ".roam" / "index.db"
    try:
        state = index.stat()
        if not stat.S_ISREG(state.st_mode) or state.st_size < len(_SQLITE_HEADER):
            return False
        with index.open("rb") as stream:
            if stream.read(len(_SQLITE_HEADER)) != _SQLITE_HEADER:
                return False
        uri = index.resolve(strict=True).as_uri() + "?mode=ro&immutable=1"
        with sqlite3.connect(uri, uri=True, timeout=0) as connection:
            connection.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone()
        return True
    except (OSError, RuntimeError, ValueError, sqlite3.Error):
        return False


def _candidate_has_trust_root_evidence(candidate: Path) -> bool:
    """Return whether *candidate* contains credible Git or roam trust-root state."""
    return _git_marker_has_evidence(candidate) or _roam_index_has_evidence(candidate)


def _workspace_trust_roots() -> tuple[Path, ...]:
    """Return local roots whose PATH entries must never authorize an agent.

    The current directory is always included. The nearest repository root is
    included as well so invoking from a nested directory cannot select a
    sibling executable planted elsewhere in the checkout.
    """
    try:
        current = Path.cwd().resolve(strict=True)
    except (OSError, RuntimeError):
        current = Path.cwd().absolute()
    roots = [current]
    for candidate in (current, *current.parents):
        if _candidate_has_trust_root_evidence(candidate):
            roots.append(candidate)
            break
    return tuple(dict.fromkeys(roots))


def _resolve_trusted_executable(name: str, *, reject_workspace: bool) -> tuple[str | None, str | None]:
    """Resolve one executable to an exact regular file with a closed failure reason."""
    import shutil

    selected = shutil.which(name)
    if not selected:
        return None, "missing"
    try:
        lexical = Path(selected).expanduser()
        if not lexical.is_absolute():
            lexical = Path.cwd() / lexical
        lexical = lexical.absolute()
        resolved = lexical.resolve(strict=True)
        if not resolved.is_file():
            return None, "not_regular"
        if os.name != "nt" and not os.access(resolved, os.X_OK):
            return None, "not_executable"
        if reject_workspace:
            for root in _workspace_trust_roots():
                if _path_is_within(lexical, root) or _path_is_within(resolved, root):
                    return None, "workspace_path"
    except (OSError, RuntimeError, ValueError):
        return None, "unavailable"
    return str(resolved), None


def _trusted_search_path() -> str:
    """Remove relative, missing, and workspace-local entries from child PATH."""
    roots = _workspace_trust_roots()
    trusted: list[str] = []
    seen: set[str] = set()
    for raw_entry in os.environ.get("PATH", "").split(os.pathsep):
        entry = raw_entry.strip().strip('"')
        if not entry:
            continue
        try:
            lexical = Path(entry).expanduser()
            if not lexical.is_absolute():
                continue
            lexical = lexical.absolute()
            resolved = lexical.resolve(strict=True)
            if not resolved.is_dir() or any(
                _path_is_within(lexical, root) or _path_is_within(resolved, root) for root in roots
            ):
                continue
        except (OSError, RuntimeError, ValueError):
            continue
        key = os.path.normcase(str(resolved))
        if key not in seen:
            seen.add(key)
            trusted.append(str(resolved))
    return os.pathsep.join(trusted)


def _trusted_tool_env(*, git: bool = False, overrides: dict[str, str] | None = None) -> dict[str, str]:
    """Build a deterministic child environment for trusted toolchain binaries."""
    env = os.environ.copy()
    for key in _PYTHON_INJECTION_ENV:
        env.pop(key, None)
    env.update(PYTHONIOENCODING="utf-8", PYTHONSAFEPATH="1", PYTHONUTF8="1")
    trusted_path = _trusted_search_path()
    if trusted_path:
        env["PATH"] = trusted_path
    else:
        env.pop("PATH", None)
    if git:
        for key in tuple(env):
            if key in _GIT_REDIRECTION_ENV or key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_"):
                env.pop(key, None)
        env.update(
            GIT_OPTIONAL_LOCKS="0",
            GIT_TERMINAL_PROMPT="0",
            GIT_PAGER="cat",
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=os.devnull,
        )
    if overrides:
        env.update(overrides)
    return env


def _resolve_roam_executable() -> str | None:
    """Return the exact ``roam`` executable selected by PATH."""
    executable, _reason = _resolve_trusted_executable("roam", reject_workspace=True)
    return executable


def _python_roam_metadata_version() -> str | None:
    """Installed Python distribution version, diagnostic only.

    Console-script shims can outlive or differ from Python metadata, so this
    value never authorizes Verify. It is reported separately to make that
    mismatch visible without adding a version-parsing dependency.
    """
    from importlib import metadata

    try:
        return metadata.version("roam-code")
    except Exception:
        return None


def _parse_version_value(raw: str) -> tuple[tuple[int, int, int], bool] | None:
    """Parse the roam release and whether it is a pre-release."""
    match = _VERSION_VALUE.fullmatch(raw.strip())
    if not match:
        return None
    try:
        release = (
            int(match.group(1)),
            int(match.group(2)),
            int(match.group(3)),
        )
    except (OverflowError, ValueError):
        return None
    suffix = match.group("suffix").lower()
    prerelease = bool(re.match(r"^(?:a|b|rc|\.?dev)", suffix))
    return release, prerelease


def _version_meets_minimum(raw: str, minimum: str = MIN_ROAM_VERSION) -> bool:
    """Enforce the Roam compatibility FLOOR without ``packaging``.

    A floor only: there is no product-major ceiling, by decision. See the
    comment on ``ROAM_VERSION_REQUIREMENT`` for why the envelope-schema major
    and the receipt cross-derivations are the compatibility question, and the
    product major is not.
    """
    parsed = _parse_version_value(raw)
    floor = _parse_version_value(minimum)
    if parsed is None or floor is None:
        return False
    release, prerelease = parsed
    floor_release, floor_prerelease = floor
    if prerelease and not floor_prerelease:
        return False
    if release != floor_release:
        return release > floor_release
    if prerelease != floor_prerelease:
        return floor_prerelease
    return True


def _parse_envelope_schema_version(raw: object) -> tuple[int, int, int] | None:
    """Parse a declared ``schema_version`` into a comparable release triple."""
    if not isinstance(raw, str):
        return None
    match = _ENVELOPE_SCHEMA_VERSION_VALUE.fullmatch(raw)
    if match is None:
        return None
    try:
        return int(match.group(1)), int(match.group(2)), int(match.group(3))
    except (OverflowError, ValueError):
        return None


def _envelope_schema_compatible(raw: object) -> bool:
    """Whether a declared envelope version is one this build can still read.

    Roam versions its envelope semantically: a minor bump adds optional fields
    and leaves every existing field meaning what it meant. So compatibility is
    a MAJOR-version question, not a string-equality question. Pinning the exact
    string turned every upstream minor release into a local verify outage on
    envelopes that were valid and strictly richer -- a gate that fails on the
    producer shipping, not on anything being wrong. An unparseable or
    absent version stays a refusal: an unidentifiable producer is not a
    compatible one.
    """
    declared = _parse_envelope_schema_version(raw)
    baseline = _parse_envelope_schema_version(VERIFY_ENVELOPE_SCHEMA_VERSION)
    return declared is not None and baseline is not None and declared[0] == baseline[0]


def _extract_roam_version(output: str) -> str | None:
    """Extract a valid version from Click's canonical ``roam --version`` line."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) != 1:
        return None
    match = _ROAM_VERSION_LINE.fullmatch(lines[0])
    if not match or _parse_version_value(match.group(1)) is None:
        return None
    return match.group(1)


def _content_digest(path: str, *, max_bytes: int = MAX_ROAM_EXECUTABLE_BYTES) -> str | None:
    """Hash one regular file's exact bytes from a single, swap-checked read.

    This is the one property in the tamper boundary observed from OUTSIDE the
    executable: raw bytes on disk, never anything the binary says about
    itself (a substituted binary can echo back a trusted ``--version`` string
    or a well-formed attestation envelope; it cannot make its own bytes hash
    to a value it does not have). Returns ``None`` -- never a stale or partial
    digest -- if the path is not a plain regular file, exceeds *max_bytes*, or
    changes while being read. ``None`` never compares equal to a real digest,
    so a file that cannot be verified this way is refused rather than
    silently trusted.

    Unlike the other bounded readers in this module, a hard-link count above
    one is not treated as unsafe here: pip/pipx routinely install console-
    script launcher stubs as hardlinks to a shared, byte-identical template
    (observed in the wild at ``st_nlink=42`` for a real ``roam.exe``), and
    rejecting that would refuse every launch against an otherwise-legitimate
    install. Hashing the resolved path's exact current bytes detects content
    change regardless of how many directory entries reference that inode.
    """
    candidate = Path(path)
    try:
        path_before = candidate.lstat()
    except OSError:
        return None
    if stat.S_ISLNK(path_before.st_mode) or not stat.S_ISREG(path_before.st_mode) or path_before.st_size > max_bytes:
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError:
        return None
    try:
        opened_before = os.fstat(descriptor)
        if not stat.S_ISREG(opened_before.st_mode) or not _same_verification_file_state(
            path_before, opened_before, cross_handle=True
        ):
            return None
        digest = hashlib.sha256()
        bytes_read = 0
        while True:
            chunk = os.read(descriptor, 256 * 1024)
            if not chunk:
                break
            bytes_read += len(chunk)
            if bytes_read > max_bytes:
                return None
            digest.update(chunk)
        opened_after = os.fstat(descriptor)
        try:
            path_after = candidate.lstat()
        except OSError:
            return None
        if (
            bytes_read != opened_before.st_size
            or not _same_verification_file_state(opened_before, opened_after)
            or not _same_verification_file_state(path_before, path_after)
        ):
            return None
    except OSError:
        return None
    finally:
        os.close(descriptor)
    return f"sha256:{digest.hexdigest()}"


def _inspect_roam(timeout: int = 10) -> dict[str, str | None]:
    """Inspect the exact PATH executable and Python metadata independently."""
    metadata_version = _python_roam_metadata_version()
    executable = _resolve_roam_executable()
    info = {
        "path": executable,
        "version": None,
        "metadata_version": metadata_version,
        "digest": None,
        "state": "missing" if executable is None else "unknown",
        "detail": None,
    }
    if executable is None:
        return info
    try:
        proc = _run_bounded_capture(
            [executable, "--version"],
            timeout=timeout,
            stdout_limit=MAX_ROAM_VERSION_BYTES,
            stderr_limit=MAX_ROAM_VERSION_BYTES,
            env=_trusted_tool_env(),
        )
    except FileNotFoundError:
        info.update(state="vanished", detail="the resolved executable vanished before launch")
        return info
    except OSError as exc:
        info.update(state="unlaunchable", detail=str(exc))
        return info
    except subprocess.TimeoutExpired:
        info.update(state="timeout", detail=f"version check timed out after {timeout}s")
        return info
    except KeyboardInterrupt:
        info.update(state="interrupted", detail="version check interrupted")
        return info
    if proc.returncode != 0:
        diagnostic_raw = proc.stderr or proc.stdout or b""
        diagnostic = (diagnostic_raw.decode("utf-8", errors="replace").strip().splitlines() or [""])[0][:200]
        detail = f"version check exited {proc.returncode}"
        if diagnostic:
            detail += f": {diagnostic}"
        info.update(state="version_failed", detail=detail)
        return info
    stdout_text = (proc.stdout or b"").decode("utf-8", errors="replace")
    stderr_text = (proc.stderr or b"").decode("utf-8", errors="replace")
    combined = "\n".join((stdout_text, stderr_text))
    version = _extract_roam_version(combined)
    if version is None:
        # Both streams are still required to be clean -- a version check is the
        # one call this CLI trusts a stranger's binary for, and a binary that
        # writes anything alongside its version is not in a state this build is
        # willing to vouch for. But the two ways to fail that need different
        # actions from the reader and used to print the same sentence. A binary
        # that emitted nothing parseable is broken; a binary that printed a
        # perfectly good version on stdout and one deprecation line on stderr
        # is not, and telling that caller their toolchain "returned no
        # parseable version" sends them to reinstall something that is fine
        # while the actual cause -- a plugin or a wrapper writing to stderr --
        # goes unmentioned. Only the count of stderr lines and the
        # regex-validated version are reported; untrusted output is never
        # replayed into the verdict.
        stdout_only = _extract_roam_version(stdout_text)
        noise = sum(1 for line in stderr_text.splitlines() if line.strip())
        if stdout_only is not None and noise:
            detail = (
                f"`roam --version` reported {stdout_only} on stdout but also wrote {noise} line(s) to stderr; "
                "a trusted version check must produce that one line and nothing else"
            )
        else:
            detail = "`roam --version` returned no parseable version"
        info.update(state="malformed_version", detail=detail)
        return info
    # The version string above is self-reported by the same binary this re-proof
    # exists to distrust -- a substituted executable can echo it back verbatim.
    # The digest is taken last, after that self-report, so it reflects content
    # at least as current as the version this call is about to vouch for.
    digest = _content_digest(executable)
    if digest is None:
        info.update(
            state="unverifiable",
            version=version,
            detail="executable content could not be hashed for verification",
        )
        return info
    info.update(state="ok", version=version, digest=digest)
    return info


def _roam_remediation() -> str:
    """The one remediation a runtime version refusal can now have.

    The constraint is a floor, so a version refusal has exactly one cause and
    one printed fix, and "upgrade roam" is the true description of it. This
    function previously carried a second arm for callers ABOVE a product-major
    ceiling, where the same sentence described the opposite of what happens:
    pip resolved the pin DOWNWARD and installed an older roam than the one
    already on PATH. That arm went with the ceiling it existed to describe.
    """
    return f'python -m pip install --upgrade "{ROAM_PACKAGE_REQUIREMENT}"'


def _roam_problem(info: dict[str, str | None]) -> tuple[int, str] | None:
    """Return the product exit code and verdict for an unusable roam install."""
    state = info.get("state")
    executable = info.get("path")
    version = info.get("version")
    metadata_version = info.get("metadata_version")
    fix = _roam_remediation()
    if state == "missing":
        return EXIT_TOOLCHAIN, f"VERDICT: toolchain missing — `roam` is not on PATH. Fix: {fix}"
    if state == "timeout":
        return EXIT_TIMEOUT, f"VERDICT: toolchain version check timed out — rerun, then fix with: {fix}"
    if state == "interrupted":
        return 130, "VERDICT: interrupted"
    if state != "ok" or not executable or not version:
        detail = info.get("detail") or "version inspection failed"
        return (
            EXIT_TOOLCHAIN,
            f"VERDICT: toolchain broken — PATH roam at `{executable or 'unknown'}` could not be verified "
            f"({detail}). Fix: {fix}",
        )
    if not _version_meets_minimum(version):
        metadata_note = (
            f" Python metadata reports roam-code {metadata_version}; PATH still selects the executable above."
            if metadata_version
            else ""
        )
        return (
            EXIT_TOOLCHAIN,
            f"VERDICT: toolchain version mismatch — PATH roam at `{executable}` reports {version}; "
            f"compile-code requires {ROAM_VERSION_REQUIREMENT}.{metadata_note} Fix: {fix}",
        )
    return None


def _exit_on_roam_problem() -> dict[str, str | None]:
    """Refuse before delegating when PATH roam is not one this build supports.

    Every verb that emits an assurance claim shares this preamble. It used to
    live only inside `_verify`, and the result was that `compile verify` exited
    2 calling the toolchain unusable while `compile report` drove that same
    binary to a PASS in the same tree, from the same shell — one install
    publishing two opposite answers about one executable. At a product boundary
    the exit code IS the claim: a CI job branches on it, and `compile report`
    exiting 0 asserts a verdict it never read.
    """
    roam_info = _inspect_roam()
    problem = _roam_problem(roam_info)
    if problem is not None:
        exit_code, verdict = problem
        click.echo(verdict)
        raise SystemExit(exit_code)
    return roam_info


def _require_index(path: str = ".") -> bool:
    """True when a compile index exists at *path*."""
    root = Path(path)
    roam_dir = root / ".roam"
    index = roam_dir / "index.db"
    try:
        canonical_root = root.resolve(strict=True)
        directory_info = roam_dir.lstat()
        index_info = index.lstat()
        return (
            stat.S_ISDIR(directory_info.st_mode)
            and not stat.S_ISLNK(directory_info.st_mode)
            and os.path.normcase(str(roam_dir.resolve(strict=True))) == os.path.normcase(str(canonical_root / ".roam"))
            and stat.S_ISREG(index_info.st_mode)
            and not stat.S_ISLNK(index_info.st_mode)
        )
    except (OSError, RuntimeError, ValueError):
        return False


def _roam(*args: str, timeout: int = 600) -> subprocess.CompletedProcess:
    """Run the roam toolchain CLI (provided by the roam-code dependency)."""
    executable, _reason = _resolve_trusted_executable("roam", reject_workspace=True)
    if not executable:
        raise FileNotFoundError("trusted roam executable not found")
    return subprocess.run(
        [executable, *args],
        timeout=timeout,
        check=False,
        env=_trusted_tool_env(),
    )


@contextmanager
def _default_agent_mode(mode: str):
    """Set the telemetry mode for a product path without clobbering callers."""
    previous = os.environ.get("ROAM_AGENT_MODE")
    if previous is None:
        os.environ["ROAM_AGENT_MODE"] = mode
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("ROAM_AGENT_MODE", None)


def _delegate(
    *args: str,
    timeout: int = 600,
    executable: str | None = None,
    env: dict[str, str] | None = None,
) -> int:
    """Run the toolchain and translate every failure mode into a clean
    verdict + exit code (no tracebacks at the product surface)."""
    try:
        if executable is None and env is None:
            return _roam(*args, timeout=timeout).returncode
        return subprocess.run([executable or "roam", *args], timeout=timeout, check=False, env=env).returncode
    except FileNotFoundError:
        click.echo(
            "VERDICT: toolchain missing — `roam` is not on PATH. "
            "Fix: pip install --force-reinstall compile-code  "
            "(installs the roam-code dependency)"
        )
        return EXIT_TOOLCHAIN
    except OSError as exc:
        # Present on PATH but not launchable: broken shim, wrong-arch binary,
        # permission denied. Same contract slot as missing: exit 2, no traceback.
        click.echo(
            f"VERDICT: toolchain broken — `roam` failed to launch ({exc}). "
            "Fix: pip install --force-reinstall compile-code"
        )
        return EXIT_TOOLCHAIN
    except subprocess.TimeoutExpired:
        click.echo(f"VERDICT: toolchain call timed out after {timeout}s — rerun with a smaller scope or file an issue")
        return EXIT_TIMEOUT
    except KeyboardInterrupt:
        click.echo("VERDICT: interrupted")
        return 130


class _WindowsKillJob:
    """A Windows job whose last handle closes every contained descendant."""

    _KILL_ON_JOB_CLOSE = 0x00002000
    _EXTENDED_LIMIT_INFORMATION = 9

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        class _BasicLimitInformation(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class _IoCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class _ExtendedLimitInformation(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", _BasicLimitInformation),
                ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = _ExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = self._KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            handle,
            self._EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            error = ctypes.WinError(ctypes.get_last_error())
            kernel32.CloseHandle(handle)
            raise error
        self._ctypes = ctypes
        self._wintypes = wintypes
        self._kernel32 = kernel32
        self._handle = handle

    def assign_and_resume(self, process: subprocess.Popen) -> None:
        """Attach a suspended process before any of its code can create children."""
        process_handle = self._wintypes.HANDLE(int(process._handle))
        if not self._kernel32.AssignProcessToJobObject(self._handle, process_handle):
            raise self._ctypes.WinError(self._ctypes.get_last_error())
        ntdll = self._ctypes.WinDLL("ntdll")
        ntdll.NtResumeProcess.argtypes = [self._wintypes.HANDLE]
        ntdll.NtResumeProcess.restype = self._wintypes.LONG
        if ntdll.NtResumeProcess(process_handle) != 0:
            raise OSError("unable to resume contained subprocess")

    def terminate(self) -> None:
        if self._handle:
            self._kernel32.TerminateJobObject(self._handle, 1)

    def close(self) -> None:
        if self._handle:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None


def _start_bounded_capture_process(
    argv: list[str],
    *,
    env: dict[str, str] | None,
    cwd: str | None,
) -> tuple[subprocess.Popen, _WindowsKillJob | None]:
    """Start one subprocess inside a tree-wide termination boundary."""
    job: _WindowsKillJob | None = None
    popen_kwargs: dict[str, object] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "bufsize": 0,
        "env": env,
        "cwd": cwd,
    }
    if os.name == "nt":
        job = _WindowsKillJob()
        popen_kwargs["creationflags"] = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200) | _WINDOWS_CREATE_SUSPENDED
        )
    else:
        popen_kwargs["start_new_session"] = True
    try:
        process = subprocess.Popen(argv, **popen_kwargs)
    except BaseException:
        if job is not None:
            job.close()
        raise
    if job is not None:
        try:
            job.assign_and_resume(process)
        except BaseException:
            job.terminate()
            job.close()
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=_VERIFY_TERMINATION_GRACE_SECONDS)
            except (OSError, subprocess.TimeoutExpired):
                pass
            for pipe in (process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()
            raise
    return process, job


def _run_bounded_capture(
    argv: list[str],
    *,
    timeout: float,
    stdout_limit: int,
    stderr_limit: int,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> subprocess.CompletedProcess:
    """Run a contained process while concurrently draining two bounded pipes."""
    if timeout <= 0 or stdout_limit < 0 or stderr_limit < 0:
        raise ValueError("invalid bounded-capture limit")
    process, job = _start_bounded_capture_process(argv, env=env, cwd=cwd)
    if process.stdout is None or process.stderr is None:  # pragma: no cover - guaranteed by PIPE
        _stop_bounded_capture(process, [], threading.Event(), job)
        raise OSError("failed to create bounded capture pipes")

    stdout = bytearray()
    stderr = bytearray()
    reader_errors: list[OSError] = []
    stop_readers = threading.Event()
    readers = [
        threading.Thread(
            target=_drain_bounded_pipe,
            args=(process.stdout, stdout, stdout_limit, reader_errors, stop_readers),
            daemon=True,
            name="compile-boundary-stdout",
        ),
        threading.Thread(
            target=_drain_bounded_pipe,
            args=(process.stderr, stderr, stderr_limit, reader_errors, stop_readers),
            daemon=True,
            name="compile-boundary-stderr",
        ),
    ]
    for reader in readers:
        reader.start()

    deadline = time.monotonic() + timeout
    try:
        returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        _stop_bounded_capture(process, readers, stop_readers, job)
        raise subprocess.TimeoutExpired(argv, timeout) from None
    except BaseException:
        _stop_bounded_capture(process, readers, stop_readers, job)
        raise

    for reader in readers:
        reader.join(max(0.0, deadline - time.monotonic()))
    if any(reader.is_alive() for reader in readers):
        _stop_bounded_capture(process, readers, stop_readers, job)
        raise subprocess.TimeoutExpired(argv, timeout)
    if reader_errors:
        _stop_bounded_capture(process, readers, stop_readers, job)
        raise reader_errors[0]
    if job is not None:
        job.close()
    return subprocess.CompletedProcess(argv, returncode, bytes(stdout), bytes(stderr))


def _roam_capture(
    *args: str,
    timeout: int = 600,
    executable: str = "roam",
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> subprocess.CompletedProcess:
    """Run Roam through the bounded Verify subprocess boundary."""
    argv = [executable, *args]
    proc = _run_bounded_capture(
        argv,
        timeout=timeout,
        stdout_limit=MAX_VERIFY_JSON_BYTES,
        stderr_limit=MAX_VERIFY_STDERR_BYTES,
        env=env,
        cwd=cwd,
    )
    return subprocess.CompletedProcess(
        proc.args,
        proc.returncode,
        proc.stdout.decode("utf-8", errors="replace"),
        proc.stderr.decode("utf-8", errors="replace"),
    )


def _drain_bounded_pipe(
    pipe: BinaryIO,
    destination: bytearray,
    max_bytes: int,
    errors: list[OSError],
    stop: threading.Event,
) -> None:
    """Drain *pipe* to EOF while retaining at most ``max_bytes + 1`` bytes."""
    retention_limit = max_bytes + 1
    try:
        while not stop.is_set():
            chunk = pipe.read(_VERIFY_CAPTURE_CHUNK_BYTES)
            if not chunk or stop.is_set():
                return
            remaining = retention_limit - len(destination)
            if remaining > 0:
                destination.extend(chunk[:remaining])
    except (OSError, ValueError):
        if not stop.is_set():
            errors.append(OSError("verifier capture pipe failed"))
    finally:
        try:
            pipe.close()
        except (OSError, ValueError):
            if not stop.is_set():
                errors.append(OSError("verifier capture pipe close failed"))


def _stop_bounded_capture(
    process: subprocess.Popen,
    readers: list[threading.Thread],
    stop: threading.Event,
    job: _WindowsKillJob | None,
) -> None:
    """Kill a whole process tree and abandon stuck pipe readers after a strict grace."""
    stop.set()
    if job is not None:
        job.terminate()
        job.close()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (AttributeError, OSError, ProcessLookupError):
            try:
                process.kill()
            except OSError:
                pass
    deadline = time.monotonic() + _VERIFY_TERMINATION_GRACE_SECONDS
    try:
        process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except (OSError, subprocess.TimeoutExpired):
        pass
    for reader in readers:
        reader.join(max(0.0, deadline - time.monotonic()))


def _delegate_capturing(
    *args: str,
    timeout: int = 600,
    executable: str = "roam",
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> tuple[int, str | None]:
    """Run the toolchain and translate failure modes like ``_delegate``.

    Returns ``(rc, stdout)`` instead of streaming, so the caller can classify
    a verify failure from roam's check output before composing the verdict.
    ``stdout`` is ``None`` when the toolchain never produced a result (missing,
    broken, timed out, interrupted) — the verdict was already emitted here, so
    callers must not layer their own failure analysis on top. That sentinel is
    what disambiguates our ``EXIT_TOOLCHAIN`` (2) from roam's own exit 2
    ("bad arguments"). Raw stderr is not replayed: Verify accepts only the
    bounded structured stdout transaction, and public protocol errors remain
    one-line verdicts rather than untrusted subprocess diagnostics.
    """
    try:
        capture_kwargs: dict[str, object] = {"timeout": timeout, "executable": executable, "env": env}
        if cwd is not None:
            capture_kwargs["cwd"] = cwd
        proc = _roam_capture(*args, **capture_kwargs)
        return proc.returncode, proc.stdout or ""
    except FileNotFoundError:
        click.echo(
            "VERDICT: toolchain missing — `roam` is not on PATH. "
            "Fix: pip install --force-reinstall compile-code  "
            "(installs the roam-code dependency)"
        )
        return EXIT_TOOLCHAIN, None
    except OSError as exc:
        click.echo(
            f"VERDICT: toolchain broken — `roam` failed to launch ({exc}). "
            "Fix: pip install --force-reinstall compile-code"
        )
        return EXIT_TOOLCHAIN, None
    except subprocess.TimeoutExpired:
        click.echo(f"VERDICT: toolchain call timed out after {timeout}s — rerun with a smaller scope or file an issue")
        return EXIT_TIMEOUT, None
    except KeyboardInterrupt:
        click.echo("VERDICT: interrupted")
        return 130, None


def _git_status_porcelain(timeout: int = 10) -> tuple[int, str]:
    """Return ``git status --porcelain`` output, or a clean verdict + code.

    `compile baseline` refuses dirty trees before it snapshots accepted debt.
    """
    executable, _reason = _resolve_trusted_executable("git", reject_workspace=True)
    if not executable:
        click.echo("VERDICT: toolchain missing — trusted `git` is not on PATH. Fix: install git and rerun.")
        return EXIT_TOOLCHAIN, ""
    try:
        proc = subprocess.run(
            [executable, "-c", "core.fsmonitor=false", "status", "--porcelain"],
            timeout=timeout,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=_trusted_tool_env(git=True),
        )
    except FileNotFoundError:
        click.echo("VERDICT: toolchain missing — `git` is not on PATH. Fix: install git and rerun `compile baseline`.")
        return EXIT_TOOLCHAIN, ""
    except OSError as exc:
        click.echo(f"VERDICT: baseline refused — `git` failed to launch ({exc}). Fix: reinstall git and rerun.")
        return EXIT_TOOLCHAIN, ""
    except subprocess.TimeoutExpired:
        click.echo(
            f"VERDICT: baseline refused — `git status` timed out after {timeout}s. "
            "Fix: rerun on a smaller checkout or file an issue."
        )
        return EXIT_TIMEOUT, ""
    except KeyboardInterrupt:
        click.echo("VERDICT: interrupted")
        return 130, ""
    if proc.returncode != 0:
        click.echo("VERDICT: baseline refused — unable to inspect the git tree. Fix: rerun from a git checkout.")
        return 1, ""
    return 0, proc.stdout or ""


def _ensure_indexed_for_launch(*, executable: str | None = None, env: dict[str, str] | None = None) -> int:
    """Ensure the repo is indexed before an all-in-one agent launch.

    Returns 0 when an index already exists or is freshly built. On
    first-run indexing failure emits the verdict and returns the
    toolchain's nonzero code, which the launcher exits with. Keeping the
    whole index-delegation contract here makes it testable without a
    click context.
    """
    if _require_index():
        if not _launch_index_needs_refresh():
            return 0
        click.echo("compile: indexing repo (HEAD drift)...")
        rc = _delegate("index", executable=executable, env=env) if executable else _delegate("index")
        if rc != 0:
            click.echo(
                f"VERDICT: indexing failed: .roam/index.db was not refreshed (roam exit {rc}); "
                "rerun `compile claude` after fixing the index"
            )
            return rc
        _mark_launch_indexed()
        return 0
    click.echo("compile: indexing repo (first run)...")
    rc = _delegate("init", executable=executable, env=env) if executable else _delegate("init")
    if rc != 0:
        click.echo(
            f"VERDICT: indexing failed: .roam/index.db was not created (roam exit {rc}); "
            "rerun `compile claude` after fixing the index"
        )
        return rc
    _mark_launch_indexed()
    return rc


def _claude_hook_args_for_canonical_write_order(
    *, uninstall: bool = False, no_verify: bool = False, user_level: bool = False
) -> list[str]:
    """Build Claude hook args once so delegated wire/unwire behavior stays aligned."""
    args = ["hooks", "claude"]
    if uninstall:
        args.append("--uninstall")
    args.append("--write")
    if no_verify:
        args.append("--no-verify")
    if user_level:
        args.append("--user")
    return args


def _exit_after_canonical_claude_hook_update(
    *, uninstall: bool = False, no_verify: bool = False, user_level: bool = False
) -> None:
    """Exit through one Claude hook mutation path so wire/unwire cannot drift.

    UNGATED BY DECISION — recovery path. `wire` and `unwire` are the two verbs
    a user needs precisely when the toolchain is unsupported: refusing here
    means they cannot install the loop that would tell them what is wrong, and
    worse, cannot un-wire a loop that is already failing on every agent turn.
    Neither emits a verdict about the code, and neither writes state any gated
    verb consumes, so the exemption costs no assurance.
    """
    rc = _delegate(
        *_claude_hook_args_for_canonical_write_order(uninstall=uninstall, no_verify=no_verify, user_level=user_level)
    )
    if rc == 0 and not uninstall:
        if no_verify:
            _wire_roam_midtask_access(user_level=user_level, require_verify=False)
        else:
            _wire_roam_midtask_access(user_level=user_level)
    raise SystemExit(rc)


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _strict_json_document(raw: str, *, max_bytes: int) -> object:
    """Parse exactly one finite JSON document and reject duplicate object keys."""
    if not isinstance(raw, str) or "\ufffd" in raw or len(raw.encode("utf-8")) > max_bytes:
        raise ValueError("invalid_json_bytes")
    _enforce_json_nesting_limit(raw)

    def reject_constant(_value: str) -> object:
        raise ValueError("non_finite_json_number")

    def parse_finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("non_finite_json_number")
        return parsed

    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=reject_constant,
            parse_float=parse_finite_float,
        )
    except (TypeError, json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise ValueError("invalid_json_document") from exc


def _enforce_json_nesting_limit(raw: str) -> None:
    """Reject pathological JSON depth without interpreting brackets in strings."""
    depth = 0
    in_string = False
    escaped = False
    for value in raw:
        if in_string:
            if escaped:
                escaped = False
            elif value == "\\":
                escaped = True
            elif value == '"':
                in_string = False
            continue
        if value == '"':
            in_string = True
        elif value in "[{":
            depth += 1
            if depth > MAX_STRICT_JSON_DEPTH:
                raise ValueError("json_nesting_limit")
        elif value in "]}":
            depth -= 1


def _read_bounded_utf8_regular_file(path: Path, *, max_bytes: int) -> str:
    """Read one non-symlink regular file under a hard byte limit."""
    try:
        path_before = path.lstat()
        if (
            stat.S_ISLNK(path_before.st_mode)
            or not stat.S_ISREG(path_before.st_mode)
            or path_before.st_nlink != 1
            or path_before.st_size > max_bytes
        ):
            raise ValueError("unsafe_file")
    except OSError as exc:
        raise ValueError("unreadable_file") from exc
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("unreadable_file") from exc
    chunks: list[bytes] = []
    bytes_read = 0
    try:
        opened_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_before.st_mode)
            or opened_before.st_nlink != 1
            or not _same_verification_file_state(path_before, opened_before, cross_handle=True)
        ):
            raise ValueError("file_changed_during_read")
        while True:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - bytes_read))
            if not chunk:
                break
            chunks.append(chunk)
            bytes_read += len(chunk)
            if bytes_read > max_bytes:
                raise ValueError("oversized_file")
        opened_after = os.fstat(descriptor)
        try:
            path_after = path.lstat()
        except OSError as exc:
            raise ValueError("file_changed_during_read") from exc
        if (
            bytes_read != opened_before.st_size
            or not _same_verification_file_state(opened_before, opened_after)
            or not _same_verification_file_state(path_before, path_after)
        ):
            raise ValueError("file_changed_during_read")
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("non_utf8_file") from exc


def _is_link_or_reparse(info: os.stat_result) -> bool:
    """Recognize POSIX links and Windows junction/reparse-point entries."""
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & reparse_flag)


def _same_path_identity(left: os.stat_result, right: os.stat_result) -> bool:
    """Compare object identity without treating ordinary metadata churn as replacement."""
    return (
        bool(left.st_dev or left.st_ino)
        and bool(right.st_dev or right.st_ino)
        and stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
        and left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and getattr(left, "st_reparse_tag", 0) == getattr(right, "st_reparse_tag", 0)
    )


def _atomic_write_lock_path(path: Path) -> Path:
    """Return a user-private, out-of-worktree lock path for one target."""
    user_key = hashlib.sha256(str(Path.home()).encode("utf-8", errors="strict")).hexdigest()[:16]
    lock_root = Path(tempfile.gettempdir()) / f"compile-code-locks-{user_key}"
    try:
        lock_root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    root_state = lock_root.lstat()
    if _is_link_or_reparse(root_state) or not stat.S_ISDIR(root_state.st_mode):
        raise ValueError("unsafe_write_lock_root")
    if os.name != "nt":
        if stat.S_IMODE(root_state.st_mode) & 0o077:
            raise ValueError("unsafe_write_lock_root")
        if hasattr(os, "geteuid") and root_state.st_uid != os.geteuid():
            raise ValueError("unsafe_write_lock_root")
    canonical_parent = path.parent.resolve(strict=True)
    target_key = os.path.normcase(str(canonical_parent / path.name))
    digest = hashlib.sha256(target_key.encode("utf-8", errors="strict")).hexdigest()
    return lock_root / f"{digest}.lock"


def _initialize_atomic_write_lock(lock_path: Path) -> None:
    """Publish one fully initialized private lock file without overwriting one."""
    temporary = lock_path.parent / f".{lock_path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(temporary, flags, 0o600)
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        state = os.fstat(descriptor)
        if not stat.S_ISREG(state.st_mode) or state.st_nlink != 1:
            raise ValueError("unsafe_write_lock")
        offset = 0
        while offset < len(_ATOMIC_WRITE_LOCK_MAGIC):
            written = os.write(descriptor, _ATOMIC_WRITE_LOCK_MAGIC[offset:])
            if written <= 0:
                raise OSError("short lock write")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(temporary, lock_path)
        except FileExistsError:
            pass
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _atomic_write_lock_is_safe(lock_path: Path, descriptor: int, opened: os.stat_result) -> bool:
    try:
        path_state = lock_path.lstat()
        if (
            _is_link_or_reparse(path_state)
            or not stat.S_ISREG(path_state.st_mode)
            or path_state.st_nlink != 1
            or not _same_verification_file_state(path_state, opened, cross_handle=True)
        ):
            return False
        if os.name != "nt":
            if stat.S_IMODE(opened.st_mode) & 0o077:
                return False
            if hasattr(os, "geteuid") and opened.st_uid != os.geteuid():
                return False
        os.lseek(descriptor, 0, os.SEEK_SET)
        content = os.read(descriptor, len(_ATOMIC_WRITE_LOCK_MAGIC) + 1)
        return content == _ATOMIC_WRITE_LOCK_MAGIC
    except OSError:
        return False


def _acquire_atomic_write_lock(descriptor: int) -> None:
    deadline = time.monotonic() + _ATOMIC_WRITE_LOCK_TIMEOUT_SECONDS
    while True:
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, len(_ATOMIC_WRITE_LOCK_MAGIC))
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except OSError as exc:
            if time.monotonic() >= deadline:
                raise TimeoutError("atomic_write_lock_timeout") from exc
            time.sleep(0.01)


def _release_atomic_write_lock(descriptor: int) -> None:
    if os.name == "nt":
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, len(_ATOMIC_WRITE_LOCK_MAGIC))
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_UN)


@contextmanager
def _owner_only_atomic_write_lock(path: Path) -> Iterator[Callable[[], bool]]:
    """Serialize target writers through a persistent private, identity-bound lock."""
    lock_path = _atomic_write_lock_path(path)
    _initialize_atomic_write_lock(lock_path)
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(lock_path, flags)
    acquired = False
    try:
        opened = os.fstat(descriptor)
        if not _atomic_write_lock_is_safe(lock_path, descriptor, opened):
            raise ValueError("unsafe_write_lock")
        _acquire_atomic_write_lock(descriptor)
        acquired = True
        locked = os.fstat(descriptor)
        if not _atomic_write_lock_is_safe(lock_path, descriptor, locked) or not _same_path_identity(opened, locked):
            raise ValueError("unsafe_write_lock")

        def still_owned() -> bool:
            try:
                current = os.fstat(descriptor)
            except OSError:
                return False
            return _same_path_identity(locked, current) and _atomic_write_lock_is_safe(lock_path, descriptor, current)

        yield still_owned
    finally:
        if acquired:
            try:
                _release_atomic_write_lock(descriptor)
            except OSError:
                pass
        os.close(descriptor)


def _atomic_write_utf8(
    path: Path,
    text: str,
    *,
    max_bytes: int,
    expected_previous: str | None = None,
) -> bool:
    """Perform one lock-serialized UTF-8 compare-and-swap."""
    payload = text.encode("utf-8")
    if len(payload) > max_bytes:
        return False
    temporary = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    descriptor = -1
    try:
        with _owner_only_atomic_write_lock(path) as lock_is_owned:
            parent_state = path.parent.lstat()
            if _is_link_or_reparse(parent_state) or not stat.S_ISDIR(parent_state.st_mode):
                return False
            target_state: os.stat_result | None = None
            if expected_previous is not None:
                current = _read_bounded_utf8_regular_file(path, max_bytes=max_bytes)
                target_state = path.lstat()
                if current != expected_previous or _is_link_or_reparse(target_state):
                    return False
                mode = stat.S_IMODE(target_state.st_mode)
            else:
                try:
                    path.lstat()
                except FileNotFoundError:
                    mode = 0o600
                else:
                    return False

            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            descriptor = os.open(temporary, flags, mode or 0o600)
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("short write")
                offset += written
            os.fsync(descriptor)
            temporary_state = os.fstat(descriptor)
            os.close(descriptor)
            descriptor = -1

            current_parent = path.parent.lstat()
            if not lock_is_owned() or not _same_path_identity(parent_state, current_parent):
                return False
            if expected_previous is None:
                try:
                    os.link(temporary, path)
                except FileExistsError:
                    return False
            else:
                current = _read_bounded_utf8_regular_file(path, max_bytes=max_bytes)
                current_state = path.lstat()
                if (
                    current != expected_previous
                    or target_state is None
                    or not _same_path_identity(target_state, current_state)
                    or not lock_is_owned()
                ):
                    return False
                os.replace(temporary, path)
            committed_state = path.lstat()
            if not _same_path_identity(temporary_state, committed_state):
                return False
            return True
    except (OSError, TimeoutError, UnicodeError, ValueError):
        return False
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass


def _hook_body_version(body: str) -> int | None:
    marker = "# roam-hook-version:"
    for line in body.splitlines()[:5]:
        stripped = line.strip()
        if stripped.startswith(marker):
            value = stripped[len(marker) :].strip()
            return int(value) if value.isdigit() else None
    return None


def _hook_body_is_current(path: Path, filename: str) -> bool:
    try:
        body = _read_bounded_utf8_regular_file(path, max_bytes=MAX_CLAUDE_HOOK_BYTES)
    except ValueError:
        return False
    if not body.splitlines() or body.splitlines()[0] != "#!/usr/bin/env python3":
        return False
    version = _hook_body_version(body)
    if version is None or version < MIN_CLAUDE_HOOK_VERSION:
        return False
    return all(marker in body for marker in _HOOK_BODY_MARKERS[filename])


def _hook_command_matches(command: object, expected_path: Path) -> bool:
    """Accept only the exact two-argument command emitted by Roam 13.10."""
    if not isinstance(command, str) or not sys.executable or not Path(sys.executable).is_absolute():
        return False
    try:
        hook_path = expected_path.resolve(strict=True)
        interpreter = Path(sys.executable)
        interpreter_info = interpreter.stat()
        if not stat.S_ISREG(interpreter_info.st_mode):
            return False
    except (OSError, RuntimeError, ValueError):
        return False
    argv = [sys.executable, str(hook_path)]
    expected = subprocess.list2cmdline(argv) if os.name == "nt" else " ".join(shlex.quote(part) for part in argv)
    return command == expected


def _read_claude_settings(settings_path: Path) -> tuple[dict[str, object] | None, str | None]:
    """Read one strict settings object without following a final symlink."""
    try:
        raw = _read_bounded_utf8_regular_file(settings_path, max_bytes=MAX_CLAUDE_SETTINGS_BYTES)
        settings = _strict_json_document(raw, max_bytes=MAX_CLAUDE_SETTINGS_BYTES)
    except ValueError:
        return None, "settings_unavailable"
    if not isinstance(settings, dict):
        return None, "settings_shape"
    return settings, None


def _settings_mapping_wiring_state(
    settings: dict[str, object], settings_path: Path, *, require_verify: bool = True
) -> tuple[bool, str]:
    """Validate the required canonical synchronous hooks in one settings object."""
    if "disableAllHooks" in settings:
        disabled = settings["disableAllHooks"]
        if type(disabled) is not bool:
            return False, "disable_all_hooks_shape"
        if disabled:
            return False, "hooks_disabled"
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return False, "hooks_shape"
    for event, filename in HOOK_EVENTS.items():
        if event == "Stop" and not require_verify:
            continue
        rules = hooks.get(event)
        if not isinstance(rules, list):
            return False, "hook_event_missing"
        expected_path = settings_path.parent / "hooks" / filename
        matched = False
        for rule in rules:
            if (
                not isinstance(rule, dict)
                or not set(rule) <= {"matcher", "hooks"}
                or rule.get("matcher") not in (None, "", "*")
                or not isinstance(rule.get("hooks"), list)
            ):
                continue
            for hook in rule["hooks"]:
                if (
                    isinstance(hook, dict)
                    and set(hook) == {"type", "command"}
                    and hook.get("type") == "command"
                    and _hook_command_matches(hook.get("command"), expected_path)
                ):
                    matched = True
                    break
            if matched:
                break
        if not matched:
            return False, "hook_command_missing"
        if not _hook_body_is_current(expected_path, filename):
            return False, "hook_body_unavailable"
    return True, "ready"


def _settings_wiring_state(settings_path: Path) -> tuple[bool, str]:
    """Validate both Claude hook events, exact commands, and current bodies."""
    settings, problem = _read_claude_settings(settings_path)
    if settings is None:
        return False, problem or "settings_unavailable"
    return _settings_mapping_wiring_state(settings, settings_path)


def _wired_in(settings_path: str) -> bool:
    """True only for structurally complete, current compile+Verify wiring."""
    return _settings_wiring_state(Path(settings_path))[0]


def _claude_tree_is_concrete(*, root: Path) -> bool:
    """Reject Claude directory symlinks, junction escapes, and path drift."""
    claude_dir = root / ".claude"
    hook_dir = claude_dir / "hooks"
    try:
        canonical_root = root.resolve(strict=True)
        for directory in (claude_dir, hook_dir):
            info = directory.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                return False
        canonical_claude = claude_dir.resolve(strict=True)
        canonical_hooks = hook_dir.resolve(strict=True)
        return os.path.normcase(str(canonical_claude)) == os.path.normcase(
            str(canonical_root / ".claude")
        ) and os.path.normcase(str(canonical_hooks)) == os.path.normcase(str(canonical_claude / "hooks"))
    except (OSError, RuntimeError, ValueError):
        return False


def _settings_tree_is_concrete(settings_path: Path, *, root: Path) -> bool:
    """Require one settings path inside a concrete Claude directory tree."""
    claude_dir = root / ".claude"
    return settings_path.absolute().parent == claude_dir.absolute() and _claude_tree_is_concrete(root=root)


def _wiring_state_for_paths(paths: tuple[Path, ...], *, root: Path, require_verify: bool = True) -> tuple[bool, str]:
    last_reason = "settings_missing"
    for path in paths:
        if not path.exists():
            continue
        if not _settings_tree_is_concrete(path, root=root):
            return False, "settings_path_unsafe"
        settings, problem = _read_claude_settings(path)
        if settings is None:
            return False, problem or "settings_unavailable"
        if "disableAllHooks" in settings:
            disabled = settings["disableAllHooks"]
            if type(disabled) is not bool:
                return False, "disable_all_hooks_shape"
            if disabled:
                return False, "hooks_disabled"
        if "hooks" not in settings:
            last_reason = "hooks_absent"
            continue
        return _settings_mapping_wiring_state(settings, path, require_verify=require_verify)
    return False, last_reason


def _project_wiring_state() -> tuple[bool, str]:
    root = Path.cwd()
    claude_dir = root / ".claude"
    return _wiring_state_for_paths((claude_dir / "settings.local.json", claude_dir / "settings.json"), root=root)


def _user_wiring_state() -> tuple[bool, str]:
    root = Path(os.path.expanduser("~"))
    claude_dir = root / ".claude"
    return _wiring_state_for_paths((claude_dir / "settings.local.json", claude_dir / "settings.json"), root=root)


def _effective_disable_all_hooks_problem() -> str | None:
    """Resolve Claude's local > project > user ``disableAllHooks`` setting."""
    project_dir = Path.cwd() / ".claude"
    user_dir = Path(os.path.expanduser("~")) / ".claude"
    paths = (
        project_dir / "settings.local.json",
        project_dir / "settings.json",
        user_dir / "settings.local.json",
        user_dir / "settings.json",
    )
    for path in paths:
        if not path.exists():
            continue
        settings, problem = _read_claude_settings(path)
        if settings is None:
            return problem or "settings_unavailable"
        if "disableAllHooks" not in settings:
            continue
        disabled = settings["disableAllHooks"]
        if type(disabled) is not bool:
            return "disable_all_hooks_shape"
        return "hooks_disabled" if disabled else None
    return None


def _claude_wiring_state() -> tuple[bool, str]:
    disable_problem = _effective_disable_all_hooks_problem()
    if disable_problem is not None:
        return False, disable_problem
    project_ready, project_reason = _project_wiring_state()
    if project_ready:
        return True, "project"
    if project_reason not in {"settings_missing", "hooks_absent"}:
        return False, project_reason
    user_ready, user_reason = _user_wiring_state()
    if user_ready:
        return True, "user"
    reason = project_reason if project_reason != "settings_missing" else user_reason
    return False, reason


def _attest_claude_hooks(executable: str, expected_version: str, *, user_level: bool) -> bool:
    """Ask the exact Roam producer to attest canonical current hook bodies."""
    argv = [executable, "--json", "hooks", "claude"]
    if user_level:
        argv.append("--user")
    env = _trusted_tool_env(overrides={"ROAM_DEFAULT_JSON_BUDGET": "0", "ROAM_AGENT_CONTRACT_BLOCK": "1"})
    try:
        proc = _run_bounded_capture(
            argv,
            timeout=15,
            stdout_limit=MAX_VERIFY_JSON_BYTES,
            stderr_limit=MAX_VERIFY_STDERR_BYTES,
            env=env,
        )
        envelope = _strict_json_document(
            (proc.stdout or b"").decode("utf-8", errors="replace"),
            max_bytes=MAX_VERIFY_JSON_BYTES,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired, ValueError):
        return False
    if proc.returncode != 0 or not isinstance(envelope, dict):
        return False
    if (
        envelope.get("schema") != VERIFY_ENVELOPE_SCHEMA
        or not _envelope_schema_compatible(envelope.get("schema_version"))
        or envelope.get("command") != "hooks"
        or envelope.get("version") != expected_version
    ):
        return False
    summary = envelope.get("summary")
    if not isinstance(summary, dict):
        return False
    body_states = summary.get("body_states")
    if (
        summary.get("already_installed") is not True
        or summary.get("foreign_bodies") != []
        or type(summary.get("hook_body_version")) is not int
        or summary["hook_body_version"] < MIN_CLAUDE_HOOK_VERSION
        or not isinstance(body_states, dict)
    ):
        return False
    return set(body_states) == set(HOOK_FILENAMES) and all(
        body_states.get(filename) == "current" for filename in HOOK_FILENAMES
    )


def _merge_roam_permissions(settings_path: str) -> bool:
    """Atomically merge curated commands without following a settings link."""
    path = Path(settings_path)
    try:
        try:
            path.lstat()
        except FileNotFoundError:
            settings = {}
            previous = None
        else:
            previous = _read_bounded_utf8_regular_file(path, max_bytes=MAX_CLAUDE_SETTINGS_BYTES)
            settings = _strict_json_document(previous, max_bytes=MAX_CLAUDE_SETTINGS_BYTES)
        if not isinstance(settings, dict):
            return False
        permissions = settings.setdefault("permissions", {})
        if not isinstance(permissions, dict):
            return False
        allow = permissions.setdefault("allow", [])
        if not isinstance(allow, list):
            return False
        changed = False
        for entry in ROAM_MIDTASK_ALLOW:
            if entry not in allow:
                allow.append(entry)
                changed = True
        if changed:
            updated = json.dumps(settings, indent=2, ensure_ascii=False) + "\n"
            return _atomic_write_utf8(
                path,
                updated,
                max_bytes=MAX_CLAUDE_SETTINGS_BYTES,
                expected_previous=previous,
            )
        return True
    except (OSError, TypeError, ValueError):
        return False


def _roam_guidance_section() -> str:
    commands = "\n".join(f"- `roam {command} --json`" for command in ROAM_MIDTASK_COMMANDS)
    return (
        f"{ROAM_GUIDANCE_BEGIN}\n"
        "## Roam graph access\n\n"
        "Use these deterministic graph queries during a task:\n\n"
        f"{commands}\n\n"
        "Mid-turn answers come from the launch-time graph; agent edits are invisible until the Stop hook.\n"
        f"{ROAM_GUIDANCE_END}"
    )


def _merge_roam_guidance(claude_path: str) -> None:
    """Best-effort atomic merge that never follows an instruction-file link."""
    path = Path(claude_path)
    try:
        try:
            path.lstat()
        except FileNotFoundError:
            content = ""
            previous = None
        else:
            content = _read_bounded_utf8_regular_file(path, max_bytes=MAX_CLAUDE_GUIDANCE_BYTES)
            previous = content
        begin = content.find(ROAM_GUIDANCE_BEGIN)
        end = content.find(ROAM_GUIDANCE_END)
        if (begin < 0) != (end < 0) or (begin >= 0 and end < begin):
            return
        section = _roam_guidance_section()
        if begin >= 0:
            end += len(ROAM_GUIDANCE_END)
            updated = content[:begin] + section + content[end:]
        else:
            prefix = content.rstrip()
            updated = f"{prefix}\n\n{section}\n" if prefix else f"{section}\n"
        if updated == content:
            return
        _atomic_write_utf8(
            path,
            updated,
            max_bytes=MAX_CLAUDE_GUIDANCE_BYTES,
            expected_previous=previous,
        )
    except (OSError, ValueError):
        return


def _wire_roam_midtask_access(*, user_level: bool, require_verify: bool = True) -> None:
    """Expose curated launch-graph queries after the delegated hook write."""
    root = Path(os.path.expanduser("~")) if user_level else Path.cwd()
    if not _claude_tree_is_concrete(root=root):
        return
    claude_dir = root / ".claude"
    settings_paths = (claude_dir / "settings.local.json", claude_dir / "settings.json")
    if not _wiring_state_for_paths(settings_paths, root=root, require_verify=require_verify)[0]:
        return
    if not _merge_roam_permissions(str(claude_dir / "settings.local.json")):
        return
    guidance = claude_dir / "CLAUDE.md" if user_level else root / "CLAUDE.md"
    _merge_roam_guidance(str(guidance))


def _project_wired() -> bool:
    """True when project-local Claude wiring is structurally ready."""
    return _project_wiring_state()[0]


def _user_wired() -> bool:
    """True when user-global Claude wiring is structurally ready."""
    return _user_wiring_state()[0]


def _launch_head() -> str | None:
    """Short git HEAD for the current repo, or ``None`` if it cannot be read."""
    executable, _reason = _resolve_trusted_executable("git", reject_workspace=True)
    if not executable:
        return None
    try:
        proc = subprocess.run(
            [executable, "rev-parse", "--short", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            env=_trusted_tool_env(git=True),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    head = proc.stdout.strip()
    if proc.returncode != 0 or not re.fullmatch(r"[0-9a-f]+", head):
        return None
    return head


def _launch_index_head() -> str | None:
    """Persisted HEAD from the last successful launch-time index."""
    try:
        head = _read_bounded_utf8_regular_file(Path(LAUNCH_INDEX_HEAD_FILE), max_bytes=256).strip()
    except ValueError:
        # A corrupted marker means "unknown HEAD" — fail open into a re-index.
        return None
    return head if re.fullmatch(r"[0-9a-f]+", head) else None


def _mark_launch_indexed(head: str | None = None) -> None:
    """Remember the HEAD that the launch-time index was built against."""
    head = head or _launch_head()
    if not head:
        return
    root = Path.cwd()
    roam_dir = root / ".roam"
    marker = root / LAUNCH_INDEX_HEAD_FILE
    try:
        canonical_root = root.resolve(strict=True)
        directory_info = roam_dir.lstat()
        if (
            stat.S_ISLNK(directory_info.st_mode)
            or not stat.S_ISDIR(directory_info.st_mode)
            or os.path.normcase(str(roam_dir.resolve(strict=True))) != os.path.normcase(str(canonical_root / ".roam"))
        ):
            return
        try:
            previous = _read_bounded_utf8_regular_file(marker, max_bytes=256)
        except ValueError:
            try:
                marker.lstat()
            except FileNotFoundError:
                previous = None
            else:
                return
        _atomic_write_utf8(marker, f"{head}\n", max_bytes=256, expected_previous=previous)
    except (OSError, RuntimeError, ValueError):
        return


def _launch_index_needs_refresh() -> bool:
    """Fail open: any uncertain HEAD comparison refreshes the index."""
    current = _launch_head()
    if not current:
        return True
    return _launch_index_head() != current


def _verify_report_status() -> str:
    """Presence and age of roam's persisted verify report, failing open."""
    try:
        age_seconds = max(0, int(time.time() - os.path.getmtime(VERIFY_REPORT_FILE)))
    except (OSError, OverflowError, ValueError):
        return "none — run `compile report`"
    if age_seconds < 60:
        age = f"{age_seconds}s"
    elif age_seconds < 3600:
        age = f"{age_seconds // 60}m"
    elif age_seconds < 86400:
        age = f"{age_seconds // 3600}h"
    else:
        age = f"{age_seconds // 86400}d"
    return f"present ({age} old)"


def _print_version(ctx: click.Context, _param: click.Parameter, value: bool) -> None:
    """Resolve and print the package version only when ``--version`` is passed.

    A plain ``click.version_option(version=__version__)`` forces the
    ``importlib.metadata`` lookup at import time on every invocation; this
    callback defers it to the one command that needs it. Output format matches
    click's default version message.
    """
    if not value or ctx.resilient_parsing:
        return
    from compile_code import __version__

    click.echo(f"{ctx.find_root().info_name}, version {__version__}")
    ctx.exit()


# Commands are dispatched by string name through this group (via the
# console-script entry points in pyproject.toml). Keep callback functions
# private and set the public Click command names explicitly.
@click.group()
@click.option(
    "--version",
    is_flag=True,
    expose_value=False,
    is_eager=True,
    callback=_print_version,
    help="Show the version and exit.",
)
def cli() -> None:
    """compile-code — pre-resolve repo facts before your AI agent's first token.

    Quickstart (Claude Code):

    \b
      cd your-repo
      compile claude        # index + wire + launch claude, all-in-one

    Or wire once and keep using `claude` natively:

    \b
      compile init
      compile wire claude

    Preflight one navigation prompt without launching an agent:

    \b
      compile run "who calls handleSave?"
    """


@cli.command("init")
@click.option("--force", is_flag=True, help="Rebuild the index from scratch.")
def _init(force: bool) -> None:
    """Index the current repo (one-time; incremental afterwards)."""
    # GATED: the index this writes is the substrate every later gated verify
    # reads, and nothing downstream records which toolchain produced it. An
    # unsupported roam must not be allowed to lay that foundation quietly.
    _exit_on_roam_problem()
    args = ["init"]
    if force:
        args = ["index", "--force"]
    raise SystemExit(_delegate(*args))


@cli.command("wire")
@click.argument("agent", type=click.Choice(["claude"]))
@click.option("--no-verify", is_flag=True, help="Skip the post-edit verify hook.")
@click.option("--user", "user_level", is_flag=True, help="Wire user-global (~/.claude) instead of project-local.")
def _wire(agent: str, no_verify: bool, user_level: bool) -> None:
    """Wire the compile/verify loop into your agent (persistent, idempotent).

    For claude: installs a UserPromptSubmit hook (compile the prompt,
    inject pre-resolved facts) and a Stop hook (scoped verify after
    edits, quiet on pass). It also best-effort merges curated Roam Bash
    permissions and a marked Roam guidance section. Prompt compilation
    fails open. After edits, verification fails closed when evidence is
    unavailable, malformed, incomplete, or failed. Undo hooks with
    `compile unwire claude`; permissions and guidance remain for reuse.
    """
    _exit_after_canonical_claude_hook_update(no_verify=no_verify, user_level=user_level)


@click.command("unwire")
@click.argument("agent", type=click.Choice(["claude"]))
@click.option("--user", "user_level", is_flag=True, help="Unwire the user-global (~/.claude) install.")
def _unwire(agent: str, user_level: bool) -> None:
    """Remove the compile/verify hooks installed by `compile wire`."""
    _exit_after_canonical_claude_hook_update(uninstall=True, user_level=user_level)


cli.add_command(_unwire)


@cli.command("baseline")
@click.argument(
    "paths",
    nargs=-1,
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=str),
)
def _baseline(paths: tuple[str, ...]) -> None:
    """Snapshot accepted debt for a clean whole-repo tree.

    Uses roam's report mode so the baseline is explicitly whole-repo and
    avoids the silent no-op shapes that the natural verify invocations hit.
    Optional directory targets let callers spell the whole repo explicitly.
    """
    # GATED: this writes the accepted-debt file that tells
    # `compile verify --new-only` which findings to SUPPRESS. A roam the gate
    # refuses to RUN must not get to decide what the gate ignores.
    _exit_on_roam_problem()
    rc, status = _git_status_porcelain()
    if rc != 0:
        raise SystemExit(rc)
    if status.strip():
        status_lines = status.strip().splitlines()
        dirty_inputs = "; ".join(
            "<credential-shaped path omitted>"
            if re.search(r"(?:token|secret|password|passwd|api[_-]?key|private[_-]?key|credential)", line, re.I)
            else line.replace("\r", "\\r")
            for line in status_lines[:8]
        )
        if len(status_lines) > 8:
            dirty_inputs += "; ..."
        click.echo(
            f"VERDICT: baseline refused: dirty tree input ({dirty_inputs}). "
            "Fix: commit, stash, or rerun on a clean checkout."
        )
        raise SystemExit(1)
    raise SystemExit(_delegate("verify", "--report", "--baseline-write", *paths, timeout=BASELINE_TIMEOUT))


@cli.command("report")
def _report() -> None:
    """Persist a whole-repo verify report without a quality gate."""
    # Report mode composes with accepted-debt --new-only; it does not add a
    # second QUALITY gate. It is toolchain-GATED all the same: this verb does
    # not write the report, roam does, and compile-code's single contribution
    # is adopting roam's exit code as its own. That adoption is the assurance
    # claim, and `.roam/verify-report.json` is state a reader treats as a
    # verdict about this tree.
    _exit_on_roam_problem()
    raise SystemExit(_delegate("verify", "--report", "--persist"))


def _launch_agent(argv: list[str], env: dict[str, str], *, use_exec: bool | None = None) -> int:
    """Hand the console to the agent binary, mapping launch failures to the contract.

    POSIX replaces this process via exec, so a return only happens on failure;
    Windows runs the agent as a child because exec* there spawns-and-detaches
    (console handling breaks). ``use_exec`` lets tests pin either branch
    regardless of the platform they run on. The caller passes an absolute path
    re-resolved at the final readiness boundary; the binary can still vanish or
    become unlaunchable before exec, and that race ends in a verdict.

    Residual window: both branches take *argv[0]* as a path string, not a held
    file descriptor -- ``os.execv``/``subprocess.run`` reopen and reread the
    file themselves. The content-digest rechecks the caller performs (roam and
    claude both) narrow the tamper window to the last possible instant before
    this call, but cannot close it: there is no portable way on Windows to
    hand this function an already-verified handle instead of a path (no
    ``fexecve`` equivalent), so a swap landing in the microseconds between the
    last digest read and this function's own open-and-exec is not detected.
    That gap is orders of magnitude smaller than the one the digest closes
    (the whole multi-step preparation window) and is believed to be the
    practical floor for a path-based launcher on this platform.
    """
    if use_exec is None:
        use_exec = os.name != "nt"
    try:
        if use_exec:
            os.environ.update(env)
            os.execv(argv[0], argv)
            return 0  # only reachable when tests stub execv; exec does not return
        return subprocess.run(argv, check=False, env=env).returncode
    except FileNotFoundError:
        click.echo(f"VERDICT: `{argv[0]}` vanished from PATH mid-launch — reinstall it and rerun")
        return 1
    except OSError as exc:
        click.echo(f"VERDICT: could not launch `{argv[0]}` ({exc}) — reinstall it and rerun")
        return 1
    except KeyboardInterrupt:
        click.echo("VERDICT: interrupted")
        return 130


@cli.command("claude", context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.argument("agent_args", nargs=-1, type=click.UNPROCESSED)
@click.option("--read-only", is_flag=True, default=False, help="Enforce read-only mode for the launched agent.")
@click.option(
    "--allow-unwired",
    is_flag=True,
    default=False,
    help="Launch even if compile/Verify hooks cannot be proven active (explicit degraded mode).",
)
@click.pass_context
def _claude(ctx: click.Context, agent_args: tuple[str, ...], read_only: bool, allow_unwired: bool) -> None:
    """Launch Claude Code with the compile/verify loop active (all-in-one).

    Ensures the repo is indexed, wires the hooks and best-effort curated
    Roam permissions/guidance if absent, then execs the real `claude` with
    remaining arguments passed through. Use `--` when an agent argument
    collides with Compile's own options. The zero-learning-curve path:
    type `compile claude` instead of `claude`,
    everything else is your normal workflow.
    """
    claude_path, claude_reason = _resolve_trusted_executable("claude", reject_workspace=True)
    if not claude_path:
        detail = (
            "`claude` not found on PATH"
            if claude_reason == "missing"
            else "workspace-local `claude` rejected from PATH"
            if claude_reason == "workspace_path"
            else "the selected `claude` executable is not a trusted regular file"
        )
        click.echo(f"VERDICT: {detail} — install Claude Code outside the repository and rerun")
        ctx.exit(1)
    # `claude` is never version-checked or self-attested the way roam is above --
    # nothing here ever runs it before the exec decision. That leaves exactly
    # the gap the roam T4 fix closed: `_resolve_trusted_executable`'s recheck
    # below only compares resolved path *strings*, so a same-path, same-name
    # in-place content swap between this line and exec would be invisible to
    # it alone. Captured now, compared against a fresh read immediately before
    # handover (see the final recheck below and `_launch_agent`'s docstring
    # for the residual window that remains even with the digest in place).
    #
    # Cost is not roam-sized: roam's console-script stub is tens of KB, but a
    # real `claude` install is a bundled single-file runtime -- 272 MiB when
    # measured on 2026-08-07 -- and this function hashes it twice per launch (here and in
    # the final recheck below). Measured on that real install: ~0.6-1.0s per
    # hash, so up to ~1.2-2s of added latency per `compile claude` launch.
    # That is real, user-visible cost, not the sub-millisecond figure the
    # roam-side digest costs; it is paid once per launch, not per turn, and
    # is judged worth it against a silent full-console-takeover substitution.
    claude_digest = _content_digest(claude_path, max_bytes=MAX_CLAUDE_EXECUTABLE_BYTES)
    if claude_digest is None:
        click.echo(
            "VERDICT: the selected `claude` executable content could not be verified for launch "
            "— install Claude Code outside the repository and rerun"
        )
        ctx.exit(1)
    initial_roam_info = _inspect_roam()
    initial_roam_problem = _roam_problem(initial_roam_info)
    preparation_degraded = initial_roam_problem is not None
    wire_rc = 0
    if initial_roam_problem is not None:
        if not allow_unwired:
            exit_code, verdict = initial_roam_problem
            click.echo(f"{verdict}; agent not launched")
            ctx.exit(exit_code)
    else:
        exact_roam = str(initial_roam_info["path"])
        tool_env = _trusted_tool_env()
        rc = _ensure_indexed_for_launch(executable=exact_roam, env=tool_env)
        if rc != 0:
            ctx.exit(rc)
        # Idempotent wiring is part of this launcher's safety contract: claiming
        # the compile/Verify loop is active while launching without hooks is a
        # false success. Degraded launch remains available only by explicit opt-in.
        wiring_ready, wiring_reason = _claude_wiring_state()
        midtask_user_level = wiring_ready and wiring_reason == "user"
        if not wiring_ready:
            wire_rc = _delegate("hooks", "claude", "--write", executable=exact_roam, env=tool_env)
        if wire_rc == 0:
            _wire_roam_midtask_access(user_level=midtask_user_level)

    # Readiness is deliberately re-proven at the last boundary. A cached index,
    # HEAD marker, prior settings substring, or successful earlier write cannot
    # authorize launch. Inspect the exact Roam executable/version and parse the
    # concrete hook events/commands/bodies again immediately before exec.
    readiness_failures: list[str] = ["preparation"] if preparation_degraded else []
    roam_info = _inspect_roam()
    roam_problem = _roam_problem(roam_info)
    roam_changed = False
    if roam_problem is not None:
        readiness_failures.append("toolchain")
    elif initial_roam_problem is None and (
        roam_info.get("path") != initial_roam_info.get("path")
        or roam_info.get("version") != initial_roam_info.get("version")
    ):
        roam_changed = True
        readiness_failures.append("toolchain_changed")
    wiring_ready, wiring_reason = _claude_wiring_state()
    if wiring_ready and roam_problem is None and not roam_changed:
        # `_attest_claude_hooks` executes the resolved roam binary and trusts
        # what it prints about its own hook wiring -- the one place in this
        # chain where a substituted executable's self-report is believed
        # rather than checked. It is deliberately still called here even
        # though a digest is available, so the readiness state after this
        # line reflects what a real attacker would have gotten: one execution
        # of their payload under this launcher's trust.
        wiring_ready = _attest_claude_hooks(
            str(roam_info["path"]),
            str(roam_info["version"]),
            user_level=wiring_reason == "user",
        )
        if not wiring_ready:
            wiring_reason = "producer_attestation"
    if not wiring_ready:
        readiness_failures.append(f"hooks:{wiring_reason}")
    if (
        roam_problem is None
        and not roam_changed
        and initial_roam_problem is None
        and _content_digest(str(roam_info["path"])) != initial_roam_info.get("digest")
    ):
        # The one property above that is NOT self-reported by the executable:
        # its exact bytes, hashed from outside it, read as late as this
        # function can manage -- after the version self-report, after the
        # attestation self-report, immediately before the exec decision. A
        # substitution that preserves path and version (the historical gap
        # this closes), or one timed to land during the attestation call
        # itself, shows up here as a digest that no longer matches the one
        # taken before any of this untrusted code ran.
        roam_changed = True
        readiness_failures.append("toolchain_changed")
    final_claude_path, _final_claude_reason = _resolve_trusted_executable("claude", reject_workspace=True)
    final_claude_digest = (
        _content_digest(final_claude_path, max_bytes=MAX_CLAUDE_EXECUTABLE_BYTES) if final_claude_path else None
    )
    if not final_claude_path or final_claude_path != claude_path or final_claude_digest != claude_digest:
        # The digest is re-read here, as late as this function can manage --
        # after every roam/hooks check above, immediately before the exec
        # decision -- so a substitution that preserves path and name (the
        # same shape the roam T4 fix closed, one binary over) shows up as a
        # mismatch instead of matching on path string alone.
        click.echo(
            "VERDICT: Claude executable changed during readiness checks; agent not launched. Rerun `compile claude`."
        )
        ctx.exit(1)
    if readiness_failures:
        if not allow_unwired:
            if roam_problem is not None:
                exit_code, verdict = roam_problem
                click.echo(f"{verdict}; agent not launched")
                ctx.exit(exit_code)
            if roam_changed:
                click.echo(
                    "VERDICT: Roam executable/version changed during readiness checks; agent not launched. "
                    "Rerun `compile claude`."
                )
                ctx.exit(EXIT_TOOLCHAIN)
            click.echo(
                "VERDICT: wiring failed — complete UserPromptSubmit + Stop hooks and current bodies are not proven "
                "active; agent not launched. Run `compile wire claude`, or pass `--allow-unwired` to acknowledge "
                "degraded mode."
            )
            ctx.exit(wire_rc or 1)
        click.echo(
            "VERDICT: explicit degraded launch accepted (--allow-unwired) — compile/Verify readiness unavailable "
            f"({', '.join(readiness_failures)})"
        )
    child_env = os.environ.copy()
    child_env.setdefault("ROAM_AGENT_MODE", "compile_claude")
    if read_only:
        child_env.update(ROAM_AGENT_MODE="read_only", ROAM_MODE_ENFORCEMENT="1")
    raise SystemExit(_launch_agent([claude_path, *agent_args], child_env))


@cli.command("run")
@click.argument("task")
@click.option("--json", "json_out", is_flag=True, help="Emit the raw JSON envelope.")
def _run(task: str, json_out: bool) -> None:
    """Compile a task headlessly and print the envelope (scripts / CI).

    The envelope contains the classified intent, pre-resolved facts
    (callers, history, blast radius, bug-site source, ...) and an answer
    contract — paste-ready as an agent prompt prefix.
    """
    if not task.strip():
        click.echo(
            "VERDICT: empty task: task argument is empty or whitespace. "
            'Pass a navigation prompt, e.g. compile run "who calls handleSave?"'
        )
        raise SystemExit(1)
    # UNGATED BY DECISION — advisory only. This prints a compiled navigation
    # envelope: it asserts nothing about whether the code is correct, and it
    # writes no state any gated verb later reads. An unsupported roam that can
    # still answer "who calls this" is more useful than a refusal.
    args = (["--json"] if json_out else []) + ["compile", task, "--artifact", "auto"]
    with _default_agent_mode("compile"):
        raise SystemExit(_delegate(*args))


@cli.command("stats")
def _stats() -> None:
    """Show compile telemetry for this repo (routing, latency, cache)."""
    # UNGATED BY DECISION — advisory only. Reads this repo's local telemetry
    # log and prints it. No verdict, no assurance claim, no state a gated verb
    # consumes.
    raise SystemExit(_delegate("compile-stats"))


# `compile verify` is the one product command that emits a *rich* failure block
# instead of a one-line VERDICT: a verify failure is only actionable when it
# names the failing command, the changed files, a likely cause, and the single
# local rerun to run next. The helpers below keep that block in one place.

# roam verify check-section label -> human cause phrase (matches `roam verify`).
_VERIFY_CAUSE_LABELS = {
    "SYNTAX": "syntax error",
    "IMPORTS": "import problem",
    "NAMING": "naming violation",
    "DUPLICATES": "duplicate logic",
    "ERROR HANDLING": "error-handling gap",
    "CLAIMS": "unverified claim",
    "COMMAND EXAMPLES": "broken command example",
    "SECRETS": "exposed secret",
    "RULES": "governance rule violation",
    "PY TYPES": "type-annotation regression",
    "PY MODERN": "Python modernization regression",
    "CALC GOLDEN": "calculation semantic regression",
}
# A check section header, e.g. ``SYNTAX (0/100):`` or ``ERROR HANDLING (100/100):``.
_VERIFY_SECTION = re.compile(r"^([A-Z][A-Z _]+)\s*\(\d+/100\):\s*$")
# A failing check line, e.g. ``  FAIL: src/cli.py:5 -- <message>``.
_VERIFY_FAIL_LINE = re.compile(r"^\s*FAIL:\s*(.+?):\d+\b")
# Cause when no FAIL line was parseable — fall back to the roam exit code.
_EXIT_CAUSE = {2: "bad arguments", 3: "index missing", 4: "index stale", EXIT_VERIFY_GATE: "quality gate"}
_VERIFY_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "request_nonce",
        "scope_sha256",
        "content_sha256",
        "content_sha256_before",
        "content_sha256_after",
        "target_file_count",
        "scope_stable",
        "request_match",
    }
)
_VERIFY_VERDICTS = frozenset({"PASS", "WARN", "FAIL"})
_VERIFY_FINDING_SEVERITIES = frozenset({"FAIL", "WARN", "INFO"})
_VERIFY_DEFAULT_CHECKS = (
    "naming",
    "imports",
    "error_handling",
    "duplicates",
    "syntax",
    "import_side_effects",
    "restore_loss",
    "secrets",
)
_VERIFY_CHECK_NAMES = frozenset(
    {
        *_VERIFY_DEFAULT_CHECKS,
        "fabricated_success",
        "unreachable_except",
        "unchecked_result",
        "return_in_finally",
        "self_comparison",
        "redundant_boolean_return",
        "unreachable_after_return",
        "none_eq_comparison",
        "complexity",
        "cycles",
        "tests",
        "command_examples",
        "claims",
        "calc_divergence",
        "breaking",
        "taint",
        "tenant_scope",
        "delete_check",
        "migration_safety",
        "smells",
        "clones",
        "magic_numbers",
        "dead",
        "n1",
        "over_fetch",
        "llm_smells",
        "test_hermeticity",
    }
)
_VERIFY_DELETE_CHECK_SUPPORTED_SUFFIXES = frozenset(
    {".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go"}
)
_VERIFY_DELETE_CHECK_UNSUPPORTED_CODE_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".cs",
        ".ex",
        ".exs",
        ".java",
        ".kt",
        ".kts",
        ".php",
        ".rb",
        ".rs",
        ".scala",
        ".swift",
    }
)
_VERIFY_DELETE_CHECK_PUBLIC_REMOVAL = re.compile(r"^\s*(?:export\b|pub(?:\([^)]*\))?(?:\s|$)|public\b|def\s+(?!_)\w+)")
_VERIFY_DELETE_CHECK_SUPPORTED_REMOVAL = re.compile(
    r"^\s*(?:(?:async\s+)?def\s+(?!_)\w+\s*\(|class\s+(?!_)\w+\s*[:(]|"
    r"(?:export\s+)?(?:async\s+)?function\s+\w+\s*\(|(?:export\s+)?class\s+\w+\b|"
    r"(?:export\s+)?const\s+\w+\s*=|func\s+(?:\([^)]*\)\s*)?\w+\s*\(|"
    r"type\s+\w+\s+(?:struct|interface)\b|(?:export\s+)?(?:type|interface)\s+\w+\b)"
)
_VERIFY_AUTO_CHECK_REGISTRY = (
    (
        "rules",
        "Any edit triggers a bounded .roam/rules YAML declaration probe; declared rules run, while an absent "
        "or empty declaration set reports not_applicable.",
    ),
    (
        "py-types",
        "Python edits run a bounded annotation-health probe and compare edited public symbols with their Git "
        "pre-edit type surface; non-Python edits report not_applicable and absolute legacy debt never gates.",
    ),
    (
        "py-modern",
        "Python edits run a bounded modernization probe and compare outdated constructs in touched files with "
        "their Git pre-edit state; non-Python edits report not_applicable and absolute legacy debt never gates.",
    ),
    (
        "calc-golden",
        "Edits to source files bound by .roam/calc-golden JSON declarations replay golden cases against the "
        "current and Git pre-edit calculations; absent declarations and unrelated edits report not_applicable.",
    ),
    (
        "collapse",
        "Python and JavaScript/TypeScript edits run bounded collapse scans over the same edited files in the "
        "current and Git pre-edit state; absolute legacy debt never gates.",
    ),
)
_VERIFY_RULE_CONFIG_STATES = frozenset(
    {"ok", "missing", "empty_file", "empty_yaml", "read_error", "parse_error", "wrong_root_type", "schema_invalid"}
)
_VERIFY_RULE_SEVERITIES = frozenset({"error", "warning", "info"})
_VERIFY_RULE_GATING_SEVERITIES = frozenset({"error"})
MAX_VERIFY_RULE_DECLARATION_ENTRIES = 4096
MAX_VERIFY_RULE_FINDINGS = 10
MAX_VERIFY_RULE_TEXT_CHARS = 1024
MAX_VERIFY_TYPE_SOURCE_BYTES = 4 * 1024 * 1024
MAX_VERIFY_TYPE_TOTAL_SOURCE_BYTES = 32 * 1024 * 1024
MAX_VERIFY_TYPE_DETAIL_FILES = 25
MAX_VERIFY_TYPE_ENVELOPE_FINDINGS = MAX_VERIFY_TYPE_DETAIL_FILES * 5
MAX_VERIFY_TYPE_FINDINGS = 10
MAX_VERIFY_TYPE_TEXT_CHARS = 1024
_VERIFY_TYPE_EMPTY_STATES = frozenset({"no_python_files", "no_public_python_functions"})
_VERIFY_TYPE_ISSUE = re.compile(r"^(?:no-return|uses-Any|legacy-typing|[1-9]\d*-untyped)$")
_VERIFY_TYPE_TOTAL_DEFINITION = "public Python functions/methods; test files excluded unless --include-tests is set"
_VERIFY_TYPE_COVERAGE_DEFINITION = "(total_public - max(no_return_annotation, untyped_params)) * 100 // total_public"
MAX_VERIFY_MODERN_DETAIL_FILES = 25
MAX_VERIFY_MODERN_ENVELOPE_OCCURRENCES = MAX_VERIFY_MODERN_DETAIL_FILES * 5
MAX_VERIFY_MODERN_FINDINGS = 10
MAX_VERIFY_MODERN_TEXT_CHARS = 1024
_VERIFY_CALC_GOLDEN_DECLARATION_SCHEMA = "compile-code.calc-golden.v1"
_VERIFY_CALC_SOURCE_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".cs",
        ".go",
        ".java",
        ".js",
        ".jsx",
        ".kt",
        ".mjs",
        ".php",
        ".py",
        ".rb",
        ".rs",
        ".ts",
        ".tsx",
        ".vue",
    }
)
MAX_VERIFY_CALC_DECLARATION_ENTRIES = 4096
MAX_VERIFY_CALC_DECLARATIONS = 8
MAX_VERIFY_CALC_DECLARATION_BYTES = 64 * 1024
MAX_VERIFY_CALC_CORPUS_BYTES = 16 * 1024 * 1024
MAX_VERIFY_CALC_TOTAL_CORPUS_BYTES = 32 * 1024 * 1024
MAX_VERIFY_CALC_RUNNER_ARGS = 32
MAX_VERIFY_CALC_SOURCES = 256
MAX_VERIFY_CALC_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_VERIFY_CALC_ARCHIVE_ENTRIES = 20_000
MAX_VERIFY_CALC_ENVELOPE_FAILURES = 20
MAX_VERIFY_CALC_DELTA_FIELDS = 16
MAX_VERIFY_CALC_FINDINGS = 10
MAX_VERIFY_CALC_TEXT_CHARS = 1024
VERIFY_CALC_RUNNER_TIMEOUT = 60
_VERIFY_COLLAPSE_SOURCE_SUFFIXES = frozenset(
    {".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
)
_VERIFY_COLLAPSE_LANGUAGES = ("python", "javascript", "typescript", "tsx", "bash")
_VERIFY_COLLAPSE_RULES = {
    "catch-to-benign-literal": (
        "catch returns only a benign literal",
        "Return a typed failure reason or rethrow after recording the error.",
    ),
    "enoent-conflation": (
        "unreadable file is treated as absent",
        "Check the error code and preserve a distinct failure state.",
    ),
    "fallback-or-zero-on-measurement": (
        "failed measurement falls back to zero",
        "Preserve measurement failure separately from numeric zero.",
    ),
    "shell-echo-fallback": (
        "failed shell command echoes a benign literal",
        "Emit a distinct failure state instead of echoing a benign literal.",
    ),
    "parse-failure-merges-with-empty": (
        "invalid input is treated as empty input",
        "Represent invalid input separately from empty input.",
    ),
}
_VERIFY_COLLAPSE_SEVERITIES = frozenset({"high", "medium"})
_VERIFY_COLLAPSE_SUPPRESSION_COMMENT = "roam: ignore-collapse[rule-id]"
_VERIFY_COLLAPSE_METRIC_DEFINITION = "Per-occurrence count of distinct collapsed error/default sites."
MAX_VERIFY_COLLAPSE_SOURCE_BYTES = 4 * 1024 * 1024
MAX_VERIFY_COLLAPSE_TOTAL_SOURCE_BYTES = 32 * 1024 * 1024
MAX_VERIFY_COLLAPSE_ENVELOPE_FINDINGS = 4096
MAX_VERIFY_COLLAPSE_FINDINGS = 10
MAX_VERIFY_COLLAPSE_TEXT_CHARS = 1024
_VERIFY_MODERN_FEATURE_KEYS = (
    "walrus",
    "match_stmt",
    "pep604",
    "pep585",
    "legacy_typing",
    "pep695",
    "fstring",
    "dot_format",
)
_VERIFY_MODERN_LEGACY_TYPING = re.compile(r"\b(?:Optional|Dict|List|Set|Tuple|FrozenSet|Type)\[")
_VERIFY_MODERN_DOT_FORMAT = re.compile(r"['\"]\s*\.format\s*\(")
_VERIFY_CATEGORY_NAMES = _VERIFY_CHECK_NAMES | {"verification"}
# There is deliberately no hand-copied "categories allowed to WARN on a PASS"
# set here. Roam declares advisory-ness per category in the envelope it sends,
# and derives its verdict from the score alone; a local copy of that judgement
# was stale by construction and refused normal output. See the PASS branch of
# `_validate_verify_protocol`.
_VERIFY_NO_CHANGES_CATEGORY_NAMES = frozenset(
    {
        "naming",
        "imports",
        "error_handling",
        "duplicates",
        "syntax",
        "import_side_effects",
        "restore_loss",
        "fabricated_success",
        "unreachable_except",
        "unchecked_result",
        "return_in_finally",
        "self_comparison",
        "redundant_boolean_return",
        "unreachable_after_return",
        "none_eq_comparison",
        "complexity",
        "cycles",
        "tests",
        "secrets",
        "verification",
    }
)
_VERIFY_ENVELOPE_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "command",
        "version",
        "project",
        "summary",
        "categories",
        "violations",
        "agent_contract",
        "_meta",
    }
)
_VERIFY_SUMMARY_KEYS = frozenset(
    {
        "verdict",
        "score",
        "threshold",
        "files_checked",
        "violation_count",
        "checks_run",
        "verification_complete",
        "partial_success",
        "state",
        "verification_receipt",
        "targets_checked",
        "quality_band",
        "index_refresh",
        "scope",
        "diff_scoped",
        "baseline",
        "baselined",
        "suppressed",
        "max_blast_radius",
        "blast_radius_definition",
        "file_remaining",
        "target_wave_violation_count",
        "residual_violation_count",
        "residual_findings_non_gating",
        "severity_filter",
        "shown_count",
        "total_count",
        "incomplete_reasons",
        # Known and gated below (`truncated is True` is a summary_binding
        # failure); listed so the gate is reachable rather than pre-empted by
        # the shape check.
        "truncated",
    }
)
_VERIFY_CATEGORY_KEYS = frozenset(
    {
        "score",
        "violation_count",
        "violations",
        "parse_failures",
        "available",
        "unavailable_reason",
        "execution_state",
        "timed_out",
        "partial_success",
        "capped",
        "tests_targeted",
        "tests_failed",
        "tests_total_impacted",
        "no_impacted_tests",
        # Why a repo-local leak catalogue contributed no patterns to this
        # category. Roam ships this on `secrets` and it is NOT a gate on its
        # own: the overwhelmingly common cause is a repository that contains a
        # catalogue nobody opted into executing, which is roam declining to run
        # untrusted repo config and is the correct, expected default. The other
        # cause -- a catalogue that was opted into and then failed to load -- is
        # a security check the operator asked for that did not run, and roam
        # signals THAT by additionally marking the category `execution_state:
        # incomplete`, which the category loop below already refuses. Read this
        # build's own limit plainly: the two causes are one free-text string
        # here, so nothing in this file can tell them apart, and the gating
        # decision rests on roam's `execution_state`. It is carried as a known
        # field rather than left unknown so the disclosure is rendered as the
        # security fact it is instead of as unreadable schema drift.
        "repo_patterns_error",
    }
)
# Forward tolerance is for fields that are unknown AND neutral. A field this
# build has never heard of whose *name* asserts that something did not fully
# run is not neutral: ignoring it would let a producer downgrade its own
# verification behind a rename and have this gate report a clean pass. Any of
# these names appearing where this build has no interpretation for it is
# refused rather than disclosed. Names already in a level's vocabulary keep
# their existing precise handling (`timed_out: False` stays legal on a
# category, `truncated: True` stays a summary_binding failure) -- this set only
# bites where the field would otherwise be silently dropped.
_VERIFY_INCOMPLETENESS_NAMES = frozenset(
    {
        "aborted",
        "approximate",
        "available",
        "best_effort",
        "canceled",
        "cancelled",
        "capped",
        "degraded",
        "did_not_run",
        "error",
        "errors",
        "failed",
        "failure",
        "fallback",
        "incomplete",
        # Roam envelope fields that mean payload was dropped or a fallback
        # fired; this build asks for an unbudgeted envelope precisely so they
        # cannot appear, and their arrival is news, not noise.
        "list_counts",
        "not_run",
        "parse_failures",
        "partial",
        "redactions",
        "skip",
        "skip_reason",
        "skipped",
        "skipped_reason",
        "stale",
        "timed_out",
        "timeout",
        "truncated",
        "unavailable",
        "unavailable_reason",
        "unsupported",
        "unverified",
        "warnings",
    }
)
# Tokens that carry the assertion above inside a COMPOUND field name. Whole-name
# equality against the set above was the entire test for eight releases, and it
# is defeated by exactly the move it exists to stop: measured against roam
# 14.0.0 through a shim that delegates to the real binary and changes one field,
# `categories.secrets.skipped = true` refuses at exit 2, while
# `categories.secrets.secrets_skipped = true` -- the same assertion, one token
# of prefix -- renders VERDICT: PASS at exit 0 with the field listed under
# "fields this build does not read". `scan_timed_out` and
# `catalogue_unavailable` bought the same pass, at category and summary level
# alike. This is not a hypothetical naming style: the producer already writes
# compound names in this exact position (`repo_patterns_error`, now known
# above), so the next incompleteness signal roam names after the thing it is
# about would have gone straight through.
#
# Derived from the names rather than hand-listed, so the two cannot drift, minus
# the tokens too generic to carry the assertion alone (`run` would refuse a
# neutral `symbols_run`; `reason`, `parse`, `list`, `counts`, `out`, `best`,
# `effort`, `did` are qualifiers, not claims) and plus the morphological
# variants those names only spell in compound (`timed`, `failures`). Over-
# refusal is the safe direction here and is bounded: it can only bite a field
# this build has no interpretation for, and it fails loudly, naming the field.
_VERIFY_INCOMPLETENESS_GENERIC_TOKENS = frozenset(
    {"best", "counts", "did", "effort", "list", "out", "parse", "reason", "run"}
)
_VERIFY_INCOMPLETENESS_TOKENS = (
    frozenset(token for name in _VERIFY_INCOMPLETENESS_NAMES for token in name.split("_"))
    - _VERIFY_INCOMPLETENESS_GENERIC_TOKENS
) | {"failures", "timed"}


def _asserts_incompleteness(name: object) -> bool:
    """Whether one field NAME claims something did not fully run.

    Only ever asked about names this build has no interpretation for; a name in
    a level's vocabulary keeps its existing precise handling.
    """
    if not isinstance(name, str):
        return False
    return name in _VERIFY_INCOMPLETENESS_NAMES or bool(set(name.split("_")) & _VERIFY_INCOMPLETENESS_TOKENS)


_VERIFY_CATEGORY_REQUIRED_KEYS = frozenset({"score", "violation_count", "violations"})
_VERIFY_NO_CHANGES_CATEGORY_KEYS = frozenset({"score", "violations"})
_VERIFY_NO_CHANGES_VERIFICATION_KEYS = frozenset({"score", "violations", "available"})
_VERIFY_SCOPE_KEYS = frozenset(
    {
        "target_file_count",
        "indexed_file_count",
        "non_code_file_count",
        "unresolved_file_count",
        "non_code_scope_definition",
        "unresolved_existing_code_count",
    }
)
_VERIFY_SCOPE_REQUIRED_KEYS = frozenset({"target_file_count", "indexed_file_count", "non_code_file_count"})
_VERIFY_NON_CODE_SCOPE_DEFINITION = (
    "Docs/product-copy surfaces are included for advisory checks such as "
    "command_examples and claims; code-gating checks use indexed source files."
)
_VERIFY_NO_CHANGES_SUMMARY_KEYS = frozenset(
    {
        "verdict",
        "score",
        "threshold",
        "files_checked",
        "violation_count",
        "checks_run",
        "verification_complete",
        "partial_success",
        "state",
    }
)


def _scope_path_separators(value: str) -> str:
    """Canonicalize filesystem separators only where backslash is not a filename byte."""
    return value.replace("\\", "/") if os.name == "nt" else value


def _require_utf8_scope_text(value: str) -> str:
    """Reject surrogate-escaped filenames instead of silently substituting bytes."""
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ValueError("scope_path_undecodable") from exc
    return value


def _decode_verify_status_path(raw: bytes) -> str:
    try:
        value = os.fsdecode(raw)
    except UnicodeError as exc:
        raise ValueError("scope_path_undecodable") from exc
    return _scope_path_separators(_require_utf8_scope_text(value))


def _parse_changed_status_paths(raw: str) -> list[str]:
    """Parse NUL-delimited porcelain status for best-effort failure context.

    Rename records contain the destination followed by the source; include
    both. Copy records consume their source without claiming it changed.
    """
    records = raw.split("\0")
    paths: list[str] = []
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if len(record) < 4:
            continue
        status = record[:2]
        path = _scope_path_separators(_require_utf8_scope_text(record[3:]))
        if path:
            paths.append(path)
        if "R" in status or "C" in status:
            source = _scope_path_separators(_require_utf8_scope_text(records[index])) if index < len(records) else ""
            index += 1
            if "R" in status and source:
                paths.append(source)
    return list(dict.fromkeys(paths))


def _changed_files() -> list[str]:
    """Best-effort status-aware paths for the human failure block only."""
    executable, _reason = _resolve_trusted_executable("git", reject_workspace=True)
    if not executable:
        return []
    try:
        proc = _run_bounded_capture(
            [executable, "-c", "core.fsmonitor=false", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            timeout=10,
            stdout_limit=MAX_VERIFY_GIT_STATUS_BYTES,
            stderr_limit=MAX_VERIFY_STDERR_BYTES,
            env=_trusted_tool_env(git=True),
        )
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return []
    if proc.returncode != 0 or len(proc.stdout or b"") > MAX_VERIFY_GIT_STATUS_BYTES:
        return []
    try:
        return [path for _status, path in _parse_verify_status_records(proc.stdout or b"")]
    except ValueError:
        return []


def _oversized_target_set(targets: list[str], cap: int = 25) -> str | None:
    """Return an advisory for an explicitly oversized target set."""
    if len(targets) <= cap:
        return None
    return (
        f"note: verifying {len(targets)} files at once (> {cap}); scope down with an explicit smaller file list "
        "for a faster, sharper check."
    )


def _verification_root() -> Path:
    """Find the nearest indexed/Git project root without launching a helper."""
    try:
        current = Path.cwd().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("verification_root_unavailable") from exc
    for candidate in (current, *current.parents):
        if (candidate / ".roam" / "index.db").exists() or (candidate / ".git").exists():
            return candidate
    return current


def _traversal_position(directories: int, entries: int, elapsed: float) -> str:
    """Describe where a bounded traversal stood on EVERY axis, not only the one that fired.

    Three bounds share one loop: a directory count, an entry count and a wall
    clock. Which one trips is decided by the user's filesystem throughput, not
    by policy -- the same tree on the same machine has reported a different
    reason on a different day. Naming only the bound that fired therefore
    reports a coin flip as if it were a finding, and tells the reader nothing
    about how far the other bounds were from firing. Every branch reports the
    same three coordinates so the reason is reproducible reading rather than a
    race outcome. This discloses more; it moves no bound and refuses nothing
    extra.
    """
    rate = f"{directories / elapsed:.0f}" if elapsed > 0 else "unmeasured"
    return (
        f"{directories} of {MAX_VERIFY_DIRECTORIES} directories, "
        f"{entries} of {MAX_VERIFY_DIRECTORY_ENTRIES} entries, "
        f"{elapsed:.1f}s of {MAX_VERIFY_TRAVERSAL_SECONDS:g} (~{rate} dirs/s)"
    )


def _expand_verify_targets(targets: list[str], root: Path) -> list[str]:
    """Expand explicit directories deterministically under closed resource bounds."""
    try:
        canonical_root = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("verification_root_unavailable") from exc
    directories: list[tuple[str, Path]] = []
    expanded: list[str] = []
    for relative in targets:
        candidate = canonical_root / Path(relative)
        try:
            candidate_state = candidate.lstat()
        except FileNotFoundError:
            expanded.append(relative)
            continue
        except OSError as exc:
            raise ValueError("verification_directory_unreadable") from exc
        if stat.S_ISDIR(candidate_state.st_mode) and not _is_link_or_reparse(candidate_state):
            directories.append((relative, candidate))
        else:
            expanded.append(relative)
    if not directories:
        return expanded
    if len(expanded) > MAX_VERIFY_TARGETS:
        raise ValueError("verification_target_limit")

    seen = set(expanded)
    seen_directories: set[str] = set()
    skip_dirs = NON_SOURCE_SCOPE_DIRECTORIES
    pending = deque(path for _relative, path in directories)
    directory_count = 0
    entry_count = 0
    started = time.monotonic()
    deadline = started + MAX_VERIFY_TRAVERSAL_SECONDS
    while pending:
        # Read the clock ONCE per check and reuse it for the disclosure. A
        # second `time.monotonic()` call at the raise site would report a
        # different instant than the one that decided the refusal.
        now = time.monotonic()
        if now > deadline:
            raise ValueError(
                "verification_directory_timeout: " + _traversal_position(directory_count, entry_count, now - started)
            )
        current = pending.popleft()
        current_key = os.path.normcase(str(current))
        if current_key in seen_directories:
            continue
        seen_directories.add(current_key)
        directory_count += 1
        if directory_count > MAX_VERIFY_DIRECTORIES:
            raise ValueError(
                "verification_directory_limit: "
                + _traversal_position(directory_count, entry_count, time.monotonic() - started)
            )
        before = _validated_verify_directory_state(current, canonical_root)
        names: list[str] = []
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    entry_count += 1
                    if entry_count > MAX_VERIFY_DIRECTORY_ENTRIES:
                        raise ValueError(
                            "verification_directory_entry_limit: "
                            + _traversal_position(directory_count, entry_count, time.monotonic() - started)
                        )
                    now = time.monotonic()
                    if now > deadline:
                        raise ValueError(
                            "verification_directory_timeout: "
                            + _traversal_position(directory_count, entry_count, now - started)
                        )
                    names.append(entry.name)
        except ValueError:
            raise
        except OSError as exc:
            raise ValueError("verification_directory_unreadable") from exc

        child_directories: list[Path] = []
        for name in sorted(names):
            child = current / name
            try:
                child_state = child.lstat()
            except OSError as exc:
                raise ValueError("verification_directory_changed") from exc
            if _is_link_or_reparse(child_state):
                raise ValueError("verification_directory_unsafe")
            if stat.S_ISDIR(child_state.st_mode):
                if name not in skip_dirs:
                    child_directories.append(child)
                continue
            if not stat.S_ISREG(child_state.st_mode):
                raise ValueError("verification_directory_unsafe")
            try:
                relative = child.relative_to(canonical_root).as_posix()
            except ValueError as exc:
                raise ValueError("scope_path_outside_root") from exc
            if relative not in seen:
                if len(expanded) >= MAX_VERIFY_TARGETS:
                    raise ValueError("verification_target_limit")
                expanded.append(relative)
                seen.add(relative)
        after = _validated_verify_directory_state(current, canonical_root)
        if not _same_verification_file_state(before, after):
            raise ValueError("verification_directory_changed")
        pending.extend(child_directories)
    if not expanded:
        raise ValueError("verification_directory_empty")
    ordered_expanded = sorted(expanded)
    for relative, _directory in directories:
        prefix = f"{relative}/"
        index = bisect_left(ordered_expanded, prefix)
        if index >= len(ordered_expanded) or not ordered_expanded[index].startswith(prefix):
            raise ValueError("verification_directory_empty")
    return expanded


def _validated_verify_directory_state(directory: Path, root: Path) -> os.stat_result:
    """Bind one traversed directory to a concrete non-reparse path under root."""
    try:
        state = directory.lstat()
        resolved = directory.resolve(strict=True)
        resolved_state = resolved.stat()
    except (OSError, RuntimeError) as exc:
        raise ValueError("verification_directory_unreadable") from exc
    if (
        _is_link_or_reparse(state)
        or not stat.S_ISDIR(state.st_mode)
        or not _path_is_within(resolved, root)
        or os.path.normcase(str(resolved)) != os.path.normcase(str(directory.absolute()))
        or not _same_path_identity(state, resolved_state)
    ):
        raise ValueError("verification_directory_unsafe")
    return state


def _parse_verify_status_records(raw: bytes) -> list[tuple[str, str]]:
    """Parse NUL-delimited porcelain v1 into ``(two-char status, path)`` records.

    The status column is the cheap trackedness oracle git already put in the
    output. Discarding it -- as this parser used to -- forces every later scope
    decision onto the path NAME, which cannot tell a live untracked index from
    tracked source that happens to live under a directory called ``venv``.
    """
    if raw and not raw.endswith(b"\0"):
        raise ValueError("changed_file_discovery_malformed")
    records = raw.split(b"\0")
    found: dict[str, str] = {}
    index = 0
    while index < len(records):
        raw_record = records[index]
        index += 1
        if not raw_record:
            continue
        record = _decode_verify_status_path(raw_record)
        if len(record) < 4:
            raise ValueError("changed_file_discovery_malformed")
        status = record[:2]
        path = record[3:]
        if path:
            found.setdefault(path, status)
        if "R" in status or "C" in status:
            if index >= len(records) or not records[index]:
                raise ValueError("changed_file_discovery_malformed")
            source = _decode_verify_status_path(records[index])
            index += 1
            if "R" in status and source:
                # A rename source is in HEAD by construction, so it carries the
                # rename's own status and is never mistaken for untracked.
                found.setdefault(source, status)
    return [(status, path) for path, status in found.items()]


def _discover_verify_targets(root: Path) -> list[tuple[str, str]]:
    """Resolve the complete worktree scope; discovery failure loses evidence.

    Returns ``(status, path)`` records, not bare paths: the caller narrows on
    trackedness and cannot recover the status column afterwards.
    """
    git_path, _reason = _resolve_trusted_executable("git", reject_workspace=True)
    if not git_path:
        raise ValueError("changed_file_discovery_failed")
    env = _trusted_tool_env(git=True)
    try:
        proc = _run_bounded_capture(
            [git_path, "-c", "core.fsmonitor=false", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            cwd=str(root),
            timeout=10,
            stdout_limit=MAX_VERIFY_GIT_STATUS_BYTES,
            stderr_limit=MAX_VERIFY_STDERR_BYTES,
            env=env,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("changed_file_discovery_failed") from exc
    if proc.returncode != 0 or len(proc.stdout or b"") > MAX_VERIFY_GIT_STATUS_BYTES:
        raise ValueError("changed_file_discovery_failed")
    return _parse_verify_status_records(proc.stdout or b"")


def _partition_non_source_scope(paths: list[str], *, untracked: Container[str]) -> tuple[list[str], list[str]]:
    """Split discovered paths into source and tool state, preserving order.

    A path is tool state when it is UNTRACKED **and** any of its DIRECTORY
    components is one of ``NON_SOURCE_SCOPE_DIRECTORIES``; the final component is
    deliberately exempt, so a tracked file named ``venv`` or ``.roamignore``
    stays in scope.

    Trackedness is the discriminator, not the name. The concern that produced
    this narrowing is a LIVE, MOVING, UNTRACKED index -- roam's own
    ``.roam/index.db-wal``, reported file by file by ``git status -uall``, which
    no scope can bind because it changes while it is read. That argument does
    not reach a path the project has committed: ``git add`` is the project
    declaring this is source, the bytes are not moving under the reader, and
    dropping it removes real code from ``--changed`` coverage. CPython itself
    ships ``Lib/venv/__init__.py``; a directory name is not a measurement.

    ``untracked`` is a required argument, not an optional one, because the
    unsafe default is the silent one: assume-untracked drops tracked source with
    no error, while assume-tracked can only ever fail loudly at bind time.
    """
    source: list[str] = []
    tool_state: list[str] = []
    for path in paths:
        parents = PurePosixPath(path).parts[:-1]
        if path in untracked and any(part in NON_SOURCE_SCOPE_DIRECTORIES for part in parents):
            tool_state.append(path)
        else:
            source.append(path)
    return source, tool_state


def _narrowed_scope_directories(excluded: Sequence[str]) -> list[str]:
    """The directory names responsible for a narrowing, sorted.

    Only names from ``NON_SOURCE_SCOPE_DIRECTORIES`` are ever returned -- never
    the discovered paths themselves, which are filesystem-supplied text this
    surface does not replay into a verdict block.
    """
    return sorted(
        {part for path in excluded for part in PurePosixPath(path).parts[:-1] if part in NON_SOURCE_SCOPE_DIRECTORIES}
    )


def _narrowed_scope_suffix(excluded: Sequence[str]) -> str:
    """Render the narrowing as a clause the VERDICT line itself carries.

    A note printed *above* a verdict is a separate line a reader can take the
    PASS without: the verdict then publishes a denominator ("N changed files")
    that silently excludes what discovery dropped. Attaching the clause to the
    verdict makes the reduced denominator unreadable-around.
    """
    if not excluded:
        return ""
    names = ", ".join(_narrowed_scope_directories(excluded)) or "tool-state directories"
    return f"; scope narrowed: {len(excluded)} untracked path(s) under {names} excluded"


def _suppressed_findings_suffix(summary: Mapping[str, object]) -> str:
    """Render roam's own suppression count as a clause the VERDICT line carries.

    Same reasoning as ``_narrowed_scope_suffix`` and the same position, for the
    same reason: the verdict publishes an issue count that a repo-local
    ``.roam-suppressions.yml`` already subtracted from, and roam recomputes the
    SCORE over the reduced set, so a suppression can lift a run across its own
    threshold. A PASS over a reduced finding set has to say so in the same
    sentence as the PASS, or the reader takes the PASS and never reaches the
    disclosure.

    Nothing producer-supplied is echoed: only the integer, already validated as
    a plain non-negative count, and a filename this build spells itself.
    """
    count = summary.get("suppressed")
    if type(count) is not int or count <= 0:
        return ""
    return f"; {count} finding{'s' if count != 1 else ''} suppressed by .roam-suppressions.yml"


def _declared_filter_warn(summary: Mapping[str, object], verdict: object, quality_band: str) -> bool:
    """Whether WARN-over-a-PASS-band is roam's documented post-filter recompute.

    Roam runs a SECOND verdict rule once a filter has removed findings. Read
    from roam 14.0.0: `_filtered_verdict_score` (cmd_verify.py:5820) answers
    "did any gating finding survive" -- `max(0, 100 - 5n)` with verdict WARN for
    any surviving non-syntax finding -- while `quality_band` (cmd_verify.py:6533)
    independently answers "what band does that score fall in". For 1..4
    survivors those two questions give WARN over a PASS band at score
    95/90/85/80. That is ordinary output, and this gate refused the whole
    transaction as a broken receipt with a remedy that reinstalls a roam which
    is behaving correctly.

    Measured against roam 14.0.0 with no mutation, all three entrances:
    `--diff-only` (`diff_scoped: true`), a checked-in `.roam-suppressions.yml`
    on a DEFAULT `compile verify` with no flag at all (`suppressed: 3`), and
    `--new-only` over a written baseline (`baselined: 4`). Each produced
    verdict WARN, score 95, quality_band PASS, and exit 2.

    Four properties keep this from being a relaxation:

    * DIRECTIONAL. Only WARN under a PASS band is admitted. `verdict == "PASS"`
      over a WARN or FAIL band -- the only direction that could overstate a
      result -- stays refused, as does WARN over a FAIL band, which is the one
      cell that could launder a low score into an exit-0 transaction.
    * FILTER-DECLARED. An unfiltered run cannot honestly produce a mismatch:
      re-derived from roam's source, the unfiltered verdict is
      `_compute_verdict(score)` -- the band itself -- and the two adjusters that
      can move it before the band is computed either move the score with it
      (`_apply_secrets_verdict_floor` pins both to WARN) or leave the enum
      (`_apply_syntax_degraded_verdict` appends a qualifier, refused earlier by
      `verdict_enum`). So a mismatch with no declared filter stays refused.
    * NO FLOOR REMOVED. The success branch still demands exit 0, `score >=` the
      threshold this process requested, no FAIL finding anywhere in the
      evidence, and roam's band agreeing with the band recomputed here.
    * NOTHING BOUGHT. Trusting the producer's filter flag costs nothing,
      because WARN and PASS take the SAME success branch: forging the flag only
      lets a producer publish a weaker label. `diff_scoped` is separately bound
      to the request, so it cannot even be forged on a run that did not ask.
    """
    if verdict != "WARN" or quality_band != "PASS":
        return False
    if summary.get("diff_scoped") is True:
        return True
    return any(type(summary.get(name)) is int and summary[name] > 0 for name in ("suppressed", "baselined"))


def _diff_scope_suffix(diff_only: bool) -> str:
    """Render `--diff-only` as a clause the VERDICT line carries.

    Keyed on the REQUEST this process made, not on roam's ``summary.diff_scoped``.
    Two measurements against roam 14.0.0 decided that. First, the producer must
    not be able to silence the disclosure: keying on the field would let a
    filtered result arrive with the field omitted and read as a whole-file
    verdict. Second, `diff_scoped` is genuinely absent on honest `--diff-only`
    runs that scoped nothing -- a clean file emits no filter fields at all, and
    an untracked file has no diff baseline, so `--diff-only` reported two
    findings over the WHOLE file with `diff_scoped` absent.

    That second row is why the wording names the request rather than asserting
    what roam did: "verdict scoped to changed lines (--diff-only)" is true in
    both rows, and where it over-states the reduction it does so in the
    conservative direction -- a reader who assumes less was checked than was is
    not harmed by a clean result, whereas a reader who takes an unannounced
    filtered PASS is. The field itself is bound to the request separately, in
    `_validate_verify_protocol`, so it can never arrive claiming a filter this
    process did not ask for.
    """
    return "; verdict scoped to changed lines (--diff-only)" if diff_only else ""


def _narrowed_scope_notice(excluded: Sequence[str]) -> str:
    """Name what discovery dropped on the paths that never reach a verdict line."""
    names = ", ".join(_narrowed_scope_directories(excluded)) or "tool-state directories"
    return (
        f"note: {len(excluded)} untracked path(s) under {names} are tool state, not source, "
        "and were excluded from the verification scope."
    )


def _unignored_tool_state_note(excluded: Sequence[str]) -> str:
    """Explain the one failure this narrowing cannot repair, with a real remedy.

    With no source path left, verify has nothing to bind and delegates
    ``--changed`` to roam, which re-discovers the same tool state under its own
    rules. When roam does not ignore it either, the run cannot bind its scope --
    and no roam version fixes that, because the project is asking both tools to
    verify a live index.

    The ``.gitignore`` remedy is true *because* narrowing is untracked-only:
    every path in ``excluded`` is one git has never been told about, so ignoring
    it removes it from ``git status -uall`` and from the next discovery. It was
    false while narrowing keyed on the directory name, since ``.gitignore``
    does not untrack an already-tracked path.
    """
    names = " ".join(f"{name}/" for name in _narrowed_scope_directories(excluded)) or "those directories"
    return (
        "note: no source path changed, so `roam verify --changed` rediscovered the excluded tool state itself. "
        f"Add {names} to .gitignore and rerun `compile verify --changed`."
    )


def _discovered_scope(root: Path) -> tuple[list[str], list[str]]:
    """Discover the changed scope and split it once, for every caller alike.

    Every discovered path is validated before any of it is dropped, so an
    unsafe path under a tool-state directory still refuses the run instead of
    being narrowed away unexamined.
    """
    records = _discover_verify_targets(root)
    validated = _verification_scope_paths([path for _status, path in records])
    untracked = {path for status, path in records if status == GIT_STATUS_UNTRACKED}
    return _partition_non_source_scope(validated, untracked=untracked)


def _verification_scope_paths(targets: list[str]) -> list[str]:
    normalized: set[str] = set()
    for index, path in enumerate(targets):
        if not isinstance(path, str):
            raise ValueError(f"scope_path_not_text: target index {index}")
        try:
            value = _scope_path_separators(_require_utf8_scope_text(path))
        except ValueError as exc:
            raise ValueError(f"{exc}: target index {index}") from exc
        if not value:
            raise ValueError(f"scope_path_empty: target index {index}")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            escaped = repr(value)
            if re.search(r"(?:token|secret|password|passwd|api[_-]?key|private[_-]?key|credential)", value, re.I):
                escaped = "<credential-shaped path omitted>"
            raise ValueError(f"scope_path_control_character: target index {index}, path {escaped}")
        parsed = PurePosixPath(value)
        if (
            parsed.is_absolute()
            or re.match(r"^[A-Za-z]:/", value)
            or any(part in {".", "..", ""} for part in parsed.parts)
            or parsed.as_posix() != value
        ):
            raise ValueError(f"scope_path_not_canonical: target index {index}, path {value!r}")
        normalized.add(value)
    return sorted(normalized)


def _verification_scope_sha256(targets: list[str]) -> str:
    payload = json.dumps(_verification_scope_paths(targets), ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _same_verification_file_state(left: os.stat_result, right: os.stat_result, *, cross_handle: bool = False) -> bool:
    fields = ["st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns"]
    if cross_handle and os.name == "nt":
        # Windows synthesizes execute bits into st_mode from the path's
        # extension (.exe/.cmd/.bat) on lstat/stat; a raw fstat() of an
        # already-open descriptor has no path to consult and never sets them.
        # That is a benign artifact of which API answered, not a change to
        # the file, and it is exactly what a launcher hashing its own
        # executable hits -- callers already assert S_ISREG independently, so
        # dropping st_mode here does not weaken the type check, only the
        # false positive.
        fields.remove("st_ctime_ns")
        fields.remove("st_mode")
    return all(getattr(left, field) == getattr(right, field) for field in fields)


def _verification_parent_snapshot(root: Path, parent: Path) -> tuple[str, tuple[tuple[str, os.stat_result], ...]]:
    """Capture every concrete parent component so junction swaps become visible."""
    try:
        relative = parent.relative_to(root)
    except ValueError as exc:
        raise ValueError("scope_path_outside_root") from exc
    states: list[tuple[str, os.stat_result]] = []
    current = root
    for component in (None, *relative.parts):
        if component is not None:
            current = current / component
        try:
            state = current.lstat()
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise ValueError("scope_file_unreadable") from exc
        if _is_link_or_reparse(state) or not stat.S_ISDIR(state.st_mode):
            raise ValueError("scope_parent_unsafe")
        states.append((os.path.normcase(str(current)), state))
    try:
        resolved = parent.resolve(strict=True)
    except FileNotFoundError:
        raise
    except (OSError, RuntimeError) as exc:
        raise ValueError("scope_file_unreadable") from exc
    if not _path_is_within(resolved, root) or os.path.normcase(str(resolved)) != os.path.normcase(
        str(parent.absolute())
    ):
        raise ValueError("scope_path_outside_root")
    return os.path.normcase(str(resolved)), tuple(states)


def _same_verification_parent_snapshot(
    left: tuple[str, tuple[tuple[str, os.stat_result], ...]],
    right: tuple[str, tuple[tuple[str, os.stat_result], ...]],
) -> bool:
    if left[0] != right[0] or len(left[1]) != len(right[1]):
        return False
    return all(
        left_path == right_path and _same_path_identity(left_state, right_state)
        for (left_path, left_state), (right_path, right_state) in zip(left[1], right[1], strict=True)
    )


def _verification_content_sha256(root: Path, targets: list[str]) -> str:
    """Hash exact target bytes with the same manifest contract as receipt v3."""
    try:
        canonical_root = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("verification_root_unavailable") from exc
    manifest: list[list[str]] = []
    total_bytes = 0
    for relative_path in _verification_scope_paths(targets):
        candidate = canonical_root / Path(relative_path)
        try:
            candidate.relative_to(canonical_root)
        except ValueError as exc:
            raise ValueError("scope_path_outside_root") from exc
        try:
            parent_before = _verification_parent_snapshot(canonical_root, candidate.parent)
        except FileNotFoundError:
            manifest.append([relative_path, "missing"])
            continue
        try:
            path_before = candidate.lstat()
        except FileNotFoundError:
            manifest.append([relative_path, "missing"])
            continue
        except OSError as exc:
            raise ValueError("scope_file_unreadable") from exc
        if stat.S_ISLNK(path_before.st_mode):
            raise ValueError("scope_file_symlink")
        if not stat.S_ISREG(path_before.st_mode):
            raise ValueError("scope_file_not_regular")
        if path_before.st_size > MAX_VERIFY_FILE_BYTES:
            raise ValueError("scope_file_too_large")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        try:
            descriptor = os.open(candidate, flags)
        except OSError as exc:
            reason = "scope_file_symlink" if exc.errno == errno.ELOOP else "scope_file_unreadable"
            raise ValueError(reason) from exc
        digest = hashlib.sha256()
        bytes_read = 0
        try:
            opened_before = os.fstat(descriptor)
            try:
                parent_opened = _verification_parent_snapshot(canonical_root, candidate.parent)
            except (FileNotFoundError, ValueError) as exc:
                raise ValueError("scope_file_changed_during_hash") from exc
            if (
                not _same_verification_parent_snapshot(parent_before, parent_opened)
                or not stat.S_ISREG(opened_before.st_mode)
                or not _same_verification_file_state(path_before, opened_before, cross_handle=True)
            ):
                raise ValueError("scope_file_changed_during_hash")
            while True:
                chunk = os.read(descriptor, 256 * 1024)
                if not chunk:
                    break
                bytes_read += len(chunk)
                if bytes_read > MAX_VERIFY_FILE_BYTES:
                    raise ValueError("scope_file_too_large")
                digest.update(chunk)
            opened_after = os.fstat(descriptor)
            try:
                path_after = candidate.lstat()
            except OSError as exc:
                raise ValueError("scope_file_changed_during_hash") from exc
            try:
                parent_after = _verification_parent_snapshot(canonical_root, candidate.parent)
            except (FileNotFoundError, ValueError) as exc:
                raise ValueError("scope_file_changed_during_hash") from exc
            if (
                bytes_read != opened_before.st_size
                or not _same_verification_parent_snapshot(parent_before, parent_after)
                or not _same_verification_file_state(opened_before, opened_after)
                or not _same_verification_file_state(path_before, path_after)
            ):
                raise ValueError("scope_file_changed_during_hash")
        finally:
            os.close(descriptor)
        total_bytes += bytes_read
        if total_bytes > MAX_VERIFY_TOTAL_BYTES:
            raise ValueError("verification_scope_too_large")
        manifest.append([relative_path, f"sha256:{digest.hexdigest()}"])
    payload = json.dumps(manifest, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _delete_check_diff_evidence(diff_text: str) -> tuple[bool, tuple[str, ...]]:
    """Find a delete-safety trigger and any language the kernel cannot parse.

    The post-edit channel already owns the Git diff and the exact target set.
    Roam's measured delete-check parser recognizes public declarations in
    Python, JavaScript/TypeScript, and Go shapes. A deleted/renamed code path or
    a removed public declaration triggers the check; when that declaration is
    in another indexed language, absence of a finding is not evidence.
    """
    triggered = False
    unsupported: set[str] = set()
    current_suffix = ""
    pending_deleted_file = False
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            current_suffix = ""
            pending_deleted_file = False
            continue
        if line.startswith("deleted file mode "):
            pending_deleted_file = True
            triggered = True
            continue
        if line.startswith("rename from "):
            triggered = True
            suffix = Path(line.removeprefix("rename from ")).suffix.lower()
            if suffix in _VERIFY_DELETE_CHECK_UNSUPPORTED_CODE_SUFFIXES:
                unsupported.add(suffix)
            continue
        if line.startswith("--- a/"):
            current_suffix = Path(line.removeprefix("--- a/")).suffix.lower()
            if pending_deleted_file and current_suffix in _VERIFY_DELETE_CHECK_UNSUPPORTED_CODE_SUFFIXES:
                unsupported.add(current_suffix)
            continue
        if not line.startswith("-") or line.startswith("---"):
            continue
        removed = line[1:]
        if current_suffix in _VERIFY_DELETE_CHECK_SUPPORTED_SUFFIXES:
            triggered = triggered or bool(_VERIFY_DELETE_CHECK_SUPPORTED_REMOVAL.match(removed))
        elif current_suffix in _VERIFY_DELETE_CHECK_UNSUPPORTED_CODE_SUFFIXES and (
            _VERIFY_DELETE_CHECK_PUBLIC_REMOVAL.match(removed)
        ):
            triggered = True
            unsupported.add(current_suffix)
    return triggered, tuple(sorted(unsupported))


def _delete_check_unavailable_reason(root: Path, targets: list[str]) -> str | None:
    """Return why a triggered delete check cannot run, otherwise ``None``.

    This is an availability preflight, not a second survivor detector. The
    kernel still owns all findings. It exists so an unsupported public-symbol
    removal cannot come back as score 100 merely because the parser extracted
    no candidate, and so an absent index is named before auto-index chatter can
    corrupt the receipt.
    """
    index_available = _require_index(str(root))
    may_need_language_guard = any(
        Path(path).suffix.lower() in _VERIFY_DELETE_CHECK_UNSUPPORTED_CODE_SUFFIXES for path in targets
    )
    if index_available and not may_need_language_guard:
        return None
    if not targets or not _git_marker_has_evidence(root):
        return None
    git_path, _reason = _resolve_trusted_executable("git", reject_workspace=True)
    if not git_path:
        return "the delete trigger diff is unavailable (trusted git was not found)"
    try:
        proc = _run_bounded_capture(
            [
                git_path,
                "-c",
                "core.fsmonitor=false",
                "diff",
                "--no-ext-diff",
                "--unified=0",
                "--find-renames",
                "HEAD",
                "--",
                *targets,
            ],
            cwd=str(root),
            timeout=10,
            stdout_limit=MAX_VERIFY_GIT_STATUS_BYTES,
            stderr_limit=MAX_VERIFY_STDERR_BYTES,
            env=_trusted_tool_env(git=True),
        )
        if proc.returncode != 0 or len(proc.stdout or b"") > MAX_VERIFY_GIT_STATUS_BYTES:
            return "the bounded delete trigger diff could not be read"
        diff_text = (proc.stdout or b"").decode("utf-8", errors="strict")
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        return "the bounded delete trigger diff could not be read"
    triggered, unsupported = _delete_check_diff_evidence(diff_text)
    if not triggered:
        return None
    if not index_available:
        return "the repository has no readable .roam/index.db"
    if unsupported:
        return "the changed public declaration uses an unsupported language suffix: " + ", ".join(unsupported)
    return None


def _delete_check_unavailable_verdict(reason: str) -> str:
    if "index.db" in reason:
        fix = "run `compile init`, then rerun `compile verify --changed`"
    elif "diff" in reason or "git" in reason:
        fix = "install or repair git, then rerun `compile verify --changed`"
    else:
        fix = (
            "restore the symbol or verify and update every reference with that language's tooling, "
            "then rerun `compile verify --changed`"
        )
    return (
        f"VERDICT: verify unavailable — delete_check did not run: {reason}. "
        f"A check that did not run cannot pass. Fix: {fix}."
    )


def _auto_select_product_verify_checks(target_paths: list[str]) -> tuple[str, ...]:
    """Select product-owned post-edit checks from the same bound target list."""
    if not target_paths:
        return ()
    collapse_applies = any(
        PurePosixPath(path).suffix.lower() in _VERIFY_COLLAPSE_SOURCE_SUFFIXES for path in target_paths
    )
    return tuple(name for name, _description in _VERIFY_AUTO_CHECK_REGISTRY if name != "collapse" or collapse_applies)


def _verify_rules_declaration_state(root: Path) -> dict[str, object]:
    """Derive whether the repository declares custom rules, without evaluating them."""
    rules_dir = root / ".roam" / "rules"
    try:
        canonical_root = root.resolve(strict=True)
        if not rules_dir.is_dir():
            return {
                "state": "not_applicable",
                "reason": "no .roam/rules YAML declarations",
                "declaration_count": 0,
            }
        canonical_rules_dir = rules_dir.resolve(strict=True)
        if not _path_is_within(canonical_rules_dir, canonical_root):
            return {
                "state": "unavailable",
                "reason": "the .roam/rules directory resolves outside the repository",
                "declaration_count": 0,
            }
        declarations: list[str] = []
        entry_count = 0
        for candidate in sorted(rules_dir.rglob("*")):
            entry_count += 1
            if entry_count > MAX_VERIFY_RULE_DECLARATION_ENTRIES:
                return {
                    "state": "unavailable",
                    "reason": "the rule declaration probe exceeded its bounded entry limit",
                    "declaration_count": len(declarations),
                }
            if candidate.suffix not in {".yaml", ".yml"} or not candidate.is_file():
                continue
            resolved = candidate.resolve(strict=True)
            if not _path_is_within(resolved, canonical_root):
                return {
                    "state": "unavailable",
                    "reason": "a rule declaration resolves outside the repository",
                    "declaration_count": len(declarations),
                }
            declarations.append(candidate.relative_to(root).as_posix())
    except (OSError, RuntimeError, ValueError):
        return {
            "state": "unavailable",
            "reason": "the bounded rule declaration probe could not be completed",
            "declaration_count": 0,
        }
    if not declarations:
        return {
            "state": "not_applicable",
            "reason": "no .roam/rules YAML declarations",
            "declaration_count": 0,
        }
    return {"state": "declared", "declaration_count": len(declarations)}


def _bounded_verify_rule_text(value: object, *, reason: str, allow_empty: bool = False) -> str:
    if (
        not isinstance(value, str)
        or (not value and not allow_empty)
        or len(value) > MAX_VERIFY_RULE_TEXT_CHARS
        or any(ord(char) < 32 for char in value)
    ):
        raise ValueError(reason)
    return value


def _verify_rule_site(root: Path, raw_path: object) -> str:
    path_text = _bounded_verify_rule_text(raw_path, reason="rules_finding_path")
    try:
        canonical_root = root.resolve(strict=True)
        candidate = Path(path_text)
        resolved = (
            candidate.resolve(strict=False)
            if candidate.is_absolute()
            else (canonical_root / candidate).resolve(strict=False)
        )
        if not _path_is_within(resolved, canonical_root):
            raise ValueError("rules_finding_path")
        relative = resolved.relative_to(canonical_root).as_posix()
        if _verification_scope_paths([relative]) != [relative]:
            raise ValueError("rules_finding_path")
        return relative
    except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
        raise ValueError("rules_finding_path") from exc


def _validate_verify_rules_protocol(
    output: str,
    *,
    returncode: int,
    expected_roam_version: str,
    expected_root: Path,
    declaration_count: int,
) -> dict[str, object]:
    """Validate the bounded ``rules --ci`` result used by the VERIFY adapter."""
    envelope = _strict_json_document(output, max_bytes=MAX_VERIFY_JSON_BYTES)
    if not isinstance(envelope, dict):
        raise ValueError("rules_envelope")
    if (
        envelope.get("schema") != VERIFY_ENVELOPE_SCHEMA
        or not _envelope_schema_compatible(envelope.get("schema_version"))
        or envelope.get("command") != "rules"
        or envelope.get("version") != expected_roam_version
    ):
        raise ValueError("rules_envelope")
    summary = envelope.get("summary")
    results = envelope.get("results")
    if not isinstance(summary, dict) or not isinstance(results, list):
        raise ValueError("rules_shape")
    config_state = summary.get("config_state")
    if config_state not in _VERIFY_RULE_CONFIG_STATES:
        raise ValueError("rules_config_state")
    total = _plain_int(summary.get("total"), maximum=len(results))
    passed = _plain_int(summary.get("passed"), maximum=total)
    failed = _plain_int(summary.get("failed"), maximum=total)
    _plain_int(summary.get("warnings"), maximum=total)
    _bounded_verify_rule_text(summary.get("verdict"), reason="rules_verdict")
    if total != len(results) or passed + failed != total or total < declaration_count:
        raise ValueError("rules_counts")

    findings: list[dict[str, object]] = []
    failed_count = 0
    gating_count = 0
    for result in results:
        if not isinstance(result, dict):
            raise ValueError("rules_result")
        name = _bounded_verify_rule_text(result.get("name"), reason="rules_name")
        severity = result.get("severity")
        result_passed = result.get("passed")
        violations = result.get("violations")
        if (
            severity not in _VERIFY_RULE_SEVERITIES
            or type(result_passed) is not bool
            or not isinstance(violations, list)
        ):
            raise ValueError("rules_result")
        if result_passed != (len(violations) == 0):
            raise ValueError("rules_result_contradiction")
        if not result_passed:
            failed_count += 1
            if severity in _VERIFY_RULE_GATING_SEVERITIES:
                gating_count += 1
        for violation in violations:
            if not isinstance(violation, dict):
                raise ValueError("rules_finding")
            site = _verify_rule_site(expected_root, violation.get("file"))
            line = violation.get("line")
            if line is not None:
                _plain_int(line, minimum=1)
            reason = _bounded_verify_rule_text(
                violation.get("reason", "rule violated"), reason="rules_finding_reason", allow_empty=False
            )
            findings.append(
                {
                    "rule": name,
                    "severity": severity,
                    "file": site,
                    "line": line,
                    "reason": reason,
                }
            )
    if failed_count != failed:
        raise ValueError("rules_counts")
    incomplete = summary.get("partial_success") is True or summary.get("scan_incomplete") is True
    if config_state != "ok" or incomplete:
        state = "unavailable"
        unavailable_reason = "declared rule configuration was not completely evaluated"
    elif gating_count:
        state = "failed"
        unavailable_reason = None
    else:
        state = "complete"
        unavailable_reason = None
    if returncode not in {0, EXIT_VERIFY_GATE} or (gating_count > 0) != (returncode != 0):
        raise ValueError("rules_exit_contradiction")
    return {
        "state": state,
        "declaration_count": declaration_count,
        "rule_count": total,
        "failed_rule_count": gating_count,
        "findings": tuple(findings),
        "unavailable_reason": unavailable_reason,
    }


def _run_verify_rules_check(
    root: Path,
    *,
    executable: str,
    expected_roam_version: str,
    env: dict[str, str],
) -> tuple[dict[str, object] | None, int]:
    """Run the product-owned custom-rule adapter, or return its typed absence."""
    declaration_state = _verify_rules_declaration_state(root)
    if declaration_state["state"] != "declared":
        return declaration_state, 0
    rc, output = _delegate_capturing(
        "--json",
        "rules",
        "--ci",
        "--top",
        str(MAX_VERIFY_RULE_FINDINGS // 2),
        executable=executable,
        env=env,
    )
    if output is None:
        return None, rc
    try:
        result = _validate_verify_rules_protocol(
            output,
            returncode=rc,
            expected_roam_version=expected_roam_version,
            expected_root=root,
            declaration_count=int(declaration_state["declaration_count"]),
        )
    except (UnicodeError, ValueError):
        return {
            "state": "unavailable",
            "reason": "rules did not return one complete structured result",
            "declaration_count": declaration_state["declaration_count"],
        }, EXIT_TOOLCHAIN
    return result, 0


_VERIFY_RULES_UNAVAILABLE_VERDICT = (
    MAX_VERIFY_RULE_TEXT_CHARS,
    "the custom-rule check could not establish a complete result",
    "rules",
    "A declared rule check that did not run cannot pass. Fix: repair the repository's .roam/rules declarations "
    "or index, then rerun `compile verify --changed`.",
)
_VERIFY_PY_TYPES_UNAVAILABLE_VERDICT = (
    MAX_VERIFY_TYPE_TEXT_CHARS,
    "the type-annotation check could not establish a complete result",
    "py-types",
    "A triggered type check that did not run cannot pass. Fix: repair Git, the Roam index, or the edited Python "
    "source, then rerun `compile verify --changed`.",
)
_VERIFY_PY_MODERN_UNAVAILABLE_VERDICT = (
    MAX_VERIFY_MODERN_TEXT_CHARS,
    "the Python modernization check could not establish a complete result",
    "py-modern",
    "A triggered modernization check that did not run cannot pass. Fix: repair Git, the Roam index, or the edited "
    "Python source, then rerun `compile verify --changed`.",
)
_VERIFY_CALC_GOLDEN_UNAVAILABLE_VERDICT = (
    MAX_VERIFY_CALC_TEXT_CHARS,
    "the golden calculation check could not establish a complete result",
    "calc-golden",
    "A declared golden case that did not run cannot pass. Fix: repair Git or the .roam/calc-golden declaration, "
    "corpus, and runner, then rerun `compile verify --changed`; preserve the golden cases.",
)
_VERIFY_COLLAPSE_UNAVAILABLE_VERDICT = (
    MAX_VERIFY_COLLAPSE_TEXT_CHARS,
    "the benign-default collapse check could not establish a complete result",
    "collapse",
    "A triggered collapse check that did not run cannot pass. Fix: repair Git, the Roam index or detector, or the "
    "edited Python/JavaScript/TypeScript source, then rerun `compile verify --changed`.",
)


def _verify_unavailable_verdict(
    reason: object,
    max_reason_chars: int,
    fallback_reason: str,
    check_name: str,
    failure_fix: str,
) -> str:
    safe_reason = (
        reason
        if isinstance(reason, str) and 0 < len(reason) <= max_reason_chars and all(ord(char) >= 32 for char in reason)
        else fallback_reason
    )
    return f"VERDICT: verify unavailable — {check_name} did not run completely: {safe_reason}. {failure_fix}"


def _verify_rules_unavailable_verdict(reason: object) -> str:
    return _verify_unavailable_verdict(reason, *_VERIFY_RULES_UNAVAILABLE_VERDICT)


def _verify_type_annotation(node: ast.expr | None) -> dict[str, object] | None:
    if node is None:
        return None
    try:
        display = ast.unparse(node)
    except (RecursionError, ValueError) as exc:
        raise ValueError("type_annotation_unreadable") from exc
    if not display or len(display) > MAX_VERIFY_TYPE_TEXT_CHARS or any(ord(char) < 32 for char in display):
        raise ValueError("type_annotation_unreadable")

    def union_members(candidate: ast.expr) -> list[str]:
        if isinstance(candidate, ast.BinOp) and isinstance(candidate.op, ast.BitOr):
            return [*union_members(candidate.left), *union_members(candidate.right)]
        return [ast.dump(candidate, annotate_fields=True, include_attributes=False)]

    names = [candidate for candidate in ast.walk(node) if isinstance(candidate, (ast.Name, ast.Attribute))]
    is_any = any(
        (isinstance(candidate, ast.Name) and candidate.id == "Any")
        or (isinstance(candidate, ast.Attribute) and candidate.attr == "Any")
        for candidate in names
    )
    is_object = isinstance(node, ast.Name) and node.id == "object"
    return {
        "display": display,
        "canonical": ast.dump(node, annotate_fields=True, include_attributes=False),
        "union_members": tuple(union_members(node)),
        "is_any": is_any,
        "is_object": is_object,
    }


def _python_annotation_surface(raw: str) -> dict[str, dict[str, object]]:
    """Return the public callable type surface in one bounded Python source."""
    try:
        tree = ast.parse(raw)
    except (MemoryError, RecursionError, SyntaxError, ValueError) as exc:
        raise ValueError("type_source_unparseable") from exc
    surface: dict[str, dict[str, object]] = {}
    scope: list[str] = []

    class SurfaceVisitor(ast.NodeVisitor):
        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            scope.append(node.name)
            self.generic_visit(node)
            scope.pop()

        def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            qualified_name = ".".join([*scope, node.name])
            if not node.name.startswith("_"):
                positional = [*node.args.posonlyargs, *node.args.args]
                keyword_only = list(node.args.kwonlyargs)
                arguments: list[ast.arg] = [*positional, *keyword_only]
                if node.args.vararg is not None:
                    arguments.append(node.args.vararg)
                if node.args.kwarg is not None:
                    arguments.append(node.args.kwarg)
                parameters = tuple(
                    {
                        "name": argument.arg,
                        "annotation": _verify_type_annotation(argument.annotation),
                    }
                    for argument in arguments
                    if argument.arg not in {"self", "cls"}
                )
                surface[qualified_name] = {
                    "line": node.lineno,
                    "parameters": parameters,
                    "return": _verify_type_annotation(node.returns),
                }
            scope.append(node.name)
            self.generic_visit(node)
            scope.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._visit_function(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._visit_function(node)

    SurfaceVisitor().visit(tree)
    return surface


def _verify_type_git_capture(root: Path, argv: list[str], *, stdout_limit: int) -> subprocess.CompletedProcess:
    git_path, _reason = _resolve_trusted_executable("git", reject_workspace=True)
    if not git_path:
        raise ValueError("type_git_unavailable")
    try:
        return _run_bounded_capture(
            [git_path, "-c", "core.fsmonitor=false", *argv],
            cwd=str(root),
            timeout=10,
            stdout_limit=stdout_limit,
            stderr_limit=MAX_VERIFY_STDERR_BYTES,
            env=_trusted_tool_env(git=True),
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("type_git_unavailable") from exc


def _verify_type_baseline_paths(root: Path, targets: Sequence[str]) -> dict[str, str | None]:
    """Map current Python paths to their pre-edit names, including detected renames."""
    inside = _verify_type_git_capture(root, ["rev-parse", "--is-inside-work-tree"], stdout_limit=32)
    if inside.returncode != 0 or (inside.stdout or b"").strip() != b"true":
        raise ValueError("type_git_unavailable")
    head = _verify_type_git_capture(root, ["cat-file", "-e", "HEAD^{commit}"], stdout_limit=1)
    if head.returncode != 0:
        return {path: None for path in targets}
    diff = _verify_type_git_capture(
        root,
        ["diff", "--name-status", "-z", "--find-renames", "HEAD", "--", *targets],
        stdout_limit=MAX_VERIFY_GIT_STATUS_BYTES,
    )
    raw = diff.stdout or b""
    if diff.returncode != 0 or len(raw) > MAX_VERIFY_GIT_STATUS_BYTES or (raw and not raw.endswith(b"\0")):
        raise ValueError("type_git_diff_unavailable")
    try:
        records = raw.split(b"\0")
        baseline: dict[str, str | None] = {path: path for path in targets}
        index = 0
        while index < len(records):
            status_raw = records[index]
            index += 1
            if not status_raw:
                continue
            status = status_raw.decode("ascii")
            if re.fullmatch(r"(?:[AMDUT]|R\d{1,3}|C\d{1,3})", status) is None or index >= len(records):
                raise ValueError("type_git_diff_malformed")
            first_path = _decode_verify_status_path(records[index])
            index += 1
            if status.startswith(("R", "C")):
                if index >= len(records):
                    raise ValueError("type_git_diff_malformed")
                current_path = _decode_verify_status_path(records[index])
                index += 1
                if current_path in baseline:
                    baseline[current_path] = first_path
            elif status == "A" and first_path in baseline:
                baseline[first_path] = None
        return baseline
    except (UnicodeError, ValueError) as exc:
        raise ValueError("type_git_diff_malformed") from exc


def _verify_type_head_source(root: Path, baseline_path: str | None) -> str:
    if baseline_path is None:
        return ""
    blob = _verify_type_git_capture(
        root,
        ["cat-file", "blob", f"HEAD:{baseline_path}"],
        stdout_limit=MAX_VERIFY_TYPE_SOURCE_BYTES,
    )
    raw = blob.stdout or b""
    if blob.returncode != 0 or len(raw) > MAX_VERIFY_TYPE_SOURCE_BYTES:
        tree = _verify_type_git_capture(
            root,
            ["ls-tree", "-z", "HEAD", "--", baseline_path],
            stdout_limit=MAX_VERIFY_GIT_STATUS_BYTES,
        )
        if tree.returncode == 0 and not (tree.stdout or b""):
            return ""
        raise ValueError("type_baseline_unavailable")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("type_baseline_non_utf8") from exc


def _verify_edited_python_sources(root: Path, targets: Sequence[str]) -> tuple[tuple[str, bool, str, str], ...]:
    """Return bounded current/HEAD source pairs for the edited Python files."""
    python_targets = tuple(path for path in targets if Path(path).suffix.lower() == ".py")
    if not python_targets:
        return ()
    baseline_paths = _verify_type_baseline_paths(root, python_targets)
    sources: list[tuple[str, bool, str, str]] = []
    total_source_bytes = 0
    for path in python_targets:
        candidate = root / Path(path)
        try:
            current_exists = candidate.exists()
            current_raw = (
                ""
                if not current_exists
                else _read_bounded_utf8_regular_file(candidate, max_bytes=MAX_VERIFY_TYPE_SOURCE_BYTES)
            )
        except (OSError, ValueError) as exc:
            raise ValueError("type_current_source_unavailable") from exc
        baseline_raw = _verify_type_head_source(root, baseline_paths[path])
        total_source_bytes += len(current_raw.encode("utf-8")) + len(baseline_raw.encode("utf-8"))
        if total_source_bytes > MAX_VERIFY_TYPE_TOTAL_SOURCE_BYTES:
            raise ValueError("type_source_scope_too_large")
        sources.append((path, current_exists, baseline_raw, current_raw))
    return tuple(sources)


def _verify_type_annotation_regressed(
    previous: Mapping[str, object], current: Mapping[str, object]
) -> tuple[bool, str]:
    previous_display = str(previous["display"])
    current_display = str(current["display"])
    if current.get("is_any") is True and previous.get("is_any") is not True:
        return True, f"widened from {previous_display} to {current_display}"
    if current.get("is_object") is True and previous.get("is_object") is not True:
        return True, f"widened from {previous_display} to object"
    previous_members = set(previous.get("union_members", ()))
    current_members = set(current.get("union_members", ()))
    if previous_members and previous_members < current_members:
        return True, f"widened from {previous_display} to {current_display}"
    return False, ""


def _verify_type_annotation_delta(root: Path, targets: Sequence[str]) -> dict[str, object]:
    """Compare edited Python callables with their Git ``HEAD`` type surface."""
    python_sources = _verify_edited_python_sources(root, targets)
    if not python_sources:
        return {
            "state": "not_applicable",
            "reason": "no changed Python files",
            "regression_count": 0,
            "findings": (),
        }
    findings: list[dict[str, object]] = []
    regression_count = 0
    required_no_return: set[tuple[str, str]] = set()
    required_untyped: set[tuple[str, str]] = set()
    required_any: set[tuple[str, str]] = set()
    current_public_count = 0
    current_python_file_count = 0

    def add_finding(
        *,
        path: str,
        line: int,
        symbol: str,
        annotation: str,
        change: str,
        support: str | None,
    ) -> None:
        nonlocal regression_count
        regression_count += 1
        key = (path, symbol)
        if support == "no_return":
            required_no_return.add(key)
        elif support == "untyped":
            required_untyped.add(key)
        elif support == "any":
            required_any.add(key)
        if len(findings) < MAX_VERIFY_TYPE_FINDINGS:
            findings.append(
                {
                    "file": path,
                    "line": line,
                    "symbol": symbol,
                    "annotation": annotation,
                    "change": change,
                }
            )

    for path, current_exists, baseline_raw, current_raw in python_sources:
        current_python_file_count += int(current_exists)
        previous_surface = _python_annotation_surface(baseline_raw)
        current_surface = _python_annotation_surface(current_raw)
        current_public_count += len(current_surface)
        for symbol, current_symbol in current_surface.items():
            previous_symbol = previous_surface.get(symbol)
            line = _plain_int(current_symbol.get("line"), minimum=1)
            current_parameters = current_symbol.get("parameters")
            if not isinstance(current_parameters, tuple):
                raise ValueError("type_surface_invalid")
            if previous_symbol is None:
                for parameter in current_parameters:
                    if isinstance(parameter, Mapping) and parameter.get("annotation") is None:
                        name = str(parameter.get("name"))
                        add_finding(
                            path=path,
                            line=line,
                            symbol=symbol,
                            annotation=f"{name} annotation",
                            change="missing on new public symbol",
                            support="untyped",
                        )
                if current_symbol.get("return") is None:
                    add_finding(
                        path=path,
                        line=line,
                        symbol=symbol,
                        annotation="return annotation",
                        change="missing on new public symbol",
                        support="no_return",
                    )
                continue

            previous_parameters = previous_symbol.get("parameters")
            if not isinstance(previous_parameters, tuple):
                raise ValueError("type_surface_invalid")
            previous_by_name = {
                str(parameter["name"]): parameter.get("annotation")
                for parameter in previous_parameters
                if isinstance(parameter, Mapping) and isinstance(parameter.get("name"), str)
            }
            for parameter_index, parameter in enumerate(current_parameters):
                if not isinstance(parameter, Mapping) or not isinstance(parameter.get("name"), str):
                    raise ValueError("type_surface_invalid")
                name = str(parameter["name"])
                current_annotation = parameter.get("annotation")
                has_previous_parameter = name in previous_by_name
                previous_annotation = previous_by_name.get(name)
                if not has_previous_parameter and parameter_index < len(previous_parameters):
                    previous_parameter = previous_parameters[parameter_index]
                    if isinstance(previous_parameter, Mapping):
                        has_previous_parameter = True
                        previous_annotation = previous_parameter.get("annotation")
                if isinstance(previous_annotation, Mapping) and current_annotation is None:
                    add_finding(
                        path=path,
                        line=line,
                        symbol=symbol,
                        annotation=f"{name} annotation",
                        change=f"removed (was {previous_annotation['display']})",
                        support="untyped",
                    )
                elif isinstance(previous_annotation, Mapping) and isinstance(current_annotation, Mapping):
                    regressed, change = _verify_type_annotation_regressed(previous_annotation, current_annotation)
                    if regressed:
                        add_finding(
                            path=path,
                            line=line,
                            symbol=symbol,
                            annotation=f"{name} annotation",
                            change=change,
                            support="any" if current_annotation.get("is_any") is True else None,
                        )
                elif not has_previous_parameter and current_annotation is None:
                    add_finding(
                        path=path,
                        line=line,
                        symbol=symbol,
                        annotation=f"{name} annotation",
                        change="missing on new parameter",
                        support="untyped",
                    )
                elif (
                    not has_previous_parameter
                    and isinstance(current_annotation, Mapping)
                    and current_annotation.get("is_any") is True
                ):
                    add_finding(
                        path=path,
                        line=line,
                        symbol=symbol,
                        annotation=f"{name} annotation",
                        change="new parameter uses Any",
                        support="any",
                    )
            previous_return = previous_symbol.get("return")
            current_return = current_symbol.get("return")
            if isinstance(previous_return, Mapping) and current_return is None:
                add_finding(
                    path=path,
                    line=line,
                    symbol=symbol,
                    annotation="return annotation",
                    change=f"removed (was {previous_return['display']})",
                    support="no_return",
                )
            elif isinstance(previous_return, Mapping) and isinstance(current_return, Mapping):
                regressed, change = _verify_type_annotation_regressed(previous_return, current_return)
                if regressed:
                    add_finding(
                        path=path,
                        line=line,
                        symbol=symbol,
                        annotation="return annotation",
                        change=change,
                        support="any" if current_return.get("is_any") is True else None,
                    )
    return {
        "state": "failed" if regression_count else "complete",
        "python_target_count": len(python_sources),
        "current_python_file_count": current_python_file_count,
        "current_public_count": current_public_count,
        "regression_count": regression_count,
        "findings": tuple(findings),
        "required_no_return": len(required_no_return),
        "required_untyped": len(required_untyped),
        "required_any": len(required_any),
    }


def _validate_verify_py_types_protocol(
    output: str,
    *,
    returncode: int,
    expected_roam_version: str,
    expected_root: Path,
    delta: Mapping[str, object],
) -> dict[str, object]:
    """Validate the bounded absolute ``py-types`` result and bind it to the edit delta."""
    envelope = _strict_json_document(output, max_bytes=MAX_VERIFY_JSON_BYTES)
    if not isinstance(envelope, dict):
        raise ValueError("py_types_envelope")
    if (
        envelope.get("schema") != VERIFY_ENVELOPE_SCHEMA
        or not _envelope_schema_compatible(envelope.get("schema_version"))
        or envelope.get("command") != "py-types"
        or envelope.get("version") != expected_roam_version
        or returncode != 0
    ):
        raise ValueError("py_types_envelope")
    summary = envelope.get("summary")
    by_file = envelope.get("by_file")
    raw_findings = envelope.get("findings")
    if not isinstance(summary, dict) or not isinstance(by_file, list) or not isinstance(raw_findings, list):
        raise ValueError("py_types_shape")
    if len(by_file) > MAX_VERIFY_TYPE_DETAIL_FILES or len(raw_findings) > MAX_VERIFY_TYPE_ENVELOPE_FINDINGS:
        raise ValueError("py_types_result_bound")
    total = _plain_int(summary.get("total_public"))
    no_return = _plain_int(summary.get("no_return_annotation"), maximum=total)
    untyped = _plain_int(summary.get("untyped_params"), maximum=total)
    uses_any = _plain_int(summary.get("uses_any"), maximum=total)
    old_typing = _plain_int(summary.get("old_typing"), maximum=total)
    coverage = _plain_int(summary.get("coverage_pct"), maximum=100)
    _bounded_verify_rule_text(summary.get("verdict"), reason="py_types_verdict")
    if (
        summary.get("partial_success") is not False
        or summary.get("total_public_definition") != _VERIFY_TYPE_TOTAL_DEFINITION
        or summary.get("coverage_pct_definition") != _VERIFY_TYPE_COVERAGE_DEFINITION
    ):
        raise ValueError("py_types_incomplete")
    if total:
        if coverage != ((total - max(no_return, untyped)) * 100) // total:
            raise ValueError("py_types_counts")
    else:
        state = summary.get("state")
        if state not in _VERIFY_TYPE_EMPTY_STATES or summary.get("coverage_pct_computable") is not False:
            raise ValueError("py_types_empty_state")
        python_files = _plain_int(summary.get("python_files"))
        _plain_int(summary.get("indexed_files"))
        if state == "no_python_files" and (
            python_files != 0 or _plain_int(delta.get("current_python_file_count")) != 0
        ):
            raise ValueError("py_types_scope_contradiction")

    for row in by_file:
        if not isinstance(row, dict):
            raise ValueError("py_types_file")
        _verify_rule_site(expected_root, row.get("path"))
        row_total = _plain_int(row.get("total"))
        _plain_int(row.get("missing"), maximum=row_total)
    for finding in raw_findings:
        if not isinstance(finding, dict):
            raise ValueError("py_types_finding")
        _bounded_verify_rule_text(finding.get("name"), reason="py_types_finding_name")
        _verify_rule_site(expected_root, finding.get("path"))
        _plain_int(finding.get("line"), minimum=1)
        issues = finding.get("issues")
        if (
            not isinstance(issues, list)
            or not issues
            or any(not isinstance(issue, str) or _VERIFY_TYPE_ISSUE.fullmatch(issue) is None for issue in issues)
        ):
            raise ValueError("py_types_finding_issues")
    if total < _plain_int(delta.get("current_public_count")):
        raise ValueError("py_types_scope_contradiction")
    if (
        no_return < _plain_int(delta.get("required_no_return"))
        or untyped < _plain_int(delta.get("required_untyped"))
        or uses_any < _plain_int(delta.get("required_any"))
    ):
        raise ValueError("py_types_delta_contradiction")
    result = dict(delta)
    result.update(
        absolute_total_public=total,
        absolute_coverage_pct=coverage if total else None,
        absolute_no_return=no_return,
        absolute_untyped=untyped,
        absolute_uses_any=uses_any,
        absolute_old_typing=old_typing,
    )
    return result


def _run_verify_py_types_check(
    root: Path,
    *,
    targets: Sequence[str],
    executable: str,
    expected_roam_version: str,
    env: dict[str, str],
) -> tuple[dict[str, object] | None, int]:
    """Run py-types for Python edits, gating only regressions against Git ``HEAD``."""
    try:
        delta = _verify_type_annotation_delta(root, targets)
    except (MemoryError, OSError, UnicodeError, ValueError):
        return {
            "state": "unavailable",
            "reason": "the bounded edited-file type delta could not be derived from Git and Python source",
        }, EXIT_TOOLCHAIN
    if delta["state"] == "not_applicable":
        return delta, 0
    rc, output = _delegate_capturing(
        "--json",
        "py-types",
        "--detail",
        "--top",
        str(MAX_VERIFY_TYPE_DETAIL_FILES),
        "--include-tests",
        executable=executable,
        env=env,
    )
    if output is None:
        return None, rc
    try:
        result = _validate_verify_py_types_protocol(
            output,
            returncode=rc,
            expected_roam_version=expected_roam_version,
            expected_root=root,
            delta=delta,
        )
    except (UnicodeError, ValueError):
        return {
            "state": "unavailable",
            "reason": "py-types did not return one complete structured result consistent with the edited files",
        }, EXIT_TOOLCHAIN
    if result.get("absolute_total_public") == 0 and result.get("current_public_count", 0) != 0:
        return {
            "state": "unavailable",
            "reason": "py-types did not index the edited public Python symbols",
        }, EXIT_TOOLCHAIN
    return result, 0


def _verify_py_types_unavailable_verdict(reason: object) -> str:
    return _verify_unavailable_verdict(reason, *_VERIFY_PY_TYPES_UNAVAILABLE_VERDICT)


def _verify_modern_occurrences(path: str, raw: str) -> tuple[dict[str, object], ...]:
    occurrences: list[dict[str, object]] = []
    for kind, pattern in (
        ("legacy-typing", _VERIFY_MODERN_LEGACY_TYPING),
        ("dot-format", _VERIFY_MODERN_DOT_FORMAT),
    ):
        occurrences.extend(
            {
                "file": path,
                "line": raw.count("\n", 0, match.start()) + 1,
                "kind": kind,
                "match": match.group(0).strip(),
            }
            for match in pattern.finditer(raw)
        )
    return tuple(occurrences)


def _verify_python_modernization_delta(root: Path, targets: Sequence[str]) -> dict[str, object]:
    """Compare outdated constructs in edited Python files with Git ``HEAD``."""
    python_sources = _verify_edited_python_sources(root, targets)
    if not python_sources:
        return {
            "state": "not_applicable",
            "reason": "no changed Python files",
            "regression_count": 0,
            "findings": (),
        }

    regression_count = 0
    findings: list[dict[str, object]] = []
    current_by_file: dict[str, dict[str, int]] = {}
    current_python_file_count = 0
    for path, current_exists, baseline_raw, current_raw in python_sources:
        current_python_file_count += int(current_exists)
        baseline_counts = Counter(
            (str(occurrence["kind"]), str(occurrence["match"]))
            for occurrence in _verify_modern_occurrences(path, baseline_raw)
        )
        current_occurrences = _verify_modern_occurrences(path, current_raw)
        current_counts = Counter(str(occurrence["kind"]) for occurrence in current_occurrences)
        current_by_file[path] = {
            "legacy_typing": current_counts["legacy-typing"],
            "dot_format": current_counts["dot-format"],
        }
        for occurrence in current_occurrences:
            key = (str(occurrence["kind"]), str(occurrence["match"]))
            if baseline_counts[key]:
                baseline_counts[key] -= 1
                continue
            regression_count += 1
            if len(findings) < MAX_VERIFY_MODERN_FINDINGS:
                findings.append(occurrence)

    return {
        "state": "failed" if regression_count else "complete",
        "python_target_count": len(python_sources),
        "current_python_file_count": current_python_file_count,
        "current_legacy_typing": sum(counts["legacy_typing"] for counts in current_by_file.values()),
        "current_dot_format": sum(counts["dot_format"] for counts in current_by_file.values()),
        "current_by_file": current_by_file,
        "regression_count": regression_count,
        "findings": tuple(findings),
    }


def _validate_verify_py_modern_protocol(
    output: str,
    *,
    returncode: int,
    expected_roam_version: str,
    expected_root: Path,
    delta: Mapping[str, object],
) -> dict[str, object]:
    """Validate the bounded absolute ``py-modern`` result and bind it to the edit delta."""
    envelope = _strict_json_document(output, max_bytes=MAX_VERIFY_JSON_BYTES)
    if not isinstance(envelope, dict):
        raise ValueError("py_modern_envelope")
    if (
        envelope.get("schema") != VERIFY_ENVELOPE_SCHEMA
        or not _envelope_schema_compatible(envelope.get("schema_version"))
        or envelope.get("command") != "py-modern"
        or envelope.get("version") != expected_roam_version
        or returncode != 0
    ):
        raise ValueError("py_modern_envelope")
    summary = envelope.get("summary")
    by_file = envelope.get("by_file")
    raw_occurrences = envelope.get("legacy_occurrences")
    if not isinstance(summary, dict) or not isinstance(by_file, list) or not isinstance(raw_occurrences, list):
        raise ValueError("py_modern_shape")
    if len(by_file) > MAX_VERIFY_MODERN_DETAIL_FILES or len(raw_occurrences) > MAX_VERIFY_MODERN_ENVELOPE_OCCURRENCES:
        raise ValueError("py_modern_result_bound")
    if summary.get("partial_success") is not False:
        raise ValueError("py_modern_incomplete")

    totals = {key: _plain_int(summary.get(key)) for key in _VERIFY_MODERN_FEATURE_KEYS}
    files_scanned = _plain_int(summary.get("files_scanned"))
    type_ratio = _plain_int(summary.get("type_modernisation_pct"), maximum=100)
    format_ratio = _plain_int(summary.get("fstring_pct"), maximum=100)
    type_total = totals["pep604"] + totals["pep585"] + totals["legacy_typing"]
    format_total = totals["fstring"] + totals["dot_format"]
    expected_type_ratio = (totals["pep604"] + totals["pep585"]) * 100 // type_total if type_total else 0
    expected_format_ratio = totals["fstring"] * 100 // format_total if format_total else 0
    if type_ratio != expected_type_ratio or format_ratio != expected_format_ratio:
        raise ValueError("py_modern_counts")
    if type_ratio >= 80 and format_ratio >= 80:
        label = "modern Python"
    elif type_ratio >= 50 and format_ratio >= 50:
        label = "mixed Python"
    else:
        label = "legacy Python"
    verdict = _bounded_verify_rule_text(summary.get("verdict"), reason="py_modern_verdict")
    if verdict != f"{label} (type-modern {type_ratio}%, f-string {format_ratio}%)":
        raise ValueError("py_modern_verdict")

    row_totals = Counter({key: 0 for key in _VERIFY_MODERN_FEATURE_KEYS})
    rows_by_path: dict[str, dict[str, int]] = {}
    for row in by_file:
        if not isinstance(row, dict):
            raise ValueError("py_modern_file")
        path = _verify_rule_site(expected_root, row.get("path"))
        if path in rows_by_path:
            raise ValueError("py_modern_file")
        counts = {key: _plain_int(row.get(key)) for key in _VERIFY_MODERN_FEATURE_KEYS}
        if not any(counts.values()):
            raise ValueError("py_modern_file")
        rows_by_path[path] = counts
        row_totals.update(counts)
    if files_scanned < len(by_file) or any(row_totals[key] > totals[key] for key in _VERIFY_MODERN_FEATURE_KEYS):
        raise ValueError("py_modern_counts")

    occurrence_counts: Counter[str] = Counter()
    occurrence_sites: Counter[tuple[str, int, str, str]] = Counter()
    for occurrence in raw_occurrences:
        if not isinstance(occurrence, dict):
            raise ValueError("py_modern_occurrence")
        path = _verify_rule_site(expected_root, occurrence.get("path"))
        line = _plain_int(occurrence.get("line"), minimum=1)
        kind = occurrence.get("kind")
        match = _bounded_verify_rule_text(occurrence.get("match"), reason="py_modern_occurrence_match")
        if kind == "legacy-typing":
            if _VERIFY_MODERN_LEGACY_TYPING.fullmatch(match) is None:
                raise ValueError("py_modern_occurrence")
        elif kind == "dot-format":
            if _VERIFY_MODERN_DOT_FORMAT.fullmatch(match) is None:
                raise ValueError("py_modern_occurrence")
        else:
            raise ValueError("py_modern_occurrence")
        occurrence_counts[kind] += 1
        occurrence_sites[(path, line, kind, match)] += 1
    outdated_total = totals["legacy_typing"] + totals["dot_format"]
    if len(raw_occurrences) != min(outdated_total, MAX_VERIFY_MODERN_ENVELOPE_OCCURRENCES):
        raise ValueError("py_modern_occurrence_count")
    if (
        occurrence_counts["legacy-typing"] > totals["legacy_typing"]
        or occurrence_counts["dot-format"] > totals["dot_format"]
    ):
        raise ValueError("py_modern_occurrence_count")

    current_python_file_count = _plain_int(delta.get("current_python_file_count"))
    current_legacy_typing = _plain_int(delta.get("current_legacy_typing"))
    current_dot_format = _plain_int(delta.get("current_dot_format"))
    if (
        files_scanned < current_python_file_count
        or totals["legacy_typing"] < current_legacy_typing
        or totals["dot_format"] < current_dot_format
    ):
        raise ValueError("py_modern_delta_contradiction")
    current_by_file = delta.get("current_by_file")
    if not isinstance(current_by_file, Mapping):
        raise ValueError("py_modern_delta_contradiction")
    for path, raw_counts in current_by_file.items():
        if not isinstance(path, str) or not isinstance(raw_counts, Mapping):
            raise ValueError("py_modern_delta_contradiction")
        expected_counts = {
            "legacy_typing": _plain_int(raw_counts.get("legacy_typing")),
            "dot_format": _plain_int(raw_counts.get("dot_format")),
        }
        row = rows_by_path.get(path)
        if row is None:
            if len(by_file) < MAX_VERIFY_MODERN_DETAIL_FILES and any(expected_counts.values()):
                raise ValueError("py_modern_delta_contradiction")
            continue
        if any(row[key] < value for key, value in expected_counts.items()):
            raise ValueError("py_modern_delta_contradiction")

    if outdated_total <= MAX_VERIFY_MODERN_ENVELOPE_OCCURRENCES:
        for finding in delta.get("findings", ()):
            if not isinstance(finding, Mapping):
                raise ValueError("py_modern_delta_contradiction")
            site = (
                str(finding.get("file")),
                _plain_int(finding.get("line"), minimum=1),
                str(finding.get("kind")),
                str(finding.get("match")),
            )
            if not occurrence_sites[site]:
                raise ValueError("py_modern_delta_contradiction")
            occurrence_sites[site] -= 1

    result = dict(delta)
    result.update(
        absolute_files_scanned=files_scanned,
        absolute_type_modernisation_pct=type_ratio,
        absolute_fstring_pct=format_ratio,
        absolute_legacy_typing=totals["legacy_typing"],
        absolute_dot_format=totals["dot_format"],
    )
    return result


def _run_verify_py_modern_check(
    root: Path,
    *,
    targets: Sequence[str],
    executable: str,
    expected_roam_version: str,
    env: dict[str, str],
) -> tuple[dict[str, object] | None, int]:
    """Run py-modern for Python edits, gating only regressions against Git ``HEAD``."""
    try:
        delta = _verify_python_modernization_delta(root, targets)
    except (MemoryError, OSError, UnicodeError, ValueError):
        return {
            "state": "unavailable",
            "reason": "the bounded edited-file modernization delta could not be derived from Git and Python source",
        }, EXIT_TOOLCHAIN
    if delta["state"] == "not_applicable":
        return delta, 0
    rc, output = _delegate_capturing(
        "--json",
        "py-modern",
        "--detail",
        "--top",
        str(MAX_VERIFY_MODERN_DETAIL_FILES),
        executable=executable,
        env=env,
    )
    if output is None:
        return None, rc
    try:
        result = _validate_verify_py_modern_protocol(
            output,
            returncode=rc,
            expected_roam_version=expected_roam_version,
            expected_root=root,
            delta=delta,
        )
    except (UnicodeError, ValueError):
        return {
            "state": "unavailable",
            "reason": "py-modern did not return one complete structured result consistent with the edited files",
        }, EXIT_TOOLCHAIN
    return result, 0


def _verify_py_modern_unavailable_verdict(reason: object) -> str:
    return _verify_unavailable_verdict(reason, *_VERIFY_PY_MODERN_UNAVAILABLE_VERDICT)


def _bounded_verify_calc_text(value: object, *, reason: str, allow_empty: bool = False) -> str:
    if (
        not isinstance(value, str)
        or (not value and not allow_empty)
        or len(value) > MAX_VERIFY_CALC_TEXT_CHARS
        or any(ord(char) < 32 for char in value)
    ):
        raise ValueError(reason)
    return value


def _verify_calc_relative_path(root: Path, raw_path: object, *, reason: str, must_exist: bool = False) -> str:
    path_text = _bounded_verify_calc_text(raw_path, reason=reason)
    pure = PurePosixPath(path_text)
    if pure.is_absolute() or path_text != pure.as_posix() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(reason)
    try:
        canonical_root = root.resolve(strict=True)
        candidate = canonical_root.joinpath(*pure.parts)
        resolved = candidate.resolve(strict=must_exist)
        if not _path_is_within(resolved, canonical_root):
            raise ValueError(reason)
        if must_exist:
            info = candidate.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise ValueError(reason)
        return pure.as_posix()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(reason) from exc


def _verify_calc_head_declaration_paths(root: Path) -> frozenset[str]:
    """Return tracked pre-edit declaration paths, so deletion cannot disable the check."""
    try:
        head = _verify_type_git_capture(root, ["cat-file", "-e", "HEAD^{commit}"], stdout_limit=1)
        if head.returncode != 0:
            return frozenset()
        tree = _verify_type_git_capture(
            root,
            ["ls-tree", "-r", "-z", "--name-only", "HEAD", "--", ".roam/calc-golden"],
            stdout_limit=MAX_VERIFY_GIT_STATUS_BYTES,
        )
        raw = tree.stdout or b""
        if tree.returncode != 0 or len(raw) > MAX_VERIFY_GIT_STATUS_BYTES or (raw and not raw.endswith(b"\0")):
            raise ValueError("calc_golden_head_declarations")
        paths = {
            _decode_verify_status_path(item)
            for item in raw.split(b"\0")
            if item and PurePosixPath(_decode_verify_status_path(item)).suffix == ".json"
        }
        return frozenset(paths)
    except (OSError, UnicodeError, ValueError):
        if not _git_marker_has_evidence(root):
            return frozenset()
        raise ValueError("calc_golden_head_declarations") from None


def _verify_calc_baseline_paths(root: Path, sources: Sequence[str]) -> dict[str, str | None]:
    """Resolve renames and distinguish untracked additions from unchanged paths."""
    baseline_paths = _verify_type_baseline_paths(root, sources)
    for source, baseline_path in tuple(baseline_paths.items()):
        if baseline_path is None:
            continue
        tree = _verify_type_git_capture(
            root,
            ["ls-tree", "-z", "HEAD", "--", baseline_path],
            stdout_limit=MAX_VERIFY_GIT_STATUS_BYTES,
        )
        raw = tree.stdout or b""
        if tree.returncode != 0 or len(raw) > MAX_VERIFY_GIT_STATUS_BYTES or (raw and not raw.endswith(b"\0")):
            raise ValueError("calc_golden_baseline_source")
        if not raw:
            baseline_paths[source] = None
    return baseline_paths


def _verify_calc_head_commit(root: Path) -> str | None:
    head = _verify_type_git_capture(root, ["rev-parse", "--verify", "HEAD^{commit}"], stdout_limit=80)
    if head.returncode != 0:
        return None
    try:
        commit = (head.stdout or b"").decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("calc_golden_head_commit") from exc
    if re.fullmatch(r"[0-9a-fA-F]{40,64}", commit) is None:
        raise ValueError("calc_golden_head_commit")
    return commit


def _verify_calc_declarations_stable(root: Path, declarations: Sequence[Mapping[str, object]]) -> bool:
    try:
        for declaration in declarations:
            declaration_path = root / Path(str(declaration["path"]))
            corpus_path = root / Path(str(declaration["corpus"]))
            declaration_raw = _read_bounded_utf8_regular_file(
                declaration_path, max_bytes=MAX_VERIFY_CALC_DECLARATION_BYTES
            ).encode("utf-8")
            corpus_raw = _read_bounded_utf8_regular_file(corpus_path, max_bytes=MAX_VERIFY_CALC_CORPUS_BYTES).encode(
                "utf-8"
            )
            if (
                len(corpus_raw) > MAX_VERIFY_CALC_CORPUS_BYTES
                or hashlib.sha256(declaration_raw).hexdigest() != declaration.get("declaration_sha256")
                or hashlib.sha256(corpus_raw).hexdigest() != declaration.get("corpus_sha256")
            ):
                return False
        return True
    except (MemoryError, OSError, UnicodeError, ValueError):
        return False


def _verify_calc_golden_declaration_state(root: Path, targets: Sequence[str]) -> dict[str, object]:
    """Read bounded public golden declarations and bind them to the edit scope."""
    declaration_dir = root / ".roam" / "calc-golden"
    try:
        canonical_root = root.resolve(strict=True)
        declarations: list[dict[str, object]] = []
        current_paths: set[str] = set()
        total_corpus_bytes = 0
        if declaration_dir.exists():
            directory_info = declaration_dir.lstat()
            canonical_dir = declaration_dir.resolve(strict=True)
            if (
                not stat.S_ISDIR(directory_info.st_mode)
                or stat.S_ISLNK(directory_info.st_mode)
                or not _path_is_within(canonical_dir, canonical_root)
            ):
                raise ValueError("calc_golden_declaration_directory")
            entry_count = 0
            for candidate in sorted(declaration_dir.rglob("*")):
                entry_count += 1
                if entry_count > MAX_VERIFY_CALC_DECLARATION_ENTRIES:
                    raise ValueError("calc_golden_declaration_bound")
                if candidate.suffix != ".json" or not candidate.is_file():
                    continue
                if len(declarations) >= MAX_VERIFY_CALC_DECLARATIONS:
                    raise ValueError("calc_golden_declaration_bound")
                declaration_path = candidate.relative_to(root).as_posix()
                if candidate.is_symlink() or not _path_is_within(candidate.resolve(strict=True), canonical_root):
                    raise ValueError("calc_golden_declaration_path")
                declaration_raw = _read_bounded_utf8_regular_file(
                    candidate, max_bytes=MAX_VERIFY_CALC_DECLARATION_BYTES
                )
                document = _strict_json_document(
                    declaration_raw,
                    max_bytes=MAX_VERIFY_CALC_DECLARATION_BYTES,
                )
                if not isinstance(document, dict) or set(document) != {
                    "schema",
                    "name",
                    "corpus",
                    "runner",
                    "sources",
                }:
                    raise ValueError("calc_golden_declaration_shape")
                if document.get("schema") != _VERIFY_CALC_GOLDEN_DECLARATION_SCHEMA:
                    raise ValueError("calc_golden_declaration_schema")
                name = _bounded_verify_calc_text(document.get("name"), reason="calc_golden_name")
                corpus = _verify_calc_relative_path(
                    root, document.get("corpus"), reason="calc_golden_corpus", must_exist=True
                )
                corpus_content = _read_bounded_utf8_regular_file(
                    root / Path(corpus), max_bytes=MAX_VERIFY_CALC_CORPUS_BYTES
                ).encode("utf-8")
                total_corpus_bytes += len(corpus_content)
                if total_corpus_bytes > MAX_VERIFY_CALC_TOTAL_CORPUS_BYTES:
                    raise ValueError("calc_golden_corpus_bound")
                raw_runner = document.get("runner")
                if (
                    not isinstance(raw_runner, list)
                    or not 1 <= len(raw_runner) <= MAX_VERIFY_CALC_RUNNER_ARGS
                    or any(not isinstance(arg, str) for arg in raw_runner)
                ):
                    raise ValueError("calc_golden_runner")
                runner = tuple(_bounded_verify_calc_text(arg, reason="calc_golden_runner") for arg in raw_runner)
                raw_sources = document.get("sources")
                if (
                    not isinstance(raw_sources, list)
                    or not 1 <= len(raw_sources) <= MAX_VERIFY_CALC_SOURCES
                    or any(not isinstance(source, str) for source in raw_sources)
                ):
                    raise ValueError("calc_golden_sources")
                sources = tuple(
                    _verify_calc_relative_path(root, source, reason="calc_golden_source") for source in raw_sources
                )
                if len(set(sources)) != len(sources) or any(
                    PurePosixPath(source).suffix.lower() not in _VERIFY_CALC_SOURCE_SUFFIXES for source in sources
                ):
                    raise ValueError("calc_golden_sources")
                declarations.append(
                    {
                        "path": declaration_path,
                        "name": name,
                        "corpus": corpus,
                        "runner": runner,
                        "sources": sources,
                        "declaration_sha256": hashlib.sha256(declaration_raw.encode("utf-8")).hexdigest(),
                        "corpus_sha256": hashlib.sha256(corpus_content).hexdigest(),
                        "corpus_content": corpus_content,
                    }
                )
                current_paths.add(declaration_path)
        removed = _verify_calc_head_declaration_paths(root) - current_paths
        if removed:
            return {
                "state": "unavailable",
                "reason": "tracked golden declarations were removed from the edit",
                "declaration_count": len(declarations),
            }
    except (MemoryError, OSError, UnicodeError, ValueError):
        return {
            "state": "unavailable",
            "reason": "the bounded .roam/calc-golden declaration probe could not be completed",
            "declaration_count": 0,
        }
    if not declarations:
        return {
            "state": "not_applicable",
            "reason": "no .roam/calc-golden JSON declarations",
            "declaration_count": 0,
        }
    triggered = tuple(
        declaration
        for declaration in declarations
        if any(target == source for target in targets for source in declaration["sources"])
    )
    if not triggered:
        return {
            "state": "not_applicable",
            "reason": "no changed files are declared calculation sources",
            "declaration_count": len(declarations),
        }
    return {
        "state": "declared",
        "declaration_count": len(declarations),
        "declarations": tuple(declarations),
        "triggered_declarations": triggered,
    }


def _validate_verify_calc_golden_protocol(
    output: str,
    *,
    returncode: int,
    expected_roam_version: str,
    expected_runner: str,
) -> dict[str, object]:
    """Validate one bounded calc-golden runner replay before comparing it with HEAD."""
    envelope = _strict_json_document(output, max_bytes=MAX_VERIFY_JSON_BYTES)
    if not isinstance(envelope, dict):
        raise ValueError("calc_golden_envelope")
    if (
        envelope.get("schema") != VERIFY_ENVELOPE_SCHEMA
        or not _envelope_schema_compatible(envelope.get("schema_version"))
        or envelope.get("command") != "calc-golden"
        or envelope.get("version") != expected_roam_version
    ):
        raise ValueError("calc_golden_envelope")
    summary = envelope.get("summary")
    raw_failures = envelope.get("failures")
    if not isinstance(summary, dict) or not isinstance(raw_failures, list):
        raise ValueError("calc_golden_shape")
    if len(raw_failures) > MAX_VERIFY_CALC_ENVELOPE_FAILURES:
        raise ValueError("calc_golden_result_bound")
    total = _plain_int(summary.get("total"))
    replayed = _plain_int(summary.get("replayed"), maximum=total)
    passed = _plain_int(summary.get("passed"), maximum=replayed)
    failed = _plain_int(summary.get("failed"), maximum=replayed)
    missing = _plain_int(summary.get("missing"), maximum=total)
    gate_failed = summary.get("gate_failed")
    pass_pct = summary.get("pass_pct")
    if (
        type(gate_failed) is not bool
        or isinstance(pass_pct, bool)
        or not isinstance(pass_pct, (int, float))
        or not math.isfinite(float(pass_pct))
        or not 0 <= float(pass_pct) <= 100
        or replayed + missing != total
        or passed + failed != replayed
        or summary.get("partial_success") is not False
        or summary.get("oracle") != f"runner:{expected_runner}"
    ):
        raise ValueError("calc_golden_counts")
    expected_pct = round(100.0 * passed / replayed, 2) if replayed else 0.0
    expected_gate = failed > 0 or (replayed == 0 and total > 0) or missing > 0
    if float(pass_pct) != expected_pct or gate_failed != expected_gate:
        raise ValueError("calc_golden_counts")
    if returncode not in {0, EXIT_VERIFY_GATE} or (returncode == EXIT_VERIFY_GATE) != expected_gate:
        raise ValueError("calc_golden_exit_contradiction")
    _bounded_verify_calc_text(summary.get("verdict"), reason="calc_golden_verdict")
    buckets = summary.get("buckets")
    if not isinstance(buckets, dict) or len(buckets) > MAX_VERIFY_CALC_ENVELOPE_FAILURES * 4:
        raise ValueError("calc_golden_buckets")
    bucket_replayed = 0
    bucket_passed = 0
    for bucket, counts in buckets.items():
        _bounded_verify_calc_text(bucket, reason="calc_golden_bucket", allow_empty=True)
        if not isinstance(counts, dict):
            raise ValueError("calc_golden_buckets")
        bucket_total = _plain_int(counts.get("replayed"))
        bucket_ok = _plain_int(counts.get("passed"), maximum=bucket_total)
        bucket_replayed += bucket_total
        bucket_passed += bucket_ok
    if bucket_replayed != replayed or bucket_passed != passed:
        raise ValueError("calc_golden_buckets")

    findings: list[dict[str, object]] = []
    failed_case_ids: set[int] = set()
    runner_failure = False
    for failure in raw_failures:
        if not isinstance(failure, dict) or set(failure) != {"id", "bucket", "inputs", "deltas"}:
            raise ValueError("calc_golden_failure")
        case_id = failure.get("id")
        if type(case_id) is not int or case_id < -1:
            raise ValueError("calc_golden_failure")
        bucket = _bounded_verify_calc_text(failure.get("bucket"), reason="calc_golden_bucket", allow_empty=True)
        inputs = failure.get("inputs")
        deltas = failure.get("deltas")
        if (
            not isinstance(inputs, dict)
            or len(inputs) > MAX_VERIFY_CALC_DELTA_FIELDS * 4
            or any(
                not isinstance(key, str)
                or not isinstance(value, str)
                or len(key) > MAX_VERIFY_CALC_TEXT_CHARS
                or len(value) > MAX_VERIFY_CALC_TEXT_CHARS
                for key, value in inputs.items()
            )
            or not isinstance(deltas, dict)
            or not 1 <= len(deltas) <= MAX_VERIFY_CALC_DELTA_FIELDS
        ):
            raise ValueError("calc_golden_failure")
        is_runner_failure = case_id == -1 or (bucket == "-" and not inputs and "runner" in deltas)
        if is_runner_failure:
            runner_failure = True
        else:
            if case_id in failed_case_ids:
                raise ValueError("calc_golden_failure")
            failed_case_ids.add(case_id)
        for field, delta in deltas.items():
            field_text = _bounded_verify_calc_text(field, reason="calc_golden_field")
            delta_text = _bounded_verify_calc_text(delta, reason="calc_golden_delta")
            if is_runner_failure:
                continue
            findings.append(
                {
                    "case_id": case_id,
                    "bucket": bucket,
                    "field": field_text,
                    "delta": delta_text,
                }
            )
    if len(failed_case_ids) != failed:
        raise ValueError("calc_golden_failure_count")
    incomplete_reason = None
    if total == 0:
        incomplete_reason = "a declared golden corpus contained no replayable cases"
    elif missing:
        incomplete_reason = "the declared golden runner did not answer every case"
    elif runner_failure:
        incomplete_reason = "the declared golden runner did not complete cleanly"
    return {
        "state": "unavailable" if incomplete_reason else ("failed" if failed else "complete"),
        "total": total,
        "failure_count": failed,
        "findings": tuple(findings),
        "unavailable_reason": incomplete_reason,
    }


def _verify_calc_extract_head_archive(root: Path, destination: Path, head_commit: str) -> None:
    archive = _verify_type_git_capture(
        root,
        ["archive", "--format=tar", head_commit],
        stdout_limit=MAX_VERIFY_CALC_ARCHIVE_BYTES,
    )
    raw = archive.stdout or b""
    if archive.returncode != 0 or len(raw) > MAX_VERIFY_CALC_ARCHIVE_BYTES:
        raise ValueError("calc_golden_head_archive")
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as stream:
            members = stream.getmembers()
            if len(members) > MAX_VERIFY_CALC_ARCHIVE_ENTRIES:
                raise ValueError("calc_golden_head_archive")
            for member in members:
                name = member.name.rstrip("/")
                if not name:
                    continue
                pure = PurePosixPath(name)
                if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
                    raise ValueError("calc_golden_head_archive")
                target = destination.joinpath(*pure.parts)
                if not _path_is_within(target.resolve(strict=False), destination.resolve(strict=True)):
                    raise ValueError("calc_golden_head_archive")
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if member.issym():
                    link = PurePosixPath(member.linkname)
                    if link.is_absolute():
                        raise ValueError("calc_golden_head_archive")
                    link_target = (target.parent / Path(*link.parts)).resolve(strict=False)
                    if not _path_is_within(link_target, destination.resolve(strict=True)):
                        raise ValueError("calc_golden_head_archive")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.symlink_to(member.linkname)
                    continue
                if not member.isfile():
                    raise ValueError("calc_golden_head_archive")
                source = stream.extractfile(member)
                if source is None:
                    raise ValueError("calc_golden_head_archive")
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("wb") as output_file:
                    while chunk := source.read(64 * 1024):
                        output_file.write(chunk)
                target.chmod(member.mode & 0o777)
    except (tarfile.TarError, OSError, ValueError):
        raise ValueError("calc_golden_head_archive") from None


@contextmanager
def _verify_calc_head_checkout(
    root: Path,
    declarations: Sequence[Mapping[str, object]],
    baseline_paths: Mapping[str, str | None],
    head_commit: str,
) -> Iterator[Path]:
    """Materialize a bounded HEAD tree, using current corpora as the unchanged oracle."""
    with tempfile.TemporaryDirectory(prefix=".compile-code-calc-", dir=str(root)) as raw_checkout:
        checkout = Path(raw_checkout)
        _verify_calc_extract_head_archive(root, checkout, head_commit)
        for declaration in declarations:
            corpus = str(declaration["corpus"])
            corpus_bytes = declaration.get("corpus_content")
            if not isinstance(corpus_bytes, bytes) or len(corpus_bytes) > MAX_VERIFY_CALC_CORPUS_BYTES:
                raise ValueError("calc_golden_corpus_bound")
            destination = checkout / Path(corpus)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(corpus_bytes)
        for current_path, baseline_path in baseline_paths.items():
            if baseline_path is None or baseline_path == current_path:
                continue
            baseline_source = checkout / Path(baseline_path)
            if not baseline_source.is_file() or baseline_source.is_symlink():
                raise ValueError("calc_golden_baseline_source")
            current_destination = checkout / Path(current_path)
            current_destination.parent.mkdir(parents=True, exist_ok=True)
            current_destination.write_bytes(baseline_source.read_bytes())
        yield checkout


def _run_verify_calc_golden_replay(
    declaration: Mapping[str, object],
    *,
    cwd: Path,
    executable: str,
    expected_roam_version: str,
    env: dict[str, str],
) -> tuple[dict[str, object] | None, int]:
    runner = declaration.get("runner")
    if not isinstance(runner, tuple) or any(not isinstance(arg, str) for arg in runner):
        return {"state": "unavailable", "reason": "the golden runner declaration was invalid"}, EXIT_TOOLCHAIN
    runner_text = shlex.join(runner)
    rc, output = _delegate_capturing(
        "--json",
        "calc-golden",
        "check",
        str(declaration["corpus"]),
        "--runner",
        runner_text,
        "--timeout",
        str(VERIFY_CALC_RUNNER_TIMEOUT),
        timeout=VERIFY_CALC_RUNNER_TIMEOUT + 10,
        executable=executable,
        env=env,
        cwd=str(cwd),
    )
    if output is None:
        return None, rc
    try:
        result = _validate_verify_calc_golden_protocol(
            output,
            returncode=rc,
            expected_roam_version=expected_roam_version,
            expected_runner=runner_text,
        )
    except (UnicodeError, ValueError):
        return {
            "state": "unavailable",
            "reason": "calc-golden did not return one complete structured runner result",
        }, EXIT_TOOLCHAIN
    return result, 0


def _run_verify_calc_golden_check(
    root: Path,
    *,
    targets: Sequence[str],
    executable: str,
    expected_roam_version: str,
    env: dict[str, str],
) -> tuple[dict[str, object] | None, int]:
    """Replay declared golden cases and gate only divergences introduced by the edit."""
    declaration_state = _verify_calc_golden_declaration_state(root, targets)
    if declaration_state["state"] != "declared":
        return declaration_state, 0
    declarations = declaration_state.get("triggered_declarations")
    if not isinstance(declarations, tuple) or any(not isinstance(declaration, Mapping) for declaration in declarations):
        return {"state": "unavailable", "reason": "the golden declaration scope was invalid"}, EXIT_TOOLCHAIN
    all_declarations = declaration_state.get("declarations", declarations)
    if not isinstance(all_declarations, tuple) or any(
        not isinstance(declaration, Mapping) for declaration in all_declarations
    ):
        return {"state": "unavailable", "reason": "the golden declaration set was invalid"}, EXIT_TOOLCHAIN

    sources = tuple(dict.fromkeys(str(source) for declaration in declarations for source in declaration["sources"]))
    try:
        head_commit = _verify_calc_head_commit(root)
        baseline_paths = _verify_calc_baseline_paths(root, sources)
    except (MemoryError, OSError, UnicodeError, ValueError):
        return {
            "state": "unavailable",
            "reason": "the Git pre-edit calculation sources could not be derived",
        }, EXIT_TOOLCHAIN

    current_results: list[tuple[Mapping[str, object], dict[str, object]]] = []
    for declaration in declarations:
        result, rc = _run_verify_calc_golden_replay(
            declaration,
            cwd=root,
            executable=executable,
            expected_roam_version=expected_roam_version,
            env=env,
        )
        if result is None:
            return None, rc
        if result.get("state") == "unavailable":
            return {
                "state": "unavailable",
                "reason": result.get("unavailable_reason", result.get("reason")),
            }, EXIT_TOOLCHAIN
        current_results.append((declaration, result))
    if not _verify_calc_declarations_stable(root, all_declarations):
        return {
            "state": "unavailable",
            "reason": "a golden declaration or corpus changed while its runner was executing",
        }, EXIT_TOOLCHAIN
    baseline_results: dict[str, dict[str, object]] = {}
    if head_commit is not None and any(path is not None for path in baseline_paths.values()):
        try:
            with _verify_calc_head_checkout(root, declarations, baseline_paths, head_commit) as checkout:
                for declaration in declarations:
                    declaration_sources = tuple(str(source) for source in declaration["sources"])
                    if all(baseline_paths[source] is None for source in declaration_sources):
                        continue
                    result, rc = _run_verify_calc_golden_replay(
                        declaration,
                        cwd=checkout,
                        executable=executable,
                        expected_roam_version=expected_roam_version,
                        env=env,
                    )
                    if result is None:
                        return None, rc
                    if result.get("state") == "unavailable":
                        return {
                            "state": "unavailable",
                            "reason": "the Git pre-edit golden replay did not complete",
                        }, EXIT_TOOLCHAIN
                    baseline_results[str(declaration["path"])] = result
        except (MemoryError, OSError, UnicodeError, ValueError):
            return {
                "state": "unavailable",
                "reason": "the bounded Git pre-edit golden replay could not be completed",
            }, EXIT_TOOLCHAIN
    if not _verify_calc_declarations_stable(root, all_declarations):
        return {
            "state": "unavailable",
            "reason": "a golden declaration or corpus changed while its runner was executing",
        }, EXIT_TOOLCHAIN

    regression_count = 0
    absolute_failure_count = 0
    baseline_failure_count = 0
    findings: list[dict[str, object]] = []
    for declaration, current in current_results:
        current_findings = current.get("findings")
        if not isinstance(current_findings, tuple):
            return {"state": "unavailable", "reason": "the golden result was invalid"}, EXIT_TOOLCHAIN
        baseline = baseline_results.get(str(declaration["path"]))
        baseline_findings = () if baseline is None else baseline.get("findings")
        if not isinstance(baseline_findings, tuple):
            return {"state": "unavailable", "reason": "the baseline golden result was invalid"}, EXIT_TOOLCHAIN
        baseline_signatures = {
            (finding.get("case_id"), finding.get("bucket"), finding.get("field"), finding.get("delta"))
            for finding in baseline_findings
            if isinstance(finding, Mapping)
        }
        absolute_failure_count += int(current.get("failure_count", 0))
        baseline_failure_count += int(baseline.get("failure_count", 0)) if baseline is not None else 0
        for finding in current_findings:
            if not isinstance(finding, Mapping):
                return {"state": "unavailable", "reason": "the golden result was invalid"}, EXIT_TOOLCHAIN
            signature = (
                finding.get("case_id"),
                finding.get("bucket"),
                finding.get("field"),
                finding.get("delta"),
            )
            if signature in baseline_signatures:
                continue
            regression_count += 1
            if len(findings) < MAX_VERIFY_CALC_FINDINGS:
                sources_value = declaration["sources"]
                findings.append(
                    {
                        "file": sources_value[0],
                        "calculation": declaration["name"],
                        **dict(finding),
                    }
                )
    return {
        "state": "failed" if regression_count else "complete",
        "declaration_count": declaration_state["declaration_count"],
        "calculation_count": len(declarations),
        "absolute_failure_count": absolute_failure_count,
        "baseline_failure_count": baseline_failure_count,
        "regression_count": regression_count,
        "findings": tuple(findings),
    }, 0


def _verify_calc_golden_unavailable_verdict(reason: object) -> str:
    return _verify_unavailable_verdict(reason, *_VERIFY_CALC_GOLDEN_UNAVAILABLE_VERDICT)


def _verify_collapse_unavailable_verdict(reason: object) -> str:
    return _verify_unavailable_verdict(reason, *_VERIFY_COLLAPSE_UNAVAILABLE_VERDICT)


def _bounded_verify_collapse_text(value: object, *, reason: str, allow_empty: bool = False) -> str:
    if (
        not isinstance(value, str)
        or (not value and not allow_empty)
        or len(value) > MAX_VERIFY_COLLAPSE_TEXT_CHARS
        or any(ord(char) < 32 for char in value)
    ):
        raise ValueError(reason)
    return value


def _verify_collapse_head_source(root: Path, baseline_path: str | None) -> str:
    if baseline_path is None:
        return ""
    blob = _verify_type_git_capture(
        root,
        ["cat-file", "blob", f"HEAD:{baseline_path}"],
        stdout_limit=MAX_VERIFY_COLLAPSE_SOURCE_BYTES,
    )
    raw = blob.stdout or b""
    if blob.returncode != 0 or len(raw) > MAX_VERIFY_COLLAPSE_SOURCE_BYTES:
        tree = _verify_type_git_capture(
            root,
            ["ls-tree", "-z", "HEAD", "--", baseline_path],
            stdout_limit=MAX_VERIFY_GIT_STATUS_BYTES,
        )
        if tree.returncode == 0 and not (tree.stdout or b""):
            return ""
        raise ValueError("collapse_baseline_unavailable")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("collapse_baseline_non_utf8") from exc


def _verify_edited_collapse_sources(root: Path, targets: Sequence[str]) -> tuple[tuple[str, str, str], ...]:
    """Return bounded current/HEAD pairs for edited collapse-supported sources."""
    supported_targets = tuple(
        path for path in targets if PurePosixPath(path).suffix.lower() in _VERIFY_COLLAPSE_SOURCE_SUFFIXES
    )
    if not supported_targets:
        return ()
    head = _verify_type_git_capture(root, ["cat-file", "-e", "HEAD^{commit}"], stdout_limit=1)
    if head.returncode != 0:
        raise ValueError("collapse_baseline_unavailable")
    baseline_paths = _verify_type_baseline_paths(root, supported_targets)
    sources: list[tuple[str, str, str]] = []
    total_source_bytes = 0
    for path in supported_targets:
        candidate = root / Path(path)
        try:
            current_raw = (
                ""
                if not candidate.exists()
                else _read_bounded_utf8_regular_file(candidate, max_bytes=MAX_VERIFY_COLLAPSE_SOURCE_BYTES)
            )
        except (OSError, ValueError) as exc:
            raise ValueError("collapse_current_source_unavailable") from exc
        baseline_raw = _verify_collapse_head_source(root, baseline_paths[path])
        total_source_bytes += len(current_raw.encode("utf-8")) + len(baseline_raw.encode("utf-8"))
        if total_source_bytes > MAX_VERIFY_COLLAPSE_TOTAL_SOURCE_BYTES:
            raise ValueError("collapse_source_scope_too_large")
        sources.append((path, baseline_raw, current_raw))
    return tuple(sources)


@contextmanager
def _verify_collapse_checkout(
    root: Path,
    sources: Sequence[tuple[str, str, str]],
    *,
    current: bool,
) -> Iterator[Path]:
    """Materialize one isolated side of the collapse comparison."""
    with tempfile.TemporaryDirectory(prefix=".compile-code-collapse-", dir=str(root)) as raw_checkout:
        checkout = Path(raw_checkout)
        initialized = _verify_type_git_capture(checkout, ["init", "-q"], stdout_limit=1024)
        if initialized.returncode != 0:
            raise ValueError("collapse_checkout_unavailable")
        for path, baseline_raw, current_raw in sources:
            destination = checkout / Path(path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(current_raw if current else baseline_raw, encoding="utf-8")
        yield checkout


def _verify_collapse_language(path: str) -> str:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in {".py", ".pyi"}:
        return "python"
    if suffix in {".js", ".jsx", ".mjs", ".cjs"}:
        return "javascript"
    if suffix == ".tsx":
        return "tsx"
    if suffix in {".ts", ".mts", ".cts"}:
        return "typescript"
    raise ValueError("collapse_language")


def _validate_verify_collapse_protocol(
    output: str,
    *,
    returncode: int,
    expected_roam_version: str,
    expected_root: Path,
    expected_path: str,
) -> tuple[dict[str, object], ...]:
    """Validate one bounded, single-file collapse result."""
    envelope = _strict_json_document(output, max_bytes=MAX_VERIFY_JSON_BYTES)
    if not isinstance(envelope, dict):
        raise ValueError("collapse_envelope")
    if (
        envelope.get("schema") != VERIFY_ENVELOPE_SCHEMA
        or not _envelope_schema_compatible(envelope.get("schema_version"))
        or envelope.get("command") != "collapse"
        or envelope.get("version") != expected_roam_version
        or returncode != 0
    ):
        raise ValueError("collapse_envelope")
    summary = envelope.get("summary")
    rules = envelope.get("rules")
    raw_findings = envelope.get("findings")
    unreadable_files = envelope.get("unreadable_files")
    unparsed_files = envelope.get("unparsed_files")
    if (
        not isinstance(summary, dict)
        or not isinstance(rules, list)
        or not isinstance(raw_findings, list)
        or not isinstance(unreadable_files, list)
        or not isinstance(unparsed_files, list)
    ):
        raise ValueError("collapse_shape")
    if len(raw_findings) > MAX_VERIFY_COLLAPSE_ENVELOPE_FINDINGS:
        raise ValueError("collapse_result_bound")
    if envelope.get("supported_languages") != list(_VERIFY_COLLAPSE_LANGUAGES):
        raise ValueError("collapse_languages")

    total = _plain_int(summary.get("total_findings"), maximum=MAX_VERIFY_COLLAPSE_ENVELOPE_FINDINGS)
    high = _plain_int(summary.get("high_findings"), maximum=total)
    medium = _plain_int(summary.get("medium_findings"), maximum=total)
    files_scanned = _plain_int(summary.get("files_scanned"), maximum=1)
    supported_files = _plain_int(summary.get("supported_files"), maximum=1)
    rules_checked = _plain_int(summary.get("rules_checked"), maximum=len(_VERIFY_COLLAPSE_RULES))
    if (
        summary.get("state") != "completed"
        or summary.get("partial_success") not in (None, False)
        or total != len(raw_findings)
        or high + medium != total
        or files_scanned != 1
        or supported_files != 1
        or rules_checked != len(_VERIFY_COLLAPSE_RULES)
        or unreadable_files
        or unparsed_files
        or summary.get("suppression_comment") != _VERIFY_COLLAPSE_SUPPRESSION_COMMENT
        or summary.get("findings_metric_definition") != _VERIFY_COLLAPSE_METRIC_DEFINITION
        or summary.get("verdict") != f"{total} collapse findings in 1 scanned files"
    ):
        raise ValueError("collapse_summary")

    declared_counts: Counter[str] = Counter()
    seen_rules: set[str] = set()
    for row in rules:
        if not isinstance(row, dict):
            raise ValueError("collapse_rule")
        rule = row.get("id")
        if not isinstance(rule, str) or rule not in _VERIFY_COLLAPSE_RULES or rule in seen_rules:
            raise ValueError("collapse_rule")
        label, repair = _VERIFY_COLLAPSE_RULES[rule]
        if row.get("label") != label or row.get("repair") != repair:
            raise ValueError("collapse_rule")
        declared_counts[rule] = _plain_int(row.get("count"), maximum=total)
        seen_rules.add(rule)
    if seen_rules != set(_VERIFY_COLLAPSE_RULES):
        raise ValueError("collapse_rule")

    expected_language = _verify_collapse_language(expected_path)
    findings: list[dict[str, object]] = []
    actual_counts: Counter[str] = Counter()
    actual_severities: Counter[str] = Counter()
    for raw_finding in raw_findings:
        if not isinstance(raw_finding, dict):
            raise ValueError("collapse_finding")
        path = _verify_rule_site(expected_root, raw_finding.get("file"))
        line = _plain_int(raw_finding.get("line"), minimum=1)
        rule = raw_finding.get("rule")
        severity = raw_finding.get("severity")
        if (
            path != expected_path
            or not isinstance(rule, str)
            or rule not in _VERIFY_COLLAPSE_RULES
            or not isinstance(severity, str)
            or severity not in _VERIFY_COLLAPSE_SEVERITIES
        ):
            raise ValueError("collapse_finding")
        facts = _bounded_verify_collapse_text(raw_finding.get("collapsed_facts"), reason="collapse_facts")
        repair = _bounded_verify_collapse_text(raw_finding.get("repair"), reason="collapse_repair")
        snippet = _bounded_verify_collapse_text(raw_finding.get("snippet"), reason="collapse_snippet", allow_empty=True)
        language = raw_finding.get("language")
        if repair != _VERIFY_COLLAPSE_RULES[str(rule)][1] or language != expected_language:
            raise ValueError("collapse_finding")
        actual_counts[str(rule)] += 1
        actual_severities[str(severity)] += 1
        findings.append(
            {
                "file": path,
                "line": line,
                "rule": rule,
                "severity": severity,
                "collapsed_facts": facts,
                "repair": repair,
                "snippet": snippet,
                "language": language,
            }
        )
    if declared_counts != actual_counts or actual_severities != Counter({"high": high, "medium": medium}):
        raise ValueError("collapse_counts")
    return tuple(findings)


def _run_verify_collapse_scan(
    root: Path,
    targets: Sequence[str],
    *,
    executable: str,
    expected_roam_version: str,
    env: dict[str, str],
) -> tuple[tuple[dict[str, object], ...] | None, int, str | None]:
    indexed_rc, indexed_output = _delegate_capturing(
        "index",
        "--force",
        executable=executable,
        env=env,
        cwd=str(root),
    )
    if indexed_output is None:
        return None, indexed_rc, None
    if indexed_rc != 0:
        return (), EXIT_TOOLCHAIN, "the isolated collapse scan index could not be built"
    findings: list[dict[str, object]] = []
    for path in targets:
        rc, output = _delegate_capturing(
            "--json",
            "collapse",
            "--file",
            path,
            "--include-tests",
            executable=executable,
            env=env,
            cwd=str(root),
        )
        if output is None:
            return None, rc, None
        try:
            findings.extend(
                _validate_verify_collapse_protocol(
                    output,
                    returncode=rc,
                    expected_roam_version=expected_roam_version,
                    expected_root=root,
                    expected_path=path,
                )
            )
        except (UnicodeError, ValueError):
            return (), EXIT_TOOLCHAIN, "collapse did not return one complete structured result for the edited file"
        if len(findings) > MAX_VERIFY_COLLAPSE_ENVELOPE_FINDINGS:
            return (), EXIT_TOOLCHAIN, "the combined collapse result exceeded its bounded finding limit"
    return tuple(findings), 0, None


def _verify_collapse_finding_key(finding: Mapping[str, object]) -> tuple[str, ...]:
    return tuple(
        str(finding[field]) for field in ("file", "rule", "severity", "collapsed_facts", "snippet", "language")
    )


def _run_verify_collapse_check(
    root: Path,
    *,
    targets: Sequence[str],
    executable: str,
    expected_roam_version: str,
    env: dict[str, str],
) -> tuple[dict[str, object] | None, int]:
    """Run collapse on identical current/HEAD file sets and gate only new findings."""
    try:
        sources = _verify_edited_collapse_sources(root, targets)
    except (MemoryError, OSError, UnicodeError, ValueError):
        return {
            "state": "unavailable",
            "reason": "the bounded pre-edit collapse source set could not be derived from Git",
        }, EXIT_TOOLCHAIN
    if not sources:
        return {
            "state": "not_applicable",
            "reason": "no changed Python or JavaScript/TypeScript files",
            "regression_count": 0,
            "findings": (),
        }, 0
    scan_targets = tuple(path for path, _baseline_raw, _current_raw in sources)
    try:
        with _verify_collapse_checkout(root, sources, current=False) as baseline_root:
            baseline_findings, baseline_rc, baseline_reason = _run_verify_collapse_scan(
                baseline_root,
                scan_targets,
                executable=executable,
                expected_roam_version=expected_roam_version,
                env=env,
            )
        if baseline_findings is None:
            return None, baseline_rc
        if baseline_reason is not None:
            return {"state": "unavailable", "reason": baseline_reason}, EXIT_TOOLCHAIN
        with _verify_collapse_checkout(root, sources, current=True) as current_root:
            current_findings, current_rc, current_reason = _run_verify_collapse_scan(
                current_root,
                scan_targets,
                executable=executable,
                expected_roam_version=expected_roam_version,
                env=env,
            )
        if current_findings is None:
            return None, current_rc
        if current_reason is not None:
            return {"state": "unavailable", "reason": current_reason}, EXIT_TOOLCHAIN
    except (MemoryError, OSError, UnicodeError, ValueError):
        return {
            "state": "unavailable",
            "reason": "the isolated pre-edit and current collapse scans could not be completed",
        }, EXIT_TOOLCHAIN

    baseline_counts = Counter(_verify_collapse_finding_key(finding) for finding in baseline_findings)
    regressions: list[dict[str, object]] = []
    regression_count = 0
    for finding in current_findings:
        key = _verify_collapse_finding_key(finding)
        if baseline_counts[key]:
            baseline_counts[key] -= 1
            continue
        regression_count += 1
        if len(regressions) < MAX_VERIFY_COLLAPSE_FINDINGS:
            regressions.append(finding)
    return {
        "state": "failed" if regression_count else "complete",
        "absolute_finding_count": len(current_findings),
        "baseline_finding_count": len(baseline_findings),
        "regression_count": regression_count,
        "findings": tuple(regressions),
    }, 0


def _prepare_verify_request(
    files: tuple[str, ...],
) -> tuple[Path, list[str], dict[str, object], dict[str, str], list[str]]:
    root = _verification_root()
    excluded: list[str] = []
    if files:
        # An explicit path is the caller's stated intent: verify it or refuse
        # it, never quietly drop it. Only discovery, which guesses at scope,
        # narrows.
        requested_targets = _verification_scope_paths(list(files))
    else:
        requested_targets, excluded = _discovered_scope(root)
    targets = _verification_scope_paths(_expand_verify_targets(requested_targets, root))
    if len(targets) > MAX_VERIFY_TARGETS or sum(len(path) + 1 for path in targets) > MAX_VERIFY_ARG_CHARS:
        raise ValueError("verification_scope_too_large")
    nonce = secrets.token_hex(16)
    scope_sha256 = _verification_scope_sha256(targets)
    content_sha256 = _verification_content_sha256(root, targets)
    expected: dict[str, object] = {
        "schema": VERIFY_RECEIPT_SCHEMA,
        "request_nonce": nonce,
        "scope_sha256": scope_sha256,
        "content_sha256": content_sha256,
        "content_sha256_before": content_sha256,
        "content_sha256_after": content_sha256,
        "target_file_count": len(targets),
        "scope_stable": True,
        "request_match": True,
    }
    env = _trusted_tool_env(
        overrides={
            "ROAM_VERIFY_REQUEST_NONCE": nonce,
            "ROAM_VERIFY_SCOPE_SHA256": scope_sha256,
            "ROAM_VERIFY_CONTENT_SHA256": content_sha256,
            "ROAM_VERIFY_SCOPE_COUNT": str(len(targets)),
            "ROAM_DEFAULT_JSON_BUDGET": "0",
            "ROAM_AGENT_CONTRACT_BLOCK": "1",
        }
    )
    return root, targets, expected, env, excluded


def _plain_int(value: object, *, minimum: int = 0, maximum: int | None = None) -> int:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise ValueError("invalid_integer")
    return value


def _validate_finding(
    finding: object,
    *,
    expected_root: Path | None = None,
    allowed_categories: frozenset[str] = _VERIFY_CATEGORY_NAMES,
) -> dict:
    """Validate one finding, binding its category to the roster the envelope declared.

    *allowed_categories* is this build's fixed roster widened by whatever extra
    categories the SAME envelope declared in its `categories` mapping -- never
    free-form. A finding may only name a detector the producer also declared
    and ran, so a newer roam's findings are read rather than dropped, and a
    finding in a category nobody declared is still refused.
    """
    if not isinstance(finding, dict):
        raise ValueError("invalid_finding")
    severity = finding.get("severity")
    category = finding.get("category")
    file_path = finding.get("file")
    message = finding.get("message", "")
    if severity not in _VERIFY_FINDING_SEVERITIES or category not in allowed_categories:
        raise ValueError("invalid_finding_severity")
    for value, limit in ((category, 128), (file_path, 4096), (message, 4096)):
        if not isinstance(value, str) or len(value) > limit or any(ord(char) < 32 for char in value):
            raise ValueError("invalid_finding_text")
    try:
        if _verification_scope_paths([file_path]) != [file_path]:
            raise ValueError("invalid_finding_path")
        if expected_root is not None:
            canonical_root = expected_root.resolve(strict=True)
            resolved_finding = (canonical_root / Path(file_path)).resolve(strict=False)
            if not _path_is_within(resolved_finding, canonical_root):
                raise ValueError("invalid_finding_path")
    except (UnicodeError, ValueError) as exc:
        raise ValueError("invalid_finding_path") from exc
    except (OSError, RuntimeError) as exc:
        raise ValueError("invalid_finding_path") from exc
    line = finding.get("line")
    if line is not None:
        _plain_int(line, minimum=1)
    return finding


def _require_known_shape(
    mapping: Mapping[str, object],
    *,
    required: frozenset[str],
    allowed: frozenset[str],
    vocabulary: frozenset[str],
    reason: str,
) -> None:
    """Gate the known vocabulary exactly; let an unknown name through to disclosure.

    A missing key and an unknown extra key are different events and must not
    share a verdict. A missing required key means the producer withheld
    something this build depends on: fail closed. An unknown extra key means
    the producer is NEWER than this build -- nothing depended-on is absent, so
    the transaction is still readable, and the right answer is to proceed and
    say what was ignored (`_unrecognised_envelope_fields` feeds the rendered
    disclosure). Every name this build has heard of is still placement-checked
    against *allowed*, so opening the world costs no existing gate: only names
    with no meaning here at all are tolerated.
    """
    present = frozenset(mapping)
    if not required <= present or not (present & vocabulary) <= allowed:
        raise ValueError(reason)
    # Name the colliding field. This branch is the one place where an entirely
    # NEUTRAL addition by a newer producer can hard-refuse: every other unknown
    # key is tolerated and disclosed, but a key whose name asserts an incomplete
    # run -- as a whole name, or as one token inside a compound one -- is
    # refused, because a rename must not buy a pass. That trade is right and
    # stays. What was wrong is that the refusal
    # said nothing about WHICH name tripped it, so a producer that added a
    # neutral field called `warnings` produced a verdict indistinguishable from
    # a broken receipt, and the reader had no way to find the cause on either
    # side of the contract. The name is rendered through the same safe filter
    # as every other disclosed field, so no producer-supplied text reaches the
    # verdict unfiltered.
    colliding = sorted(name for name in (present - vocabulary) if _asserts_incompleteness(name))
    if colliding:
        raise ValueError(
            "unknown_incompleteness_signal: " + ", ".join(_disclosable_field_name(name) for name in colliding)
        )


def _disclosable_field_name(name: object) -> str:
    """Render one producer-supplied field name safely inside a verdict block."""
    return name if isinstance(name, str) and _SAFE_FIELD_NAME.fullmatch(name) else "<unprintable>"


def _extra_category_names(categories: Mapping[str, object], known: frozenset[str]) -> frozenset[str]:
    """Categories a newer producer declared beyond *known*, refusing unrenderable names.

    A missing known category and an extra unknown one are different events, the
    same way they are for `_require_known_shape`: a missing gate is something
    this build depends on going absent, an extra one is a producer that is
    NEWER. Adding a detector is the most frequently exercised extension point
    roam has -- 11 new category names in five weeks of its own history -- and
    an exact set equality made every one of them a total verify outage.

    The extras are NOT waved through: each is validated by the same category
    rules as a known one, its findings enter the evidence multiset and the
    FAIL floor, and the name itself must be renderable, because it reaches the
    verdict block as a section heading and as a `checks:` entry. That last
    check refuses more than today's equality did in one direction: a producer
    cannot introduce a category whose name would inject text into the verdict.
    """
    extra = frozenset(categories) - known
    unsafe = sorted(
        _disclosable_field_name(name)
        for name in extra
        if not isinstance(name, str) or not _SAFE_FIELD_NAME.fullmatch(name)
    )
    if unsafe:
        raise ValueError("unknown_category: " + ", ".join(unsafe))
    return extra


def _named_incomplete_checks(reasons: object) -> str:
    """Which named checks roam declared incomplete, drawn from a fixed vocabulary."""
    if not isinstance(reasons, list):
        return ""
    named = {
        reason[: -len("_incomplete")]
        for reason in reasons
        if isinstance(reason, str)
        and reason.endswith("_incomplete")
        and reason[: -len("_incomplete")] in _VERIFY_CHECK_NAMES
    }
    return ", ".join(sorted(named))


def _is_bounded_disclosure_text(value: object) -> bool:
    """Whether a producer-supplied disclosure string is non-empty and bounded."""
    return isinstance(value, str) and 0 < len(value) <= MAX_DISCLOSURE_TEXT_CHARS and all(ord(c) >= 32 for c in value)


def _leak_catalogue_note(envelope: Mapping[str, object]) -> str | None:
    """Say that a PASS does not rest on a repo-local leak catalogue, or nothing.

    Before this build read `repo_patterns_error`, the one visible trace of a
    skipped leak catalogue was the forward-compatibility line -- "roam envelope
    schema 1.2.0 carried 1 field this build does not read" -- which files a
    security disclosure under schema drift and is exactly the sentence a reader
    is trained to skip. Roam's own message is not replayed: it is producer text,
    and the two causes it distinguishes in prose are not separable here anyway.
    Only the category names are printed, and those are checked against a fixed
    set before this runs.
    """
    categories = envelope.get("categories")
    if not isinstance(categories, Mapping):
        return None
    named = sorted(
        _disclosable_field_name(name)
        for name, result in categories.items()
        if isinstance(result, Mapping) and result.get("repo_patterns_error")
    )
    if not named:
        return None
    return (
        f"note: a repo-local leak catalogue contributed no patterns to {', '.join(named)}; "
        "roam's built-in secret checks still ran, and this verdict does not rest on the catalogue. "
        "A catalogue nobody opted into executing is the expected default and gates nothing; one that "
        "was opted into and failed to load is reported as an incomplete check and refuses instead."
    )


def _unrecognised_envelope_fields(envelope: Mapping[str, object]) -> tuple[str, ...]:
    """Dotted paths of every validated-envelope field this build could not read.

    Deliberately does not walk `verification_receipt`: that mapping is bound by
    exact equality to the request this process constructed, so it has no
    forward-compatibility surface to disclose.
    """
    unknown = {_disclosable_field_name(name) for name in frozenset(envelope) - _VERIFY_ENVELOPE_KEYS}
    summary = envelope.get("summary")
    if isinstance(summary, Mapping):
        unknown.update(f"summary.{_disclosable_field_name(name)}" for name in frozenset(summary) - _VERIFY_SUMMARY_KEYS)
    categories = envelope.get("categories")
    if isinstance(categories, Mapping):
        for category_name, result in categories.items():
            if isinstance(result, Mapping):
                unknown.update(
                    f"categories.{_disclosable_field_name(category_name)}.{_disclosable_field_name(name)}"
                    for name in frozenset(result) - _VERIFY_CATEGORY_KEYS
                )
    return tuple(sorted(unknown))


def _forward_compatibility_note(envelope: Mapping[str, object]) -> str | None:
    """Disclose what a newer producer sent that this build ignored, or nothing.

    Silence when nothing was ignored is the point: a note on every run of a
    newer roam would train readers to skip the line that matters. The note
    fires on observed unreadable content, never on the version number alone.
    """
    unknown = _unrecognised_envelope_fields(envelope)
    if not unknown:
        return None
    shown = list(unknown[:MAX_DISCLOSED_UNKNOWN_FIELDS])
    if len(unknown) > len(shown):
        shown.append(f"+{len(unknown) - len(shown)} more")
    declared = envelope.get("schema_version")
    version = declared if isinstance(declared, str) and _ENVELOPE_SCHEMA_VERSION_VALUE.fullmatch(declared) else "?"
    return (
        f"note: roam envelope schema {version} carried {len(unknown)} "
        f"field{'s' if len(unknown) != 1 else ''} this build does not read; "
        f"gate applied to the rest. Ignored: {', '.join(shown)}"
    )


def _finding_fingerprint(finding: dict) -> str:
    """Return one canonical, multiplicity-preserving evidence identity."""
    try:
        return json.dumps(finding, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("invalid_finding") from exc


def _validate_verify_scope_summary(scope: object, *, expected_count: int, files_checked: int) -> None:
    """Validate Roam's canonical indexed/non-code target accounting."""
    if files_checked > expected_count:
        raise ValueError("scope_count")
    if scope is None:
        if files_checked != expected_count:
            raise ValueError("scope_missing")
        return
    if (
        not isinstance(scope, dict)
        or not _VERIFY_SCOPE_REQUIRED_KEYS <= set(scope)
        or not set(scope) <= _VERIFY_SCOPE_KEYS
        or "unresolved_existing_code_count" in scope
    ):
        raise ValueError("scope_schema")
    target_count = _plain_int(scope.get("target_file_count"))
    indexed_count = _plain_int(scope.get("indexed_file_count"))
    non_code_count = _plain_int(scope.get("non_code_file_count"))
    unresolved_count = _plain_int(scope.get("unresolved_file_count", 0))
    # Roam derives the block arithmetically: unresolved is target_count minus
    # the indexed file map (omitted at zero) and non_code counts doc surfaces
    # among the SAME targets, resolved or not. The two are independent, so
    # requiring `non_code <= unresolved` -- or any unresolved file at all --
    # refused every changed set that included an INDEXED doc, which is what a
    # touched README is. The accounting still has to close exactly.
    if (
        target_count != expected_count
        or indexed_count != files_checked
        or indexed_count + unresolved_count != expected_count
        or non_code_count > expected_count
        or not (non_code_count or unresolved_count)
    ):
        raise ValueError("scope_binding")
    definition = scope.get("non_code_scope_definition")
    if (non_code_count > 0 and definition != _VERIFY_NON_CODE_SCOPE_DEFINITION) or (
        non_code_count == 0 and "non_code_scope_definition" in scope
    ):
        raise ValueError("scope_definition")


def _validate_verify_protocol(
    output: str,
    *,
    returncode: int,
    expected_receipt: dict[str, object],
    expected_roam_version: str,
    expected_threshold: int | None,
    expected_root: Path | None = None,
    diff_only: bool = False,
) -> dict:
    """Validate one complete, request-bound Roam Verify receipt-v3 transaction."""
    envelope = _strict_json_document(output, max_bytes=MAX_VERIFY_JSON_BYTES)
    if not isinstance(envelope, dict):
        raise ValueError("envelope_shape")
    if not _envelope_schema_compatible(envelope.get("schema_version")):
        raise ValueError("envelope_schema_incompatible")
    _require_known_shape(
        envelope,
        required=_VERIFY_ENVELOPE_KEYS,
        allowed=_VERIFY_ENVELOPE_KEYS,
        vocabulary=_VERIFY_ENVELOPE_KEYS,
        reason="envelope_contract",
    )
    if (
        envelope.get("schema") != VERIFY_ENVELOPE_SCHEMA
        or envelope.get("command") != "verify"
        or envelope.get("version") != expected_roam_version
        or not isinstance(envelope.get("project"), str)
        or not envelope.get("project")
        or not isinstance(envelope.get("_meta"), dict)
        or not isinstance(envelope.get("agent_contract"), dict)
    ):
        raise ValueError("envelope_contract")
    summary = envelope.get("summary")
    categories = envelope.get("categories")
    violations = envelope.get("violations")
    if not isinstance(summary, dict) or not isinstance(categories, dict) or not isinstance(violations, list):
        raise ValueError("verify_shape")
    _require_known_shape(
        summary,
        required=frozenset(),
        allowed=_VERIFY_SUMMARY_KEYS,
        vocabulary=_VERIFY_SUMMARY_KEYS,
        reason="summary_schema",
    )
    verdict = summary.get("verdict")
    if verdict not in _VERIFY_VERDICTS:
        raise ValueError("verdict_enum")
    score = _plain_int(summary.get("score"), maximum=100)
    threshold = _plain_int(summary.get("threshold"), maximum=100)
    files_checked = _plain_int(summary.get("files_checked"))
    violation_count = _plain_int(summary.get("violation_count"))
    expected_count = _plain_int(expected_receipt.get("target_file_count"))
    if (
        (expected_threshold is not None and threshold != expected_threshold)
        or len(violations) != violation_count
        or summary.get("truncated") is True
    ):
        raise ValueError("summary_binding")
    # `suppressed` is how many findings a checked-in `.roam-suppressions.yml`
    # removed BEFORE roam recomputed the score, and it is accepted rather than
    # refused on purpose: unlike every other filter roam applies, this one has
    # no request-side correlate -- it arrives on a DEFAULT `compile verify` with
    # no flag at all, so refusing it would take every repo that uses roam
    # suppressions dark. What it must not do is arrive unread; it is rendered
    # into the verdict line below, and a field this build now claims to
    # understand has to actually be understood. Measured against roam 14.0.0
    # through a pass-through shim: the real producer writes `sum(1 for ...)`
    # and omits the key entirely at zero, so a plain non-negative int refuses
    # nothing honest.
    # `baselined` is the `--new-only` counterpart and is shape-checked for the
    # same reason: it is now READ, by `_declared_filter_warn`, and a field this
    # build acts on has to be understood. Measured: roam emits a plain int
    # (`baselined: 4` over a written baseline) and omits the key at zero.
    for filter_count in ("suppressed", "baselined"):
        if filter_count in summary:
            try:
                _plain_int(summary[filter_count])
            except ValueError:
                raise ValueError("summary_filter_shape") from None
    # `diff_scoped` is the OTHER kind of filter: unlike `suppressed` it has a
    # request-side correlate, so it is bound to the request rather than merely
    # disclosed. This process knows whether it passed `--diff-only`, so binding
    # the answer to the question costs no honest run and closes the mutation
    # measured here: `summary += {"diff_scoped": true}` on a plain
    # `compile verify` was accepted at exit 0 and rendered as a whole-file PASS,
    # which is a producer reporting only the lines it chose to call changed.
    #
    # Two deliberate non-rules, both measured against roam 14.0.0:
    #  * bind on TRUTH, not on presence. A future producer that always emits the
    #    field would otherwise become a total exit-2 outage on the day it ships.
    #    An explicit `false` means "not scoped" and is ordinary.
    #  * do NOT require the field when `--diff-only` WAS passed. Roam omits it
    #    on honest `--diff-only` runs that scoped nothing -- a clean file emits
    #    no filter fields, and an untracked file has no diff baseline -- so
    #    requiring it would refuse those runs on day one. The disclosure is
    #    keyed on the request instead, so it survives the omission.
    if "diff_scoped" in summary and type(summary["diff_scoped"]) is not bool:
        raise ValueError("summary_filter_shape")
    if summary.get("diff_scoped") is True and not diff_only:
        raise ValueError("unrequested_scope_filter")
    incomplete_reasons = summary.get("incomplete_reasons")
    # Carry WHICH check roam said was incomplete into every refusal below, not
    # just the last one. Roam sets `verification_complete: false` and
    # `incomplete_reasons` together, so the flag branch always won the race and
    # the reason list -- the only part that names anything -- was never read.
    # Every reason is producer text, so nothing is echoed: a reason survives
    # only by matching `<check>_incomplete` for a check name already in this
    # build's fixed vocabulary, and what reaches the verdict is that
    # vocabulary entry.
    named_incomplete = _named_incomplete_checks(incomplete_reasons)
    if (
        summary.get("verification_complete") is not True
        or summary.get("partial_success") is not False
        or incomplete_reasons not in (None, [])
    ):
        raise ValueError("verification_incomplete" + (f": {named_incomplete}" if named_incomplete else ""))

    if expected_count == 0:
        _require_known_shape(
            summary,
            required=_VERIFY_NO_CHANGES_SUMMARY_KEYS,
            allowed=_VERIFY_NO_CHANGES_SUMMARY_KEYS,
            vocabulary=_VERIFY_SUMMARY_KEYS,
            reason="no_changes_contract",
        )
        if (
            returncode != 0
            or verdict != "PASS"
            or score != 100
            or files_checked != 0
            or violation_count != 0
            or violations != []
            or summary.get("state") != "no_changes"
            or summary.get("checks_run") != []
            or "verification_receipt" in summary
            or not _VERIFY_NO_CHANGES_CATEGORY_NAMES <= frozenset(categories)
        ):
            raise ValueError("no_changes_contract")
        # A floor, not an equality, for the same reason as the changed-file
        # branch below: a repo with nothing to check is the most common verify
        # there is, and one new roam detector must not take it dark. Extra
        # names buy nothing here -- the loop that follows pins every category,
        # known or not, to score 100 and an empty violation list.
        _extra_category_names(categories, _VERIFY_NO_CHANGES_CATEGORY_NAMES)
        for category_name, result in categories.items():
            expected_keys = (
                _VERIFY_NO_CHANGES_VERIFICATION_KEYS
                if category_name == "verification"
                else _VERIFY_NO_CHANGES_CATEGORY_KEYS
            )
            if not isinstance(category_name, str) or not category_name or not isinstance(result, dict):
                raise ValueError("no_changes_category")
            _require_known_shape(
                result,
                required=expected_keys,
                allowed=expected_keys,
                vocabulary=_VERIFY_CATEGORY_KEYS,
                reason="no_changes_category",
            )
            if (
                result.get("score") != 100
                or result.get("violations") != []
                or (category_name == "verification" and result.get("available") is not True)
            ):
                raise ValueError("no_changes_category")
        return envelope

    # A FLOOR, not an equality. Every gate this build knows about must still be
    # present -- a missing one is a check that did not run, and that stays a
    # refusal. What is no longer refused is a category this build has not heard
    # of: adding a detector is roam's most frequently exercised extension point
    # (11 new category names in five weeks of its own history), and an exact
    # set equality made each one a total verify outage on a producer that was
    # working correctly. The extras are not ignored, which is the part that
    # matters here: ignoring them would drop a new detector's FAIL findings on
    # the floor and render a failing tree as PASS. They go through the same
    # shape, completeness and counting rules as every known category below,
    # their findings enter `category_findings` -- so the evidence multiset and
    # the FAIL floor both see them -- and their names are bound to what the
    # producer declared, never free-form.
    if not _VERIFY_CATEGORY_NAMES <= frozenset(categories):
        raise ValueError("category_enum")
    extra_categories = _extra_category_names(categories, _VERIFY_CATEGORY_NAMES)
    declared_categories = _VERIFY_CATEGORY_NAMES | extra_categories
    verification_category = categories.get("verification")
    if not isinstance(verification_category, dict):
        raise ValueError("verification_category")
    _require_known_shape(
        verification_category,
        required=_VERIFY_CATEGORY_REQUIRED_KEYS,
        allowed=_VERIFY_CATEGORY_REQUIRED_KEYS,
        vocabulary=_VERIFY_CATEGORY_KEYS,
        reason="verification_category",
    )
    if (
        verification_category.get("score") != 100
        or verification_category.get("violation_count") != 0
        or verification_category.get("violations") != []
    ):
        raise ValueError("verification_category")
    top_level_findings = [
        _validate_finding(finding, expected_root=expected_root, allowed_categories=declared_categories)
        for finding in violations
    ]
    category_findings: list[dict] = []
    for category_name, result in categories.items():
        if not isinstance(category_name, str) or not category_name or not isinstance(result, dict):
            raise ValueError("category_shape")
        _require_known_shape(
            result,
            required=_VERIFY_CATEGORY_REQUIRED_KEYS,
            allowed=_VERIFY_CATEGORY_KEYS,
            vocabulary=_VERIFY_CATEGORY_KEYS,
            reason="category_shape",
        )
        _plain_int(result.get("score"), maximum=100)
        nested = result.get("violations", [])
        if not isinstance(nested, list):
            raise ValueError("category_findings")
        if _plain_int(result["violation_count"]) != len(nested):
            raise ValueError("category_count")
        for counter in ("tests_targeted", "tests_failed", "tests_total_impacted"):
            if counter in result:
                _plain_int(result[counter])
        if "repo_patterns_error" in result and not _is_bounded_disclosure_text(result["repo_patterns_error"]):
            # Accepting a field means accepting its shape. This one is never
            # replayed into a verdict, so the bound is not the only thing
            # standing between producer text and the output -- but a field this
            # build now claims to understand has to actually be understood.
            raise ValueError("category_disclosure")
        if "no_impacted_tests" in result and type(result["no_impacted_tests"]) is not bool:
            raise ValueError("category_counter")
        if (
            "available" in result
            or "unavailable_reason" in result
            or "parse_failures" in result
            or result.get("execution_state") not in {None, "complete"}
            or ("partial_success" in result and result["partial_success"] is not False)
            or ("timed_out" in result and result["timed_out"] is not False)
            or ("capped" in result and result["capped"] is not False)
        ):
            # `category_name` is no longer drawn from a fixed set -- a newer
            # producer's own detector name can reach here -- so it goes through
            # the same safe filter as every other disclosed name. Extras are
            # already `_SAFE_FIELD_NAME`-bound above; this keeps that the
            # rendering rule rather than a fact one has to go and re-derive.
            raise ValueError(f"category_incomplete: {_disclosable_field_name(category_name)}")
        for finding in nested:
            validated = _validate_finding(finding, expected_root=expected_root, allowed_categories=declared_categories)
            if validated.get("category") != category_name:
                raise ValueError("category_finding_contradiction")
            category_findings.append(validated)
    if Counter(map(_finding_fingerprint, top_level_findings)) != Counter(map(_finding_fingerprint, category_findings)):
        raise ValueError("finding_multiset_contradiction")
    evidence_findings = top_level_findings
    has_fail = any(finding.get("severity") == "FAIL" for finding in evidence_findings)

    checks_run = summary.get("checks_run")
    # The check roster widens with the category roster or not at all. A new
    # detector arrives as a new category AND a new `checks_run` entry, so
    # widening only the category equality converts a `category_enum` outage
    # into a `completion_binding` one -- measured, not assumed. This grants no
    # free-form name: `extra_categories` is exactly what the same envelope
    # declared under `categories`, and `missing_category` below independently
    # requires every run check to have a category, so a producer cannot invent
    # a check it did not also declare and gate.
    allowed_checks = _VERIFY_CHECK_NAMES | extra_categories
    quality_band = "PASS" if score >= 80 else "WARN" if score >= 60 else "FAIL"
    index_refresh = summary.get("index_refresh")
    if (
        summary.get("state") != "verified"
        or summary.get("targets_checked") != expected_count
        or summary.get("quality_band") != quality_band
        or (
            verdict in {"PASS", "WARN"}
            and verdict != quality_band
            and not _declared_filter_warn(summary, verdict, quality_band)
        )
        or not isinstance(index_refresh, dict)
        or set(index_refresh) != {"state", "refreshed_file_count"}
        or index_refresh.get("state") not in {"current", "refreshed"}
        or type(index_refresh.get("refreshed_file_count")) is not int
        or index_refresh["refreshed_file_count"] < 0
        or index_refresh["refreshed_file_count"] > files_checked
        or (index_refresh["state"] == "current" and index_refresh["refreshed_file_count"] != 0)
        or not isinstance(checks_run, list)
        or not checks_run
        or any(not isinstance(check, str) or not check for check in checks_run)
        or any(check not in allowed_checks for check in checks_run)
        or len(set(checks_run)) != len(checks_run)
    ):
        raise ValueError("completion_binding")
    _validate_verify_scope_summary(summary.get("scope"), expected_count=expected_count, files_checked=files_checked)
    if any(finding.get("category") not in checks_run for finding in evidence_findings):
        raise ValueError("finding_check_contradiction")
    receipt = summary.get("verification_receipt")
    if (
        not isinstance(receipt, dict)
        or set(receipt) != _VERIFY_RECEIPT_KEYS
        or set(expected_receipt) != _VERIFY_RECEIPT_KEYS
        or receipt != expected_receipt
    ):
        raise ValueError("receipt_binding")
    for check in checks_run:
        if check not in categories:
            raise ValueError("missing_category")
    if verdict in {"PASS", "WARN"}:
        # A PASS is pinned by four independently re-derived facts, all above:
        # exit 0, score >= the threshold this process requested, no FAIL
        # finding anywhere in the evidence, and roam's own `quality_band`
        # agreeing with the band recomputed here from the score. Nothing else
        # is a contradiction. There used to be a fifth rule -- a PASS could
        # carry WARN findings only in seven hard-coded category names -- and it
        # was a claim about roam that roam does not make: its verdict is
        # `score >= 80` and nothing else, so no category name enters it. An
        # earlier version of this comment said advisory-ness is DECLARED per
        # category in the envelope; that is false as measured -- roam sets an
        # `advisory` flag on individual checks internally, but the per-category
        # summary it emits is a strict allowlist whose key set is exactly
        # `score`, `violation_count`, `violations`, and the string "advisory"
        # appears nowhere in a real envelope. The deletion never rested on that
        # claim, which is the only reason correcting it changes no behaviour:
        # it rests on the verdict arithmetic above and on the floors below.
        # Both verdict floors that can override the band trigger on
        # FAIL-severity findings only, so a roam that skipped one still emits a
        # FAIL finding and is caught by `has_fail`. What the rule actually did
        # was refuse ordinary output: a file containing nothing but
        # `except Exception: pass` produced verdict PASS, score 96 and two WARN
        # findings in `error_handling`, and the whole transaction was rejected
        # at exit 2 as a malformed receipt, with a remedy that reinstalls a
        # roam that was already correct.
        if returncode != 0 or score < threshold or has_fail:
            raise ValueError("success_contradiction")
    elif returncode != EXIT_VERIFY_GATE or (score >= threshold and not has_fail):
        raise ValueError("failure_contradiction")
    return envelope


def _render_verify_envelope(envelope: dict, *, excluded: Sequence[str] = (), diff_only: bool = False) -> str:
    """Render validated structured evidence without replaying raw subprocess text.

    ``excluded`` is what discovery narrowed away. It rides on the VERDICT line
    rather than above it: the denominator that line publishes is the scope roam
    was actually given, and a PASS over a reduced scope must say so in the same
    sentence as the PASS.

    The same rule binds roam's OWN filters, and it was written here without
    being applied to them: ``summary.suppressed`` is a numerator reduction of
    exactly the same kind, arriving with no flag at all whenever the repo has a
    ``.roam-suppressions.yml``, and it rode through unrendered. ``diff_only``
    is the third reduction on the same line -- a verdict over edited lines is
    not a verdict over the file, and it read identically to one.
    """
    summary = envelope["summary"]
    issue_count = summary["violation_count"]
    files_checked = summary["files_checked"]
    targets_checked = summary.get("targets_checked", files_checked)
    lines = [
        f"VERDICT: {summary['verdict']} (score {summary['score']}/100) -- "
        f"{issue_count} issue{'s' if issue_count != 1 else ''} in "
        f"{targets_checked} changed file{'s' if targets_checked != 1 else ''}"
        f"{_narrowed_scope_suffix(excluded)}"
        f"{_diff_scope_suffix(diff_only)}"
        f"{_suppressed_findings_suffix(summary)}"
    ]
    catalogue_note = _leak_catalogue_note(envelope)
    if catalogue_note:
        lines.append(catalogue_note)
    note = _forward_compatibility_note(envelope)
    if note:
        lines.append(note)
    checks = summary.get("checks_run") or []
    if checks:
        lines.append(f"checks: {', '.join(checks)}")
    grouped: dict[str, list[dict]] = {}
    for finding in envelope["violations"]:
        grouped.setdefault(finding["category"], []).append(finding)
    for category, findings in grouped.items():
        result = envelope["categories"].get(category) or {}
        lines.extend(("", f"{category.replace('_', ' ').upper()} ({result.get('score', 0)}/100):"))
        for finding in findings:
            location = finding["file"]
            if finding.get("line") is not None:
                location += f":{finding['line']}"
            message = finding.get("message") or "verification finding"
            lines.append(f"  {finding['severity']}: {location} -- {message}")
    return "\n".join(lines)


def _render_verify_with_rules_check(
    envelope: dict,
    rules_result: Mapping[str, object] | None,
    *,
    excluded: Sequence[str] = (),
    diff_only: bool = False,
) -> str:
    """Add the validated product-owned rule result to the Verify rendering."""
    rendered = _render_verify_envelope(envelope, excluded=excluded, diff_only=diff_only)
    if rules_result is None:
        return rendered
    lines = rendered.splitlines()
    state = rules_result.get("state")
    if state == "not_applicable":
        lines.append("rules [not_applicable]: no .roam/rules YAML declarations")
        return "\n".join(lines)
    if state not in {"complete", "failed"}:
        raise ValueError("rules_render_state")

    for index, line in enumerate(lines):
        if line.startswith("checks:"):
            roster = [item.strip() for item in line.removeprefix("checks:").split(",")]
            if "rules" not in roster:
                lines[index] = f"{line}, rules"
            break
    else:
        lines.insert(1, "checks: rules")

    rule_count = _plain_int(rules_result.get("rule_count"))
    declaration_count = _plain_int(rules_result.get("declaration_count"))
    findings_value = rules_result.get("findings")
    if not isinstance(findings_value, tuple):
        raise ValueError("rules_render_findings")
    findings = list(findings_value)
    gating_findings = [
        finding
        for finding in findings
        if isinstance(finding, Mapping) and finding.get("severity") in _VERIFY_RULE_GATING_SEVERITIES
    ]
    if state == "complete":
        lines.append(
            f"rules [complete]: {rule_count} rule{'s' if rule_count != 1 else ''} from "
            f"{declaration_count} declaration{'s' if declaration_count != 1 else ''}"
        )
    else:
        issue_count = len(gating_findings)
        summary = envelope["summary"]
        targets_checked = summary.get("targets_checked", summary["files_checked"])
        lines[0] = (
            f"VERDICT: FAIL (governance rules) -- {issue_count} rule violation"
            f"{'s' if issue_count != 1 else ''} in {targets_checked} changed file"
            f"{'s' if targets_checked != 1 else ''}{_narrowed_scope_suffix(excluded)}"
            f"{_diff_scope_suffix(diff_only)}{_suppressed_findings_suffix(summary)}"
        )

    if findings:
        lines.extend(("", f"RULES ({'0' if state == 'failed' else '100'}/100):"))
        for finding in findings[:MAX_VERIFY_RULE_FINDINGS]:
            if not isinstance(finding, Mapping):
                raise ValueError("rules_render_finding")
            location = str(finding["file"])
            if finding.get("line") is not None:
                location += f":{finding['line']}"
            level = "FAIL" if finding["severity"] in _VERIFY_RULE_GATING_SEVERITIES else "WARN"
            lines.append(f"  {level}: {location} -- {finding['rule']}: {finding['reason']}")
        if len(findings) > MAX_VERIFY_RULE_FINDINGS:
            lines.append(f"  (+{len(findings) - MAX_VERIFY_RULE_FINDINGS} more rule findings omitted by output bound)")
    return "\n".join(lines)


def _render_verify_with_product_checks(
    envelope: dict,
    rules_result: Mapping[str, object] | None,
    py_types_result: Mapping[str, object] | None,
    py_modern_result: Mapping[str, object] | None,
    *,
    excluded: Sequence[str] = (),
    diff_only: bool = False,
) -> str:
    """Compose core Verify with the validated product-owned check results."""
    rendered = _render_verify_with_rules_check(
        envelope,
        rules_result,
        excluded=excluded,
        diff_only=diff_only,
    )
    lines = rendered.splitlines()
    summary = envelope["summary"]
    targets_checked = summary.get("targets_checked", summary["files_checked"])

    if py_types_result is not None:
        state = py_types_result.get("state")
        if state == "not_applicable":
            lines.append("py-types [not_applicable]: no changed Python files")
        elif state in {"complete", "failed"}:
            for index, line in enumerate(lines):
                if line.startswith("checks:"):
                    roster = [item.strip() for item in line.removeprefix("checks:").split(",")]
                    if "py-types" not in roster:
                        lines[index] = f"{line}, py-types"
                    break
            else:
                lines.insert(1, "checks: py-types")

            total_public = _plain_int(py_types_result.get("absolute_total_public"))
            coverage = py_types_result.get("absolute_coverage_pct")
            if coverage is not None:
                _plain_int(coverage, maximum=100)
                absolute = (
                    f"absolute repository coverage observed at {coverage}% across {total_public} public callables"
                )
            else:
                absolute = "absolute repository coverage not computable (no public callables)"
            if state == "complete":
                lines.append(f"py-types [complete]: edited-file annotation delta clean; {absolute}")
            else:
                regression_count = _plain_int(py_types_result.get("regression_count"), minimum=1)
                if lines[0].startswith("VERDICT: FAIL (governance rules)"):
                    lines[0] = (
                        "VERDICT: FAIL (governance rules + type-annotation regression) -- "
                        "product-owned edit gates failed"
                    )
                else:
                    lines[0] = (
                        f"VERDICT: FAIL (type-annotation regression) -- {regression_count} degraded annotation"
                        f"{'s' if regression_count != 1 else ''} in {targets_checked} changed file"
                        f"{'s' if targets_checked != 1 else ''}{_narrowed_scope_suffix(excluded)}"
                        f"{_diff_scope_suffix(diff_only)}{_suppressed_findings_suffix(summary)}"
                    )
                findings = py_types_result.get("findings")
                if not isinstance(findings, tuple):
                    raise ValueError("py_types_render_findings")
                lines.extend(("", "PY TYPES (0/100):"))
                for finding in findings[:MAX_VERIFY_TYPE_FINDINGS]:
                    if not isinstance(finding, Mapping):
                        raise ValueError("py_types_render_finding")
                    location = str(finding["file"])
                    if finding.get("line") is not None:
                        location += f":{finding['line']}"
                    lines.append(
                        f"  FAIL: {location} -- {finding['symbol']}: {finding['annotation']} {finding['change']}"
                    )
                omitted = regression_count - len(findings)
                if omitted > 0:
                    lines.append(f"  (+{omitted} more type-annotation regressions omitted by output bound)")
        else:
            raise ValueError("py_types_render_state")

    if py_modern_result is None:
        return "\n".join(lines)
    modern_state = py_modern_result.get("state")
    if modern_state == "not_applicable":
        lines.append("py-modern [not_applicable]: no changed Python files")
        return "\n".join(lines)
    if modern_state not in {"complete", "failed"}:
        raise ValueError("py_modern_render_state")

    for index, line in enumerate(lines):
        if line.startswith("checks:"):
            roster = [item.strip() for item in line.removeprefix("checks:").split(",")]
            if "py-modern" not in roster:
                lines[index] = f"{line}, py-modern"
            break
    else:
        lines.insert(1, "checks: py-modern")
    type_ratio = _plain_int(py_modern_result.get("absolute_type_modernisation_pct"), maximum=100)
    format_ratio = _plain_int(py_modern_result.get("absolute_fstring_pct"), maximum=100)
    absolute_legacy = _plain_int(py_modern_result.get("absolute_legacy_typing"))
    absolute_dot_format = _plain_int(py_modern_result.get("absolute_dot_format"))
    absolute = (
        f"absolute repository adoption observed at type-modern {type_ratio}%, f-string {format_ratio}% "
        f"({absolute_legacy} legacy-typing, {absolute_dot_format} dot-format)"
    )
    if modern_state == "complete":
        lines.append(f"py-modern [complete]: edited-file outdated-construct delta clean; {absolute}")
        return "\n".join(lines)

    modern_regression_count = _plain_int(py_modern_result.get("regression_count"), minimum=1)
    failed_labels: list[str] = []
    if rules_result is not None and rules_result.get("state") == "failed":
        failed_labels.append("governance rules")
    if py_types_result is not None and py_types_result.get("state") == "failed":
        failed_labels.append("type-annotation regression")
    failed_labels.append("Python modernization regression")
    if len(failed_labels) > 1:
        lines[0] = f"VERDICT: FAIL ({' + '.join(failed_labels)}) -- product-owned edit gates failed"
    else:
        lines[0] = (
            f"VERDICT: FAIL (Python modernization regression) -- {modern_regression_count} outdated construct"
            f"{'s' if modern_regression_count != 1 else ''} introduced in {targets_checked} changed file"
            f"{'s' if targets_checked != 1 else ''}{_narrowed_scope_suffix(excluded)}"
            f"{_diff_scope_suffix(diff_only)}{_suppressed_findings_suffix(summary)}"
        )
    modern_findings = py_modern_result.get("findings")
    if not isinstance(modern_findings, tuple):
        raise ValueError("py_modern_render_findings")
    lines.extend(("", "PY MODERN (0/100):"))
    for finding in modern_findings[:MAX_VERIFY_MODERN_FINDINGS]:
        if not isinstance(finding, Mapping):
            raise ValueError("py_modern_render_finding")
        location = str(finding["file"])
        if finding.get("line") is not None:
            location += f":{finding['line']}"
        lines.append(f"  FAIL: {location} -- {finding['kind']} introduced: {finding['match']}")
    omitted = modern_regression_count - len(modern_findings)
    if omitted > 0:
        lines.append(f"  (+{omitted} more modernization regressions omitted by output bound)")
    return "\n".join(lines)


def _render_verify_with_calc_golden_check(
    rendered: str,
    envelope: Mapping[str, object],
    calc_golden_result: Mapping[str, object] | None,
    *,
    excluded: Sequence[str] = (),
    diff_only: bool = False,
) -> str:
    """Compose the validated golden semantic delta with the other Verify checks."""
    if calc_golden_result is None:
        return rendered
    lines = rendered.splitlines()
    state = calc_golden_result.get("state")
    if state == "not_applicable":
        reason = _bounded_verify_calc_text(calc_golden_result.get("reason"), reason="calc_golden_render_reason")
        lines.append(f"calc-golden [not_applicable]: {reason}")
        return "\n".join(lines)
    if state not in {"complete", "failed"}:
        raise ValueError("calc_golden_render_state")

    for index, line in enumerate(lines):
        if line.startswith("checks:"):
            roster = [item.strip() for item in line.removeprefix("checks:").split(",")]
            if "calc-golden" not in roster:
                lines[index] = f"{line}, calc-golden"
            break
    else:
        lines.insert(1, "checks: calc-golden")
    calculation_count = _plain_int(calc_golden_result.get("calculation_count"), minimum=1)
    absolute_failure_count = _plain_int(calc_golden_result.get("absolute_failure_count"))
    baseline_failure_count = _plain_int(calc_golden_result.get("baseline_failure_count"))
    if state == "complete":
        lines.append(
            f"calc-golden [complete]: {calculation_count} declared calculation"
            f"{'s' if calculation_count != 1 else ''} replayed; semantic delta clean "
            f"({absolute_failure_count} current vs {baseline_failure_count} pre-edit golden case failures)"
        )
        return "\n".join(lines)

    regression_count = _plain_int(calc_golden_result.get("regression_count"), minimum=1)
    summary = envelope.get("summary")
    if not isinstance(summary, Mapping):
        raise ValueError("calc_golden_render_summary")
    targets_checked = summary.get("targets_checked", summary.get("files_checked"))
    _plain_int(targets_checked)
    if lines[0].startswith("VERDICT: PASS"):
        lines[0] = (
            f"VERDICT: FAIL (calculation semantic regression) -- {regression_count} golden output divergence"
            f"{'s' if regression_count != 1 else ''} introduced in {targets_checked} changed file"
            f"{'s' if targets_checked != 1 else ''}{_narrowed_scope_suffix(excluded)}"
            f"{_diff_scope_suffix(diff_only)}{_suppressed_findings_suffix(summary)}"
        )
    else:
        label_match = re.match(r"^VERDICT: FAIL \(([^)]*)\)", lines[0])
        previous_label = label_match.group(1) if label_match else "another Verify gate"
        lines[0] = (
            f"VERDICT: FAIL ({previous_label} + calculation semantic regression) -- product-owned edit gates failed"
        )
    findings = calc_golden_result.get("findings")
    if not isinstance(findings, tuple):
        raise ValueError("calc_golden_render_findings")
    lines.extend(("", "CALC GOLDEN (0/100):"))
    for finding in findings[:MAX_VERIFY_CALC_FINDINGS]:
        if not isinstance(finding, Mapping):
            raise ValueError("calc_golden_render_finding")
        location = str(finding["file"])
        calculation = str(finding["calculation"])
        case_id = finding["case_id"]
        bucket = str(finding["bucket"])
        field = str(finding["field"])
        delta = str(finding["delta"])
        lines.append(f"  FAIL: {location} -- {calculation}: case {case_id} ({bucket}), {field}: {delta}")
    omitted = regression_count - len(findings)
    if omitted > 0:
        lines.append(f"  (+{omitted} more golden output divergences omitted by output bound)")
    return "\n".join(lines)


def _render_verify_with_collapse_check(
    rendered: str,
    envelope: Mapping[str, object],
    collapse_result: Mapping[str, object] | None,
    *,
    excluded: Sequence[str] = (),
    diff_only: bool = False,
) -> str:
    """Compose the validated benign-default delta with the other Verify checks."""
    if collapse_result is None:
        return rendered
    lines = rendered.splitlines()
    state = collapse_result.get("state")
    if state == "not_applicable":
        lines.append("collapse [not_applicable]: no changed Python or JavaScript/TypeScript files")
        return "\n".join(lines)
    if state not in {"complete", "failed"}:
        raise ValueError("collapse_render_state")

    for index, line in enumerate(lines):
        if line.startswith("checks:"):
            roster = [item.strip() for item in line.removeprefix("checks:").split(",")]
            if "collapse" not in roster:
                lines[index] = f"{line}, collapse"
            break
    else:
        lines.insert(1, "checks: collapse")
    absolute_count = _plain_int(collapse_result.get("absolute_finding_count"))
    baseline_count = _plain_int(collapse_result.get("baseline_finding_count"))
    if state == "complete":
        lines.append(
            "collapse [complete]: edited-file benign-default delta clean "
            f"({absolute_count} current vs {baseline_count} pre-edit findings)"
        )
        return "\n".join(lines)

    regression_count = _plain_int(collapse_result.get("regression_count"), minimum=1)
    summary = envelope.get("summary")
    if not isinstance(summary, Mapping):
        raise ValueError("collapse_render_summary")
    targets_checked = summary.get("targets_checked", summary.get("files_checked"))
    _plain_int(targets_checked)
    if lines[0].startswith("VERDICT: PASS"):
        lines[0] = (
            f"VERDICT: FAIL (benign-default collapse regression) -- {regression_count} collapse finding"
            f"{'s' if regression_count != 1 else ''} introduced in {targets_checked} changed file"
            f"{'s' if targets_checked != 1 else ''}{_narrowed_scope_suffix(excluded)}"
            f"{_diff_scope_suffix(diff_only)}{_suppressed_findings_suffix(summary)}"
        )
    else:
        label_match = re.match(r"^VERDICT: FAIL \(([^)]*)\)", lines[0])
        previous_label = label_match.group(1) if label_match else "another Verify gate"
        lines[0] = (
            f"VERDICT: FAIL ({previous_label} + benign-default collapse regression) -- product-owned edit gates failed"
        )
    findings = collapse_result.get("findings")
    if not isinstance(findings, tuple):
        raise ValueError("collapse_render_findings")
    lines.extend(("", "COLLAPSE (0/100):"))
    for finding in findings[:MAX_VERIFY_COLLAPSE_FINDINGS]:
        if not isinstance(finding, Mapping):
            raise ValueError("collapse_render_finding")
        location = str(finding["file"])
        if finding.get("line") is not None:
            location += f":{finding['line']}"
        lines.append(
            f"  FAIL: {location} -- {finding['rule']}: {finding['collapsed_facts']} Repair: {finding['repair']}"
        )
    omitted = regression_count - len(findings)
    if omitted > 0:
        lines.append(f"  (+{omitted} more benign-default collapse regressions omitted by output bound)")
    return "\n".join(lines)


def _verify_failing_files(
    result: Mapping[str, object], *, gating_severities: Container[object] | None = None
) -> list[str]:
    files: list[str] = []
    findings = result.get("findings")
    if not isinstance(findings, tuple):
        return files
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        if gating_severities is not None and finding.get("severity") not in gating_severities:
            continue
        path = finding.get("file")
        if isinstance(path, str) and path not in files:
            files.append(path)
    return files


def _failing_files(envelope: dict) -> list[str]:
    """Return exact validated FAIL paths without round-tripping through display text."""
    failing: list[str] = []
    for finding in envelope["violations"]:
        if finding["severity"] != "FAIL":
            continue
        failed_file = finding["file"]
        if failed_file not in failing:
            failing.append(failed_file)
    return failing


def _classify_verify_failure(output: str, rc: int) -> str:
    """Map a roam verify failure to a one-phrase cause category.

    Prefers the check sections that contain a ``FAIL:`` line; falls back to
    the roam exit code so non-gate failures (missing/stale index, bad args)
    still get a meaningful label rather than a generic "verify failure".
    """
    lines = output.splitlines()
    section_at: dict[int, str] = {
        i: match.group(1).strip() for i, line in enumerate(lines) if (match := _VERIFY_SECTION.match(line))
    }
    failing: list[str] = []
    current: str | None = None
    for i, line in enumerate(lines):
        if i in section_at:
            current = section_at[i]
            continue
        if current and _VERIFY_FAIL_LINE.match(line):
            failing.append(current)
            current = None  # one failing section per category is enough signal
    if failing:
        labels = [_VERIFY_CAUSE_LABELS.get(name, name.lower()) for name in failing]
        return " + ".join(dict.fromkeys(labels))
    return _EXIT_CAUSE.get(rc, "verify failure")


def _format_command_inventory(commands: Mapping[str, click.Command]) -> str:
    """Render a deterministic, greppable dispatch inventory: one 'name — short_help' line per verb."""
    lines = []
    for name in sorted(commands):
        cmd = commands[name]
        help_text = (cmd.get_short_help_str() or "").strip()
        lines.append(f"{name} — {help_text}" if help_text else name)
    return "\n".join(lines)


@cli.command("commands")
def _commands() -> None:
    """Print a deterministic inventory of all CLI verbs (for scripts / CI)."""
    click.echo(_format_command_inventory(cli.commands))


def _format_verify_failure(**failure: object) -> str:
    """Render the verify-failure block from the context needed to act locally."""
    command = failure.get("command")
    files = failure.get("files")
    cause = failure.get("cause")
    next_action = failure.get("next_action")
    if not isinstance(command, str) or not isinstance(cause, str) or not isinstance(next_action, str):
        raise TypeError("verify failure context must include command, cause, and next_action strings")
    if not isinstance(files, list) or not all(isinstance(file, str) for file in files):
        raise TypeError("verify failure context must include files as a list of strings")

    files_line = ", ".join(files) if files else "(no changed files)"
    return (
        "VERDICT: verify failed.\n"
        f"  command : {command}\n"
        f"  files   : {files_line}\n"
        f"  cause   : {cause}\n"
        f"  next    : {next_action}"
    )


def _render_verify_command(
    *,
    new_only: bool,
    diff_only: bool,
    threshold: int | None,
) -> str:
    """Render one shell-neutral recovery command containing no path content."""
    tokens = ["compile", "verify"]
    if new_only:
        tokens.append("--new-only")
    if diff_only:
        tokens.append("--diff-only")
    if threshold is not None:
        tokens.extend(["--threshold", str(threshold)])
    return " ".join([*tokens, "--changed"])


def _unsafe_scope_verdict(error: BaseException) -> str | None:
    raw_reason = str(error)
    reason, _, detail = raw_reason.partition(": ")
    location = f" ({detail})" if detail else " (scope location unavailable)"
    # The three traversal bounds race on the user's filesystem, so each of them
    # reports the reader's position on all three rather than only the one that
    # tripped. An older raise site that carries no detail still renders.
    position = f" at {detail}" if detail else ""
    if reason == "scope_path_control_character":
        return (
            f"VERDICT: verify refused: scope path{location} contains an unsafe control character "
            "(including a newline). Rename that file and rerun `compile verify --changed`."
        )
    if reason == "scope_path_undecodable":
        return (
            f"VERDICT: verify refused: scope path{location} is not representable as UTF-8. "
            "Rename that file and rerun `compile verify --changed`."
        )
    if reason == "verification_directory_limit":
        return (
            f"VERDICT: verify refused — explicit-directory traversal exceeded the "
            f"{MAX_VERIFY_DIRECTORIES}-directory safety limit{position}. Pass a smaller explicit file scope."
        )
    if reason == "verification_directory_entry_limit":
        return (
            f"VERDICT: verify refused — explicit-directory traversal exceeded the "
            f"{MAX_VERIFY_DIRECTORY_ENTRIES}-entry safety limit{position}. Pass a smaller explicit file scope."
        )
    if reason == "verification_target_limit":
        return (
            f"VERDICT: verify refused — explicit-directory expansion exceeded the "
            f"{MAX_VERIFY_TARGETS}-file safety limit. Pass a smaller explicit file scope."
        )
    if reason == "verification_directory_timeout":
        return (
            f"VERDICT: verify refused — explicit-directory traversal exceeded the "
            f"{MAX_VERIFY_TRAVERSAL_SECONDS:g}-second safety limit{position}. Pass explicit file paths."
        )
    if reason in {
        "verification_directory_changed",
        "verification_directory_empty",
        "verification_directory_unreadable",
        "verification_directory_unsafe",
    }:
        return (
            "VERDICT: verify refused — an explicit directory was unreadable, unsafe, empty, or changed during "
            "bounded traversal. Stabilize the directory or pass explicit file paths."
        )
    return None


def _verify_protocol_verdict(error: BaseException, *, executable: str, targets: list[str]) -> str:
    """Describe a rejected receipt without replaying untrusted tool output."""
    reason = str(error).split(":", 1)[0] or "unknown_validation_error"
    indices = ",".join(str(index) for index in range(len(targets))) or "none"
    if reason == "envelope_schema_incompatible":
        # An incompatible MAJOR envelope means this build is too old to read
        # what the producer emits, so upgrading the producer cannot help.
        return (
            f"VERDICT: verifier protocol failure: receipt field/reason {reason}; "
            f"scope target indices {indices}; executable `{executable}` declared an envelope schema this build "
            f"cannot read (reads any {VERIFY_ENVELOPE_SCHEMA} major "
            f"{VERIFY_ENVELOPE_SCHEMA_VERSION.split('.')[0]} shape; this build was written against "
            f"{VERIFY_ENVELOPE_SCHEMA_VERSION}). Fix: python -m pip install --upgrade compile-code"
        )
    if reason == "unknown_incompleteness_signal":
        # Distinguished from the generic protocol failure below because the
        # remedy is different and the cause is nameable. Prescribing a roam
        # upgrade here would be wrong: the producer is the NEWER side.
        _, _, colliding = str(error).partition(": ")
        named = f" (field: {colliding})" if colliding else ""
        return (
            f"VERDICT: verifier protocol failure: receipt field/reason {reason}; "
            f"scope target indices {indices}; executable `{executable}` sent a field this build has no "
            f"interpretation for whose NAME asserts an incomplete run{named}. A renamed incompleteness signal "
            "must not buy a pass, so this is refused rather than ignored and disclosed like other unknown "
            "fields. If that field is neutral, this build is too old to know it. "
            "Fix: python -m pip install --upgrade compile-code"
        )
    if reason == "unknown_category":
        # Reached only by a name that cannot be safely rendered: a newer roam's
        # own detector categories are accepted and gated, not refused, so this
        # is never the "your compile-code is too old" case and must not read
        # like one. The colliding name is deliberately not echoed -- it is
        # unrenderable, which is the whole reason it is here.
        return (
            f"VERDICT: verifier protocol failure: receipt field/reason {reason}; "
            f"scope target indices {indices}; executable `{executable}` declared a check category whose NAME "
            "cannot be safely rendered inside a verdict block, so the receipt was refused rather than printed. "
            "A category this build has never heard of is otherwise read and gated like any other; only the name "
            f'is the problem here. Fix: python -m pip install --upgrade "{ROAM_PACKAGE_REQUIREMENT}"'
        )
    if reason in {"verification_incomplete", "category_incomplete"}:
        # Roam ran to completion and said so; what it withheld is evidence, not
        # a receipt. Measured on a repository whose opted-in
        # `.roam-leak-patterns.py` raises on load: roam 14.0.0 refuses with
        # `secrets` incomplete, and this branch used to answer with the generic
        # protocol failure -- "did not return one complete, bound Verify receipt
        # v3. Fix: pip install --upgrade roam-code>=13.10.0" -- naming neither
        # the check nor the cause, and prescribing an upgrade to a producer
        # already four majors past the floor it quotes. Reinstalling roam
        # cannot make a broken catalogue load, and a reader who follows that
        # remedy and watches it change nothing is being taught that this gate
        # is the thing in the way.
        _, _, named = str(error).partition(": ")
        checks = f" (check{'s' if ',' in named else ''}: {named})" if named else ""
        return (
            f"VERDICT: verifier protocol failure: receipt field/reason {reason}; "
            f"scope target indices {indices}; executable `{executable}` ran to completion but declared its own "
            f"evidence incomplete{checks}, so part of what this gate is asked to prove did not run. A check that "
            "did not run cannot be passed. Fix: repair what that check depends on in THIS repository (its "
            "configuration, index, or inputs) and rerun `compile verify --changed`; upgrading roam does not make "
            "an unrun check run."
        )
    if reason in {"post_verify_content_changed", "post_verify_scope_changed"}:
        # Raised by this CLI's own post-run recheck, never by roam's receipt:
        # the tree moved under a completed run. Prescribing a roam upgrade here
        # sends the caller after a version that was already in range.
        return (
            f"VERDICT: verifier protocol failure: receipt field/reason {reason}; "
            f"scope target indices {indices}; the verification scope changed while verify ran, so the receipt no "
            "longer describes the tree. Fix: stop anything writing to the worktree and rerun "
            "`compile verify --changed`"
        )
    return (
        f"VERDICT: verifier protocol failure: receipt field/reason {reason}; "
        f"scope target indices {indices}; executable `{executable}` did not return one complete, bound Verify "
        f'receipt v3. Fix: python -m pip install --upgrade "{ROAM_PACKAGE_REQUIREMENT}"'
    )


@cli.command("verify")
@click.argument("files", nargs=-1)
@click.option(
    "--changed",
    is_flag=True,
    help="Verify the complete changed-file scope (also the default when no files are supplied).",
)
@click.option(
    "--new-only",
    is_flag=True,
    help="Ignore findings already present in .roam/verify-baseline.json (absent baseline behaves like today).",
)
@click.option(
    "--diff-only",
    is_flag=True,
    help="Report only violations on edited lines (noise cut; still fails on new violations).",
)
@click.option(
    "--threshold",
    type=click.IntRange(0, 100),
    default=None,
    help="Fail below this score (otherwise use .roam/verify.yaml or Roam's default).",
)
def _verify(files: tuple[str, ...], changed: bool, new_only: bool, diff_only: bool, threshold: int | None) -> None:
    """Run scoped verify on changed files; on failure, explain the next local action.

    Delegates to `roam verify --auto`, which selects checks from the bound
    changed set. Its delete-safety check derives its trigger from the same Git
    change: a deleted or renamed path, or a diff hunk removing an
    exported/public symbol, is checked for surviving references. The
    product-owned adapters are also auto-selected from that scope: a bounded
    declaration probe runs `.roam/rules` YAML rules when present, and Python
    edits run `py-types` and `py-modern` with edited-file deltas against Git
    ``HEAD`` so legacy absolute debt does not gate unrelated work. Declared
    `.roam/calc-golden` calculations replay their cases against both the edited
    source and Git ``HEAD`` so only the edit's semantic divergence gates.
    Edited Python and JavaScript/TypeScript sources run `collapse` against
    isolated current and Git ``HEAD`` materializations of the same file set,
    so only newly introduced benign-default collapses gate.
    Inapplicable adapters report typed not_applicable states. If any triggered
    check lacks the inputs needed for a complete result, VERIFY names the
    unavailable state and refuses instead of publishing a false pass.
    `--new-only` passes through to roam's accepted-debt baseline; `--diff-only`
    keeps the output scoped to changed lines. Only a complete, bound JSON
    receipt is rendered. A validated gate failure is followed by a block naming
    the failing command, changed files, likely cause category, and the single
    local rerun to run next.
    """
    if changed and files:
        raise click.UsageError("--changed cannot be combined with explicit file arguments")
    roam_info = _inspect_roam()
    roam_problem = _roam_problem(roam_info)
    if roam_problem is not None:
        exit_code, verdict = roam_problem
        click.echo(verdict)
        raise SystemExit(exit_code)
    executable = roam_info.get("path")
    if not executable:  # Defensive: _roam_problem() rejects this state.
        click.echo("VERDICT: toolchain missing — `roam` is not on PATH")
        raise SystemExit(EXIT_TOOLCHAIN)

    targets = list(files)
    advisory = _oversized_target_set(targets, cap=25)
    if advisory:
        click.echo(advisory)
    try:
        root, bound_targets, expected_receipt, verify_env, excluded = _prepare_verify_request(files)
    except (UnicodeError, ValueError) as exc:
        click.echo(
            _unsafe_scope_verdict(exc) or (_verify_protocol_verdict(exc, executable=str(executable), targets=targets))
        )
        raise SystemExit(EXIT_TOOLCHAIN)
    delete_check_unavailable = _delete_check_unavailable_reason(root, bound_targets)
    if delete_check_unavailable is not None:
        click.echo(_delete_check_unavailable_verdict(delete_check_unavailable))
        raise SystemExit(EXIT_TOOLCHAIN)

    # VERIFY is the post-edit channel, so selection must follow the edit. In
    # particular, roam's delete_check adapter is registered only in AUTO mode:
    # omitting this flag left deleted public symbols outside the gate even
    # though their changed files were bound into the receipt below.
    argv = ["--json", "verify", "--auto"]
    if new_only:
        argv.append("--new-only")
    if diff_only:
        argv.append("--diff-only")
    if threshold is not None:
        argv.extend(["--threshold", str(threshold)])
    if bound_targets:
        argv.extend(["--", *bound_targets])
    else:
        argv.append("--changed")
    rc, output = _delegate_capturing(*argv, executable=executable, env=verify_env)
    if output is None:
        # No envelope means no VERDICT line to carry the narrowing, so it gets
        # its own line here rather than going unsaid.
        if excluded:
            click.echo(_narrowed_scope_notice(excluded))
        raise SystemExit(rc)
    rules_result: dict[str, object] | None = None
    py_types_result: dict[str, object] | None = None
    py_modern_result: dict[str, object] | None = None
    calc_golden_result: dict[str, object] | None = None
    collapse_result: dict[str, object] | None = None
    try:
        envelope = _validate_verify_protocol(
            output,
            returncode=rc,
            expected_receipt=expected_receipt,
            expected_roam_version=str(roam_info["version"]),
            expected_threshold=threshold,
            expected_root=root,
            diff_only=diff_only,
        )
        selected_product_checks = _auto_select_product_verify_checks(bound_targets)
        if "rules" in selected_product_checks:
            rules_result, rules_rc = _run_verify_rules_check(
                root,
                executable=str(executable),
                expected_roam_version=str(roam_info["version"]),
                env=verify_env,
            )
            if rules_result is None:
                raise SystemExit(rules_rc)
            if rules_result.get("state") == "unavailable":
                click.echo(
                    _verify_rules_unavailable_verdict(
                        rules_result.get("unavailable_reason", rules_result.get("reason"))
                    )
                )
                raise SystemExit(EXIT_TOOLCHAIN)
        if "py-types" in selected_product_checks:
            py_types_result, py_types_rc = _run_verify_py_types_check(
                root,
                targets=bound_targets,
                executable=str(executable),
                expected_roam_version=str(roam_info["version"]),
                env=verify_env,
            )
            if py_types_result is None:
                raise SystemExit(py_types_rc)
            if py_types_result.get("state") == "unavailable":
                click.echo(
                    _verify_py_types_unavailable_verdict(
                        py_types_result.get("unavailable_reason", py_types_result.get("reason"))
                    )
                )
                raise SystemExit(EXIT_TOOLCHAIN)
        if "py-modern" in selected_product_checks:
            py_modern_result, py_modern_rc = _run_verify_py_modern_check(
                root,
                targets=bound_targets,
                executable=str(executable),
                expected_roam_version=str(roam_info["version"]),
                env=verify_env,
            )
            if py_modern_result is None:
                raise SystemExit(py_modern_rc)
            if py_modern_result.get("state") == "unavailable":
                click.echo(
                    _verify_py_modern_unavailable_verdict(
                        py_modern_result.get("unavailable_reason", py_modern_result.get("reason"))
                    )
                )
                raise SystemExit(EXIT_TOOLCHAIN)
        if "calc-golden" in selected_product_checks:
            calc_golden_result, calc_golden_rc = _run_verify_calc_golden_check(
                root,
                targets=bound_targets,
                executable=str(executable),
                expected_roam_version=str(roam_info["version"]),
                env=verify_env,
            )
            if calc_golden_result is None:
                raise SystemExit(calc_golden_rc)
            if calc_golden_result.get("state") == "unavailable":
                click.echo(
                    _verify_calc_golden_unavailable_verdict(
                        calc_golden_result.get("unavailable_reason", calc_golden_result.get("reason"))
                    )
                )
                raise SystemExit(EXIT_TOOLCHAIN)
        if "collapse" in selected_product_checks:
            collapse_result, collapse_rc = _run_verify_collapse_check(
                root,
                targets=bound_targets,
                executable=str(executable),
                expected_roam_version=str(roam_info["version"]),
                env=verify_env,
            )
            if collapse_result is None:
                raise SystemExit(collapse_rc)
            if collapse_result.get("state") == "unavailable":
                click.echo(
                    _verify_collapse_unavailable_verdict(
                        collapse_result.get("unavailable_reason", collapse_result.get("reason"))
                    )
                )
                raise SystemExit(EXIT_TOOLCHAIN)
        if _verification_content_sha256(root, bound_targets) != expected_receipt["content_sha256"]:
            raise ValueError("post_verify_content_changed")
        # Recompute through the SAME narrowing as the request, or a repo whose
        # scope was narrowed would fail post_verify_scope_changed on every run.
        post_requested_targets = _verification_scope_paths(list(files)) if files else _discovered_scope(root)[0]
        post_targets = _verification_scope_paths(_expand_verify_targets(post_requested_targets, root))
        if post_targets != bound_targets:
            raise ValueError("post_verify_scope_changed")
    except (UnicodeError, ValueError) as exc:
        click.echo(
            _unsafe_scope_verdict(exc)
            or (_verify_protocol_verdict(exc, executable=str(executable), targets=bound_targets))
        )
        if excluded:
            click.echo(_narrowed_scope_notice(excluded))
        if excluded and not bound_targets:
            click.echo(_unignored_tool_state_note(excluded))
        raise SystemExit(EXIT_TOOLCHAIN)
    rendered = _render_verify_with_product_checks(
        envelope,
        rules_result,
        py_types_result,
        py_modern_result,
        excluded=excluded,
        diff_only=diff_only,
    )
    rendered = _render_verify_with_calc_golden_check(
        rendered,
        envelope,
        calc_golden_result,
        excluded=excluded,
        diff_only=diff_only,
    )
    rendered = _render_verify_with_collapse_check(
        rendered,
        envelope,
        collapse_result,
        excluded=excluded,
        diff_only=diff_only,
    )
    click.echo(rendered)
    # output is None => the toolchain never ran to completion (missing, broken,
    # timed out, interrupted) and its verdict is already on screen. Every
    # completed nonzero run gets the failure block — including roam's own
    # exit 2 ("bad arguments"), which only the sentinel can distinguish from
    # this CLI's EXIT_TOOLCHAIN (also 2).
    product_failed = any(
        result is not None and result.get("state") == "failed"
        for result in (rules_result, py_types_result, py_modern_result, calc_golden_result, collapse_result)
    )
    final_rc = EXIT_VERIFY_GATE if product_failed else rc
    if final_rc != 0:
        failing = _failing_files(envelope)
        if rules_result is not None:
            failing.extend(
                path
                for path in _verify_failing_files(rules_result, gating_severities=_VERIFY_RULE_GATING_SEVERITIES)
                if path not in failing
            )
        if py_types_result is not None:
            failing.extend(path for path in _verify_failing_files(py_types_result) if path not in failing)
        if py_modern_result is not None:
            failing.extend(path for path in _verify_failing_files(py_modern_result) if path not in failing)
        if calc_golden_result is not None:
            failing.extend(path for path in _verify_failing_files(calc_golden_result) if path not in failing)
        if collapse_result is not None:
            failing.extend(path for path in _verify_failing_files(collapse_result) if path not in failing)
        scoped = failing or targets or bound_targets
        click.echo(
            _format_verify_failure(
                command=_render_verify_command(
                    new_only=new_only,
                    diff_only=diff_only,
                    threshold=threshold,
                ),
                files=scoped,
                cause=_classify_verify_failure(rendered, final_rc),
                next_action=_render_verify_command(
                    new_only=new_only,
                    diff_only=diff_only,
                    threshold=threshold,
                ),
            )
        )
    raise SystemExit(final_rc)


@cli.command("doctor")
def _doctor() -> None:
    """Check the install: toolchain present, index state, wiring state.

    Wiring is checked at both levels — project (.claude/settings.local.json
    / settings.json) and user-global (~/.claude/settings.local.json /
    settings.json); either counts as wired.
    """
    roam_info = _inspect_roam()
    roam_problem = _roam_problem(roam_info)
    toolchain_ok = roam_problem is None
    indexed = _require_index()
    project_wired = _project_wired()
    # Only read the user-global settings when the project isn't already wired —
    # the label below reports "wired (project)" regardless, so this IO is
    # redundant when project_wired is true.
    user_wired = project_wired or _user_wired()
    wired = project_wired or user_wired
    wired_label = (
        "wired (project)"
        if project_wired
        else "wired (user-global)"
        if user_wired
        else "not wired (run `compile wire claude`)"
    )
    state = roam_info.get("state")
    toolchain_label = "ok" if toolchain_ok else "MISSING" if state == "missing" else "INCOMPATIBLE"
    click.echo(f"toolchain : {toolchain_label}")
    click.echo(f"roam path : {roam_info.get('path') or 'not found'}")
    click.echo(f"roam version: {roam_info.get('version') or 'unknown'} (required {ROAM_VERSION_REQUIREMENT})")
    click.echo(f"python metadata: roam-code {roam_info.get('metadata_version') or 'not installed'}")
    click.echo(f"index     : {'ok' if indexed else 'absent (run `compile init`)'}")
    click.echo(f"claude    : {wired_label}")
    click.echo(f"verify report: {_verify_report_status()}")
    if roam_problem is not None:
        exit_code, verdict = roam_problem
        click.echo(verdict)
        raise SystemExit(exit_code)
    click.echo("VERDICT: ready" if indexed and wired else "VERDICT: install ok — finish setup above")


if __name__ == "__main__":  # pragma: no cover
    cli()
