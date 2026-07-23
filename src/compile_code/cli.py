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

import errno
import hashlib
import json
import math
import os
import re
import secrets
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from bisect import bisect_left
from collections import Counter, deque
from collections.abc import Callable, Mapping
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
MAX_ROAM_MAJOR_EXCLUSIVE = 14
ROAM_VERSION_REQUIREMENT = f">={MIN_ROAM_VERSION},<{MAX_ROAM_MAJOR_EXCLUSIVE}"
ROAM_PACKAGE_REQUIREMENT = f"roam-code{ROAM_VERSION_REQUIREMENT}"
MAX_VERIFY_JSON_BYTES = 2 * 1024 * 1024
MAX_VERIFY_STDERR_BYTES = 64 * 1024
MAX_ROAM_VERSION_BYTES = 8 * 1024
MAX_VERIFY_GIT_STATUS_BYTES = 1024 * 1024
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
VERIFY_ENVELOPE_SCHEMA_VERSION = "1.1.0"
VERIFY_RECEIPT_SCHEMA = "roam.verify.receipt.v3"

_ROAM_VERSION_LINE = re.compile(r"^roam(?:\.exe)?,\s+version\s+(\S+)\s*$", re.IGNORECASE)
_VERSION_VALUE = re.compile(
    r"^(\d+)\.(\d+)\.(\d+)"
    r"(?P<suffix>(?:(?:a|b|rc)\d+|\.?dev\d+|\.post\d+)?(?:\+[A-Za-z0-9.-]+)?)$",
    re.IGNORECASE,
)

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
        if (candidate / ".git").exists() or (candidate / ".roam" / "index.db").exists():
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
    """Enforce the closed Roam compatibility interval without ``packaging``."""
    parsed = _parse_version_value(raw)
    floor = _parse_version_value(minimum)
    if parsed is None or floor is None:
        return False
    release, prerelease = parsed
    floor_release, floor_prerelease = floor
    if release[0] >= MAX_ROAM_MAJOR_EXCLUSIVE:
        return False
    if prerelease and not floor_prerelease:
        return False
    if release != floor_release:
        return release > floor_release
    if prerelease != floor_prerelease:
        return floor_prerelease
    return True


def _extract_roam_version(output: str) -> str | None:
    """Extract a valid version from Click's canonical ``roam --version`` line."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) != 1:
        return None
    match = _ROAM_VERSION_LINE.fullmatch(lines[0])
    if not match or _parse_version_value(match.group(1)) is None:
        return None
    return match.group(1)


def _inspect_roam(timeout: int = 10) -> dict[str, str | None]:
    """Inspect the exact PATH executable and Python metadata independently."""
    metadata_version = _python_roam_metadata_version()
    executable = _resolve_roam_executable()
    info = {
        "path": executable,
        "version": None,
        "metadata_version": metadata_version,
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
    combined = b"\n".join((proc.stdout or b"", proc.stderr or b"")).decode("utf-8", errors="replace")
    version = _extract_roam_version(combined)
    if version is None:
        info.update(state="malformed_version", detail="`roam --version` returned no parseable version")
        return info
    info.update(state="ok", version=version)
    return info


def _roam_problem(info: dict[str, str | None]) -> tuple[int, str] | None:
    """Return the product exit code and verdict for an unusable roam install."""
    state = info.get("state")
    executable = info.get("path")
    version = info.get("version")
    metadata_version = info.get("metadata_version")
    fix = f'python -m pip install --upgrade "{ROAM_PACKAGE_REQUIREMENT}"'
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
) -> subprocess.CompletedProcess:
    """Run Roam through the bounded Verify subprocess boundary."""
    argv = [executable, *args]
    proc = _run_bounded_capture(
        argv,
        timeout=timeout,
        stdout_limit=MAX_VERIFY_JSON_BYTES,
        stderr_limit=MAX_VERIFY_STDERR_BYTES,
        env=env,
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
        proc = _roam_capture(*args, timeout=timeout, executable=executable, env=env)
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
            click.echo("VERDICT: indexing failed — rerun `compile claude` after fixing the index")
            return rc
        _mark_launch_indexed()
        return 0
    click.echo("compile: indexing repo (first run)...")
    rc = _delegate("init", executable=executable, env=env) if executable else _delegate("init")
    if rc != 0:
        click.echo("VERDICT: indexing failed — rerun `compile claude` after fixing the index")
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
    """Exit through one Claude hook mutation path so wire/unwire cannot drift."""
    rc = _delegate(
        *_claude_hook_args_for_canonical_write_order(uninstall=uninstall, no_verify=no_verify, user_level=user_level)
    )
    if rc == 0 and not uninstall:
        if no_verify:
            _wire_roam_midtask_access(user_level=user_level, require_verify=False)
        else:
            _wire_roam_midtask_access(user_level=user_level)
    raise SystemExit(rc)


def _strict_json_document(raw: str, *, max_bytes: int) -> object:
    """Parse exactly one finite JSON document and reject duplicate object keys."""
    if not isinstance(raw, str) or "\ufffd" in raw or len(raw.encode("utf-8")) > max_bytes:
        raise ValueError("invalid_json_bytes")
    _enforce_json_nesting_limit(raw)

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

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
            object_pairs_hook=reject_duplicates,
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
        or envelope.get("schema_version") != VERIFY_ENVELOPE_SCHEMA_VERSION
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
    rc, status = _git_status_porcelain()
    if rc != 0:
        raise SystemExit(rc)
    if status.strip():
        click.echo("VERDICT: baseline refused — dirty tree. Fix: commit, stash, or rerun on a clean checkout.")
        raise SystemExit(1)
    raise SystemExit(_delegate("verify", "--report", "--baseline-write", *paths, timeout=BASELINE_TIMEOUT))


@cli.command("report")
def _report() -> None:
    """Persist a whole-repo verify report without gating."""
    # Report mode composes with accepted-debt --new-only; it does not add a second gate.
    raise SystemExit(_delegate("verify", "--report", "--persist"))


def _launch_agent(argv: list[str], env: dict[str, str], *, use_exec: bool | None = None) -> int:
    """Hand the console to the agent binary, mapping launch failures to the contract.

    POSIX replaces this process via exec, so a return only happens on failure;
    Windows runs the agent as a child because exec* there spawns-and-detaches
    (console handling breaks). ``use_exec`` lets tests pin either branch
    regardless of the platform they run on. The caller passes an absolute path
    re-resolved at the final readiness boundary; the binary can still vanish or
    become unlaunchable before exec, and that race ends in a verdict.
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
        wiring_ready = _attest_claude_hooks(
            str(roam_info["path"]),
            str(roam_info["version"]),
            user_level=wiring_reason == "user",
        )
        if not wiring_ready:
            wiring_reason = "producer_attestation"
    if not wiring_ready:
        readiness_failures.append(f"hooks:{wiring_reason}")
    final_claude_path, _final_claude_reason = _resolve_trusted_executable("claude", reject_workspace=True)
    if not final_claude_path or final_claude_path != claude_path:
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
        click.echo('VERDICT: empty task — pass a navigation prompt, e.g. compile run "who calls handleSave?"')
        raise SystemExit(1)
    args = (["--json"] if json_out else []) + ["compile", task, "--artifact", "auto"]
    with _default_agent_mode("compile"):
        raise SystemExit(_delegate(*args))


@cli.command("stats")
def _stats() -> None:
    """Show compile telemetry for this repo (routing, latency, cache)."""
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
_VERIFY_CATEGORY_NAMES = _VERIFY_CHECK_NAMES | {"verification"}
_VERIFY_PASS_ADVISORY_CATEGORIES = frozenset(
    {"n1", "over_fetch", "dead", "magic_numbers", "llm_smells", "test_hermeticity", "smells"}
)
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
    }
)
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
        return _parse_verify_status_paths(proc.stdout or b"")
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
    skip_dirs = {".git", ".roam", ".venv", "venv", "node_modules", "__pycache__"}
    pending = deque(path for _relative, path in directories)
    directory_count = 0
    entry_count = 0
    deadline = time.monotonic() + MAX_VERIFY_TRAVERSAL_SECONDS
    while pending:
        if time.monotonic() > deadline:
            raise ValueError("verification_directory_timeout")
        current = pending.popleft()
        current_key = os.path.normcase(str(current))
        if current_key in seen_directories:
            continue
        seen_directories.add(current_key)
        directory_count += 1
        if directory_count > MAX_VERIFY_DIRECTORIES:
            raise ValueError("verification_directory_limit")
        before = _validated_verify_directory_state(current, canonical_root)
        names: list[str] = []
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    entry_count += 1
                    if entry_count > MAX_VERIFY_DIRECTORY_ENTRIES:
                        raise ValueError("verification_directory_entry_limit")
                    if time.monotonic() > deadline:
                        raise ValueError("verification_directory_timeout")
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


def _parse_verify_status_paths(raw: bytes) -> list[str]:
    if raw and not raw.endswith(b"\0"):
        raise ValueError("changed_file_discovery_malformed")
    records = raw.split(b"\0")
    paths: list[str] = []
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
            paths.append(path)
        if "R" in status or "C" in status:
            if index >= len(records) or not records[index]:
                raise ValueError("changed_file_discovery_malformed")
            source = _decode_verify_status_path(records[index])
            index += 1
            if "R" in status and source:
                paths.append(source)
    return list(dict.fromkeys(paths))


def _discover_verify_targets(root: Path) -> list[str]:
    """Resolve the complete worktree scope; discovery failure loses evidence."""
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
    return _parse_verify_status_paths(proc.stdout or b"")


def _verification_scope_paths(targets: list[str]) -> list[str]:
    normalized: set[str] = set()
    for path in targets:
        if not isinstance(path, str):
            raise ValueError("scope_path_not_text")
        value = _scope_path_separators(_require_utf8_scope_text(path))
        if not value:
            raise ValueError("scope_path_empty")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("scope_path_control_character")
        parsed = PurePosixPath(value)
        if (
            parsed.is_absolute()
            or re.match(r"^[A-Za-z]:/", value)
            or any(part in {".", "..", ""} for part in parsed.parts)
            or parsed.as_posix() != value
        ):
            raise ValueError("scope_path_not_canonical")
        normalized.add(value)
    return sorted(normalized)


def _verification_scope_sha256(targets: list[str]) -> str:
    payload = json.dumps(_verification_scope_paths(targets), ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _same_verification_file_state(left: os.stat_result, right: os.stat_result, *, cross_handle: bool = False) -> bool:
    fields = ["st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns"]
    if cross_handle and os.name == "nt":
        fields.remove("st_ctime_ns")
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


def _prepare_verify_request(files: tuple[str, ...]) -> tuple[Path, list[str], dict[str, object], dict[str, str]]:
    root = _verification_root()
    raw_targets = list(files) if files else _discover_verify_targets(root)
    requested_targets = _verification_scope_paths(raw_targets)
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
    return root, targets, expected, env


def _plain_int(value: object, *, minimum: int = 0, maximum: int | None = None) -> int:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise ValueError("invalid_integer")
    return value


def _validate_finding(finding: object, *, expected_root: Path | None = None) -> dict:
    if not isinstance(finding, dict):
        raise ValueError("invalid_finding")
    severity = finding.get("severity")
    category = finding.get("category")
    file_path = finding.get("file")
    message = finding.get("message", "")
    if severity not in _VERIFY_FINDING_SEVERITIES or category not in _VERIFY_CATEGORY_NAMES:
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
    if (
        target_count != expected_count
        or indexed_count != files_checked
        or indexed_count + unresolved_count != expected_count
        or non_code_count > unresolved_count
        or unresolved_count == 0
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
) -> dict:
    """Validate one complete, request-bound Roam Verify receipt-v3 transaction."""
    envelope = _strict_json_document(output, max_bytes=MAX_VERIFY_JSON_BYTES)
    if not isinstance(envelope, dict):
        raise ValueError("envelope_shape")
    if (
        set(envelope) != _VERIFY_ENVELOPE_KEYS
        or envelope.get("schema") != VERIFY_ENVELOPE_SCHEMA
        or envelope.get("schema_version") != VERIFY_ENVELOPE_SCHEMA_VERSION
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
    if not set(summary) <= _VERIFY_SUMMARY_KEYS:
        raise ValueError("summary_schema")
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
    if summary.get("verification_complete") is not True or summary.get("partial_success") is not False:
        raise ValueError("verification_incomplete")
    incomplete_reasons = summary.get("incomplete_reasons")
    if incomplete_reasons not in (None, []):
        raise ValueError("verification_incomplete")

    if expected_count == 0:
        if (
            set(summary) != _VERIFY_NO_CHANGES_SUMMARY_KEYS
            or returncode != 0
            or verdict != "PASS"
            or score != 100
            or files_checked != 0
            or violation_count != 0
            or violations != []
            or summary.get("state") != "no_changes"
            or summary.get("checks_run") != []
            or "verification_receipt" in summary
            or set(categories) != _VERIFY_NO_CHANGES_CATEGORY_NAMES
        ):
            raise ValueError("no_changes_contract")
        for category_name, result in categories.items():
            expected_keys = (
                _VERIFY_NO_CHANGES_VERIFICATION_KEYS
                if category_name == "verification"
                else _VERIFY_NO_CHANGES_CATEGORY_KEYS
            )
            if (
                not isinstance(category_name, str)
                or not category_name
                or not isinstance(result, dict)
                or set(result) != expected_keys
                or result.get("score") != 100
                or result.get("violations") != []
                or (category_name == "verification" and result.get("available") is not True)
            ):
                raise ValueError("no_changes_category")
        return envelope

    if set(categories) != _VERIFY_CATEGORY_NAMES:
        raise ValueError("category_enum")
    verification_category = categories.get("verification")
    if (
        not isinstance(verification_category, dict)
        or set(verification_category) != _VERIFY_CATEGORY_REQUIRED_KEYS
        or verification_category.get("score") != 100
        or verification_category.get("violation_count") != 0
        or verification_category.get("violations") != []
    ):
        raise ValueError("verification_category")
    top_level_findings = [_validate_finding(finding, expected_root=expected_root) for finding in violations]
    category_findings: list[dict] = []
    for category_name, result in categories.items():
        if (
            not isinstance(category_name, str)
            or not category_name
            or not isinstance(result, dict)
            or not _VERIFY_CATEGORY_REQUIRED_KEYS <= set(result)
            or not set(result) <= _VERIFY_CATEGORY_KEYS
        ):
            raise ValueError("category_shape")
        _plain_int(result.get("score"), maximum=100)
        nested = result.get("violations", [])
        if not isinstance(nested, list):
            raise ValueError("category_findings")
        if _plain_int(result["violation_count"]) != len(nested):
            raise ValueError("category_count")
        for counter in ("tests_targeted", "tests_failed", "tests_total_impacted"):
            if counter in result:
                _plain_int(result[counter])
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
            raise ValueError("category_incomplete")
        for finding in nested:
            validated = _validate_finding(finding, expected_root=expected_root)
            if validated.get("category") != category_name:
                raise ValueError("category_finding_contradiction")
            category_findings.append(validated)
    if Counter(map(_finding_fingerprint, top_level_findings)) != Counter(map(_finding_fingerprint, category_findings)):
        raise ValueError("finding_multiset_contradiction")
    evidence_findings = top_level_findings
    has_fail = any(finding.get("severity") == "FAIL" for finding in evidence_findings)

    checks_run = summary.get("checks_run")
    quality_band = "PASS" if score >= 80 else "WARN" if score >= 60 else "FAIL"
    index_refresh = summary.get("index_refresh")
    if (
        summary.get("state") != "verified"
        or summary.get("targets_checked") != expected_count
        or summary.get("quality_band") != quality_band
        or (verdict in {"PASS", "WARN"} and verdict != quality_band)
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
        or any(check not in _VERIFY_CHECK_NAMES for check in checks_run)
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
        if returncode != 0 or score < threshold or has_fail:
            raise ValueError("success_contradiction")
        if verdict == "PASS" and any(
            finding.get("severity") != "WARN" or finding.get("category") not in _VERIFY_PASS_ADVISORY_CATEGORIES
            for finding in evidence_findings
        ):
            raise ValueError("pass_finding_contradiction")
    elif returncode != EXIT_VERIFY_GATE or (score >= threshold and not has_fail):
        raise ValueError("failure_contradiction")
    return envelope


def _render_verify_envelope(envelope: dict) -> str:
    """Render validated structured evidence without replaying raw subprocess text."""
    summary = envelope["summary"]
    issue_count = summary["violation_count"]
    files_checked = summary["files_checked"]
    targets_checked = summary.get("targets_checked", files_checked)
    lines = [
        f"VERDICT: {summary['verdict']} (score {summary['score']}/100) -- "
        f"{issue_count} issue{'s' if issue_count != 1 else ''} in "
        f"{targets_checked} changed file{'s' if targets_checked != 1 else ''}"
    ]
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
    reason = str(error)
    if reason == "scope_path_control_character":
        return (
            "VERDICT: verify refused — the scope contains a filename with an unsafe control character "
            "(including a newline). Rename that file and rerun `compile verify --changed`."
        )
    if reason == "scope_path_undecodable":
        return (
            "VERDICT: verify refused — the scope contains a filename that is not representable as UTF-8. "
            "Rename that file and rerun `compile verify --changed`."
        )
    if reason == "verification_directory_limit":
        return (
            f"VERDICT: verify refused — explicit-directory traversal exceeded the "
            f"{MAX_VERIFY_DIRECTORIES}-directory safety limit. Pass a smaller explicit file scope."
        )
    if reason == "verification_directory_entry_limit":
        return (
            f"VERDICT: verify refused — explicit-directory traversal exceeded the "
            f"{MAX_VERIFY_DIRECTORY_ENTRIES}-entry safety limit. Pass a smaller explicit file scope."
        )
    if reason == "verification_target_limit":
        return (
            f"VERDICT: verify refused — explicit-directory expansion exceeded the "
            f"{MAX_VERIFY_TARGETS}-file safety limit. Pass a smaller explicit file scope."
        )
    if reason == "verification_directory_timeout":
        return (
            f"VERDICT: verify refused — explicit-directory traversal exceeded the "
            f"{MAX_VERIFY_TRAVERSAL_SECONDS:g}-second safety limit. Pass explicit file paths."
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

    Delegates to `roam verify` (naming, imports, error handling, duplicates,
    syntax on the changed set). `--new-only` passes through to roam's accepted-
    debt baseline; `--diff-only` keeps the output scoped to changed lines.
    Only a complete, bound JSON receipt is rendered. A validated gate failure
    is followed by a block naming the failing command, changed files, likely
    cause category, and the single local rerun to run next.
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
        root, bound_targets, expected_receipt, verify_env = _prepare_verify_request(files)
    except (UnicodeError, ValueError) as exc:
        click.echo(
            _unsafe_scope_verdict(exc)
            or (
                f"VERDICT: verifier protocol failure — the exact Verify scope could not be bound. "
                f'Fix: python -m pip install --upgrade "{ROAM_PACKAGE_REQUIREMENT}"'
            )
        )
        raise SystemExit(EXIT_TOOLCHAIN)

    argv = ["--json", "verify"]
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
        raise SystemExit(rc)
    try:
        envelope = _validate_verify_protocol(
            output,
            returncode=rc,
            expected_receipt=expected_receipt,
            expected_roam_version=str(roam_info["version"]),
            expected_threshold=threshold,
            expected_root=root,
        )
        if _verification_content_sha256(root, bound_targets) != expected_receipt["content_sha256"]:
            raise ValueError("post_verify_content_changed")
        post_raw_targets = list(files) if files else _discover_verify_targets(root)
        post_requested_targets = _verification_scope_paths(post_raw_targets)
        post_targets = _verification_scope_paths(_expand_verify_targets(post_requested_targets, root))
        if post_targets != bound_targets:
            raise ValueError("post_verify_scope_changed")
    except (UnicodeError, ValueError) as exc:
        click.echo(
            _unsafe_scope_verdict(exc)
            or (
                f"VERDICT: verifier protocol failure — `{executable}` did not return one complete, bound Verify "
                f'receipt v3. Fix: python -m pip install --upgrade "{ROAM_PACKAGE_REQUIREMENT}"'
            )
        )
        raise SystemExit(EXIT_TOOLCHAIN)
    rendered = _render_verify_envelope(envelope)
    click.echo(rendered)
    # output is None => the toolchain never ran to completion (missing, broken,
    # timed out, interrupted) and its verdict is already on screen. Every
    # completed nonzero run gets the failure block — including roam's own
    # exit 2 ("bad arguments"), which only the sentinel can distinguish from
    # this CLI's EXIT_TOOLCHAIN (also 2).
    if rc != 0:
        failing = _failing_files(envelope)
        scoped = failing or targets or bound_targets
        click.echo(
            _format_verify_failure(
                command=_render_verify_command(
                    new_only=new_only,
                    diff_only=diff_only,
                    threshold=threshold,
                ),
                files=scoped,
                cause=_classify_verify_failure(rendered, rc),
                next_action=_render_verify_command(
                    new_only=new_only,
                    diff_only=diff_only,
                    threshold=threshold,
                ),
            )
        )
    raise SystemExit(rc)


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
