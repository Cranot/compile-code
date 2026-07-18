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
import os
import re
import secrets
import stat
import subprocess
import time
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

import click

__all__ = ["cli"]

EXIT_TOOLCHAIN = 2
EXIT_TIMEOUT = 124
# roam verify quality-gate failure (see `roam exit-codes`); the one verify exit
# code the product surface acts on — checks ran and the score fell below threshold.
EXIT_VERIFY_GATE = 5
BASELINE_TIMEOUT = 1200
MIN_ROAM_VERSION = "13.10.0"
MAX_VERIFY_JSON_BYTES = 2 * 1024 * 1024
MAX_VERIFY_FILE_BYTES = 64 * 1024 * 1024
MAX_VERIFY_TOTAL_BYTES = 256 * 1024 * 1024
MAX_VERIFY_TARGETS = 4096
MAX_VERIFY_ARG_CHARS = 128 * 1024
MAX_CLAUDE_SETTINGS_BYTES = 1024 * 1024
MAX_CLAUDE_HOOK_BYTES = 512 * 1024
MAX_CLAUDE_GUIDANCE_BYTES = 4 * 1024 * 1024
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
    release = (
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3)),
    )
    suffix = match.group("suffix").lower()
    prerelease = bool(re.match(r"^(?:a|b|rc|\.?dev)", suffix))
    return release, prerelease


def _version_meets_minimum(raw: str, minimum: str = MIN_ROAM_VERSION) -> bool:
    """Compare roam versions without requiring ``packaging`` at runtime."""
    parsed = _parse_version_value(raw)
    floor = _parse_version_value(minimum)
    if parsed is None or floor is None:
        return False
    release, prerelease = parsed
    floor_release, floor_prerelease = floor
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
        proc = subprocess.run(
            [executable, "--version"],
            timeout=timeout,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
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
        diagnostic = ((proc.stderr or proc.stdout or "").strip().splitlines() or [""])[0][:200]
        detail = f"version check exited {proc.returncode}"
        if diagnostic:
            detail += f": {diagnostic}"
        info.update(state="version_failed", detail=detail)
        return info
    version = _extract_roam_version("\n".join((proc.stdout or "", proc.stderr or "")))
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
    fix = f'python -m pip install --upgrade "roam-code>={MIN_ROAM_VERSION}"'
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
            f"compile-code requires >={MIN_ROAM_VERSION}.{metadata_note} Fix: {fix}",
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


def _roam_capture(
    *args: str,
    timeout: int = 600,
    executable: str = "roam",
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Run the roam toolchain CLI capturing stdout (``_roam`` streams it).

    Kept as a separate indirection so tests stub it the way they stub
    ``_roam``. Only ``verify`` needs captured output so it can validate one
    canonical JSON transaction before rendering any producer-controlled data;
    the other commands keep streaming via ``_delegate``.

    Decoding is pinned to UTF-8 with replacement so undecodable toolchain
    bytes can never raise mid-capture (Windows would otherwise decode roam's
    UTF-8 output as the legacy code page — or crash on it).
    """
    return subprocess.run(
        [executable, *args],
        timeout=timeout,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )


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
        _wire_roam_midtask_access(user_level=user_level)
    raise SystemExit(rc)


def _strict_json_document(raw: str, *, max_bytes: int) -> object:
    """Parse exactly one finite JSON document and reject duplicate object keys."""
    if not isinstance(raw, str) or "\ufffd" in raw or len(raw.encode("utf-8")) > max_bytes:
        raise ValueError("invalid_json_bytes")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> object:
        raise ValueError("non_finite_json_number")

    try:
        return json.loads(raw, object_pairs_hook=reject_duplicates, parse_constant=reject_constant)
    except (TypeError, json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError("invalid_json_document") from exc


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


def _atomic_write_utf8(
    path: Path,
    text: str,
    *,
    max_bytes: int,
    expected_previous: str | None = None,
) -> bool:
    """Atomically write UTF-8 without following a repository-controlled link.

    ``expected_previous`` turns the operation into a compare-and-swap: the
    exact regular file read by the caller must still be present immediately
    before replacement. A final-component symlink is never opened for write;
    ``os.replace`` replaces the directory entry itself.
    """
    payload = text.encode("utf-8")
    if len(payload) > max_bytes:
        return False
    try:
        parent_info = path.parent.lstat()
        if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
            return False
        if expected_previous is not None:
            current = _read_bounded_utf8_regular_file(path, max_bytes=max_bytes)
            if current != expected_previous:
                return False
            mode = stat.S_IMODE(path.lstat().st_mode)
        else:
            try:
                path.lstat()
            except FileNotFoundError:
                mode = 0o600
            else:
                return False
    except (OSError, ValueError):
        return False

    temporary = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(temporary, flags, mode or 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short write")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        if expected_previous is not None:
            current = _read_bounded_utf8_regular_file(path, max_bytes=max_bytes)
            if current != expected_previous:
                return False
        os.replace(temporary, path)
        return True
    except (OSError, ValueError):
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
    """Accept only Roam's literal ``python3 <absolute-hook-path>`` command."""
    if not isinstance(command, str) or not command.startswith("python3 "):
        return False
    raw_path = command[len("python3 ") :]
    if not raw_path or raw_path != raw_path.strip() or any(char in raw_path for char in "\r\n\0;&|<>`$"):
        return False
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        return False
    try:
        return os.path.normcase(str(candidate.resolve(strict=True))) == os.path.normcase(
            str(expected_path.resolve(strict=True))
        )
    except (OSError, RuntimeError, ValueError):
        return False


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


def _settings_mapping_wiring_state(settings: dict[str, object], settings_path: Path) -> tuple[bool, str]:
    """Validate both canonical synchronous hook entries in one settings object."""
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


def _wiring_state_for_paths(paths: tuple[Path, ...], *, root: Path) -> tuple[bool, str]:
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
        return _settings_mapping_wiring_state(settings, path)
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
        proc = subprocess.run(
            argv,
            timeout=15,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
        )
        envelope = _strict_json_document(proc.stdout or "", max_bytes=MAX_VERIFY_JSON_BYTES)
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


def _wire_roam_midtask_access(*, user_level: bool) -> None:
    """Expose curated launch-graph queries after the delegated hook write."""
    root = Path(os.path.expanduser("~")) if user_level else Path.cwd()
    if not _claude_tree_is_concrete(root=root):
        return
    claude_dir = root / ".claude"
    settings_paths = (claude_dir / "settings.local.json", claude_dir / "settings.json")
    if not _wiring_state_for_paths(settings_paths, root=root)[0]:
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
    edits, quiet on pass). Both fail-open — a broken install can never
    block your agent. Undo anytime with `compile unwire claude`.
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

    Ensures the repo is indexed, wires the hooks if absent, then execs
    the real `claude` with any arguments passed through. The zero-
    learning-curve path: type `compile claude` instead of `claude`,
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
        wiring_ready, _wiring_reason = _claude_wiring_state()
        if not wiring_ready:
            wire_rc = _delegate("hooks", "claude", "--write", executable=exact_roam, env=tool_env)

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
        path = record[3:].replace("\\", "/")
        if path:
            paths.append(path)
        if "R" in status or "C" in status:
            source = records[index].replace("\\", "/") if index < len(records) else ""
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
        proc = subprocess.run(
            [executable, "-c", "core.fsmonitor=false", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            env=_trusted_tool_env(git=True),
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    return _parse_changed_status_paths(proc.stdout or "")


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
    """Mirror Roam 13.10's bounded, symlink-safe directory expansion."""
    directories = [path for path in targets if (root / path).is_dir() and not (root / path).is_symlink()]
    if not directories:
        return targets
    expanded = [path for path in targets if path not in directories]
    seen = set(expanded)
    skip_dirs = {".git", ".roam", ".venv", "venv", "node_modules", "__pycache__"}
    cap = 20_000
    for directory in directories:
        before_count = len(expanded)
        try:
            for current, child_dirs, filenames in os.walk(root / directory, followlinks=False):
                child_dirs[:] = sorted(
                    name for name in child_dirs if name not in skip_dirs and not (Path(current) / name).is_symlink()
                )
                for filename in sorted(filenames):
                    candidate = Path(current) / filename
                    if candidate.is_symlink() or not candidate.is_file():
                        continue
                    relative = candidate.relative_to(root).as_posix()
                    if relative not in seen:
                        expanded.append(relative)
                        seen.add(relative)
                    if len(expanded) >= cap:
                        break
                if len(expanded) >= cap:
                    break
        except (OSError, ValueError):
            pass
        if len(expanded) == before_count or len(expanded) >= cap:
            if directory not in seen:
                expanded.append(directory)
                seen.add(directory)
    return expanded


def _parse_verify_status_paths(raw: bytes) -> list[str]:
    records = raw.split(b"\0")
    paths: list[str] = []
    index = 0
    while index < len(records):
        record = os.fsdecode(records[index])
        index += 1
        if len(record) < 4:
            continue
        status = record[:2]
        path = record[3:].replace("\\", "/")
        if path:
            paths.append(path)
        if "R" in status or "C" in status:
            source = os.fsdecode(records[index]).replace("\\", "/") if index < len(records) else ""
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
        proc = subprocess.run(
            [git_path, "-c", "core.fsmonitor=false", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            cwd=str(root),
            check=False,
            capture_output=True,
            timeout=10,
            env=env,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("changed_file_discovery_failed") from exc
    if proc.returncode != 0:
        raise ValueError("changed_file_discovery_failed")
    return _parse_verify_status_paths(proc.stdout or b"")


def _verification_scope_paths(targets: list[str]) -> list[str]:
    normalized: set[str] = set()
    for path in targets:
        value = str(path).strip().replace("\\", "/")
        if not value:
            continue
        if any(ord(character) < 32 for character in value):
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
            canonical_parent = candidate.parent.resolve(strict=True)
        except FileNotFoundError:
            manifest.append([relative_path, "missing"])
            continue
        except (OSError, RuntimeError) as exc:
            raise ValueError("scope_file_unreadable") from exc
        if not _path_is_within(canonical_parent, canonical_root):
            raise ValueError("scope_path_outside_root")
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
            if not stat.S_ISREG(opened_before.st_mode) or not _same_verification_file_state(
                path_before, opened_before, cross_handle=True
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
            if (
                bytes_read != opened_before.st_size
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
    raw_targets = [path.replace("\\", "/") for path in files] if files else _discover_verify_targets(root)
    targets = _verification_scope_paths(_expand_verify_targets(raw_targets, root))
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


def _validate_finding(finding: object) -> dict:
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
    line = finding.get("line")
    if line is not None:
        _plain_int(line, minimum=1)
    return finding


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
    expected_threshold: int,
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
    if threshold != expected_threshold or len(violations) != violation_count or summary.get("truncated") is True:
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
    evidence_findings = [_validate_finding(finding) for finding in violations]
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
        evidence_findings.extend(_validate_finding(finding) for finding in nested)
    has_fail = any(finding.get("severity") == "FAIL" for finding in evidence_findings)

    checks_run = summary.get("checks_run")
    quality_band = "PASS" if score >= 80 else "WARN" if score >= 60 else "FAIL"
    index_refresh = summary.get("index_refresh")
    if (
        summary.get("state") != "verified"
        or summary.get("targets_checked") != expected_count
        or summary.get("quality_band") != quality_band
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


def _failing_files(output: str) -> list[str]:
    """Files named on ``FAIL: file:line`` lines, de-duplicated, order-preserving."""
    failing: list[str] = []
    for line in output.splitlines():
        match = _VERIFY_FAIL_LINE.match(line)
        if not match:
            continue
        failed_file = match.group(1).strip()
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


@cli.command("verify")
@click.argument("files", nargs=-1)
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
    type=int,
    default=70,
    show_default=True,
    help="Fail below this score (default 70, or .roam/verify.yaml; diff-only keeps its own score scale).",
)
def _verify(files: tuple[str, ...], new_only: bool, diff_only: bool, threshold: int) -> None:
    """Run scoped verify on changed files; on failure, explain the next local action.

    Delegates to `roam verify` (naming, imports, error handling, duplicates,
    syntax on the changed set). `--new-only` passes through to roam's accepted-
    debt baseline; `--diff-only` keeps the output scoped to changed lines.
    Only a complete, bound JSON receipt is rendered. A validated gate failure
    is followed by a block naming the failing command, changed files, likely
    cause category, and the single local rerun to run next.
    """
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
    except ValueError:
        click.echo(
            f"VERDICT: verifier protocol failure — the exact Verify scope could not be bound. "
            f'Fix: python -m pip install --upgrade "roam-code>={MIN_ROAM_VERSION}"'
        )
        raise SystemExit(EXIT_TOOLCHAIN)

    argv = ["--json", "verify"]
    command = ["compile", "verify"]
    if new_only:
        argv.append("--new-only")
        command.append("--new-only")
    if diff_only:
        argv.append("--diff-only")
        command.append("--diff-only")
    argv.extend(["--threshold", str(threshold)])
    if threshold != 70:
        command.extend(["--threshold", str(threshold)])
    if bound_targets:
        argv.extend(["--", *bound_targets])
    else:
        argv.append("--changed")
    command.extend(targets or ["--changed"])
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
        )
        if _verification_content_sha256(root, bound_targets) != expected_receipt["content_sha256"]:
            raise ValueError("post_verify_content_changed")
        post_raw_targets = [path.replace("\\", "/") for path in files] if files else _discover_verify_targets(root)
        post_targets = _verification_scope_paths(_expand_verify_targets(post_raw_targets, root))
        if post_targets != bound_targets:
            raise ValueError("post_verify_scope_changed")
    except ValueError:
        click.echo(
            f"VERDICT: verifier protocol failure — `{executable}` did not return one complete, bound Verify "
            f'receipt v3. Fix: python -m pip install --upgrade "roam-code>={MIN_ROAM_VERSION}"'
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
        failing = _failing_files(rendered)
        scoped = failing or targets or bound_targets
        next_tokens = ["compile", "verify"]
        if new_only:
            next_tokens.append("--new-only")
        if diff_only:
            next_tokens.append("--diff-only")
        next_tokens.extend(failing or targets or ["--changed"])
        click.echo(
            _format_verify_failure(
                command=" ".join(command),
                files=scoped,
                cause=_classify_verify_failure(rendered, rc),
                next_action=" ".join(next_tokens),
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
    click.echo(f"roam version: {roam_info.get('version') or 'unknown'} (required >={MIN_ROAM_VERSION})")
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
