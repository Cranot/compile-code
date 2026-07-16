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

import os
import re
import subprocess
import time
from contextlib import contextmanager

import click

__all__ = ["cli"]

EXIT_TOOLCHAIN = 2
EXIT_TIMEOUT = 124
# roam verify quality-gate failure (see `roam exit-codes`); the one verify exit
# code the product surface acts on — checks ran and the score fell below threshold.
EXIT_VERIFY_GATE = 5
BASELINE_TIMEOUT = 1200
MIN_ROAM_VERSION = "13.10.0"

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


def _on_path(name: str) -> bool:
    """True when *name* is an executable on PATH.

    ``shutil`` is imported lazily here so the common commands
    (``run``, ``stats``, ``init``, ``--help``) never pay its import cost —
    only ``claude`` does this boolean PATH lookup. Doctor and Verify use the
    stronger version-aware resolver below.
    """
    import shutil

    return shutil.which(name) is not None


def _resolve_roam_executable() -> str | None:
    """Return the exact ``roam`` executable selected by PATH."""
    import shutil

    return shutil.which("roam")


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
    release = tuple(int(match.group(index)) for index in range(1, 4))
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
    for line in output.splitlines():
        match = _ROAM_VERSION_LINE.fullmatch(line.strip())
        if match and _parse_version_value(match.group(1)) is not None:
            return match.group(1)
    return None


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
    return os.path.exists(os.path.join(path, ".roam", "index.db"))


def _roam(*args: str, timeout: int = 600) -> subprocess.CompletedProcess:
    """Run the roam toolchain CLI (provided by the roam-code dependency)."""
    return subprocess.run(["roam", *args], timeout=timeout, check=False)


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


def _delegate(*args: str, timeout: int = 600) -> int:
    """Run the toolchain and translate every failure mode into a clean
    verdict + exit code (no tracebacks at the product surface)."""
    try:
        return _roam(*args, timeout=timeout).returncode
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


def _roam_capture(*args: str, timeout: int = 600, executable: str = "roam") -> subprocess.CompletedProcess:
    """Run the roam toolchain CLI capturing stdout (``_roam`` streams it).

    Kept as a separate indirection so tests stub it the way they stub
    ``_roam``. Only ``verify`` needs the captured output — to classify the
    failure and explain the next local action — so the other commands keep
    streaming via ``_delegate``.

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
    )


def _delegate_capturing(*args: str, timeout: int = 600, executable: str = "roam") -> tuple[int, str | None]:
    """Run the toolchain and translate failure modes like ``_delegate``.

    Returns ``(rc, stdout)`` instead of streaming, so the caller can classify
    a verify failure from roam's check output before composing the verdict.
    ``stdout`` is ``None`` when the toolchain never produced a result (missing,
    broken, timed out, interrupted) — the verdict was already emitted here, so
    callers must not layer their own failure analysis on top. That sentinel is
    what disambiguates our ``EXIT_TOOLCHAIN`` (2) from roam's own exit 2
    ("bad arguments"). Captured stderr is surfaced on failure so a toolchain
    crash keeps its diagnostic instead of collapsing to a bare exit code.
    """
    try:
        proc = _roam_capture(*args, timeout=timeout, executable=executable)
        if proc.returncode != 0:
            stderr = getattr(proc, "stderr", "") or ""
            if stderr.strip():
                click.echo(stderr.rstrip(), err=True)
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
    try:
        proc = subprocess.run(
            ["git", "status", "--porcelain"],
            timeout=timeout,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
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


def _ensure_indexed_for_launch() -> int:
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
        rc = _delegate("index")
        if rc != 0:
            click.echo("VERDICT: indexing failed — rerun `compile claude` after fixing the index")
            return rc
        _mark_launch_indexed()
        return 0
    click.echo("compile: indexing repo (first run)...")
    rc = _delegate("init")
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


def _override_hook_maintenance_commands(script: str) -> str:
    """Put roam's group-level mode override before hook maintenance commands.

    roam-code owns the generated hook bodies, so compile-code normalizes the
    small command-construction seam after installation without copying those
    bodies into this package. The dynamic form is used by the current Stop
    hook; the direct form keeps this compatible with simpler hook versions.
    """
    dynamic_command = '["roam", "--json", *args]'
    overridden_dynamic_command = (
        '["roam", *(["--override-mode"] if args and args[0] in {"verify", "index"} else []), "--json", *args]'
    )
    script = script.replace(dynamic_command, overridden_dynamic_command)
    return re.sub(
        r'(["\']roam["\']\s*,\s*)(["\'])(verify|index)\2',
        r'\1"--override-mode", \2\3\2',
        script,
    )


def _ensure_hook_mode_overrides(*, user_level: bool) -> None:
    """Best-effort upgrade of roam-managed Claude hook command ordering."""
    claude_dir = os.path.join(os.path.expanduser("~"), ".claude") if user_level else ".claude"
    for filename in HOOK_FILENAMES:
        hook_path = os.path.join(claude_dir, "hooks", filename)
        try:
            with open(hook_path, encoding="utf-8") as fh:
                script = fh.read()
            updated = _override_hook_maintenance_commands(script)
            if updated != script:
                with open(hook_path, "w", encoding="utf-8") as fh:
                    fh.write(updated)
        except (OSError, UnicodeDecodeError):
            continue


def _exit_after_canonical_claude_hook_update(
    *, uninstall: bool = False, no_verify: bool = False, user_level: bool = False
) -> None:
    """Exit through one Claude hook mutation path so wire/unwire cannot drift."""
    rc = _delegate(
        *_claude_hook_args_for_canonical_write_order(uninstall=uninstall, no_verify=no_verify, user_level=user_level)
    )
    if rc == 0 and not uninstall:
        _ensure_hook_mode_overrides(user_level=user_level)
        _wire_roam_midtask_access(user_level=user_level)
    raise SystemExit(rc)


def _wired_in(settings_path: str) -> bool:
    """True when the compile hook is present in a Claude settings file.

    ``UnicodeDecodeError`` counts as "not wired": a settings file saved in a
    non-UTF-8 encoding (PowerShell defaults to UTF-16 with a BOM) must degrade
    to re-wiring, never crash `doctor` / `wire` / `claude`.
    """
    if not os.path.exists(settings_path):
        return False
    try:
        with open(settings_path, encoding="utf-8") as fh:
            return HOOK_MARKER in fh.read()
    except (OSError, UnicodeDecodeError):
        return False


def _merge_roam_permissions(settings_path: str) -> bool:
    """Best-effort merge of curated roam commands into Claude's Bash allow-list.

    ``json`` is imported lazily (same contract as ``_on_path``'s shutil): only
    the wire path parses settings files, so the common commands skip the cost.
    """
    import json

    try:
        if os.path.exists(settings_path):
            with open(settings_path, encoding="utf-8") as fh:
                settings = json.load(fh)
        else:
            settings = {}
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
            os.makedirs(os.path.dirname(settings_path), exist_ok=True)
            with open(settings_path, "w", encoding="utf-8") as fh:
                json.dump(settings, fh, indent=2)
                fh.write("\n")
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
    """Best-effort, idempotent merge of the curated command advertisement."""
    try:
        if os.path.exists(claude_path):
            with open(claude_path, encoding="utf-8") as fh:
                content = fh.read()
        else:
            content = ""
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
        parent = os.path.dirname(claude_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(claude_path, "w", encoding="utf-8") as fh:
            fh.write(updated)
    except (OSError, UnicodeDecodeError):
        return


def _wire_roam_midtask_access(*, user_level: bool) -> None:
    """Expose curated launch-graph queries after the delegated hook write."""
    claude_dir = os.path.join(os.path.expanduser("~"), ".claude") if user_level else ".claude"
    if not any(_wired_in(os.path.join(claude_dir, name)) for name in ("settings.local.json", "settings.json")):
        return
    if not _merge_roam_permissions(os.path.join(claude_dir, "settings.local.json")):
        return
    claude_path = os.path.join(claude_dir, "CLAUDE.md") if user_level else "CLAUDE.md"
    _merge_roam_guidance(claude_path)


def _project_wired() -> bool:
    """True when either project-local Claude settings file contains the hook."""
    return _wired_in(os.path.join(".claude", "settings.local.json")) or _wired_in(
        os.path.join(".claude", "settings.json")
    )


def _user_wired() -> bool:
    """True when either user-global Claude settings file contains the hook."""
    user_claude = os.path.join(os.path.expanduser("~"), ".claude")
    return _wired_in(os.path.join(user_claude, "settings.local.json")) or _wired_in(
        os.path.join(user_claude, "settings.json")
    )


def _launch_head() -> str | None:
    """Short git HEAD for the current repo, or ``None`` if it cannot be read."""
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
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
        with open(LAUNCH_INDEX_HEAD_FILE, encoding="utf-8") as fh:
            head = fh.read().strip()
    except (OSError, UnicodeDecodeError):
        # A corrupted marker means "unknown HEAD" — fail open into a re-index.
        return None
    return head if re.fullmatch(r"[0-9a-f]+", head) else None


def _mark_launch_indexed(head: str | None = None) -> None:
    """Remember the HEAD that the launch-time index was built against."""
    head = head or _launch_head()
    if not head:
        return
    try:
        os.makedirs(os.path.dirname(LAUNCH_INDEX_HEAD_FILE), exist_ok=True)
        with open(LAUNCH_INDEX_HEAD_FILE, "w", encoding="utf-8") as fh:
            fh.write(f"{head}\n")
    except OSError:
        pass


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
    regardless of the platform they run on. The PATH check at command start is
    advisory only — the binary can vanish or be unlaunchable by the time we
    get here, and that race must end in a verdict, not a traceback.
    """
    if use_exec is None:
        use_exec = os.name != "nt"
    try:
        if use_exec:
            os.environ.update(env)
            os.execvp(argv[0], argv)
            return 0  # only reachable when tests stub execvp; exec does not return
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
    if not _on_path("claude"):
        click.echo("VERDICT: `claude` not found on PATH — install Claude Code first (https://claude.com/claude-code)")
        ctx.exit(1)
    rc = _ensure_indexed_for_launch()
    if rc != 0:
        ctx.exit(rc)
    # Idempotent wiring is part of this launcher's safety contract: claiming
    # the compile/Verify loop is active while launching without hooks is a
    # false success. Degraded launch remains available only by explicit opt-in.
    if not (_project_wired() or _user_wired()):
        wire_rc = _delegate("hooks", "claude", "--write")
        wired = wire_rc == 0 and (_project_wired() or _user_wired())
        if not wired:
            click.echo(
                "VERDICT: wiring failed — compile/Verify hooks are not proven active; agent not launched. "
                "Run `compile doctor`, or pass `--allow-unwired` to acknowledge degraded mode."
            )
            if not allow_unwired:
                ctx.exit(wire_rc or 1)
            click.echo("compile: explicit degraded launch accepted (--allow-unwired)")
    # Keep both project-local and user-global managed hooks compatible with
    # read-only enforcement, including hooks installed before this release.
    _ensure_hook_mode_overrides(user_level=False)
    _ensure_hook_mode_overrides(user_level=True)
    child_env = os.environ.copy()
    child_env.setdefault("ROAM_AGENT_MODE", "compile_claude")
    if read_only:
        child_env.update(ROAM_AGENT_MODE="read_only", ROAM_MODE_ENFORCEMENT="1")
    raise SystemExit(_launch_agent(["claude", *agent_args], child_env))


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
_VERIFY_COMPLETION_LINE = re.compile(r"^VERDICT:\s+(?:PASS|WARN)\b")
# Cause when no FAIL line was parseable — fall back to the roam exit code.
_EXIT_CAUSE = {2: "bad arguments", 3: "index missing", 4: "index stale", EXIT_VERIFY_GATE: "quality gate"}


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
    try:
        proc = subprocess.run(
            ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
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


def _valid_verify_completion(output: str) -> bool:
    """A zero exit is valid only with an explicit non-failing verdict."""
    first_line = next((line.strip() for line in output.splitlines() if line.strip()), "")
    return bool(_VERIFY_COMPLETION_LINE.match(first_line))


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


def _format_command_inventory(commands: dict) -> str:
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
    On a failure the raw check output is kept and followed by a block naming
    the failing command, the changed files, a likely cause category, and the
    single local rerun to run next.
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
    scope_args = targets or ["--changed"]
    advisory = _oversized_target_set(list(files), cap=25)
    if advisory:
        click.echo(advisory)
    argv = ["verify"]
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
    argv.extend(scope_args)
    command.extend(scope_args)
    rc, output = _delegate_capturing(*argv, executable=executable)
    if output:
        click.echo(output.rstrip())
    if rc == 0 and (output is None or not _valid_verify_completion(output)):
        click.echo(
            f"VERDICT: verifier protocol failure — `{executable}` exited 0 without a parseable PASS/WARN "
            f'verdict. Fix: python -m pip install --upgrade "roam-code>={MIN_ROAM_VERSION}"'
        )
        raise SystemExit(EXIT_TOOLCHAIN)
    # output is None => the toolchain never ran to completion (missing, broken,
    # timed out, interrupted) and its verdict is already on screen. Every
    # completed nonzero run gets the failure block — including roam's own
    # exit 2 ("bad arguments"), which only the sentinel can distinguish from
    # this CLI's EXIT_TOOLCHAIN (also 2).
    if rc != 0 and output is not None:
        failing = _failing_files(output)
        status_paths = _changed_files() if not failing and not targets else []
        scoped = failing or targets or status_paths
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
                cause=_classify_verify_failure(output, rc),
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
