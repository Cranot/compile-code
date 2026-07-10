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

import json
import os
import re
import subprocess
import time

import click

from compile_code import __version__

__all__ = ["cli"]

EXIT_TOOLCHAIN = 2
EXIT_TIMEOUT = 124
# roam verify quality-gate failure (see `roam exit-codes`); the one verify exit
# code the product surface acts on — checks ran and the score fell below threshold.
EXIT_VERIFY_GATE = 5
BASELINE_TIMEOUT = 1200

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
    only ``claude`` and ``doctor`` do a PATH lookup.
    """
    import shutil

    return shutil.which(name) is not None


def _require_index(path: str = ".") -> bool:
    """True when a compile index exists at *path*."""
    return os.path.exists(os.path.join(path, ".roam", "index.db"))


def _roam(*args: str, timeout: int = 600) -> subprocess.CompletedProcess:
    """Run the roam toolchain CLI (provided by the roam-code dependency)."""
    return subprocess.run(["roam", *args], timeout=timeout, check=False)


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
    except subprocess.TimeoutExpired:
        click.echo(f"VERDICT: toolchain call timed out after {timeout}s — rerun with a smaller scope or file an issue")
        return EXIT_TIMEOUT
    except KeyboardInterrupt:
        click.echo("VERDICT: interrupted")
        return 130


def _roam_capture(*args: str, timeout: int = 600) -> subprocess.CompletedProcess:
    """Run the roam toolchain CLI capturing stdout (``_roam`` streams it).

    Kept as a separate indirection so tests stub it the way they stub
    ``_roam``. Only ``verify`` needs the captured output — to classify the
    failure and explain the next local action — so the other commands keep
    streaming via ``_delegate``.
    """
    return subprocess.run(["roam", *args], timeout=timeout, check=False, capture_output=True, text=True)


def _delegate_capturing(*args: str, timeout: int = 600) -> tuple[int, str]:
    """Run the toolchain and translate failure modes like ``_delegate``.

    Returns ``(rc, stdout)`` instead of streaming, so the caller can classify
    a verify failure from roam's check output before composing the verdict.
    """
    try:
        proc = _roam_capture(*args, timeout=timeout)
        return proc.returncode, proc.stdout or ""
    except FileNotFoundError:
        click.echo(
            "VERDICT: toolchain missing — `roam` is not on PATH. "
            "Fix: pip install --force-reinstall compile-code  "
            "(installs the roam-code dependency)"
        )
        return EXIT_TOOLCHAIN, ""
    except subprocess.TimeoutExpired:
        click.echo(f"VERDICT: toolchain call timed out after {timeout}s — rerun with a smaller scope or file an issue")
        return EXIT_TIMEOUT, ""
    except KeyboardInterrupt:
        click.echo("VERDICT: interrupted")
        return 130, ""


def _git_status_porcelain(timeout: int = 10) -> tuple[int, str]:
    """Return ``git status --porcelain`` output, or a clean verdict + code.

    `compile baseline` refuses dirty trees before it snapshots accepted debt.
    """
    try:
        proc = subprocess.run(
            ["git", "status", "--porcelain"], timeout=timeout, check=False, capture_output=True, text=True
        )
    except FileNotFoundError:
        click.echo("VERDICT: toolchain missing — `git` is not on PATH. Fix: install git and rerun `compile baseline`.")
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
        except OSError:
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
    """True when the compile hook is present in a Claude settings file."""
    if not os.path.exists(settings_path):
        return False
    try:
        with open(settings_path, encoding="utf-8") as fh:
            return HOOK_MARKER in fh.read()
    except OSError:
        return False


def _merge_roam_permissions(settings_path: str) -> bool:
    """Best-effort merge of curated roam commands into Claude's Bash allow-list."""
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
    except OSError:
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
            ["git", "rev-parse", "--short", "HEAD"], check=False, capture_output=True, text=True, timeout=10
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
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
    except OSError:
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


# Commands are dispatched by string name through this group (via the
# console-script entry points in pyproject.toml). Keep callback functions
# private and set the public Click command names explicitly.
@click.group()
@click.version_option(version=__version__, package_name="compile-code")
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


@cli.command("claude", context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.argument("agent_args", nargs=-1, type=click.UNPROCESSED)
@click.option("--read-only", is_flag=True, default=False, help="Enforce read-only mode for the launched agent.")
@click.pass_context
def _claude(ctx: click.Context, agent_args: tuple[str, ...], read_only: bool) -> None:
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
    # Idempotent wiring. Fail-open by contract: a wiring failure must not
    # block the agent launch — but say so instead of swallowing it.
    if not (_project_wired() or _user_wired()) and _delegate("hooks", "claude", "--write") != 0:
        click.echo("compile: wiring failed (continuing without hooks — run `compile doctor`)")
    # Keep both project-local and user-global managed hooks compatible with
    # read-only enforcement, including hooks installed before this release.
    _ensure_hook_mode_overrides(user_level=False)
    _ensure_hook_mode_overrides(user_level=True)
    child_env = os.environ.copy()
    if read_only:
        child_env.update(ROAM_AGENT_MODE="read_only", ROAM_MODE_ENFORCEMENT="1")
    if os.name == "nt":  # pragma: no cover - windows-only branch
        # exec* on Windows spawns-and-detaches instead of replacing the
        # process (console handling breaks). Run as a child instead.
        raise SystemExit(subprocess.run(["claude", *agent_args], check=False, env=child_env).returncode)
    os.environ.update(child_env)
    os.execvp("claude", ["claude", *agent_args])


@cli.command("run")
@click.argument("task")
@click.option("--json", "json_out", is_flag=True, help="Emit the raw JSON envelope.")
def _run(task: str, json_out: bool) -> None:
    """Compile a task headlessly and print the envelope (scripts / CI).

    The envelope contains the classified intent, pre-resolved facts
    (callers, history, blast radius, bug-site source, ...) and an answer
    contract — paste-ready as an agent prompt prefix.
    """
    args = (["--json"] if json_out else []) + ["compile", task, "--artifact", "auto"]
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
_VERIFY_FAIL_LINE = re.compile(r"^\s*FAIL:\s*(\S+?):\d+\b")
# Cause when no FAIL line was parseable — fall back to the roam exit code.
_EXIT_CAUSE = {2: "bad arguments", 3: "index missing", 4: "index stale", EXIT_VERIFY_GATE: "quality gate"}


def _changed_files() -> list[str]:
    """Tracked files that differ from HEAD (staged + unstaged). Empty outside git."""
    try:
        out = subprocess.run(
            ["git", "diff", "--name-only", "HEAD"], check=False, capture_output=True, text=True, timeout=10
        ).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def _failing_files(output: str) -> list[str]:
    """Files named on ``FAIL: file:line`` lines, de-duplicated, order-preserving."""
    failing: list[str] = []
    for line in output.splitlines():
        match = _VERIFY_FAIL_LINE.match(line)
        if not match:
            continue
        failed_file = match.group(1)
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
    targets = list(files) or _changed_files()
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
    argv.extend(targets if targets else ["--changed"])
    command.extend(targets if targets else ["--changed"])
    rc, output = _delegate_capturing(*argv)
    if output:
        click.echo(output.rstrip())
    if rc not in (0, EXIT_TOOLCHAIN, EXIT_TIMEOUT, 130):
        failing = _failing_files(output)
        scoped = failing or targets
        next_tokens = ["compile", "verify"]
        if new_only:
            next_tokens.append("--new-only")
        if diff_only:
            next_tokens.append("--diff-only")
        next_tokens.extend(scoped if scoped else ["--changed"])
        click.echo(
            _format_verify_failure(
                command=" ".join(command),
                files=targets,
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
    toolchain_ok = _on_path("roam")
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
    click.echo(f"toolchain : {'ok' if toolchain_ok else 'MISSING'}")
    click.echo(f"index     : {'ok' if indexed else 'absent (run `compile init`)'}")
    click.echo(f"claude    : {wired_label}")
    click.echo(f"verify report: {_verify_report_status()}")
    if not toolchain_ok:
        click.echo("VERDICT: toolchain missing — `roam` not on PATH (pip install --force-reinstall compile-code)")
        raise SystemExit(EXIT_TOOLCHAIN)
    click.echo("VERDICT: ready" if indexed and wired else "VERDICT: install ok — finish setup above")


if __name__ == "__main__":  # pragma: no cover
    cli()
