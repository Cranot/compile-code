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

import click

from compile_code import __version__

__all__ = ["cli"]

EXIT_TOOLCHAIN = 2
EXIT_TIMEOUT = 124
# roam verify quality-gate failure (see `roam exit-codes`); the one verify exit
# code the product surface acts on — checks ran and the score fell below threshold.
EXIT_VERIFY_GATE = 5

# The hook script the roam-code dependency installs into a Claude settings
# file; its presence is how we detect that compile is wired in. Kept as a
# named constant so the delegated hook-detection contract is explicit and
# updates in lockstep if roam-code renames the hook.
HOOK_MARKER = "roam-compile-ups.py"


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


def _ensure_indexed_for_launch() -> int:
    """Ensure the repo is indexed before an all-in-one agent launch.

    Returns 0 when an index already exists or is freshly built. On
    first-run indexing failure emits the verdict and returns the
    toolchain's nonzero code, which the launcher exits with. Keeping the
    whole index-delegation contract here makes it testable without a
    click context.
    """
    if _require_index():
        return 0
    click.echo("compile: indexing repo (first run)...")
    rc = _delegate("init")
    if rc != 0:
        click.echo("VERDICT: indexing failed — run `compile init` for details")
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
    raise SystemExit(
        _delegate(
            *_claude_hook_args_for_canonical_write_order(
                uninstall=uninstall, no_verify=no_verify, user_level=user_level
            )
        )
    )


def _wired_in(settings_path: str) -> bool:
    """True when the compile hook is present in a Claude settings file."""
    if not os.path.exists(settings_path):
        return False
    try:
        with open(settings_path, encoding="utf-8") as fh:
            return HOOK_MARKER in fh.read()
    except OSError:
        return False


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


@cli.command("claude", context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.argument("agent_args", nargs=-1, type=click.UNPROCESSED)
@click.pass_context
def _claude(ctx: click.Context, agent_args: tuple[str, ...]) -> None:
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
    if _delegate("hooks", "claude", "--write") != 0:
        click.echo("compile: wiring failed (continuing without hooks — run `compile doctor`)")
    if os.name == "nt":  # pragma: no cover - windows-only branch
        # exec* on Windows spawns-and-detaches instead of replacing the
        # process (console handling breaks). Run as a child instead.
        raise SystemExit(subprocess.run(["claude", *agent_args], check=False).returncode)
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
        i: match.group(1).strip()
        for i, line in enumerate(lines)
        if (match := _VERIFY_SECTION.match(line))
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


def _format_verify_failure(*, command: str, files: list[str], cause: str, next_action: str) -> str:
    """Render the verify-failure block — the four things needed to act locally."""
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
    "--threshold",
    type=int,
    default=70,
    show_default=True,
    help="Fail below this score (default 70, or .roam/verify.yaml).",
)
def _verify(files: tuple[str, ...], threshold: int) -> None:
    """Run scoped verify on changed files; on failure, explain the next local action.

    Delegates to `roam verify` (naming, imports, error handling, duplicates,
    syntax on the changed set). On a failure the raw check output is kept and
    followed by a block naming the failing command, the changed files, a
    likely cause category, and the single local rerun to run next.
    """
    targets = list(files) or _changed_files()
    argv = ["verify", "--threshold", str(threshold), *(targets if targets else ["--changed"])]
    rc, output = _delegate_capturing(*argv)
    if output:
        click.echo(output.rstrip())
    if rc not in (0, EXIT_TOOLCHAIN, EXIT_TIMEOUT, 130):
        failing = _failing_files(output)
        scoped = failing or targets
        files_suffix = " ".join(targets) if targets else "--changed"
        next_suffix = " ".join(scoped) if scoped else "--changed"
        threshold_suffix = f" --threshold {threshold}" if threshold != 70 else ""
        click.echo(
            _format_verify_failure(
                command=f"compile verify{threshold_suffix} {files_suffix}",
                files=targets,
                cause=_classify_verify_failure(output, rc),
                next_action=f"compile verify {next_suffix}",
            )
        )
    raise SystemExit(rc)


@cli.command("doctor")
def _doctor() -> None:
    """Check the install: toolchain present, index state, wiring state.

    Wiring is checked at both levels — project (.claude/settings.json)
    and user-global (~/.claude/settings.json); either counts as wired.
    """
    toolchain_ok = _on_path("roam")
    indexed = _require_index()
    project_wired = _wired_in(os.path.join(".claude", "settings.json"))
    # Only read the user-global settings when the project isn't already wired —
    # the label below reports "wired (project)" regardless, so this IO is
    # redundant when project_wired is true.
    user_wired = project_wired or _wired_in(os.path.join(os.path.expanduser("~"), ".claude", "settings.json"))
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
    if not toolchain_ok:
        click.echo("VERDICT: toolchain missing — `roam` not on PATH (pip install --force-reinstall compile-code)")
        raise SystemExit(EXIT_TOOLCHAIN)
    click.echo("VERDICT: ready" if indexed and wired else "VERDICT: install ok — finish setup above")


if __name__ == "__main__":  # pragma: no cover
    cli()
