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
import shutil
import subprocess

import click

EXIT_TOOLCHAIN = 2
EXIT_TIMEOUT = 124


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
        return 130


def _wired_in(settings_path: str) -> bool:
    """True when the compile hook is present in a Claude settings file."""
    if not os.path.exists(settings_path):
        return False
    try:
        with open(settings_path, encoding="utf-8") as fh:
            return "roam-compile-ups.py" in fh.read()
    except OSError:
        return False


@click.group()
@click.version_option(package_name="compile-code")
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
    """


@cli.command()
@click.option("--force", is_flag=True, help="Rebuild the index from scratch.")
def init(force: bool) -> None:
    """Index the current repo (one-time; incremental afterwards)."""
    args = ["init"]
    if force:
        args = ["index", "--force"]
    raise SystemExit(_delegate(*args))


@cli.command()
@click.argument("agent", type=click.Choice(["claude"]))
@click.option("--no-verify", is_flag=True, help="Skip the post-edit verify hook.")
@click.option("--user", "user_level", is_flag=True, help="Wire user-global (~/.claude) instead of project-local.")
def wire(agent: str, no_verify: bool, user_level: bool) -> None:
    """Wire the compile/verify loop into your agent (persistent, idempotent).

    For claude: installs a UserPromptSubmit hook (compile the prompt,
    inject pre-resolved facts) and a Stop hook (scoped verify after
    edits, quiet on pass). Both fail-open — a broken install can never
    block your agent. Undo anytime with `compile unwire claude`.
    """
    args = ["hooks", "claude", "--write"]
    if no_verify:
        args.append("--no-verify")
    if user_level:
        args.append("--user")
    raise SystemExit(_delegate(*args))


@cli.command()
@click.argument("agent", type=click.Choice(["claude"]))
@click.option("--user", "user_level", is_flag=True, help="Unwire the user-global (~/.claude) install.")
def unwire(agent: str, user_level: bool) -> None:
    """Remove the compile/verify hooks installed by `compile wire`."""
    args = ["hooks", "claude", "--uninstall", "--write"]
    if user_level:
        args.append("--user")
    raise SystemExit(_delegate(*args))


@cli.command(context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.argument("agent_args", nargs=-1, type=click.UNPROCESSED)
@click.pass_context
def claude(ctx: click.Context, agent_args: tuple[str, ...]) -> None:
    """Launch Claude Code with the compile/verify loop active (all-in-one).

    Ensures the repo is indexed, wires the hooks if absent, then execs
    the real `claude` with any arguments passed through. The zero-
    learning-curve path: type `compile claude` instead of `claude`,
    everything else is your normal workflow.
    """
    if shutil.which("claude") is None:
        click.echo("VERDICT: `claude` not found on PATH — install Claude Code first (https://claude.com/claude-code)")
        ctx.exit(1)
    if not _require_index():
        click.echo("compile: indexing repo (first run)...")
        rc = _delegate("init")
        if rc != 0:
            click.echo("VERDICT: indexing failed — run `compile init` for details")
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


@cli.command()
@click.argument("task")
@click.option("--json", "json_out", is_flag=True, help="Emit the raw JSON envelope.")
def run(task: str, json_out: bool) -> None:
    """Compile a task headlessly and print the envelope (scripts / CI).

    The envelope contains the classified intent, pre-resolved facts
    (callers, history, blast radius, bug-site source, ...) and an answer
    contract — paste-ready as an agent prompt prefix.
    """
    args = (["--json"] if json_out else []) + ["compile", task, "--artifact", "auto"]
    raise SystemExit(_delegate(*args))


@cli.command()
def stats() -> None:
    """Show compile telemetry for this repo (routing, latency, cache)."""
    raise SystemExit(_delegate("compile-stats"))


@cli.command()
def doctor() -> None:
    """Check the install: toolchain present, index state, wiring state.

    Wiring is checked at both levels — project (.claude/settings.json)
    and user-global (~/.claude/settings.json); either counts as wired.
    """
    toolchain_ok = shutil.which("roam") is not None
    indexed = _require_index()
    project_wired = _wired_in(os.path.join(".claude", "settings.json"))
    user_wired = _wired_in(os.path.join(os.path.expanduser("~"), ".claude", "settings.json"))
    wired = project_wired or user_wired
    wired_label = (
        "wired (project)" if project_wired
        else "wired (user-global)" if user_wired
        else "not wired (run `compile wire claude`)"
    )
    click.echo(f"toolchain : {'ok' if toolchain_ok else 'MISSING'}")
    click.echo(f"index     : {'ok' if indexed else 'absent (run `compile init`)'}")
    click.echo(f"claude    : {wired_label}")
    if not toolchain_ok:
        click.echo(
            "VERDICT: toolchain missing — `roam` not on PATH "
            "(pip install --force-reinstall compile-code)"
        )
        raise SystemExit(EXIT_TOOLCHAIN)
    click.echo("VERDICT: ready" if indexed and wired else "VERDICT: install ok — finish setup above")


if __name__ == "__main__":  # pragma: no cover
    cli()
