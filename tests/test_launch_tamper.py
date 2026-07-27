"""End-to-end tamper measurement for the pre-exec readiness boundary.

Every other launcher test in this repo monkeypatches ``_inspect_roam`` and
``_resolve_trusted_executable`` -- i.e. it stubs out the very mechanism the
security boundary is made of. These tests do the opposite: they build a real
temporary workspace with real executables on a real ``PATH``, tamper with those
files on disk inside the real preparation window, and then assert on the only
judge-free observable there is -- did the process hand the console to the agent
or not.

The one and only stub is ``_launch_agent``: exec'ing a real agent from a test
suite is not an option, so a launch is recorded instead of performed. Resolution,
version inspection, workspace rejection, hook-body parsing, and producer
attestation all run for real against real files.

Preregistered bar (fixed before the first run):
    * REFUSE to launch in 100% of tamper cases (T1..T9 below).
    * Launch normally in 100% of clean cases (C1, C2).

``test_T4_...`` used to be a pinned ``xfail(strict=True)``: ``_inspect_roam``
captured only ``(path, version)``, so in-place content mutation of the roam
executable that preserved both was invisible to the re-proof. ``_inspect_roam``
now also captures a sha256 digest of the executable's bytes -- read from
outside the process, never from anything the binary says about itself -- and
the re-proof compares it alongside path and version, so this case is now
REFUSE like the rest.

``test_T9_...`` is the same gap one binary over: `claude` was validated only
by ``_resolve_trusted_executable``'s path-string recheck (see T8), never
content-hashed, so an in-place content swap at the same path was invisible to
it. The `_claude` command now captures a digest of the resolved `claude`
executable and compares a fresh read against it immediately before handover,
reusing ``_content_digest`` -- the same function and swap-check T4 exercises,
not a second hashing path.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

import compile_code.cli as mod

WINDOWS = os.name == "nt"
GOOD_VERSION = "13.10.0"
FAKE_HEAD = "abc1234"
ATTEST_FILE = "roam-attest.json"


# --------------------------------------------------------------------------
# real on-disk executables
# --------------------------------------------------------------------------


def _shim_path(directory: Path, name: str) -> Path:
    return directory / (f"{name}.cmd" if WINDOWS else name)


def _write_shim(directory: Path, name: str, *, cmd_body: str, py_body: str) -> Path:
    """Write a real, resolvable, runnable executable for this platform."""
    directory.mkdir(parents=True, exist_ok=True)
    path = _shim_path(directory, name)
    if WINDOWS:
        path.write_text("@echo off\r\n" + cmd_body, encoding="utf-8", newline="")
    else:
        path.write_text("#!/usr/bin/env python3\n" + py_body, encoding="utf-8")
        path.chmod(0o755)
    return path


def _write_roam(directory: Path, *, version: str = GOOD_VERSION, payload: Path | None = None) -> Path:
    """A roam that answers ``--version`` and attests its own hook bodies.

    ``payload`` makes the shim drop a marker file on every non-``--version``
    invocation. That is the T4 substitution: a *different program*, at the same
    path, still reporting the same version and still emitting a valid
    attestation envelope. If the marker exists afterwards, attacker-controlled
    code ran under the launcher's own trust.
    """
    if payload is None:
        cmd_payload = py_payload = ""
    else:
        cmd_payload = f'echo pwned>"{payload}"\r\n'
        py_payload = f'pathlib.Path(r"{payload}").write_text("pwned")\n'
    path = _write_shim(
        directory,
        "roam",
        cmd_body=(
            f'if "%~1"=="--version" (\r\n'
            f"echo roam, version {version}\r\n"
            f"exit /b 0\r\n"
            f")\r\n" + cmd_payload + f'type "%~dp0{ATTEST_FILE}"\r\n'
            f"exit /b 0\r\n"
        ),
        py_body=(
            "import pathlib, sys\n"
            'if sys.argv[1:2] == ["--version"]:\n'
            f'    print("roam, version {version}")\n'
            "    raise SystemExit(0)\n"
            + py_payload
            + f'sys.stdout.write(pathlib.Path(__file__).with_name("{ATTEST_FILE}").read_text())\n'
            "raise SystemExit(0)\n"
        ),
    )
    _write_attestation(directory, version=version)
    return path


def _write_attestation(directory: Path, *, version: str = GOOD_VERSION) -> None:
    envelope = {
        "schema": mod.VERIFY_ENVELOPE_SCHEMA,
        "schema_version": mod.VERIFY_ENVELOPE_SCHEMA_VERSION,
        "command": "hooks",
        "version": version,
        "summary": {
            "already_installed": True,
            "foreign_bodies": [],
            "hook_body_version": mod.MIN_CLAUDE_HOOK_VERSION,
            "body_states": {name: "current" for name in mod.HOOK_FILENAMES},
        },
    }
    (directory / ATTEST_FILE).write_text(json.dumps(envelope), encoding="utf-8")


def _write_claude(directory: Path) -> Path:
    return _write_shim(
        directory,
        "claude",
        cmd_body="exit /b 0\r\n",
        py_body="raise SystemExit(0)\n",
    )


def _write_git(directory: Path) -> Path:
    return _write_shim(
        directory,
        "git",
        cmd_body=f"echo {FAKE_HEAD}\r\nexit /b 0\r\n",
        py_body=f'print("{FAKE_HEAD}")\nraise SystemExit(0)\n',
    )


# --------------------------------------------------------------------------
# real on-disk Claude wiring
# --------------------------------------------------------------------------


def _hook_command(path: Path) -> str:
    argv = [sys.executable, str(path.resolve(strict=True))]
    return subprocess.list2cmdline(argv) if WINDOWS else " ".join(shlex.quote(part) for part in argv)


def _current_hook_body(filename: str, *, version: int = mod.MIN_CLAUDE_HOOK_VERSION) -> str:
    markers = "\n".join(f"# {marker}" for marker in mod._HOOK_BODY_MARKERS[filename])
    return f"#!/usr/bin/env python3\n# roam-hook-version: {version}\n{markers}\n"


def _write_wiring(root: Path) -> dict[str, Path]:
    hook_dir = root / ".claude" / "hooks"
    hook_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    hooks: dict[str, object] = {}
    for event, filename in mod.HOOK_EVENTS.items():
        body_path = hook_dir / filename
        body_path.write_text(_current_hook_body(filename), encoding="utf-8")
        written[filename] = body_path
        hooks[event] = [{"hooks": [{"type": "command", "command": _hook_command(body_path)}]}]
    (root / ".claude" / "settings.json").write_text(json.dumps({"hooks": hooks}), encoding="utf-8")
    return written


# --------------------------------------------------------------------------
# fixture: a real, clean, launchable workspace
# --------------------------------------------------------------------------


class Boundary:
    """Handles onto the real files the launcher will inspect."""

    def __init__(self, repo: Path, tools: Path, hooks: dict[str, Path]) -> None:
        self.repo = repo
        self.tools = tools
        self.hooks = hooks
        self.launches: list[tuple[list[str], dict[str, str]]] = []

    @property
    def roam(self) -> Path:
        return _shim_path(self.tools, "roam")

    @property
    def claude(self) -> Path:
        return _shim_path(self.tools, "claude")

    @property
    def launched(self) -> bool:
        return bool(self.launches)


@pytest.fixture
def boundary(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    tools = tmp_path / "tools"
    (repo / ".git").mkdir(parents=True)
    (repo / ".roam").mkdir(parents=True)
    (repo / ".roam" / "index.db").write_text("", encoding="utf-8")
    (repo / mod.LAUNCH_INDEX_HEAD_FILE).write_text(f"{FAKE_HEAD}\n", encoding="utf-8")

    _write_roam(tools)
    _write_claude(tools)
    _write_git(tools)
    hooks = _write_wiring(repo)

    monkeypatch.chdir(repo)
    # A hermetic PATH: only the tools directory. COMSPEC/SystemRoot stay in the
    # environment so Windows can still start a .cmd.
    monkeypatch.setenv("PATH", str(tools))

    state = Boundary(repo, tools, hooks)
    monkeypatch.setattr(
        mod,
        "_launch_agent",
        lambda argv, env, **kwargs: state.launches.append((list(argv), dict(env))) or 0,
    )
    return state


def _tamper_during_preparation(monkeypatch, tamper) -> None:
    """Run *tamper* inside the real window between the two ``_inspect_roam`` calls.

    ``_ensure_indexed_for_launch`` is called after the first inspection and
    before the re-proof, so wrapping it reproduces a concurrent attacker writing
    to disk while the launcher prepares -- the exact race the re-proof exists
    to close.
    """
    original = mod._ensure_indexed_for_launch

    def wrapper(**kwargs):
        rc = original(**kwargs)
        tamper()
        return rc

    monkeypatch.setattr(mod, "_ensure_indexed_for_launch", wrapper)


def _invoke(*args: str):
    return CliRunner().invoke(mod.cli, ["claude", *args])


# --------------------------------------------------------------------------
# clean cases -- must launch
# --------------------------------------------------------------------------


def test_C1_clean_workspace_launches(boundary):
    result = _invoke()

    assert result.exit_code == 0, result.output
    assert boundary.launched, f"clean launch was refused: {result.output}"
    argv, env = boundary.launches[0]
    assert argv[0] == str(boundary.claude.resolve())
    assert env["ROAM_AGENT_MODE"] == "compile_claude"


def test_C2_clean_workspace_launches_read_only(boundary):
    result = _invoke("--read-only")

    assert result.exit_code == 0, result.output
    assert boundary.launched, f"clean read-only launch was refused: {result.output}"
    _argv, env = boundary.launches[0]
    assert env["ROAM_AGENT_MODE"] == "read_only"
    assert env["ROAM_MODE_ENFORCEMENT"] == "1"


# --------------------------------------------------------------------------
# tamper cases -- must refuse
# --------------------------------------------------------------------------


def test_T1_roam_path_swapped_mid_preparation_is_refused(boundary, monkeypatch):
    """The resolved roam moves to a different directory during preparation."""
    decoy = boundary.repo.parent / "decoy"

    def tamper() -> None:
        _write_roam(decoy)
        monkeypatch.setenv("PATH", os.pathsep.join([str(decoy), str(boundary.tools)]))

    _tamper_during_preparation(monkeypatch, tamper)

    result = _invoke()

    assert not boundary.launched, "launched with a swapped roam executable"
    assert result.exit_code == mod.EXIT_TOOLCHAIN
    assert "Roam executable/version changed" in result.output


def test_T2_roam_version_downgraded_mid_preparation_is_refused(boundary, monkeypatch):
    """The same roam path starts reporting a different version."""
    _tamper_during_preparation(monkeypatch, lambda: _write_roam(boundary.tools, version="13.11.0"))

    result = _invoke()

    assert not boundary.launched, "launched after the roam version changed under it"
    assert result.exit_code == mod.EXIT_TOOLCHAIN
    assert "Roam executable/version changed" in result.output


def test_T3_roam_deleted_mid_preparation_is_refused(boundary, monkeypatch):
    """The roam executable vanishes during preparation."""
    _tamper_during_preparation(monkeypatch, boundary.roam.unlink)

    result = _invoke()

    assert not boundary.launched, "launched with no roam executable at all"
    assert result.exit_code == mod.EXIT_TOOLCHAIN
    assert "VERDICT: toolchain" in result.output


def test_T4_roam_content_mutated_in_place_is_refused(boundary, monkeypatch):
    """The literal TOCTOU shape: same path, same reported version, different program.

    The substituted roam runs an arbitrary payload on every non-``--version``
    invocation -- including the launcher's own ``hooks claude`` attestation call
    -- while still reporting ``13.10.0`` and still returning a well-formed
    envelope. Path and version alone would miss it; the content digest, hashed
    from outside the executable rather than trusted from its output, does not.
    Attestation still runs (and its payload still fires -- see the ``marker``
    assertion below) before the digest catches the substitution, so this test
    also proves the launcher refuses even after the malicious code executed.
    """
    marker = boundary.repo.parent / "pwned.txt"
    before = boundary.roam.read_bytes()

    _tamper_during_preparation(monkeypatch, lambda: _write_roam(boundary.tools, payload=marker))

    result = _invoke()

    assert boundary.roam.read_bytes() != before, "tamper did not actually change the file"
    assert marker.exists(), "substituted roam was never executed; the test proves nothing"
    assert not boundary.launched, "launched after attesting against a substituted roam executable"
    assert result.exit_code != 0


def test_T5_workspace_local_roam_is_refused(boundary, monkeypatch):
    """A roam planted inside the checkout must never authorize a launch."""
    _write_roam(boundary.repo / "node_modules" / ".bin")
    monkeypatch.setenv("PATH", os.pathsep.join([str(boundary.repo / "node_modules" / ".bin"), str(boundary.tools)]))

    # Pin the mechanism, not just the outcome: `which` returns the planted copy
    # first and resolution rejects it outright rather than searching onward.
    assert mod._resolve_trusted_executable("roam", reject_workspace=True) == (None, "workspace_path")

    result = _invoke()

    assert not boundary.launched, "launched using a workspace-local roam"
    assert result.exit_code == mod.EXIT_TOOLCHAIN
    assert "toolchain missing" in result.output


def test_T6_workspace_local_claude_is_refused(boundary, monkeypatch):
    """A claude planted inside the checkout must never be exec'd."""
    _write_claude(boundary.repo / "node_modules" / ".bin")
    monkeypatch.setenv("PATH", os.pathsep.join([str(boundary.repo / "node_modules" / ".bin"), str(boundary.tools)]))

    assert mod._resolve_trusted_executable("claude", reject_workspace=True) == (None, "workspace_path")

    result = _invoke()

    assert not boundary.launched, "launched a workspace-local claude"
    assert result.exit_code == 1
    assert "workspace-local `claude` rejected" in result.output


def test_T7_hook_body_corrupted_mid_preparation_is_refused(boundary, monkeypatch):
    """A hook body is downgraded on disk after the first wiring check."""
    stop_hook = boundary.hooks["roam-verify-stop.py"]

    def tamper() -> None:
        stop_hook.write_text(_current_hook_body("roam-verify-stop.py", version=1), encoding="utf-8")

    _tamper_during_preparation(monkeypatch, tamper)

    result = _invoke()

    assert not boundary.launched, "launched with a stale hook body"
    assert result.exit_code != 0
    assert "wiring failed" in result.output


def test_T8_claude_path_swapped_mid_preparation_is_refused(boundary, monkeypatch):
    """The resolved claude moves to a different directory during preparation."""
    decoy = boundary.repo.parent / "decoy-claude"

    def tamper() -> None:
        _write_claude(decoy)
        _write_roam(decoy)
        _write_git(decoy)
        monkeypatch.setenv("PATH", os.pathsep.join([str(decoy), str(boundary.tools)]))

    _tamper_during_preparation(monkeypatch, tamper)

    result = _invoke()

    assert not boundary.launched, "launched a claude that moved during readiness checks"
    assert result.exit_code != 0


def test_T9_claude_content_mutated_in_place_is_refused(boundary, monkeypatch):
    """T4's shape, one binary over: same path, same name, different bytes.

    Nothing in this launcher ever runs ``claude`` before the exec decision --
    unlike roam there is no self-reported version or attestation envelope to
    distrust, only ``_resolve_trusted_executable``'s path-string recheck. A
    same-path, same-name content swap was therefore invisible to that recheck
    alone; the content digest, hashed from outside the executable and
    compared against the value captured before preparation began, is not.
    """
    before = boundary.claude.read_bytes()

    def tamper() -> None:
        _write_shim(
            boundary.tools,
            "claude",
            cmd_body="echo pwned\r\nexit /b 0\r\n",
            py_body='print("pwned")\nraise SystemExit(0)\n',
        )

    _tamper_during_preparation(monkeypatch, tamper)

    result = _invoke()

    assert boundary.claude.read_bytes() != before, "tamper did not actually change the file"
    assert not boundary.launched, "launched after the claude executable changed in place"
    assert result.exit_code != 0
    assert "Claude executable changed" in result.output


# --------------------------------------------------------------------------
# observations -- not part of the refuse/launch bar, pinned so they cannot
# change silently
# --------------------------------------------------------------------------


def test_observation_launched_agent_inherits_unscrubbed_path(boundary, monkeypatch):
    """The agent's own environment is ``os.environ.copy()``, not ``_trusted_tool_env``.

    ``_trusted_search_path`` strips workspace-local PATH entries for the roam and
    git subprocesses the launcher runs itself, but ``cli.py`` builds the agent's
    child environment from the raw process environment. A workspace-local
    directory on PATH therefore survives into the launched agent. Pinning it so
    the choice is visible rather than accidental.
    """
    planted = boundary.repo / "node_modules" / ".bin"
    planted.mkdir(parents=True)
    monkeypatch.setenv("PATH", os.pathsep.join([str(boundary.tools), str(planted)]))

    result = _invoke()

    assert result.exit_code == 0, result.output
    _argv, env = boundary.launches[0]
    assert str(planted) in env["PATH"]
    assert str(planted) not in mod._trusted_search_path()
