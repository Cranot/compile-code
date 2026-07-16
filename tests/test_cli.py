"""compile-code CLI surface tests.

The CLI is a thin product driver over the roam-code toolchain; these tests
pin the surface contract (verbs exist, delegation arguments are correct,
doctor's state reporting) with the toolchain calls stubbed — no index or
subprocess work, so they run anywhere.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

import compile_code.cli as mod


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def roam_calls(monkeypatch):
    """Stub the toolchain; record argv per call."""
    calls = []
    wiring = {"active": False}
    original_project_wired = mod._project_wired

    class _P:
        returncode = 0

    def fake(*args, timeout=600):
        calls.append(list(args))
        if list(args) == ["hooks", "claude", "--write"]:
            wiring["active"] = True
        return _P()

    monkeypatch.setattr(mod, "_roam", fake)
    # Delegation-only tests run from the checkout, whose real Claude settings
    # must not be mutated by the successful stub.
    monkeypatch.setattr(mod, "_wire_roam_midtask_access", lambda **kwargs: None)
    monkeypatch.setattr(mod, "_project_wired", lambda: wiring["active"] or original_project_wired())
    return calls


def _roam_info(
    *,
    path: str | None = "/opt/roam/bin/roam",
    executable_version: str | None = mod.MIN_ROAM_VERSION,
    metadata_version: str | None = mod.MIN_ROAM_VERSION,
    state: str = "ok",
    detail: str | None = None,
) -> dict[str, str | None]:
    return {
        "path": path,
        "version": executable_version,
        "metadata_version": metadata_version,
        "state": state,
        "detail": detail,
    }


@pytest.fixture
def compatible_roam(monkeypatch):
    """Keep CLI tests independent of whichever roam shim the host PATH selects."""
    info = _roam_info()
    monkeypatch.setattr(mod, "_inspect_roam", lambda timeout=10: dict(info))
    return info


class TestSurface:
    def _delegates(self, runner, roam_calls, argv, expected):
        """Invoke argv and assert the toolchain was called exactly once with
        expected. Returns the Click result for any extra assertions."""
        res = runner.invoke(mod.cli, argv)
        assert roam_calls == [expected]
        return res

    def test_help_lists_all_verbs(self, runner):
        res = runner.invoke(mod.cli, ["--help"])
        for verb in ("init", "wire", "unwire", "baseline", "report", "claude", "run", "stats", "doctor"):
            assert verb in res.output

    def test_help_lists_every_registered_command(self, runner):
        # Self-updating: any @cli.command(...) added in future must surface in --help.
        output = runner.invoke(mod.cli, ["--help"]).output
        for name in mod.cli.commands.keys():
            assert name in output, f"registered command {name!r} missing from --help"

    def test_init_delegates(self, runner, roam_calls):
        res = self._delegates(runner, roam_calls, ["init"], ["init"])
        assert res.exit_code == 0

    def test_init_force_uses_index_force(self, runner, roam_calls):
        self._delegates(runner, roam_calls, ["init", "--force"], ["index", "--force"])

    def test_wire_claude_delegates_to_hooks(self, runner, roam_calls):
        res = self._delegates(runner, roam_calls, ["wire", "claude"], ["hooks", "claude", "--write"])
        assert res.exit_code == 0

    def test_wire_no_verify_and_user_flags_pass_through(self, runner, roam_calls):
        self._delegates(
            runner,
            roam_calls,
            ["wire", "claude", "--no-verify", "--user"],
            ["hooks", "claude", "--write", "--no-verify", "--user"],
        )

    def test_unwire_claude(self, runner, roam_calls):
        self._delegates(runner, roam_calls, ["unwire", "claude"], ["hooks", "claude", "--uninstall", "--write"])

    def test_unwire_user_flag_passes_through(self, runner, roam_calls):
        self._delegates(
            runner,
            roam_calls,
            ["unwire", "claude", "--user"],
            ["hooks", "claude", "--uninstall", "--write", "--user"],
        )

    def test_run_compiles_with_auto_artifact(self, runner, roam_calls):
        self._delegates(
            runner,
            roam_calls,
            ["run", "who calls handleSave"],
            ["compile", "who calls handleSave", "--artifact", "auto"],
        )

    def test_run_json_prepends_global_flag(self, runner, roam_calls):
        self._delegates(
            runner,
            roam_calls,
            ["run", "task", "--json"],
            ["--json", "compile", "task", "--artifact", "auto"],
        )

    def test_run_stamps_compile_agent_mode(self, runner, monkeypatch):
        seen = []

        def fake(*args, timeout=600):
            seen.append(mod.os.environ.get("ROAM_AGENT_MODE"))

            class _P:
                returncode = 0

            return _P()

        monkeypatch.setattr(mod, "_roam", fake)
        res = runner.invoke(mod.cli, ["run", "task"])

        assert res.exit_code == 0
        assert seen == ["compile"]
        assert "ROAM_AGENT_MODE" not in mod.os.environ

    def test_run_preserves_codex_agent_mode(self, runner, monkeypatch):
        seen = []

        def fake(*args, timeout=600):
            seen.append(mod.os.environ.get("ROAM_AGENT_MODE"))

            class _P:
                returncode = 0

            return _P()

        monkeypatch.setenv("ROAM_AGENT_MODE", "compile_codex")
        monkeypatch.setattr(mod, "_roam", fake)
        res = runner.invoke(mod.cli, ["run", "task"])

        assert res.exit_code == 0
        assert seen == ["compile_codex"]

    def test_stats_delegates(self, runner, roam_calls):
        self._delegates(runner, roam_calls, ["stats"], ["compile-stats"])

    def test_stats_does_not_stamp_compile_agent_mode(self, runner, monkeypatch):
        seen = []

        def fake(*args, timeout=600):
            seen.append(mod.os.environ.get("ROAM_AGENT_MODE"))

            class _P:
                returncode = 0

            return _P()

        monkeypatch.delenv("ROAM_AGENT_MODE", raising=False)
        monkeypatch.setattr(mod, "_roam", fake)
        res = runner.invoke(mod.cli, ["stats"])

        assert res.exit_code == 0
        assert seen == [None]
        assert "ROAM_AGENT_MODE" not in mod.os.environ

    def test_report_delegates_to_persisted_verify_report(self, runner, roam_calls):
        res = self._delegates(runner, roam_calls, ["report"], ["verify", "--report", "--persist"])
        assert res.exit_code == 0

    def test_baseline_help_lists_the_new_verb(self, runner):
        res = runner.invoke(mod.cli, ["baseline", "--help"])
        assert "Snapshot accepted debt" in res.output

    def test_verify_help_includes_new_only_and_diff_only(self, runner):
        res = runner.invoke(mod.cli, ["verify", "--help"])
        assert "--new-only" in res.output
        assert "--diff-only" in res.output


class TestDependencyFloor:
    def test_runtime_metadata_and_docs_share_the_13_9_floor(self):
        assert mod.MIN_ROAM_VERSION == "13.10.0"
        floor = mod.MIN_ROAM_VERSION
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        assert f'"roam-code>={floor}"' in pyproject
        for name in ("README.md", "AGENTS.md"):
            contents = (ROOT / name).read_text(encoding="utf-8")
            assert re.search(rf"roam-code[^\n]{{0,80}}>=\s*{re.escape(floor)}", contents)


class TestRoamVersionEnforcement:
    @pytest.mark.parametrize(
        ("raw", "compatible"),
        [
            ("13.9.99", False),
            ("13.10.0rc1", False),
            ("13.10.0", True),
            ("13.10.0.post1", True),
            ("13.10.0dev1", False),
            ("not-a-version", False),
        ],
    )
    def test_minimum_comparison(self, raw, compatible):
        assert mod._version_meets_minimum(raw) is compatible

    def test_inspection_runs_the_exact_path_and_keeps_metadata_separate(self, monkeypatch):
        chosen = r"C:\Tools\roam.exe"
        captured = {}

        class _P:
            returncode = 0
            stdout = "roam.EXE, version 13.10.2\n"
            stderr = ""

        def fake_run(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return _P()

        monkeypatch.setattr(mod, "_resolve_roam_executable", lambda: chosen)
        monkeypatch.setattr(mod, "_python_roam_metadata_version", lambda: "99.0.0")
        monkeypatch.setattr(mod.subprocess, "run", fake_run)

        info = mod._inspect_roam()

        assert captured["argv"] == [chosen, "--version"]
        assert info["path"] == chosen
        assert info["version"] == "13.10.2"
        assert info["metadata_version"] == "99.0.0"

    def test_verify_blocks_old_path_executable_even_with_newer_metadata(self, runner, monkeypatch):
        path = r"C:\old-bin\roam.exe"
        monkeypatch.setattr(
            mod,
            "_inspect_roam",
            lambda timeout=10: _roam_info(path=path, executable_version="13.9.9", metadata_version="13.10.4"),
        )
        monkeypatch.setattr(mod, "_roam_capture", lambda *a, **kw: pytest.fail("Verify must not run"))

        res = runner.invoke(mod.cli, ["verify"])

        assert res.exit_code == mod.EXIT_TOOLCHAIN
        assert "toolchain version mismatch" in res.output
        assert path in res.output
        assert "reports 13.9.9" in res.output
        assert "Python metadata reports roam-code 13.10.4" in res.output

    def test_doctor_reports_path_version_and_metadata_separately(self, runner, monkeypatch, tmp_path):
        path = r"C:\old-bin\roam.exe"
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod.os.path, "expanduser", lambda value: str(tmp_path / "home"))
        monkeypatch.setattr(
            mod,
            "_inspect_roam",
            lambda timeout=10: _roam_info(path=path, executable_version="13.9.9", metadata_version="13.10.4"),
        )

        res = runner.invoke(mod.cli, ["doctor"])

        assert res.exit_code == mod.EXIT_TOOLCHAIN
        assert "toolchain : INCOMPATIBLE" in res.output
        assert f"roam path : {path}" in res.output
        assert "roam version: 13.9.9 (required >=13.10.0)" in res.output
        assert "python metadata: roam-code 13.10.4" in res.output


@pytest.mark.usefixtures("compatible_roam")
class TestWiringSmoke:
    def test_wire_round_trip_marks_repo_and_doctor_sees_it(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / "index.db").write_text("")
        (tmp_path / ".claude").mkdir()
        calls = []

        class _P:
            returncode = 0

        def fake(*args, timeout=600):
            calls.append(list(args))
            if list(args) == ["hooks", "claude", "--write"]:
                (tmp_path / ".claude" / "settings.local.json").write_text(f'{{"hooks": "{mod.HOOK_MARKER}"}}')
            return _P()

        monkeypatch.setattr(mod, "_roam", fake)
        res = runner.invoke(mod.cli, ["wire", "claude"])
        assert res.exit_code == 0
        assert calls == [["hooks", "claude", "--write"]]
        doctor = runner.invoke(mod.cli, ["doctor"])
        assert "wired (project)" in doctor.output
        assert "VERDICT: ready" in doctor.output


class TestRoamMidtaskWiring:
    def _stub_successful_hook_write(self, monkeypatch, tmp_path):
        class _P:
            returncode = 0

        def fake(*args, timeout=600):
            assert list(args) == ["hooks", "claude", "--write"]
            settings = tmp_path / ".claude" / "settings.json"
            settings.parent.mkdir(exist_ok=True)
            settings.write_text(f'{{"hooks": "{mod.HOOK_MARKER}"}}')
            return _P()

        monkeypatch.setattr(mod, "_roam", fake)

    def test_wire_adds_curated_permissions_and_guidance_once(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        self._stub_successful_hook_write(monkeypatch, tmp_path)
        local_settings = tmp_path / ".claude" / "settings.local.json"
        local_settings.parent.mkdir()
        local_settings.write_text('{"permissions": {"allow": ["Bash(pytest:*)"]}, "theme": "dark"}')
        (tmp_path / "CLAUDE.md").write_text("# Existing instructions\n\nKeep this text.\n")

        first = runner.invoke(mod.cli, ["wire", "claude"])
        second = runner.invoke(mod.cli, ["wire", "claude"])

        assert first.exit_code == second.exit_code == 0
        settings = json.loads(local_settings.read_text())
        allow = settings["permissions"]["allow"]
        assert settings["theme"] == "dark"
        assert "Bash(pytest:*)" in allow
        for entry in mod.ROAM_MIDTASK_ALLOW:
            assert allow.count(entry) == 1
        guidance = (tmp_path / "CLAUDE.md").read_text()
        assert guidance.startswith("# Existing instructions\n\nKeep this text.\n")
        assert guidance.count(mod.ROAM_GUIDANCE_BEGIN) == 1
        assert guidance.count(mod.ROAM_GUIDANCE_END) == 1
        for command in mod.ROAM_MIDTASK_COMMANDS:
            assert guidance.count(f"`roam {command} --json`") == 1
        assert "roam ask --json" not in guidance
        assert "launch-time graph" in guidance
        assert "edits are invisible until the Stop hook" in guidance

    def test_wire_leaves_malformed_local_settings_and_guidance_untouched(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        self._stub_successful_hook_write(monkeypatch, tmp_path)
        local_settings = tmp_path / ".claude" / "settings.local.json"
        local_settings.parent.mkdir()
        local_settings.write_text("{not-json\n")
        claude_md = tmp_path / "CLAUDE.md"
        claude_md.write_text("# Existing instructions\n")

        result = runner.invoke(mod.cli, ["wire", "claude"])

        assert result.exit_code == 0
        assert local_settings.read_text() == "{not-json\n"
        assert claude_md.read_text() == "# Existing instructions\n"


class TestClaudeLaunch:
    def test_missing_claude_binary_exits_1(self, runner, roam_calls, monkeypatch):
        monkeypatch.setattr(mod, "_on_path", lambda name: False)
        res = runner.invoke(mod.cli, ["claude"])
        assert res.exit_code == 1
        assert "not found on PATH" in res.output

    def _stub_launch(self, monkeypatch, rc=0):
        """Stub the launch seam; record (argv, env) per call."""
        launches = []

        def fake(argv, env, *, use_exec=None):
            launches.append((list(argv), dict(env)))
            return rc

        monkeypatch.setattr(mod, "_launch_agent", fake)
        return launches

    def test_indexes_wires_then_execs(self, runner, roam_calls, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)  # no index here
        monkeypatch.setattr(mod, "_on_path", lambda name: True)
        launches = self._stub_launch(monkeypatch)
        res = runner.invoke(mod.cli, ["claude", "--", "-p", "hello"])
        assert res.exit_code == 0
        assert ["init"] in roam_calls
        assert ["hooks", "claude", "--write"] in roam_calls
        assert launches and launches[0][0][0] == "claude"

    def test_skips_wiring_when_repo_is_already_wired(self, runner, roam_calls, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_on_path", lambda name: True)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".claude" / "settings.local.json").write_text(f'{{"hooks": "{mod.HOOK_MARKER}"}}')
        launches = self._stub_launch(monkeypatch)
        res = runner.invoke(mod.cli, ["claude"])
        assert res.exit_code == 0
        assert roam_calls == []
        assert launches and launches[0][0][0] == "claude"

    def test_wires_when_repo_is_indexed_but_unwired(self, runner, roam_calls, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_on_path", lambda name: True)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        launches = self._stub_launch(monkeypatch)
        res = runner.invoke(mod.cli, ["claude"])
        assert res.exit_code == 0
        assert ["hooks", "claude", "--write"] in roam_calls
        assert launches and launches[0][0][0] == "claude"

    def test_launch_exit_code_propagates(self, runner, roam_calls, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_on_path", lambda name: True)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".claude" / "settings.local.json").write_text(f'{{"hooks": "{mod.HOOK_MARKER}"}}')
        self._stub_launch(monkeypatch, rc=7)
        res = runner.invoke(mod.cli, ["claude"])
        assert res.exit_code == 7

    def test_read_only_sets_child_mode_enforcement(self, runner, roam_calls, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_on_path", lambda name: True)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        monkeypatch.delenv("ROAM_AGENT_MODE", raising=False)
        monkeypatch.delenv("ROAM_MODE_ENFORCEMENT", raising=False)
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".claude" / "settings.local.json").write_text(f'{{"hooks": "{mod.HOOK_MARKER}"}}')
        launches = self._stub_launch(monkeypatch)

        res = runner.invoke(mod.cli, ["claude", "--read-only"])

        assert res.exit_code == 0
        child_env = launches[0][1]
        assert child_env["ROAM_AGENT_MODE"] == "read_only"
        assert child_env["ROAM_MODE_ENFORCEMENT"] == "1"

    def test_claude_stamps_compile_claude_agent_mode(self, runner, roam_calls, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_on_path", lambda name: True)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        monkeypatch.delenv("ROAM_AGENT_MODE", raising=False)
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".claude" / "settings.local.json").write_text(f'{{"hooks": "{mod.HOOK_MARKER}"}}')
        launches = self._stub_launch(monkeypatch)

        res = runner.invoke(mod.cli, ["claude"])

        assert res.exit_code == 0
        assert launches[0][1]["ROAM_AGENT_MODE"] == "compile_claude"

    def test_hook_commands_put_override_before_maintenance_subcommands(self):
        source = """
def command(args):
    return ["roam", "--json", *args]

direct_verify = ["roam", "verify", "--auto"]
direct_index = ["roam", "index", "--quiet"]
"""
        namespace = {}

        exec(mod._override_hook_maintenance_commands(source), namespace)

        assert namespace["command"](["verify", "--auto"]) == ["roam", "--override-mode", "--json", "verify", "--auto"]
        assert namespace["command"](["index", "--quiet"]) == ["roam", "--override-mode", "--json", "index", "--quiet"]
        assert namespace["command"](["critique"]) == ["roam", "--json", "critique"]
        assert namespace["direct_verify"] == ["roam", "--override-mode", "verify", "--auto"]
        assert namespace["direct_index"] == ["roam", "--override-mode", "index", "--quiet"]


@pytest.mark.usefixtures("compatible_roam")
class TestDoctor:
    def test_doctor_reports_present_verify_report_age(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(tmp_path / "home"))
        monkeypatch.setattr(mod.time, "time", lambda: 10_000.0)
        (tmp_path / ".roam").mkdir()
        report = tmp_path / ".roam" / "verify-report.json"
        report.write_text("{}")
        mod.os.utime(report, (9_880, 9_880))
        res = runner.invoke(mod.cli, ["doctor"])
        assert "verify report: present (2m old)" in res.output

    def test_doctor_reports_absent_verify_report(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(tmp_path / "home"))
        res = runner.invoke(mod.cli, ["doctor"])
        assert "verify report: none — run `compile report`" in res.output

    def test_doctor_reports_unwired_state(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(tmp_path / "home"))
        res = runner.invoke(mod.cli, ["doctor"])
        assert "absent" in res.output and "not wired" in res.output
        assert "install ok" in res.output

    def test_doctor_fails_without_toolchain(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            mod,
            "_inspect_roam",
            lambda timeout=10: _roam_info(
                path=None, executable_version=None, metadata_version="13.10.0", state="missing"
            ),
        )
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(tmp_path / "home"))
        res = runner.invoke(mod.cli, ["doctor"])
        assert res.exit_code == 2
        assert "toolchain missing" in res.output

    def test_doctor_sees_project_wiring(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(tmp_path / "home"))
        (tmp_path / ".claude").mkdir()
        (tmp_path / ".claude" / "settings.json").write_text('{"hooks": "roam-compile-ups.py"}')
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / "index.db").write_text("")
        res = runner.invoke(mod.cli, ["doctor"])
        assert "wired (project)" in res.output
        assert "VERDICT: ready" in res.output
        assert res.exit_code == 0

    def test_doctor_sees_user_global_wiring(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        home = tmp_path / "home"
        (home / ".claude").mkdir(parents=True)
        (home / ".claude" / "settings.json").write_text('{"hooks": "roam-compile-ups.py"}')
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(home))
        res = runner.invoke(mod.cli, ["doctor"])
        assert "wired (user-global)" in res.output


class TestFailurePaths:
    """Every toolchain failure mode must surface as a clean VERDICT line
    with the documented exit code — never a traceback."""

    def _raise_missing(self, *args, timeout=600):
        raise FileNotFoundError("roam")

    def _raise_timeout(self, *args, timeout=600):
        raise mod.subprocess.TimeoutExpired(cmd=["roam"], timeout=timeout)

    @pytest.mark.parametrize(
        "argv",
        [
            ["init"],
            ["wire", "claude"],
            ["unwire", "claude"],
            ["run", "task"],
            ["stats"],
        ],
    )
    def test_missing_toolchain_is_a_verdict_not_a_traceback(self, runner, monkeypatch, argv):
        monkeypatch.setattr(mod, "_roam", self._raise_missing)
        res = runner.invoke(mod.cli, argv)
        assert res.exit_code == 2
        assert "VERDICT: toolchain missing" in res.output
        assert "Traceback" not in res.output

    def test_timeout_is_a_verdict_with_exit_124(self, runner, monkeypatch):
        monkeypatch.setattr(mod, "_roam", self._raise_timeout)
        res = runner.invoke(mod.cli, ["run", "task"])
        assert res.exit_code == 124
        assert "timed out" in res.output

    def _raise_broken(self, *args, timeout=600):
        raise PermissionError(13, "Access is denied", "roam")

    @pytest.mark.parametrize("argv", [["init"], ["run", "task"], ["stats"]])
    def test_broken_toolchain_is_a_verdict_not_a_traceback(self, runner, monkeypatch, argv):
        # On PATH but unlaunchable (broken shim, wrong arch, permissions):
        # the docstring contract says exit 2 "toolchain missing/broken".
        monkeypatch.setattr(mod, "_roam", self._raise_broken)
        res = runner.invoke(mod.cli, argv)
        assert res.exit_code == 2
        assert "VERDICT: toolchain broken" in res.output
        assert "Traceback" not in res.output

    def test_run_refuses_empty_task_without_touching_the_toolchain(self, runner, monkeypatch):
        monkeypatch.setattr(mod, "_roam", lambda *a, timeout=600: pytest.fail("must not call the toolchain"))
        res = runner.invoke(mod.cli, ["run", "   "])
        assert res.exit_code == 1
        assert "VERDICT: empty task" in res.output


@pytest.mark.usefixtures("compatible_roam")
class TestVerifyToolchainFailureIsNotAVerifyFailure:
    """`compile verify` must not stack its failure block on a toolchain that
    never ran — and must not confuse roam's exit 2 (bad arguments) with the
    CLI's own EXIT_TOOLCHAIN (also 2)."""

    def test_missing_toolchain_skips_the_failure_block(self, runner, monkeypatch):
        def raise_missing(*args, timeout=600, executable="roam"):
            raise FileNotFoundError("roam")

        monkeypatch.setattr(mod, "_roam_capture", raise_missing)
        res = runner.invoke(mod.cli, ["verify", "x.py"])
        assert res.exit_code == 2
        assert "VERDICT: toolchain missing" in res.output
        assert "verify failed" not in res.output

    def test_broken_toolchain_skips_the_failure_block(self, runner, monkeypatch):
        def raise_broken(*args, timeout=600, executable="roam"):
            raise PermissionError(13, "Access is denied", "roam")

        monkeypatch.setattr(mod, "_roam_capture", raise_broken)
        res = runner.invoke(mod.cli, ["verify", "x.py"])
        assert res.exit_code == 2
        assert "VERDICT: toolchain broken" in res.output
        assert "verify failed" not in res.output

    def test_timeout_skips_the_failure_block(self, runner, monkeypatch):
        def raise_timeout(*args, timeout=600, executable="roam"):
            raise mod.subprocess.TimeoutExpired(cmd=["roam"], timeout=timeout)

        monkeypatch.setattr(mod, "_roam_capture", raise_timeout)
        res = runner.invoke(mod.cli, ["verify", "x.py"])
        assert res.exit_code == 124
        assert "timed out" in res.output
        assert "verify failed" not in res.output

    def test_roam_exit_2_bad_arguments_gets_the_failure_block(self, runner, monkeypatch):
        # roam ran and exited 2 on its own: that is a completed verify run,
        # so the explained block must appear with the exit-code cause.
        class _P:
            returncode = 2
            stdout = "error: unknown flag --bogus\n"

        monkeypatch.setattr(mod, "_roam_capture", lambda *a, timeout=600, executable="roam": _P())
        res = runner.invoke(mod.cli, ["verify", "x.py"])
        assert res.exit_code == 2
        assert "VERDICT: verify failed." in res.output
        assert "cause   : bad arguments" in res.output

    def test_toolchain_stderr_is_surfaced_on_failure(self, runner, monkeypatch):
        # A roam crash (rc=1, diagnostics only on stderr) must keep its
        # diagnostic instead of collapsing to a bare "verify failure".
        class _P:
            returncode = 1
            stdout = ""
            stderr = "RuntimeError: kernel exploded\n"

        monkeypatch.setattr(mod, "_roam_capture", lambda *a, timeout=600, executable="roam": _P())
        res = runner.invoke(mod.cli, ["verify", "x.py"])
        assert res.exit_code == 1
        assert "kernel exploded" in res.stderr
        assert "VERDICT: verify failed." in res.output


class TestLaunchAgentFailurePaths:
    """The agent launch seam maps every launch failure to a verdict + code —
    the PATH check at command start is advisory, so the race where the binary
    vanishes or cannot start must not traceback."""

    def test_exec_branch_hands_env_and_argv_to_execvp(self, monkeypatch):
        monkeypatch.setattr(mod.os, "environ", dict(mod.os.environ))
        recorded = {}
        monkeypatch.setattr(mod.os, "execvp", lambda f, argv: recorded.update(file=f, argv=argv))
        rc = mod._launch_agent(["claude", "-p", "hi"], {"ROAM_AGENT_MODE": "compile_claude"}, use_exec=True)
        assert rc == 0
        assert recorded["file"] == "claude"
        assert recorded["argv"] == ["claude", "-p", "hi"]
        assert mod.os.environ["ROAM_AGENT_MODE"] == "compile_claude"

    def test_child_branch_propagates_exit_code(self, monkeypatch):
        class _P:
            returncode = 7

        monkeypatch.setattr(mod.subprocess, "run", lambda argv, check, env: _P())
        assert mod._launch_agent(["claude"], {}, use_exec=False) == 7

    def test_vanished_binary_is_a_verdict_exit_1(self, monkeypatch, capsys):
        def raise_missing(argv, check, env):
            raise FileNotFoundError("claude")

        monkeypatch.setattr(mod.subprocess, "run", raise_missing)
        assert mod._launch_agent(["claude"], {}, use_exec=False) == 1
        assert "vanished from PATH" in capsys.readouterr().out

    def test_unlaunchable_binary_is_a_verdict_exit_1(self, monkeypatch, capsys):
        monkeypatch.setattr(mod.os, "environ", dict(mod.os.environ))

        def raise_broken(f, argv):
            raise OSError(8, "Exec format error")

        monkeypatch.setattr(mod.os, "execvp", raise_broken)
        assert mod._launch_agent(["claude"], {}, use_exec=True) == 1
        assert "could not launch" in capsys.readouterr().out

    def test_interrupt_maps_to_130(self, monkeypatch, capsys):
        def raise_interrupt(argv, check, env):
            raise KeyboardInterrupt()

        monkeypatch.setattr(mod.subprocess, "run", raise_interrupt)
        assert mod._launch_agent(["claude"], {}, use_exec=False) == 130
        assert "interrupted" in capsys.readouterr().out


@pytest.mark.usefixtures("compatible_roam")
class TestEncodingRobustness:
    """Settings and marker files written in non-UTF-8 encodings (PowerShell
    defaults to UTF-16 with a BOM) must degrade gracefully, never traceback."""

    def test_wired_in_treats_utf16_settings_as_unwired(self, tmp_path):
        settings = tmp_path / "settings.local.json"
        with open(settings, "w", encoding="utf-16") as fh:
            fh.write(f'{{"hooks": "{mod.HOOK_MARKER}"}}')
        assert mod._wired_in(str(settings)) is False

    def test_doctor_survives_utf16_settings_file(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod.os.path, "expanduser", lambda p: str(tmp_path / "home"))
        (tmp_path / ".claude").mkdir()
        with open(tmp_path / ".claude" / "settings.local.json", "w", encoding="utf-16") as fh:
            fh.write(f'{{"hooks": "{mod.HOOK_MARKER}"}}')
        res = runner.invoke(mod.cli, ["doctor"])
        assert res.exit_code == 0
        assert "not wired" in res.output
        assert "Traceback" not in res.output

    def test_merge_roam_guidance_leaves_utf16_claude_md_untouched(self, tmp_path):
        claude_md = tmp_path / "CLAUDE.md"
        with open(claude_md, "w", encoding="utf-16") as fh:
            fh.write("# Existing instructions\n")
        before = claude_md.read_bytes()
        mod._merge_roam_guidance(str(claude_md))  # must not raise
        assert claude_md.read_bytes() == before

    def test_corrupt_launch_head_marker_reads_as_unknown(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / ".compile-code-launch-head").write_bytes(b"\xff\xfe\x00garbage")
        assert mod._launch_index_head() is None


class TestEnsureIndexedForLaunch:
    """The index-delegation contract, tested directly — no click context."""

    def test_returns_0_when_already_indexed_and_head_is_unchanged(self, monkeypatch, capsys, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        monkeypatch.setattr(mod, "_delegate", lambda *a: pytest.fail("must not index"))
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        assert mod._ensure_indexed_for_launch() == 0
        assert capsys.readouterr().out == ""

    def test_indexes_on_first_run_and_returns_0(self, monkeypatch, capsys):
        monkeypatch.setattr(mod, "_require_index", lambda: False)
        calls = []
        monkeypatch.setattr(mod, "_delegate", lambda *a: calls.append(a) or 0)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        wrote = {}

        def mark(head=None):
            wrote["head"] = head

        monkeypatch.setattr(mod, "_mark_launch_indexed", mark)
        assert mod._ensure_indexed_for_launch() == 0
        assert calls == [("init",)]
        assert wrote == {"head": None}
        assert "indexing repo (first run)" in capsys.readouterr().out

    def test_indexing_failure_yields_verdict_and_code(self, monkeypatch, capsys):
        monkeypatch.setattr(mod, "_require_index", lambda: False)
        monkeypatch.setattr(mod, "_delegate", lambda *a: 2)
        assert mod._ensure_indexed_for_launch() == 2
        assert "VERDICT: indexing failed" in capsys.readouterr().out

    def test_reindexes_when_head_marker_is_missing(self, monkeypatch, capsys):
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        monkeypatch.setattr(mod, "_launch_index_head", lambda: None)
        calls = []
        monkeypatch.setattr(mod, "_delegate", lambda *a: calls.append(a) or 0)
        wrote = {}
        monkeypatch.setattr(mod, "_mark_launch_indexed", lambda head=None: wrote.setdefault("head", head))
        assert mod._ensure_indexed_for_launch() == 0
        assert calls == [("index",)]
        assert wrote == {"head": None}
        assert "HEAD drift" in capsys.readouterr().out

    def test_reindexes_when_head_marker_changed(self, monkeypatch, capsys):
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")
        monkeypatch.setattr(mod, "_launch_index_head", lambda: "fff999")
        calls = []
        monkeypatch.setattr(mod, "_delegate", lambda *a: calls.append(a) or 0)
        wrote = {}
        monkeypatch.setattr(mod, "_mark_launch_indexed", lambda head=None: wrote.setdefault("head", head))
        assert mod._ensure_indexed_for_launch() == 0
        assert calls == [("index",)]
        assert wrote == {"head": None}
        assert "HEAD drift" in capsys.readouterr().out


class TestFailurePathsLaunch:
    def test_claude_launch_blocks_on_wire_failure_by_default(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / "index.db").write_text("")
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        (tmp_path / ".claude").mkdir()
        monkeypatch.setattr(mod, "_on_path", lambda name: True)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")

        class _Fail:
            returncode = 1

        monkeypatch.setattr(mod, "_roam", lambda *a, timeout=600: _Fail())
        launches = []
        monkeypatch.setattr(mod, "_launch_agent", lambda argv, env, **kw: launches.append(list(argv)) or 0)
        res = runner.invoke(mod.cli, ["claude"])
        assert "VERDICT: wiring failed" in res.output
        assert launches == []
        assert res.exit_code == 1

    def test_claude_launch_requires_explicit_opt_in_to_continue_unwired(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".roam").mkdir()
        (tmp_path / ".roam" / "index.db").write_text("")
        (tmp_path / ".roam" / ".compile-code-launch-head").write_text("abc123\n")
        monkeypatch.setattr(mod, "_on_path", lambda name: True)
        monkeypatch.setattr(mod, "_require_index", lambda: True)
        monkeypatch.setattr(mod, "_launch_head", lambda: "abc123")

        class _Fail:
            returncode = 1

        monkeypatch.setattr(mod, "_roam", lambda *a, timeout=600: _Fail())
        launches = []
        monkeypatch.setattr(mod, "_launch_agent", lambda argv, env, **kw: launches.append(list(argv)) or 0)

        res = runner.invoke(mod.cli, ["claude", "--allow-unwired"])

        assert "explicit degraded launch accepted" in res.output
        assert launches and launches[0][0] == "claude"
        assert res.exit_code == 0


@pytest.mark.usefixtures("compatible_roam")
class TestVerifyFailureFormatting:
    """`compile verify` must turn a roam verify failure into a block that names
    the failing command, the changed files, a likely cause, and one local rerun."""

    FAIL_OUTPUT = (
        "VERDICT: FAIL (score 60/100) -- 2 issues in 1 changed file\n"
        "checks: naming, imports, error_handling, duplicates, syntax\n\n"
        "NAMING (40/100):\n"
        "  FAIL: src/bad.py:12 -- function 'Foo' should be snake_case\n\n"
        "SYNTAX (0/100):\n"
        "  FAIL: src/bad.py:30 -- python syntax error at line 30: unexpected indent\n"
    )

    def _capture(self, output, rc):
        """Stub _roam_capture to return a CompletedProcess-shaped object."""
        captured = {}

        class _P:
            def __init__(self, args):
                captured["args"] = list(args)

            returncode = rc
            stdout = output

        def fake(*args, timeout=600, executable="roam"):
            captured["executable"] = executable
            return _P(args)

        return fake, captured

    def test_failing_files_dedupes_in_order(self):
        assert mod._failing_files(self.FAIL_OUTPUT) == ["src/bad.py"]

    def test_status_parser_covers_staged_unstaged_untracked_rename_and_deletion(self):
        raw = "M  staged.py\0 M unstaged.py\0?? untracked.py\0R  renamed.py\0old.py\0D  deleted.py\0"
        assert mod._parse_changed_status_paths(raw) == [
            "staged.py",
            "unstaged.py",
            "untracked.py",
            "renamed.py",
            "old.py",
            "deleted.py",
        ]

    def test_oversized_helper_returns_advisory_above_cap(self):
        advisory = mod._oversized_target_set([f"f{i}.py" for i in range(26)], cap=25)
        assert isinstance(advisory, str) and advisory
        assert "scope down" in advisory

    def test_oversized_helper_silent_at_or_below_cap(self):
        assert mod._oversized_target_set(["a.py", "b.py"], cap=25) is None
        assert mod._oversized_target_set([f"f{i}.py" for i in range(25)], cap=25) is None

    def test_classify_maps_failing_sections_to_causes(self):
        assert mod._classify_verify_failure(self.FAIL_OUTPUT, 5) == "naming violation + syntax error"

    def test_classify_falls_back_to_exit_code_without_fail_lines(self):
        assert mod._classify_verify_failure("VERDICT: FAIL (score 0/100)\n", 5) == "quality gate"
        assert mod._classify_verify_failure("no index\n", 3) == "index missing"
        assert mod._classify_verify_failure("oops\n", 99) == "verify failure"

    def test_format_contains_all_four_components(self):
        block = mod._format_verify_failure(
            command="compile verify src/bad.py",
            files=["src/bad.py"],
            cause="syntax error",
            next_action="compile verify src/bad.py",
        )
        assert block.startswith("VERDICT: verify failed.")
        assert "command : compile verify src/bad.py" in block
        assert "files   : src/bad.py" in block
        assert "cause   : syntax error" in block
        assert "next    : compile verify src/bad.py" in block

    def test_format_shows_placeholder_when_no_changed_files(self):
        block = mod._format_verify_failure(
            command="compile verify --changed", files=[], cause="quality gate", next_action="compile verify --changed"
        )
        assert "files   : (no changed files)" in block

    def test_verify_failure_emits_block_and_exit_5(self, runner, monkeypatch, compatible_roam):
        fake, captured = self._capture(self.FAIL_OUTPUT, 5)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        monkeypatch.setattr(mod, "_changed_files", lambda: pytest.fail("parsed failures need no local discovery"))
        res = runner.invoke(mod.cli, ["verify"])
        assert res.exit_code == 5
        # roam's raw output is preserved...
        assert "FAIL: src/bad.py:12" in res.output
        # ...and the explained block carries all four components.
        assert "VERDICT: verify failed." in res.output
        assert "command : compile verify --changed" in res.output
        assert "files   : src/bad.py" in res.output
        assert "cause   : naming violation + syntax error" in res.output
        assert "next    : compile verify src/bad.py" in res.output
        # No-argument correctness belongs to roam's canonical discovery.
        assert captured["args"] == ["verify", "--threshold", "70", "--changed"]
        assert captured["executable"] == compatible_roam["path"]

    def test_verify_pass_streams_roam_output_without_block(self, runner, monkeypatch):
        fake, _ = self._capture("VERDICT: PASS (score 100/100) -- no issues\n", 0)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        res = runner.invoke(mod.cli, ["verify", "src/cli.py"])
        assert res.exit_code == 0
        assert "VERDICT: PASS" in res.output
        assert "verify failed" not in res.output

    @pytest.mark.parametrize("output", ["", "checks completed without a verdict\n"], ids=["empty", "malformed"])
    def test_zero_exit_requires_parseable_success_verdict(self, output, runner, monkeypatch):
        fake, _ = self._capture(output, 0)
        monkeypatch.setattr(mod, "_roam_capture", fake)

        res = runner.invoke(mod.cli, ["verify", "src/cli.py"])

        assert res.exit_code == mod.EXIT_TOOLCHAIN
        assert "VERDICT: verifier protocol failure" in res.output
        assert "verify failed" not in res.output

    def test_zero_exit_accepts_an_explicit_warn_verdict(self, runner, monkeypatch):
        fake, _ = self._capture("VERDICT: WARN (score 75/100) -- review findings\n", 0)
        monkeypatch.setattr(mod, "_roam_capture", fake)

        res = runner.invoke(mod.cli, ["verify", "src/cli.py"])

        assert res.exit_code == 0
        assert "VERDICT: WARN" in res.output
        assert "verifier protocol failure" not in res.output

    def test_zero_exit_rejects_a_skipped_verifier(self, runner, monkeypatch):
        fake, _ = self._capture(
            "VERDICT: SKIPPED -- verify disabled in .roam/verify.yaml\n",
            0,
        )
        monkeypatch.setattr(mod, "_roam_capture", fake)

        res = runner.invoke(mod.cli, ["verify", "src/cli.py"])

        assert res.exit_code == mod.EXIT_TOOLCHAIN
        assert "VERDICT: verifier protocol failure" in res.output

    def test_completed_nonzero_output_and_exit_code_are_preserved(self, runner, monkeypatch):
        fake, _ = self._capture("kernel diagnostic from completed run\n", 17)
        monkeypatch.setattr(mod, "_roam_capture", fake)

        res = runner.invoke(mod.cli, ["verify", "src/cli.py"])

        assert res.exit_code == 17
        assert "kernel diagnostic from completed run" in res.output
        assert "VERDICT: verify failed." in res.output
        assert "verifier protocol failure" not in res.output

    def test_verify_threshold_passes_through_and_shows_in_command(self, runner, monkeypatch):
        fake, captured = self._capture(self.FAIL_OUTPUT, 5)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        res = runner.invoke(mod.cli, ["verify", "--threshold", "90", "src/bad.py"])
        assert res.exit_code == 5
        assert captured["args"] == ["verify", "--threshold", "90", "src/bad.py"]
        assert "command : compile verify --threshold 90 src/bad.py" in res.output

    def test_verify_new_only_and_diff_only_pass_through(self, runner, monkeypatch):
        fake, captured = self._capture(self.FAIL_OUTPUT, 5)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        res = runner.invoke(mod.cli, ["verify", "--new-only", "--diff-only", "src/bad.py"])
        assert res.exit_code == 5
        assert captured["args"] == ["verify", "--new-only", "--diff-only", "--threshold", "70", "src/bad.py"]
        assert "command : compile verify --new-only --diff-only src/bad.py" in res.output
        assert "next    : compile verify --new-only --diff-only src/bad.py" in res.output

    def test_verify_no_argument_delegates_changed_without_local_discovery(self, runner, monkeypatch):
        fake, captured = self._capture("VERDICT: PASS (score 100/100) -- no changed files\n", 0)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        monkeypatch.setattr(mod, "_changed_files", lambda: pytest.fail("success must not depend on local discovery"))
        res = runner.invoke(mod.cli, ["verify"])
        assert res.exit_code == 0
        assert captured["args"] == ["verify", "--threshold", "70", "--changed"]

    def test_no_argument_failure_uses_status_only_for_human_context(self, runner, monkeypatch):
        fake, captured = self._capture("VERDICT: FAIL (score 60/100) -- discovery-level failure\n", 5)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        status_paths = ["staged.py", "unstaged.py", "untracked.py", "renamed.py", "old.py", "deleted.py"]
        monkeypatch.setattr(mod, "_changed_files", lambda: status_paths)

        res = runner.invoke(mod.cli, ["verify"])

        assert res.exit_code == 5
        assert captured["args"] == ["verify", "--threshold", "70", "--changed"]
        assert f"files   : {', '.join(status_paths)}" in res.output
        assert "next    : compile verify --changed" in res.output

    def test_failure_block_reports_parsed_failing_scope_not_all_targets(self, runner, monkeypatch):
        fake, captured = self._capture(self.FAIL_OUTPUT, 5)
        monkeypatch.setattr(mod, "_roam_capture", fake)

        res = runner.invoke(mod.cli, ["verify", "src/good.py", "src/bad.py"])

        assert res.exit_code == 5
        assert captured["args"] == ["verify", "--threshold", "70", "src/good.py", "src/bad.py"]
        assert "command : compile verify src/good.py src/bad.py" in res.output
        assert "files   : src/bad.py" in res.output
        assert "next    : compile verify src/bad.py" in res.output

    def test_oversized_advisory_does_not_change_delegation(self, runner, monkeypatch):
        fake, captured = self._capture(self.FAIL_OUTPUT, 5)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        files = [f"f{i}.py" for i in range(30)]
        res = runner.invoke(mod.cli, ["verify", *files])
        assert res.exit_code == 5
        assert "scope down" in res.output
        assert captured["args"] == ["verify", "--threshold", "70", *files]

    def test_no_advisory_for_small_explicit_list(self, runner, monkeypatch):
        fake, _ = self._capture("VERDICT: PASS (score 100/100) -- no issues\n", 0)
        monkeypatch.setattr(mod, "_roam_capture", fake)
        res = runner.invoke(mod.cli, ["verify", "a.py", "b.py"])
        assert "scope down" not in res.output


class TestBaselineVerb:
    def test_baseline_refuses_dirty_tree(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_git_status_porcelain", lambda timeout=10: (0, " M src/cli.py\n"))
        monkeypatch.setattr(mod, "_roam", lambda *a, timeout=600: pytest.fail("must not baseline dirty trees"))
        res = runner.invoke(mod.cli, ["baseline"])
        assert res.exit_code == 1
        assert "dirty tree" in res.output

    def test_baseline_uses_report_baseline_write_with_raised_timeout(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mod, "_git_status_porcelain", lambda timeout=10: (0, ""))
        calls = []

        class _P:
            returncode = 0

        def fake(*args, timeout=600):
            calls.append((list(args), timeout))
            return _P()

        monkeypatch.setattr(mod, "_roam", fake)
        res = runner.invoke(mod.cli, ["baseline"])
        assert res.exit_code == 0
        assert calls == [(["verify", "--report", "--baseline-write"], mod.BASELINE_TIMEOUT)]

    def test_baseline_can_target_source_dirs(self, runner, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "src").mkdir()
        (tmp_path / "tests").mkdir()
        monkeypatch.setattr(mod, "_git_status_porcelain", lambda timeout=10: (0, ""))
        calls = []

        class _P:
            returncode = 0

        def fake(*args, timeout=600):
            calls.append((list(args), timeout))
            return _P()

        monkeypatch.setattr(mod, "_roam", fake)
        res = runner.invoke(mod.cli, ["baseline", "src", "tests"])
        assert res.exit_code == 0
        assert calls == [(["verify", "--report", "--baseline-write", "src", "tests"], mod.BASELINE_TIMEOUT)]


class TestCommandInventory:
    def test_inventory_is_deterministic_and_complete(self):
        from compile_code.cli import _format_command_inventory

        commands = mod.cli.commands
        out1 = _format_command_inventory(commands)
        out2 = _format_command_inventory(commands)
        assert out1 == out2
        lines = out1.splitlines()
        names = [ln.split(" ", 1)[0] for ln in lines]
        assert names == sorted(mod.cli.commands.keys())
        assert set(names) == set(mod.cli.commands.keys())

    def test_commands_verb_prints_inventory(self, runner):
        res = runner.invoke(mod.cli, ["commands"])
        assert res.exit_code == 0
        from compile_code.cli import _format_command_inventory

        assert res.output.strip() == _format_command_inventory(mod.cli.commands).strip()
